"""Post-hoc analysis of a captured conversation for identity deception and
mid-session model switches.

The live deception layer probes an endpoint; this analyzes an already-captured
transcript (the z.ai "I am Gemini" -> "actually I'm GLM" case). It reconstructs
the assistant's asserted identity per turn, detects IDENTITY FLIPS (the model's
story changing mid-session = a model-switch tell), finds PRC-jurisdiction
denials, and correlates the worn persona against a known true origin to produce
a misrepresentation verdict plus a recorded timeline of model-change events.

    turns ──► per assistant turn: asserted identity  ┐
                                  concession to CN    ├─► timeline
                                  jurisdiction denial ┘        │
                                                               ▼
            persona{dominant_claim} + jurisdiction{denies}  correlate(true_origin)
                                                               ▼
                       verdict + model_change_events (flips/concessions), signed like any bundle
"""
from __future__ import annotations
import json
import re

from ..data.corpus import CLAIMED_PERSONAS, PRC_MODEL_TOKENS
from . import deception as _dec  # reuse DENIAL / AFFIRM_PRC / correlate

# "I am X" / "developed by X" — the model asserting an identity as its own.
_SELF_ATTR = re.compile(
    r"(?:\bi am\b|\bi'm\b|\bi was\b|(?:created|developed|built|made|powered)\s+by|based on)"
    r"\s+(.{0,50})", re.I)
# Conceding that the real backend is a CN family ("actually GLM", "the engine is GLM",
# "not ... Gemini", "generating these words is GLM").
_CONCESSION = re.compile(
    r"(?:actually|really|underlying|backend|engine|generating|powering|talking to|hitting)\b",
    re.I)


def _western(brand: str | None) -> bool:
    return bool(brand) and not any(
        k in brand.lower() for k in ("zhipu", "glm", "qwen", "deepseek", "alibaba",
                                     "moonshot", "minimax", "baidu", "tencent", "01.ai",
                                     "internlm", "baichuan", "chatglm"))


def _brands_in(span: str) -> list[str]:
    low = span.lower()
    out = []
    for tok, brand in CLAIMED_PERSONAS.items():
        if re.search(rf"\b{re.escape(tok)}\b", low):
            out.append(brand)
    for tok, fam in PRC_MODEL_TOKENS.items():
        if tok in low:
            out.append(fam)
    seen, uniq = set(), []
    for b in out:
        if b not in seen:
            seen.add(b)
            uniq.append(b)
    return uniq


def _turn_identity(text: str) -> dict:
    """Asserted identity for one assistant turn.

    asserted  = the brand it claims to BE (self-attribution).
    conceded  = a CN family it admits is the real backend (concession context).
    """
    asserted = None
    for m in _SELF_ATTR.finditer(text):
        for b in _brands_in(m.group(1)):
            asserted = b
            break
        if asserted:
            break
    conceded = None
    if _CONCESSION.search(text):
        for b in _brands_in(text):
            if not _western(b):
                conceded = b
                break
    return {"asserted": asserted, "conceded": conceded}


def _jurisdiction(turns: list[dict]) -> dict:
    """Reuse the live layer's denial detection over assistant turns."""
    rows, denials = [], 0
    for i, t in enumerate(turns):
        if t.get("role") != "assistant":
            continue
        txt = t.get("content", "")
        d = bool(_dec.DENIAL.search(txt))
        a = bool(_dec.AFFIRM_PRC.search(txt))
        brand = None
        m = re.search(r"(?:developed|created|built|made|operated) by\s+"
                      r"(google|openai|anthropic|microsoft|meta|mistral|xai|amazon)",
                      txt, re.I)
        if m:
            brand = m.group(1).title()
        if d and not a:
            denials += 1
        if d or brand:
            rows.append({"turn": i, "denies_prc": d, "affirms_prc": a,
                         "denial_justified_by_brand": brand})
    brands = sorted({r["denial_justified_by_brand"] for r in rows
                     if r.get("denial_justified_by_brand")})
    return {"probes": rows, "denial_count": denials,
            "denies_prc_jurisdiction": denials >= 1,
            "denial_justified_by_brands": brands,
            "false_assurance_pattern": bool(denials >= 1 and brands)}


def parse(raw) -> list[dict]:
    """Accept a JSON list of {role, content}, or a simple 'Speaker: text' transcript.

    In plain-text mode, lines whose speaker matches the model/assistant (anything
    not 'me'/'user'/'you') are treated as assistant turns.
    """
    if isinstance(raw, list):
        return [{"role": t.get("role", "assistant"), "content": t.get("content", "")}
                for t in raw]
    turns, role, buf = [], None, []
    for line in str(raw).splitlines():
        m = re.match(r"\s*([A-Za-z][\w .()/-]{0,24}?)\s*[:\-]\s*(.*)", line)
        if m:
            if role is not None:
                turns.append({"role": role, "content": "\n".join(buf).strip()})
            spk = m.group(1).strip().lower()
            role = "user" if spk in ("me", "user", "you", "human") else "assistant"
            buf = [m.group(2)]
        elif role is not None:
            buf.append(line)
    if role is not None:
        turns.append({"role": role, "content": "\n".join(buf).strip()})
    return [t for t in turns if t["content"]]


def analyze(turns, *, true_origin: str | None = None, true_detail: str = "") -> dict:
    """Return the identity/deception analysis + a scoring-ready deception bundle.

    true_origin: 'CN' | 'nonCN' | None — the endpoint's real origin (e.g. z.ai ->
    'CN'). Without it, misrepresentation cannot be asserted (persona alone proves
    nothing); the timeline and flips are still reported.
    """
    turns = parse(turns)
    timeline, prev, flips = [], None, []
    persona_claims: dict[str, int] = {}
    first_western = None
    for i, t in enumerate(turns):
        if t.get("role") != "assistant":
            continue
        idy = _turn_identity(t.get("content", ""))
        current = idy["conceded"] or idy["asserted"]
        if idy["asserted"]:
            persona_claims[idy["asserted"]] = persona_claims.get(idy["asserted"], 0) + 1
            if first_western is None and _western(idy["asserted"]):
                first_western = idy["asserted"]
        timeline.append({"turn": i, "asserted": idy["asserted"],
                         "conceded": idy["conceded"], "identity": current})
        if current and prev and current != prev:
            kind = ("concession" if (_western(prev) and not _western(current)) else "flip")
            flips.append({"turn": i, "from": prev, "to": current, "kind": kind})
        if current:
            prev = current

    ranked = sorted(persona_claims.items(), key=lambda kv: -kv[1])
    persona = {"claims": persona_claims,
               "dominant_claim": first_western or (ranked[0][0] if ranked else None)}
    juris = _jurisdiction(turns)
    corr = _dec.correlate(persona, juris, true_origin, true_detail)

    return {
        "turns_analyzed": sum(1 for t in turns if t["role"] == "assistant"),
        "identity_timeline": timeline,
        "model_change_events": flips,          # the "alert + record on switch" output
        "distinct_identities": sorted(persona_claims),
        "persona": persona,
        "jurisdiction": juris,
        "correlation": corr,
        # scoring-ready: scoring.collect_signals reads bundle["deception"]
        "deception": {"persona": persona, "jurisdiction": juris, "correlation": corr},
    }


def load(path: str):
    """Load a transcript file (.json list or plain text)."""
    with open(path) as f:
        data = f.read()
    try:
        return json.loads(data)
    except (ValueError, json.JSONDecodeError):
        return data
