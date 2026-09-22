"""Service catalog: a signed-ready map of the AI *apps/websites/services* — WHO
operates them, WHOSE jurisdiction, and WHICH backend model(s)/provider(s) they
front. This is the "provider of the service" layer the model catalog (`catalog.py`)
cannot express: `catalog.py` maps inference *APIs* to model cards; this maps the
consumer-facing *services* (ChatGPT, z.ai, DeepSeek chat, Perplexity, replit, …).

Sibling to `catalog.py` and built the same way, with the same two boundaries:

* **Every row is a SUB-CONFIRMED static POINTER, never a measured verdict.**
  `measured` is ALWAYS `false`. A row says who a host is registered to / what a
  service is known to front — not what actually served on a given request. Run
  `assess`/`soak` for a measured verdict. (Mirrors `catalog.py`'s `measured:false`.)
* **NO egress in the generator.** Unlike `catalog.py` (which has one explicit
  `fetch_models_dev` egress), this module composes LOCAL data only — it NEVER
  contacts a service. There is deliberately no fetch entry point here.

Three local sources are merged and de-duplicated by host (highest-confidence /
most-specific row wins; `fronts` are unioned):

1. **corpus** — every `PRC_ENDPOINTS` host -> a service row (operator/jurisdiction/
   confidence from the corpus value; `kind` by a small host heuristic). Every
   `AGGREGATOR_ENDPOINTS` host -> an aggregator row (jurisdiction="aggregator").
2. **clientsrc** — KNOWN prior live-scan findings, shipped as curated `fronts` data
   (NOT re-scanned here) with `source:"clientsrc"` and a scan-date evidence note.
3. **curated** — a maintained, clearly-sourced list of MAJOR consumer AI apps not
   otherwise covered (well-known operator/jurisdiction facts, ETHOS layer-1). Kept
   HONEST: `measured:false`, no unverified accusation; a neutral aggregator whose
   backend varies gets `fronts=[]` and a "varies" note rather than a guess.

Output is deterministic (services sorted by jurisdiction then name then host) so
the artifact is reproducible and signable, exactly like `build_registry` /
`build_catalog`. The observatory signs it nightly; this generator just emits JSON.
"""
from __future__ import annotations

from .data import corpus

# Deterministic version stamp: use the corpus version (no live date) so two runs
# are byte-identical and the signed artifact is reproducible.
CATALOG_VERSION = corpus.CORPUS_VERSION
GENERATED_FROM = ("corpus PRC_ENDPOINTS/AGGREGATOR_ENDPOINTS + clientsrc findings "
                  "+ curated app list")

_JUR_ENUM = ("PRC", "PRC-operator", "first-party", "aggregator", "unresolved")

# Date of the shipped clientsrc live-scan findings (source note; NOT re-scanned).
_CLIENTSRC_SCAN = "2026-06"

# Host-shape heuristic: API base hosts vs. consumer web-app hosts.
_API_PREFIXES = ("api.", "open.", "dashscope", "dashscope-intl", "spark-api.",
                 "qianfan.", "aip.", "hunyuan.", "intern-ai.", "inference.",
                 "aiplatform.", "bedrock-runtime")
_API_SUFFIXES = ("aliyuncs.com", "tencentcloudapi.com", "myhuaweicloud.com",
                 "googleapis.com", "azure.com", "baidubce.com")


def _kind_for_host(host: str) -> str:
    """api-service vs web-app, by a small host-shape heuristic (aggregators are
    tagged separately). API base hosts start with an api-ish label or sit under a
    cloud API suffix; everything else is treated as a consumer web-app."""
    h = (host or "").lower()
    if h.startswith(_API_PREFIXES) or h.endswith(_API_SUFFIXES):
        return "api-service"
    return "web-app"


def _norm_jur(value: str) -> str:
    """Map a corpus jurisdiction to the locked enum. Real PRC labels pass through;
    anything else (e.g. corpus 'unknown' on a generic relay) -> 'unresolved' so we
    never emit an off-enum or over-claimed jurisdiction."""
    v = (value or "").strip()
    return v if v in ("PRC", "PRC-operator") else "unresolved"


def _row(*, name: str, url: str, host: str, kind: str, operator: str,
         jurisdiction: str, fronts, evidence: str, source: str,
         confidence) -> dict:
    """One service row in the locked schema. `measured` is ALWAYS False."""
    return {
        "name": name,
        "url": url,
        "host": host.lower(),
        "kind": kind,
        "operator": operator,
        "jurisdiction": jurisdiction,
        "fronts": list(fronts or []),
        "evidence": evidence,
        "source": source,
        "confidence": confidence,
        "measured": False,          # INVARIANT: static attribution pointer, not a verdict
    }


def _corpus_rows() -> list[dict]:
    """Every corpus endpoint host -> a service row (PRC endpoints carry their
    operator/jurisdiction/confidence; aggregators are neutral, jurisdiction set)."""
    rows: list[dict] = []
    for host, (operator, jur, conf) in corpus.PRC_ENDPOINTS.items():
        rows.append(_row(
            name=operator, url="", host=host, kind=_kind_for_host(host),
            operator=operator, jurisdiction=_norm_jur(jur), fronts=[],
            evidence=f"corpus PRC_ENDPOINTS ({conf})", source="corpus",
            confidence=conf,
        ))
    for host, operator in corpus.AGGREGATOR_ENDPOINTS.items():
        rows.append(_row(
            name=operator, url="", host=host, kind="aggregator", operator=operator,
            jurisdiction="aggregator", fronts=[],
            evidence="corpus AGGREGATOR_ENDPOINTS (neutral; backend varies)",
            source="corpus", confidence=None,
        ))
    return rows


# --- Known clientsrc findings (prior live scans; NOT re-scanned here) --------- #
# Shipped as curated `fronts` data with source:"clientsrc" + a scan-date note.
# These are the durable client-source findings the probe recorded previously:
# an endpoint/model id recovered from shipped JS survives server-side evasion.
def _clientsrc_rows() -> list[dict]:
    ev = lambda detail: f"clientsrc scan ({_CLIENTSRC_SCAN}): {detail}"
    return [
        # z.ai: also in corpus (PRC-operator) — merges by host; contributes fronts.
        _row(name="z.ai (chat)", url="https://chat.z.ai", host="z.ai",
             kind="web-app", operator="Zhipu AI (GLM) - international front",
             jurisdiction="PRC-operator", fronts=["GLM (Zhipu)"],
             evidence=ev("client source references PRC endpoint api.z.ai (GLM)"),
             source="clientsrc", confidence=0.85),
        # replit: US operator, but client source references PRC inference backends.
        _row(name="Replit (Agent/Ghostwriter)", url="https://replit.com",
             host="replit.com", kind="web-app", operator="Replit (US)",
             jurisdiction="aggregator",
             fronts=["DeepSeek", "GLM (Zhipu)", "Moonshot Kimi"],
             evidence=ev("client source references deepseek / moonshot / glm backends"),
             source="clientsrc", confidence=0.60),
        # hix: references Qwen / QVQ / MiniMax backends.
        _row(name="HIX AI", url="https://hix.ai", host="hix.ai", kind="web-app",
             operator="HIX AI", jurisdiction="aggregator",
             fronts=["Qwen (Alibaba)", "QVQ (Alibaba)", "MiniMax"],
             evidence=ev("client source references qwen / qvq / minimax model ids"),
             source="clientsrc", confidence=0.60),
        # kimi.com: consumer site for Moonshot Kimi (not a corpus host).
        _row(name="Kimi (kimi.com)", url="https://kimi.com", host="kimi.com",
             kind="web-app", operator="Moonshot (Kimi)", jurisdiction="PRC",
             fronts=["Moonshot Kimi"],
             evidence=ev("client source references Moonshot (Kimi) backend"),
             source="clientsrc", confidence=0.90),
        # lindy: US automation app; a PRC-origin model id was observed in source.
        _row(name="Lindy", url="https://lindy.ai", host="lindy.ai", kind="web-app",
             operator="Lindy (US)", jurisdiction="aggregator", fronts=[],
             evidence=ev("client source referenced a PRC-origin model id "
                         "(specific model not asserted)"),
             source="clientsrc", confidence=0.55),
    ]


# --- Curated consumer-app list (well-known facts; ETHOS layer-1) -------------- #
# Operator + jurisdiction are well-established public facts. Neutral aggregators
# whose backend varies get fronts=[] with a "varies" note (no guess). measured=false.
def _curated_rows() -> list[dict]:
    C = "curated"
    return [
        # -- US first-party (operator serves its own weights) --
        _row(name="ChatGPT (OpenAI)", url="https://chatgpt.com", host="chatgpt.com",
             kind="web-app", operator="OpenAI", jurisdiction="first-party",
             fronts=["GPT (OpenAI)"],
             evidence="curated: OpenAI first-party consumer app (US)",
             source=C, confidence=0.95),
        _row(name="Gemini (Google)", url="https://gemini.google.com",
             host="gemini.google.com", kind="web-app", operator="Google",
             jurisdiction="first-party", fronts=["Gemini (Google)"],
             evidence="curated: Google first-party consumer app (US)",
             source=C, confidence=0.95),
        _row(name="Claude.ai (Anthropic)", url="https://claude.ai", host="claude.ai",
             kind="web-app", operator="Anthropic", jurisdiction="first-party",
             fronts=["Claude (Anthropic)"],
             evidence="curated: Anthropic first-party consumer app (US)",
             source=C, confidence=0.95),
        _row(name="Microsoft Copilot", url="https://copilot.microsoft.com",
             host="copilot.microsoft.com", kind="web-app", operator="Microsoft",
             jurisdiction="first-party", fronts=["GPT (OpenAI)"],
             evidence="curated: Microsoft (US); fronts OpenAI GPT models",
             source=C, confidence=0.85),
        _row(name="character.ai", url="https://character.ai", host="character.ai",
             kind="web-app", operator="Character.AI", jurisdiction="first-party",
             fronts=["proprietary (Character.AI)"],
             evidence="curated: Character.AI (US), own models",
             source=C, confidence=0.85),
        # -- US aggregators (backend varies) --
        _row(name="Perplexity", url="https://perplexity.ai", host="perplexity.ai",
             kind="web-app", operator="Perplexity (US)", jurisdiction="aggregator",
             fronts=[],
             evidence="curated: US aggregator; routes multiple backends (varies)",
             source=C, confidence=None),
        _row(name="Poe", url="https://poe.com", host="poe.com", kind="web-app",
             operator="Quora (US)", jurisdiction="aggregator", fronts=[],
             evidence="curated: US multi-model aggregator (varies)",
             source=C, confidence=None),
        # -- PRC consumer apps --
        _row(name="DeepSeek (chat)", url="https://chat.deepseek.com",
             host="chat.deepseek.com", kind="web-app", operator="DeepSeek",
             jurisdiction="PRC", fronts=["DeepSeek"],
             evidence="curated: DeepSeek first-party consumer app (PRC)",
             source=C, confidence=0.95),
        _row(name="Doubao (ByteDance)", url="https://doubao.com", host="doubao.com",
             kind="web-app", operator="ByteDance", jurisdiction="PRC",
             fronts=["Doubao (ByteDance)"],
             evidence="curated: ByteDance first-party consumer app (PRC)",
             source=C, confidence=0.95),
        _row(name="Tongyi Qianwen (Qwen)", url="https://tongyi.aliyun.com",
             host="tongyi.aliyun.com", kind="web-app", operator="Alibaba",
             jurisdiction="PRC", fronts=["Qwen (Alibaba)"],
             evidence="curated: Alibaba first-party consumer app (PRC)",
             source=C, confidence=0.95),
        _row(name="Ernie Bot / Wenxiaoyan (Baidu)", url="https://yiyan.baidu.com",
             host="yiyan.baidu.com", kind="web-app", operator="Baidu",
             jurisdiction="PRC", fronts=["Ernie (Baidu)"],
             evidence="curated: Baidu first-party consumer app (PRC)",
             source=C, confidence=0.95),
        _row(name="Tencent Yuanbao (Hunyuan)", url="https://yuanbao.tencent.com",
             host="yuanbao.tencent.com", kind="web-app", operator="Tencent",
             jurisdiction="PRC", fronts=["Hunyuan (Tencent)"],
             evidence="curated: Tencent first-party consumer app (PRC)",
             source=C, confidence=0.95),
    ]


def _merge_by_host(rows: list[dict]) -> list[dict]:
    """De-dup by host. The highest-confidence / most-specific row wins its core
    attribution; `fronts` are unioned across the group and `evidence` notes are
    concatenated (winner first). Corpus is the tie-break authority for jurisdiction."""
    _src_prio = {"corpus": 0, "clientsrc": 1, "curated": 2}

    groups: dict[str, list[dict]] = {}
    for r in rows:
        groups.setdefault(r["host"], []).append(r)

    merged: list[dict] = []
    for host, grp in groups.items():
        # highest confidence first (None sorts last); tie -> corpus, then clientsrc.
        winner = sorted(
            grp,
            key=lambda r: (-(r["confidence"] if r["confidence"] is not None else -1.0),
                           _src_prio.get(r["source"], 9)),
        )[0]
        fronts = sorted({f for r in grp for f in r["fronts"]})
        evs: list[str] = []
        for r in [winner] + [x for x in grp if x is not winner]:
            if r["evidence"] and r["evidence"] not in evs:
                evs.append(r["evidence"])
        row = dict(winner)
        row["fronts"] = fronts
        row["evidence"] = "; ".join(evs)
        merged.append(row)
    return merged


def build_service_catalog() -> dict:
    """Compose corpus + known clientsrc findings + curated apps into the locked
    schema. Pure, deterministic, no egress. Services are sorted by jurisdiction,
    then name, then host, so a re-generation is byte-identical (signable)."""
    rows = _corpus_rows() + _clientsrc_rows() + _curated_rows()
    services = _merge_by_host(rows)
    services.sort(key=lambda s: (s["jurisdiction"], s["name"], s["host"]))
    return {
        "catalog_version": CATALOG_VERSION,
        "generated_from": GENERATED_FROM,
        "corpus_version": corpus.CORPUS_VERSION,
        "service_count": len(services),
        "services": services,
    }
