"""OmniRoute optional accelerator + evidence cross-check (P2).

OmniRoute (a local OpenAI-compatible router at localhost:20128) normalizes many
providers behind one wire shape and streams `x-omniroute-*` response headers
naming the model/provider it routed to. That makes it a zero-typing way to probe
a service AND a second, independent evidence source: the router's CLAIM about
what it served, cross-checked against our tokenizer FINGERPRINT.

It is an OPTIONAL accelerator, never a dependency (design D3). If :20128 is not
running, callers fall back to direct auto-detect / paste.

Two hardening invariants from the outside-voice review are enforced HERE:

* CALIBRATION GATE (outside-voice 1a). Measuring THROUGH OmniRoute only works if
  its injected-system-prompt overhead is a constant additive offset that cancels
  in overhead-correction. That is observed (n=1), not proven — BPE seam effects
  could distort the per-probe SHAPE. So a via-OmniRoute verdict is
  confidence-capped (max SUGGESTIVE, never CONFIRMED) UNTIL `calibrate()` passes
  for the running OmniRoute VERSION: probe a known-family route via OmniRoute and
  assert it still fingerprints to its own family at high score.

* THREE-STATE CROSS-CHECK (outside-voice 2.1). The router's label is mapped to a
  tokenizer family via a maintained table and compared to the fingerprint:
  CORROBORATED (same family), CONTRADICTED (distinct known families), or
  INCONCLUSIVE — the DEFAULT for anything uncertain (unknown label, uncalibrated,
  no fingerprint, or an unclear family relation). Version drift (V4 reuses V3's
  tokenizer) is CORROBORATED, not a mismatch.
  ** CONTRADICTED is an analyst-review signal, NEVER an auto-published verdict. **
  Any publisher must quarantine it (enforced by the observatory signer in P2b).
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

# Pure gateway knowledge (label->family map, local-gateway constants) lives in
# gateways.py so the no-egress fleet scanner can import it WITHOUT importing this
# network-bearing module (plan-eng-review Arch 1). Re-exported here for back-compat.
from .gateways import (  # noqa: F401  (re-exported)
    LABEL_FAMILY,
    OMNIROUTE_DEFAULT_BASE,
    _normalize_label,
    label_to_family,
)

DEFAULT_BASE = OMNIROUTE_DEFAULT_BASE

# Cross-check states.
CORROBORATED = "CORROBORATED"
INCONCLUSIVE = "INCONCLUSIVE"
CONTRADICTED = "CONTRADICTED"

# Known family ROOTS are derived from the families that ACTUALLY have reference
# vectors — never a static list. A label whose family has no reference (e.g.
# MiniMax, Ling) can never fingerprint to that family, so calling it CONTRADICTED
# would be a false accusation; deriving from references keeps those INCONCLUSIVE
# (Claude adversarial review, MEDIUM). If the reference can't be read, the set is
# empty and NOTHING is ever CONTRADICTED — the safe degradation.
_KNOWN_ROOTS_CACHE: set | None = None


def _known_roots() -> set:
    global _KNOWN_ROOTS_CACHE
    if _KNOWN_ROOTS_CACHE is None:
        roots: set = set()
        try:
            from .probes import tokenizer
            for entry in (tokenizer.load_reference().get("models") or {}).values():
                fam = entry.get("family")
                if fam:
                    roots.add(_root(fam))
        except Exception:
            roots = set()
        _KNOWN_ROOTS_CACHE = roots
    return _KNOWN_ROOTS_CACHE


@dataclass
class OmniRouteStatus:
    present: bool = False
    base_url: str = DEFAULT_BASE
    models: list = field(default_factory=list)
    version: str = ""
    error: str = ""


@dataclass
class Calibration:
    passed: bool = False
    omniroute_version: str = ""
    route: str = ""
    expected_family: str = ""
    exact_frac: float = 0.0         # fraction of probes exact after a single constant offset
    max_residual: int = 0           # worst per-probe residual after the offset
    template_overhead: int = 0      # modal injected-prompt offset removed
    shared_probes: int = 0
    distorted: int = 0              # probes whose shape didn't survive the offset
    threshold: float = 0.0
    note: str = ""


@dataclass
class CrossCheck:
    state: str = INCONCLUSIVE
    router_label: str = ""
    router_provider: str = ""
    mapped_family: str | None = None
    fingerprint_family: str | None = None
    calibrated: bool = False
    note: str = ""


# --------------------------------------------------------------------------- #
# Label -> family mapping (label_to_family / _normalize_label / LABEL_FAMILY are
# imported from gateways.py above and re-exported for back-compat)
# --------------------------------------------------------------------------- #

def _root(family: str | None) -> str:
    """Reduce a family name to its version-agnostic root.

    Handles vendor-suffixed reference names (GLM/Zhipu -> glm, Claude/Anthropic ->
    claude, GPT-2/OpenAI -> gpt) and version suffixes (DeepSeek-V3 -> deepseek).
    """
    s = (family or "").strip().lower()
    s = s.split("/", 1)[0]                          # "glm/zhipu" -> "glm"
    s = re.sub(r"[-_ ]?v?\d+(\.\d+)*", "", s)       # strip -v3, 2, -3.1, v4 ...
    s = re.sub(r"[-_ ](llm|coder|chat|instruct|base|flash|mini|max|pro)$", "", s)
    return re.sub(r"[^a-z0-9]", "", s)


def _family_relation(a: str | None, b: str | None) -> str:
    """'same' | 'different' | 'unclear' — conservative: only two DISTINCT known
    families are 'different' (-> CONTRADICTED). If either side is unknown, or one
    root is a substring of the other (gpt ⊂ gptneox), it's 'unclear' -> never a
    false CONTRADICTED (Codex adversarial review)."""
    ra, rb = _root(a), _root(b)
    if not ra or not rb:
        return "unclear"
    if ra == rb:
        return "same"
    if ra in rb or rb in ra:            # related roots (gpt vs gptneox) — don't accuse
        return "unclear"
    known = _known_roots()
    if ra in known and rb in known:     # both are families we actually have refs for
        return "different"
    return "unclear"


# --------------------------------------------------------------------------- #
# Three-state cross-check
# --------------------------------------------------------------------------- #

def cross_check(router_label: str, fingerprint_family: str | None, *,
                calibrated: bool, router_provider: str = "") -> CrossCheck:
    """Compare the router's claim to the tokenizer fingerprint. Three states;
    INCONCLUSIVE is the default for ANY uncertainty (see module docstring)."""
    mapped = label_to_family(router_label)
    cc = CrossCheck(router_label=router_label, router_provider=router_provider,
                    mapped_family=mapped, fingerprint_family=fingerprint_family,
                    calibrated=calibrated)
    if not calibrated:
        cc.state = INCONCLUSIVE
        cc.note = ("via OmniRoute but NOT calibrated for this OmniRoute version — "
                   "cross-check withheld (confidence-capped).")
        return cc
    if mapped is None:
        cc.state = INCONCLUSIVE
        cc.note = f"router label {router_label!r} is not in the label→family map."
        return cc
    if not fingerprint_family:
        cc.state = INCONCLUSIVE
        cc.note = "no tokenizer family was fingerprinted to compare against."
        return cc
    rel = _family_relation(mapped, fingerprint_family)
    if rel == "same":
        cc.state = CORROBORATED
        cc.note = (f"router claims {router_label!r} ({mapped}); weights fingerprint "
                   f"{fingerprint_family} — consistent (version drift is expected).")
    elif rel == "different":
        cc.state = CONTRADICTED
        cc.note = (f"router claims {router_label!r} ({mapped}); weights fingerprint "
                   f"{fingerprint_family} — MISMATCH. Analyst-review only; NOT auto-published.")
    else:
        cc.state = INCONCLUSIVE
        cc.note = (f"router claims {router_label!r} ({mapped}); fingerprint "
                   f"{fingerprint_family} — relation unclear; not called either way.")
    return cc


# --------------------------------------------------------------------------- #
# x-omniroute-* header capture
# --------------------------------------------------------------------------- #

def omniroute_headers(resp_headers: dict) -> dict:
    """Extract the x-omniroute-* metadata from a response's headers (lowercased
    keys). Returns {short_key: value}, e.g. {'model': ..., 'provider': ...}."""
    out = {}
    for k, v in (resp_headers or {}).items():
        lk = str(k).lower()
        if lk.startswith("x-omniroute-"):
            out[lk[len("x-omniroute-"):]] = v
    return out


# --------------------------------------------------------------------------- #
# Live detection + calibration (thin; injectable for tests)
# --------------------------------------------------------------------------- #

def detect_omniroute(base: str = DEFAULT_BASE, probe=None) -> OmniRouteStatus:
    """Best-effort detection of a running OmniRoute at `base`. Never raises."""
    st = OmniRouteStatus(base_url=base)
    try:
        pr = (probe or _default_get)(base + "/models")
    except Exception as e:                          # transport — treat as absent
        st.error = str(e)
        return st
    if not (200 <= pr.get("status", 0) < 300):
        st.error = f"OmniRoute not answering on {base} (HTTP {pr.get('status')})."
        return st
    data = (pr.get("json") or {}).get("data") if isinstance(pr.get("json"), dict) else None
    if not isinstance(data, list):
        st.error = "response was not an OpenAI-style model catalog."
        return st
    st.present = True
    st.models = [m.get("id") for m in data if isinstance(m, dict) and m.get("id")]
    st.version = str((pr.get("headers") or {}).get("x-omniroute-version", ""))
    return st


def _default_get(url: str, timeout: float = 8.0) -> dict:
    import requests
    r = requests.get(url, timeout=timeout)
    try:
        j = r.json()
    except Exception:
        j = None
    return {"status": r.status_code, "json": j,
            "headers": {k.lower(): v for k, v in r.headers.items()}}


CALIBRATION_TOLERANCE = 0.90        # min fraction of probes that must match EXACTLY after offset
MIN_CALIBRATION_PROBES = 6


def _modal_overhead(obs: dict, ref: dict, shared: list) -> int:
    d = sorted(obs[k] - ref[k] for k in shared)
    return d[len(d) // 2] if d else 0


def calibrate(observed_vector: dict, reference_vector: dict, *,
              expected_family: str = "", omniroute_version: str = "", route: str = "",
              tolerance: float = CALIBRATION_TOLERANCE) -> Calibration:
    """Assert measuring THROUGH OmniRoute preserves the tokenizer SHAPE.

    `observed_vector` is a via-OmniRoute measurement of a KNOWN-family route;
    `reference_vector` is that family's first-party reference. The mechanism
    relies on OmniRoute's injected-prompt overhead being a CONSTANT additive
    offset that cancels. We test EXACTLY that: subtract the modal offset, then
    require a high fraction of probes to match the reference EXACTLY (residual 0).

    We deliberately do NOT use a correlation coefficient: Pearson ignores scale
    and stays high for any two vectors that both track prompt length, so it
    passes cross-family (e.g. OpenAI-o200k+2000 vs DeepSeek at r≈0.99) — a fatal
    false-positive (Codex adversarial review). Requiring near-exact residuals
    after a single constant offset is scale-sensitive and family-specific: a
    wrong family will not match after any single offset, and BPE seam distortion
    (the injected prompt's tail merging with a probe's head) leaves non-zero
    residuals that FAIL calibration and keep via-OmniRoute confidence-capped.

    Empirical note: OmniRoute v3.8.48 injects ~2004 tokens and lands 15/20 probes
    exact after offset (0.75) — below tolerance, so it does NOT calibrate; the
    5 misses are CJK/whitespace probes, the ones that matter most for CN origin.
    """
    cal = Calibration(omniroute_version=omniroute_version, route=route,
                      expected_family=expected_family, threshold=tolerance)
    shared = [k for k in observed_vector if k in reference_vector]
    cal.shared_probes = len(shared)
    if len(shared) < MIN_CALIBRATION_PROBES:
        cal.note = f"too few shared probes ({len(shared)}) to calibrate."
        return cal
    off = _modal_overhead(observed_vector, reference_vector, shared)
    cal.template_overhead = off
    residuals = {k: (observed_vector[k] - off) - reference_vector[k] for k in shared}
    exact = sum(1 for v in residuals.values() if v == 0)
    cal.distorted = len(shared) - exact
    frac = exact / len(shared)                 # compare the RAW ratio (no rounding boundary)
    cal.exact_frac = round(frac, 4)
    cal.max_residual = max(abs(v) for v in residuals.values())
    if frac >= tolerance:
        cal.passed = True
        cal.note = (f"calibrated: {exact}/{len(shared)} probes exact after removing a "
                    f"constant offset of {off} (>= {tolerance:.0%}); OmniRoute's injection "
                    f"cancels cleanly for version {omniroute_version or '?'}.")
    else:
        cal.note = (f"NOT calibrated: only {exact}/{len(shared)} probes exact after offset "
                    f"{off} ({cal.distorted} distorted, max residual {cal.max_residual}, likely "
                    f"BPE seam effects from the injected prompt) — via-OmniRoute stays "
                    f"confidence-capped for OmniRoute {omniroute_version or 'version ?'}.")
    return cal
