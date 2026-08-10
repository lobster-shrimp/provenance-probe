"""Attribution: map a host to (operator, origin) using bundled corpus.py.

Imports the corpus.py endpoint dicts DIRECTLY — one source of truth, already
bundled with the package, no separate registry file (plan-eng-review Code
Quality 1). The B-phase signed public registry is GENERATED from corpus.py, not
maintained in parallel.

Matching is exact-or-subdomain on the hostname, never substring, so
`api.deepseek.com.evil.test` is NOT attributed to DeepSeek (guardrail 5). Every
result is a SUB-CONFIRMED pointer (`measured=False`) — a domain lookup, never a
tokenizer-fingerprint provenance verdict.
"""
from __future__ import annotations

from ..data.corpus import (
    AGGREGATOR_ENDPOINTS,
    FIRST_PARTY_ENDPOINTS,
    PRC_ENDPOINTS,
)
from .evidence import Attribution

# First-party vendor hosts are canonical; corpus carries no per-host confidence
# for them, so use a fixed high value (still a static pointer, still measured=False).
_FIRST_PARTY_CONFIDENCE = 0.9


def _host_matches(host: str, key: str) -> bool:
    """Exact-or-subdomain: host == key or host ends with '.' + key. Never substring."""
    return host == key or host.endswith("." + key)


def _lookup(host: str, table: dict) -> str | None:
    """Return the matching key in `table` for `host` (exact-or-subdomain), or None.
    Prefers the most specific (longest) matching key so a broad suffix like
    `tencentcloudapi.com` doesn't shadow a specific `hunyuan.tencentcloudapi.com`.
    """
    best: str | None = None
    for key in table:
        if _host_matches(host, key) and (best is None or len(key) > len(best)):
            best = key
    return best


def is_aggregator(host: str) -> str | None:
    """Return the aggregator name if this host is a known neutral aggregator."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return None
    key = _lookup(h, AGGREGATOR_ENDPOINTS)
    return AGGREGATOR_ENDPOINTS[key] if key else None


def attribute(host: str) -> Attribution | None:
    """Attribute a host to (operator, origin, confidence) from corpus.py.

    PRC endpoints take priority (the finding that matters most), then first-party
    US/EU vendors. Aggregators are handled separately (they are unresolvable, not
    attributable). Returns None for unknown hosts.
    """
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return None

    prc_key = _lookup(h, PRC_ENDPOINTS)
    if prc_key:
        operator, origin, confidence = PRC_ENDPOINTS[prc_key]
        return Attribution(operator=operator, origin=origin, confidence=confidence)

    fp_key = _lookup(h, FIRST_PARTY_ENDPOINTS)
    if fp_key:
        operator, origin = FIRST_PARTY_ENDPOINTS[fp_key]
        return Attribution(operator=operator, origin=origin,
                           confidence=_FIRST_PARTY_CONFIDENCE)

    return None
