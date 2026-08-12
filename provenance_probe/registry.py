"""Provider-attribution registry — generated FROM corpus.py.

The public, verifiable map of inference endpoint -> operating entity ->
jurisdiction that external consumers and the observatory publish. corpus.py stays
the single source of truth (the prober + fleet scanner read it directly); this
module projects it into a stable, schema'd registry document. It is GENERATED,
never hand-edited — regenerate with `provenance-probe build-registry`.

Two deliberate properties:

* **Deterministic.** Entries are sorted (domain, then kind), so regenerating from
  the same corpus yields byte-identical output — a drift check (`verify_registry`)
  can assert a checked-in copy still matches corpus.py, and a signature over the
  document is stable.
* **Exact-or-subdomain only.** The public registry is consumed by exact-or-subdomain
  matchers (fleet/attribute, external tools), so corpus bare-token keys that only
  work for the substring probers (network.py/clientsrc.py) — e.g. `openai-proxy`,
  `bedrock-runtime` — are EXCLUDED and counted, not emitted as misleading hostnames.

Signing (cosign/Rekor) and publication are the observatory's job (it owns the
signing machinery and the P2b publish policy); this repo only produces the
canonical unsigned document.
"""
from __future__ import annotations

REGISTRY_VERSION = "1"
# First-party vendor hosts carry no per-host confidence in corpus.py; use the same
# fixed value fleet attribution uses so the registry and the scanner agree.
_FIRST_PARTY_CONFIDENCE = 0.9


def _is_hostname(key: str) -> bool:
    """A registry domain must be a real hostname/suffix (contains a dot). Bare
    tokens are substring-only corpus hints and are excluded (see module docstring)."""
    return "." in key


def build_registry() -> dict:
    """Project corpus.py's endpoint intelligence into the registry document."""
    from .data import corpus

    entries: list[dict] = []
    excluded: list[str] = []

    for host, (operator, jurisdiction, confidence) in corpus.PRC_ENDPOINTS.items():
        if not _is_hostname(host):
            excluded.append(host)
            continue
        entries.append({"domain": host, "operating_entity": operator,
                        "jurisdiction": jurisdiction, "kind": "prc",
                        "confidence": confidence})

    for host, name in corpus.AGGREGATOR_ENDPOINTS.items():
        if not _is_hostname(host):
            excluded.append(host)
            continue
        # An aggregator resolves jurisdiction (non-PRC operator) but NOT provenance;
        # it carries no origin confidence — provenance is unresolved by design.
        entries.append({"domain": host, "operating_entity": name,
                        "jurisdiction": "unresolved", "kind": "aggregator",
                        "confidence": None})

    for host, (operator, origin) in corpus.FIRST_PARTY_ENDPOINTS.items():
        if not _is_hostname(host):
            excluded.append(host)
            continue
        entries.append({"domain": host, "operating_entity": operator,
                        "jurisdiction": origin, "kind": "first-party",
                        "confidence": _FIRST_PARTY_CONFIDENCE})

    entries.sort(key=lambda e: (e["domain"], e["kind"]))
    return {
        "registry_version": REGISTRY_VERSION,
        "corpus_version": corpus.CORPUS_VERSION,
        # A host matches an entry whose domain it equals or is a subdomain of; when
        # several entries match (nested suffixes like hunyuan.tencentcloudapi.com vs
        # tencentcloudapi.com), the MOST-SPECIFIC (longest domain) wins — matching
        # fleet/attribute._lookup. A consumer must reproduce both rules.
        "match": "exact-or-subdomain; most-specific (longest domain) wins",
        "note": ("generated from corpus.py — do not hand-edit; regenerate with "
                 "`provenance-probe build-registry`. Sub-CONFIRMED static pointers "
                 "(who a domain is registered to), never a measured provenance verdict."),
        "entry_count": len(entries),
        "excluded_nonhostname": sorted(excluded),
        "entries": entries,
    }


def verify_registry(doc: dict) -> list[str]:
    """Return a list of problems (empty = OK). Used by `verify-registry` and CI to
    assert a checked-in/published registry still matches corpus.py exactly.

    Compares the ENTIRE document to a fresh generation (build_registry is
    deterministic) — not just `entries`. Until the observatory signs it, this is the
    only integrity gate, so a tampered honesty `note` or a `match` field flipped to
    `substring` (the suffix-attack bypass) must be caught, not just entry drift."""
    problems: list[str] = []
    current = build_registry()
    for k in current:
        if doc.get(k) != current[k]:
            problems.append(f"field {k!r} does not match a fresh generation from "
                            "corpus.py (stale or tampered — regenerate with "
                            "`provenance-probe build-registry`)")
    for k in set(doc) - set(current):
        problems.append(f"unexpected field {k!r} not produced by the generator")
    # schema well-formedness of the generator output itself (guards the generator)
    seen: set[str] = set()
    for e in current["entries"]:
        if e["kind"] not in ("prc", "aggregator", "first-party"):
            problems.append(f"{e['domain']}: bad kind {e['kind']!r}")
        if e["kind"] in ("prc", "first-party") and not isinstance(e["confidence"], (int, float)):
            problems.append(f"{e['domain']}: {e['kind']} entry missing confidence")
        key = f"{e['domain']}/{e['kind']}"
        if key in seen:
            problems.append(f"duplicate entry {key}")
        seen.add(key)
    return problems
