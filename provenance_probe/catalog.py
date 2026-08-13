"""LLM-API catalog: a searchable table of inference APIs, their models, and
model-card facts — JOINED with this project's provenance/jurisdiction attribution.

The catalog is built FROM an external open catalog (models.dev, MIT-licensed,
`https://models.dev/api.json`) which supplies the breadth: per-provider `api`
base URL, per-model context window, cost, modalities, open-weights, dates. The
value THIS project adds is the join: each provider's `api` host is looked up in
the bundled `corpus.py` endpoint intelligence (via `fleet.attribute`, the same
exact-or-subdomain matcher the fleet scanner and the signed registry use), so
every row carries a provenance/jurisdiction *pointer* no generic model catalog
has ("this API is operated by a PRC entity").

Two deliberate boundaries:

* **Provenance here is a SUB-CONFIRMED pointer, never a measured verdict.** A
  domain match tells you who an API host is registered to, not which model
  actually served — that needs a tokenizer fingerprint (`assess`). The join sets
  `measured: false`, keeping "two verdicts, never collapse them" honest.
* **No egress on the read path.** Building the catalog fetches models.dev
  (explicit, opt-in — the `build-catalog` command, like `build-reference`), but
  searching reads a bundled/local snapshot. The local tool sends nothing to
  models.dev just to render a table; the observatory owns the nightly refresh.
"""
from __future__ import annotations

import json
import os
from urllib.parse import urlsplit

from .data import corpus
from .fleet.attribute import attribute, is_aggregator

CATALOG_VERSION = "1"
SOURCE_URL = "https://models.dev/api.json"
SOURCE_NOTE = "generated from models.dev (MIT, github.com/sst/models.dev), joined with corpus.py"
_BUNDLED = os.path.join(os.path.dirname(__file__), "data", "catalog.json")


def _host_of(api_url: str) -> str:
    """Hostname of a provider `api` base URL (lowercased, trailing dot stripped)."""
    if not api_url:
        return ""
    u = api_url if "://" in api_url else "https://" + api_url
    return (urlsplit(u).hostname or "").strip().lower().rstrip(".")


def is_cn_origin(origin: str) -> bool:
    """True for a Chinese-origin / PRC-jurisdiction label (PRC, PRC-operator, CN)."""
    o = (origin or "").strip().upper()
    return o.startswith("PRC") or o == "CN"


def _provenance_for(host: str) -> dict | None:
    """Join a provider host to corpus.py provenance. Mirrors registry.py semantics:
    PRC/first-party come from `attribute()`, aggregators from `is_aggregator()`,
    unknown hosts return None. A SUB-CONFIRMED pointer (`measured: false`)."""
    if not host:
        return None
    attr = attribute(host)
    if attr is not None:
        kind = "prc" if is_cn_origin(attr.origin) else "first-party"
        return {"operating_entity": attr.operator, "jurisdiction": attr.origin,
                "kind": kind, "confidence": attr.confidence,
                "measured": False, "source": f"corpus:{host}"}
    agg = is_aggregator(host)
    if agg is not None:
        # An aggregator resolves jurisdiction (neutral operator) but NOT provenance.
        return {"operating_entity": agg, "jurisdiction": "unresolved",
                "kind": "aggregator", "confidence": None,
                "measured": False, "source": f"corpus:{host}"}
    return None


def _model_card(model_id: str, m: dict) -> dict:
    """Project one models.dev model object into a flat, stable model-card record."""
    limit = m.get("limit") or {}
    cost = m.get("cost") or {}
    modal = m.get("modalities") or {}
    return {
        "id": m.get("id") or model_id,
        "name": m.get("name") or model_id,
        "family": m.get("family") or "",
        "context": limit.get("context"),
        "max_output": limit.get("output"),
        "cost_input": cost.get("input"),
        "cost_output": cost.get("output"),
        "modalities_in": list(modal.get("input") or []),
        "modalities_out": list(modal.get("output") or []),
        "open_weights": bool(m.get("open_weights")) if "open_weights" in m else None,
        "reasoning": bool(m.get("reasoning")) if "reasoning" in m else None,
        "tool_call": bool(m.get("tool_call")) if "tool_call" in m else None,
        "release_date": m.get("release_date") or "",
        "knowledge": m.get("knowledge") or "",
        "last_updated": m.get("last_updated") or "",
    }


def build_catalog(models_dev: dict) -> dict:
    """Pure join: a models.dev `api.json` object (provider_id -> provider) plus
    corpus.py -> the catalog document. Deterministic (providers + models sorted),
    so a re-generation from the same input is byte-identical (like build_registry)."""
    providers: list[dict] = []
    model_count = 0
    for pid in sorted(models_dev):
        p = models_dev[pid] or {}
        if not isinstance(p, dict):
            continue
        api_url = p.get("api") or ""
        host = _host_of(api_url)
        models_obj = p.get("models") or {}
        models = [_model_card(mid, models_obj[mid])
                  for mid in sorted(models_obj) if isinstance(models_obj[mid], dict)]
        model_count += len(models)
        providers.append({
            "provider_id": p.get("id") or pid,
            "name": p.get("name") or pid,
            "api_url": api_url,
            "api_host": host,
            "doc": p.get("doc") or "",
            "auth_env": list(p.get("env") or []),
            "provenance": _provenance_for(host),
            "models": models,
        })
    return {
        "catalog_version": CATALOG_VERSION,
        "generated_from": SOURCE_URL,
        "source_note": SOURCE_NOTE,
        "corpus_version": corpus.CORPUS_VERSION,
        "provider_count": len(providers),
        "model_count": model_count,
        "providers": providers,
    }


def flatten(catalog: dict) -> list[dict]:
    """One row per (provider, model) — the searchable running table. Provenance
    columns are repeated per model so a row stands alone in a table view."""
    rows: list[dict] = []
    for p in catalog.get("providers") or []:
        prov = p.get("provenance") or {}
        base = {
            "provider_id": p.get("provider_id", ""),
            "provider_name": p.get("name", ""),
            "api_url": p.get("api_url", ""),
            "api_host": p.get("api_host", ""),
            "doc": p.get("doc", ""),
            "jurisdiction": prov.get("jurisdiction", ""),
            "operating_entity": prov.get("operating_entity", ""),
            "kind": prov.get("kind", ""),
            "confidence": prov.get("confidence"),
            "cn_flagged": is_cn_origin(prov.get("jurisdiction", "")),
        }
        for m in p.get("models") or []:
            row = dict(base)
            row.update({f"model_{k}" if k in ("id", "name", "family") else k: v
                        for k, v in m.items()})
            rows.append(row)
    return rows


def _row_haystack(row: dict) -> str:
    """The text a free-text query matches against for one row."""
    parts = [row.get("provider_name", ""), row.get("provider_id", ""),
             row.get("api_host", ""), row.get("api_url", ""),
             row.get("operating_entity", ""), row.get("model_id", ""),
             row.get("model_name", ""), row.get("family", "")]
    return " ".join(str(x) for x in parts).lower()


def search(catalog: dict, *, query: str = "", jurisdiction: str = "",
           kind: str = "", cn_only: bool = False, open_weights: bool | None = None,
           modality: str = "") -> list[dict]:
    """Filter the flattened rows. `query` is a case-insensitive substring over the
    provider/host/model/family text; the rest are exact-ish column filters.
    `jurisdiction` matches by prefix ('PRC' matches 'PRC-operator'); 'CN' is an
    alias for any Chinese-origin label."""
    rows = flatten(catalog)
    q = (query or "").strip().lower()
    jur = (jurisdiction or "").strip().upper()
    knd = (kind or "").strip().lower()
    mod = (modality or "").strip().lower()

    def keep(r: dict) -> bool:
        if q and q not in _row_haystack(r):
            return False
        if cn_only and not r.get("cn_flagged"):
            return False
        if jur:
            rj = (r.get("jurisdiction") or "").upper()
            if jur in ("CN", "PRC"):
                if not is_cn_origin(r.get("jurisdiction", "")):
                    return False
            elif not rj.startswith(jur):
                return False
        if knd and (r.get("kind") or "").lower() != knd:
            return False
        if open_weights is not None:
            ow = r.get("open_weights")
            # tri-state: unknown (None) matches neither True nor False.
            if ow is None or bool(ow) != open_weights:
                return False
        if mod and mod not in [str(x).lower() for x in
                               (list(r.get("modalities_in") or []) + list(r.get("modalities_out") or []))]:
            return False
        return True

    return [r for r in rows if keep(r)]


def load_bundled() -> dict | None:
    """Read the bundled catalog snapshot, or None if it isn't present / is invalid."""
    return load_path(_BUNDLED)


def load_path(path: str) -> dict | None:
    try:
        with open(path, encoding="utf-8") as fh:
            doc = json.load(fh)
        return doc if isinstance(doc, dict) and "providers" in doc else None
    except (OSError, json.JSONDecodeError):
        return None


def fetch_models_dev(url: str = SOURCE_URL, *, timeout: int = 30) -> dict:
    """Fetch the models.dev catalog (the ONE explicit egress in this module, used by
    `build-catalog`). Kept off the search/read path on purpose."""
    import requests
    r = requests.get(url, timeout=timeout, headers={"accept": "application/json"})
    r.raise_for_status()
    data = r.json()
    if not isinstance(data, dict):
        raise ValueError("models.dev did not return a JSON object")
    return data
