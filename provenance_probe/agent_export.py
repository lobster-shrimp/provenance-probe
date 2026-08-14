"""Deterministic evidence bundle for an agent assessment (E5).

The bundle IS a `verdict.json` record shaped like the observatory's other records,
so it can be dropped under the observatory data tree and signed by the existing
daily cosign+Rekor manifest job (record-drop — no signing in the engine, no
duplicated crypto). Deterministic: the same input produces byte-identical output
except the isolated `captured_at` field, so a signature is reproducible.
"""
from __future__ import annotations

import hashlib
import json

SCHEMA_VERSION = "0.1.0"


def _engine_version() -> str:
    try:
        from importlib.metadata import version
        # PyPI distribution name is llm-provenance-probe (the CLI command + import
        # package stay provenance-probe / provenance_probe).
        return f"llm-provenance-probe=={version('llm-provenance-probe')}"
    except Exception:
        return "llm-provenance-probe"


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def build_bundle(result: dict, *, target: str, input_sha256: str | None = None,
                 endpoint: str | None = None, model: str | None = None,
                 observation: list[str] | None = None, captured_at: str | None = None) -> dict:
    """Assemble the evidence record. `captured_at` is the ONLY non-deterministic
    field (pass None for a reproducible core; the caller stamps it at write time)."""
    steps = [{k: v for k, v in s.items() if k != "score"} for s in result["steps"]]
    return {
        "schema_version": SCHEMA_VERSION,
        "kind": "agent",
        "captured_at": captured_at,
        "target": target,
        "endpoint": endpoint,
        "model": model,
        "observation": observation or ["trace"],
        "engine": _engine_version(),
        "input_sha256": input_sha256,
        "verdict": result["verdict"],
        "steps": steps,
    }


def canonical(bundle: dict) -> str:
    """Canonical JSON: sorted keys, stable separators — so the same bundle hashes
    identically (matches how monitor.fingerprint canonicalizes)."""
    return json.dumps(bundle, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def write_bundle(path: str, result: dict, *, target: str, input_text: str = "",
                 captured_at: str | None = None, **meta) -> dict:
    bundle = build_bundle(result, target=target,
                          input_sha256=sha256_text(input_text) if input_text else None,
                          captured_at=captured_at, **meta)
    with open(path, "w", encoding="utf-8") as f:
        f.write(json.dumps(bundle, sort_keys=True, indent=2, ensure_ascii=False))
    return bundle
