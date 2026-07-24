"""Backend fingerprinting + drift diff — shared by the CLI, the web UI, and the
observatory runner so there is ONE definition of "did the model change".

    baseline bundle ──┐
                      ├─▶ diff() ─▶ {changes:[{severity,field,detail}], drift_detected}
    current  bundle ──┘

A "change" is graded by severity:
    critical  fingerprint_id or tokenizer shape moved  → different model/stack
    high      error schema or a verdict changed        → likely different backend
    medium    latency profile drifted                  → weaker corroboration

The tokenizer comparison uses the overhead-invariant *shape* (tokenizer.shape_
vector), not raw prompt_tokens: a constant chat-template / accounting shift
moves every probe by the same amount and is NOT a model change. Only a shift in
the relative structure between probes indicates a different tokenizer family.
"""
from __future__ import annotations
import hashlib
import json

from .probes import tokenizer, latency


def fingerprint(b: dict) -> str:
    """Stable identity of the serving backend, for drift detection.

    Hashes the overhead-invariant tokenizer shape (not raw counts) plus the
    error schema, header shape, greedy signature, and streaming chunk fields.
    A constant token-accounting shift by the endpoint therefore does NOT flip
    the fingerprint; a genuine tokenizer-family / stack change still does.
    """
    parts = [
        json.dumps(tokenizer.shape_vector((b.get("tokenizer") or {}).get("vector", {})),
                   sort_keys=True),
        (b.get("errors") or {}).get("error_signature", ""),
        (b.get("headers") or {}).get("header_shape_hash", ""),
        (b.get("greedy") or {}).get("signature", ""),
        json.dumps((b.get("streaming") or {}).get("chunk_fields", [])),
    ]
    return hashlib.sha256("||".join(parts).encode()).hexdigest()[:24]


def _tokenizer_usable(b: dict) -> bool:
    return bool((b.get("tokenizer") or {}).get("usable"))


def diff(base: dict, cur: dict) -> dict:
    """Compare a current assessment against a baseline. Detects silent swaps.

    Returns {"changes": [...], "drift_detected": bool, "confidence": "full"|
    "degraded", "confidence_note": str?}. Pure — no I/O, no process exit — so the
    CLI, the web UI, and the observatory runner can all reuse it and present the
    result their own way.

    Confidence is "degraded" when the tokenizer layer was unavailable (the
    endpoint suppressed usage.prompt_tokens) in either run. The tokenizer
    fingerprint is the strongest signal; without it the comparison rests on
    wire + latency only, so a same-family model swap can slip through and a
    "no drift" verdict is weaker. Web apps commonly hit this. Making it explicit
    stops a degraded no-drift from reading as a clean bill of health.
    """
    changes: list[dict] = []

    if base.get("fingerprint_id") != cur.get("fingerprint_id"):
        changes.append({
            "severity": "critical", "field": "fingerprint_id",
            "detail": "Composite backend fingerprint changed — the serving model "
                      "or stack was altered since baseline."})

    bt = tokenizer.shape_vector((base.get("tokenizer") or {}).get("vector", {}))
    ct = tokenizer.shape_vector((cur.get("tokenizer") or {}).get("vector", {}))
    tdiff = {k: (bt[k], ct[k]) for k in bt if k in ct and bt[k] != ct[k]}
    if tdiff:
        changes.append({
            "severity": "critical", "field": "tokenizer_vector",
            "detail": f"Tokenizer shape changed on {len(tdiff)} probes (overhead-corrected): "
                      + ", ".join(f"{k} {v[0]}->{v[1]}" for k, v in list(tdiff.items())[:6]),
            "implication": "Different tokenizer => different model family."})

    if (base.get("errors") or {}).get("error_signature") != \
       (cur.get("errors") or {}).get("error_signature"):
        changes.append({
            "severity": "high", "field": "error_signature",
            "detail": "Error schema changed — likely a different backend provider."})

    for k in ("jurisdictional_risk", "provenance_risk"):
        bv = (base.get("score") or {}).get(k, {}).get("verdict")
        cv = (cur.get("score") or {}).get(k, {}).get("verdict")
        if bv != cv:
            changes.append({"severity": "high", "field": k,
                            "detail": f"{k}: {bv} -> {cv}"})

    if base.get("latency") and cur.get("latency"):
        d = latency.drift(base["latency"], cur["latency"])
        if d["drifted"]:
            changes.append({"severity": "medium", "field": "latency",
                            "detail": json.dumps(d["signals"])})

    degraded = not (_tokenizer_usable(base) and _tokenizer_usable(cur))
    out = {"changes": changes, "drift_detected": bool(changes),
           "confidence": "degraded" if degraded else "full"}
    if degraded:
        out["confidence_note"] = (
            "Tokenizer layer unavailable (usage suppressed) in at least one run — "
            "the strongest signal is absent. Drift judged on wire + latency only; "
            "a same-family model swap could go undetected and a no-drift result is "
            "not a clean bill of health.")
    return out
