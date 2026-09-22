"""Backend fingerprinting + drift diff — shared by the CLI, the web UI, and the
observatory runner so there is ONE definition of "did the model change".

    baseline bundle ──┐
                      ├─▶ diff() ─▶ {changes:[{severity,field,detail}], drift_detected}
    current  bundle ──┘

A "change" is graded by severity — and ONLY the tokenizer shape can be critical:
    critical  tokenizer SHAPE moved (both runs measurable) → CONFIRMED model/stack switch
    high      error schema or a verdict changed            → provider/wire change (advisory)
    medium    header / streaming / greedy / latency drifted → wire noise (advisory)

WS1 (#127): the tokenizer shape is the *switch authority*. The composite
``fingerprint_id`` folds wire/error noise (error_signature, header_shape_hash,
streaming chunk_fields, greedy signature) alongside the real model signal, so a
mere composite change is NOT graded critical — that produced FALSE confirmed
switches on a stable local model whose error_signature merely moved between two
probes. ``drift_detected`` is True iff a critical (tokenizer-shape) change exists;
non-tokenizer moves are reported as advisories but never set drift.

The tokenizer comparison uses the overhead-invariant *shape* (tokenizer.shape_
vector), not raw prompt_tokens: a constant chat-template / accounting shift
moves every probe by the same amount and is NOT a model change. Only a shift in
the relative structure between probes indicates a different tokenizer family.

ACCEPTED LIMITATION (WS1-honest): identical tokenizer shapes do NOT *prove* the
model is unchanged — two models sharing a tokenizer (e.g. a finetune) look
identical here. A same-tokenizer swap therefore yields at most an ADVISORY (from
greedy/wire), never a CONFIRMED switch. This is correct and intended: you can
only CONFIRM a switch you can measure.
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


def _shape(b: dict) -> dict:
    return tokenizer.shape_vector((b.get("tokenizer") or {}).get("vector", {}))


def _tokenizer_comparable(base: dict, cur: dict) -> bool:
    """The tokenizer shapes are comparable — and can therefore arbitrate a switch —
    ONLY when BOTH runs have a usable tokenizer: the ``usable`` flag is true AND the
    shape vector is non-empty. If either side is missing/empty/unusable the shape
    cannot confirm a switch, and the comparison falls back to a degraded advisory."""
    return bool(_tokenizer_usable(base) and _tokenizer_usable(cur)
                and _shape(base) and _shape(cur))


# Advisory tail appended to every NON-tokenizer wire/error advisory so the read is
# unambiguous: a provider/wire move is not a confirmed model switch on its own.
_WIRE_NOTE = " — provider/wire change, NOT a confirmed model switch."


def diff(base: dict, cur: dict) -> dict:
    """Compare a current assessment against a baseline. Detects silent swaps.

    Returns {"changes": [...], "drift_detected": bool, "confidence": "full"|
    "degraded", "confidence_note": str?}. Pure — no I/O, no process exit — so the
    CLI, the web UI, and the observatory runner can all reuse it and present the
    result their own way.

    #127 grading contract: ``critical`` is reserved for a tokenizer-SHAPE change
    (the switch authority); the composite ``fingerprint_id`` is a pin/label only
    and is NOT graded. Every non-tokenizer component (error_signature, header
    shape, streaming chunk fields, greedy signature, verdicts, latency) is reported
    with its existing non-critical severity but never sets ``drift_detected``.
    ``drift_detected`` is True iff a critical change exists — nothing else.

    Confidence is "degraded" when the tokenizer layer is not comparable (usage
    suppressed / empty shape) in either run. The tokenizer is the strongest — and
    the ONLY confirming — signal; without it the comparison rests on wire + latency
    advisories only, so a same-family model swap can slip through and a "no drift"
    verdict is weaker. Web apps commonly hit this. Making it explicit stops a
    degraded no-drift from reading as a clean bill of health.
    """
    changes: list[dict] = []

    # (1) The tokenizer SHAPE is the switch authority — the ONLY signal graded
    #     critical. Compared only when measurable on BOTH sides (see #127: a stable
    #     local model tripped a false CONFIRMED purely on error_signature noise
    #     folded into the composite fingerprint_id — that grading is gone).
    comparable = _tokenizer_comparable(base, cur)
    if comparable:
        bt, ct = _shape(base), _shape(cur)
        tdiff = {k: (bt[k], ct[k]) for k in bt if k in ct and bt[k] != ct[k]}
        if tdiff:
            changes.append({
                "severity": "critical", "field": "tokenizer_vector",
                "detail": f"Tokenizer shape changed on {len(tdiff)} probes (overhead-corrected): "
                          + ", ".join(f"{k} {v[0]}->{v[1]}" for k, v in list(tdiff.items())[:6]),
                "implication": "Different tokenizer => different model family — "
                               "a CONFIRMED model/stack switch."})

    # (2) Non-tokenizer components: reported with their existing NON-critical
    #     severities. A move here is a provider/wire change (or, for greedy, a
    #     possible same-tokenizer variation) — advisory only, never a switch.
    if (base.get("errors") or {}).get("error_signature") != \
       (cur.get("errors") or {}).get("error_signature"):
        changes.append({
            "severity": "high", "field": "error_signature",
            "detail": "Error schema changed" + _WIRE_NOTE})

    if (base.get("headers") or {}).get("header_shape_hash") != \
       (cur.get("headers") or {}).get("header_shape_hash"):
        changes.append({
            "severity": "medium", "field": "header_shape",
            "detail": "Response header shape changed" + _WIRE_NOTE})

    if (base.get("streaming") or {}).get("chunk_fields") != \
       (cur.get("streaming") or {}).get("chunk_fields"):
        changes.append({
            "severity": "medium", "field": "streaming",
            "detail": "Streaming chunk fields changed" + _WIRE_NOTE})

    if (base.get("greedy") or {}).get("signature") != \
       (cur.get("greedy") or {}).get("signature"):
        changes.append({
            "severity": "medium", "field": "greedy",
            "detail": "Greedy-decoding signature changed — possible same-tokenizer "
                      "variation; advisory, NOT a confirmed switch."})

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

    # drift_detected == (a critical tokenizer-shape change exists). Nothing else.
    drift = any(c["severity"] == "critical" for c in changes)
    degraded = not comparable
    out = {"changes": changes, "drift_detected": drift,
           "confidence": "degraded" if degraded else "full"}
    if degraded:
        out["confidence_note"] = (
            "Tokenizer layer not comparable (usage suppressed / empty shape) in at "
            "least one run — the only CONFIRMING signal is absent, so a switch cannot "
            "be confirmed here. Any change is reported as a wire/latency ADVISORY "
            "only; a same-family model swap could go undetected and a no-drift result "
            "is not a clean bill of health.")
    return out
