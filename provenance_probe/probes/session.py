"""Session-boundary model-switch detection (live endpoints).

The nightly `monitor` catches a backend swap between runs. This catches a swap
WITHIN a single session: fingerprint the served model at the start, advance the
session (a few filler turns, as a load balancer would rotate on), fingerprint
again at the end, and diff. Reuses the same fingerprint + diff as `monitor`, so
a within-session swap and a day-over-day swap are judged identically.

    start snapshot ──┐
     (fingerprint)   ├── gap probes advance the session ──► end snapshot
                     │                                        (fingerprint)
                     └────────────── monitor.diff ────────────────┘
                                        │
                       boundary_switch = fingerprint changed
"""
from __future__ import annotations

from . import tokenizer, wire, logprob
from .. import monitor


def _snapshot(client, variant_seed: int = 0) -> dict:
    """A fingerprintable slice of the served backend (tokenizer + wire)."""
    b = {
        "tokenizer": tokenizer.measure(client, variant_seed=variant_seed),
        "headers": wire.header_fingerprint(client),
        "errors": wire.error_schema_fingerprint(client),
        "greedy": logprob.greedy_signature(client),
        "streaming": wire.streaming_fingerprint(client),
    }
    b["fingerprint_id"] = monitor.fingerprint(b)
    return b


def boundary_check(client, *, gap_probes: int = 5, variant_seed: int = 0) -> dict:
    """Fingerprint at session start and end; report a within-session switch.

    gap_probes: filler turns sent between the two snapshots to advance the
    session (some endpoints rotate the served model after N requests).
    """
    start = _snapshot(client, variant_seed)
    for _ in range(max(0, gap_probes)):
        client.chat("Continue.", max_tokens=1, temperature=0.0)
    end = _snapshot(client, variant_seed)
    d = monitor.diff(start, end)
    return {
        "gap_probes": gap_probes,
        "start_fingerprint": start["fingerprint_id"],
        "end_fingerprint": end["fingerprint_id"],
        "boundary_switch": d["drift_detected"],
        "confidence": d["confidence"],
        "changes": d["changes"],
    }
