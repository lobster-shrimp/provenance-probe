"""Characterization tests for the three engine contracts the Provenance
Observatory depends on:

1. fingerprint_id is stable across a benign chat-template / token-accounting
   shift, and changes only on a genuine backend change.
2. `monitor` exits 2 on drift, 0 on no-change (and does NOT false-drift on a
   constant token-overhead shift — the bug this branch fixes).
3. The tokenizer vector match identifies a known family (Qwen2) from the
   shipped reference, and survives a constant overhead offset.

These pin behavior the observatory's public verdicts rest on. Written
alongside the _fp() overhead-invariance fix (see cli._fp / tokenizer.shape_vector).
"""
from __future__ import annotations

import argparse
import json
import os

import pytest

from provenance_probe import cli
from provenance_probe.probes import tokenizer

REF_PATH = os.path.join(
    os.path.dirname(tokenizer.__file__), "..", "data", "tokenizer_ref.json"
)


def _shift(vec: dict, c: int) -> dict:
    """Apply a constant token overhead to every probe (a benign template change)."""
    return {k: v + c for k, v in vec.items()}


# --- Contract 1 + the fix: shape_vector / fingerprint overhead-invariance ---


def test_shape_vector_cancels_constant_offset():
    vec = {"a": 10, "b": 13, "c": 21}
    assert tokenizer.shape_vector(_shift(vec, 5)) == tokenizer.shape_vector(vec)
    assert tokenizer.shape_vector(_shift(vec, 100)) == tokenizer.shape_vector(vec)


def test_shape_vector_preserves_structure():
    # Different relative structure must NOT normalize to the same shape.
    a = {"p1": 10, "p2": 12, "p3": 20}
    b = {"p1": 10, "p2": 18, "p3": 20}
    assert tokenizer.shape_vector(a) != tokenizer.shape_vector(b)


def test_shape_vector_empty():
    assert tokenizer.shape_vector({}) == {}


def _backend(vector: dict, error_sig: str = "sig-A") -> dict:
    return {
        "tokenizer": {"vector": vector},
        "errors": {"error_signature": error_sig},
        "headers": {"header_shape_hash": "h1"},
        "greedy": {"signature": "g1"},
        "streaming": {"chunk_fields": ["choices", "delta"]},
    }


def test_fingerprint_stable_across_benign_overhead_shift():
    base = _backend({"p1": 12, "p2": 15, "p3": 22, "p4": 30})
    shifted = _backend(_shift(base["tokenizer"]["vector"], 4))
    assert cli._fp(base) == cli._fp(shifted), (
        "a constant template-overhead shift must not flip the fingerprint"
    )


def test_fingerprint_changes_on_real_tokenizer_change():
    base = _backend({"p1": 12, "p2": 15, "p3": 22, "p4": 30})
    swapped = _backend({"p1": 12, "p2": 25, "p3": 14, "p4": 30})
    assert cli._fp(base) != cli._fp(swapped)


def test_fingerprint_changes_on_non_tokenizer_signal():
    base = _backend({"p1": 12, "p2": 15, "p3": 22})
    changed = _backend({"p1": 12, "p2": 15, "p3": 22}, error_sig="sig-B")
    assert cli._fp(base) != cli._fp(changed)


# --- Contract 2: monitor exit-2 drift semantics ---


def _write(tmp_path, name, backend):
    p = tmp_path / name
    p.write_text(json.dumps(backend))
    return str(p)


def _run_monitor(baseline_path, current_path):
    a = argparse.Namespace(baseline=baseline_path, current=current_path, json_out=None)
    with pytest.raises(SystemExit) as exc:
        cli.cmd_monitor(a)
    return exc.value.code


def _scored(vector, error_sig="sig-A"):
    b = _backend(vector, error_sig)
    b["fingerprint_id"] = cli._fp(b)
    return b


def test_monitor_exit_0_on_identical(tmp_path):
    b = _scored({"p1": 12, "p2": 15, "p3": 22})
    base = _write(tmp_path, "base.json", b)
    cur = _write(tmp_path, "cur.json", b)
    assert _run_monitor(base, cur) == 0


def test_monitor_exit_2_on_fingerprint_drift(tmp_path):
    base = _write(tmp_path, "base.json", _scored({"p1": 12, "p2": 15, "p3": 22}))
    cur = _write(tmp_path, "cur.json", _scored({"p1": 12, "p2": 25, "p3": 14}))
    assert _run_monitor(base, cur) == 2


def test_monitor_no_false_drift_on_benign_overhead(tmp_path):
    """The regression this branch fixes: a constant token-overhead shift used
    to flip fingerprint_id and trip a critical drift. It must not any more."""
    v = {"p1": 12, "p2": 15, "p3": 22, "p4": 30}
    base = _write(tmp_path, "base.json", _scored(v))
    cur = _write(tmp_path, "cur.json", _scored(_shift(v, 3)))
    assert _run_monitor(base, cur) == 0, (
        "benign constant-overhead shift must not register as drift"
    )


# --- Contract 3: tokenizer match against the shipped reference ---


@pytest.fixture(scope="module")
def reference():
    with open(REF_PATH) as f:
        return json.load(f)


def test_qwen2_reference_present(reference):
    assert "Qwen2/Qwen2.5" in reference.get("models", {})


def test_tokenizer_match_identifies_qwen2(reference):
    qwen = reference["models"]["Qwen2/Qwen2.5"]["vector"]
    observed = {"vector": dict(qwen)}
    results = tokenizer.compare(observed, reference)
    assert results, "compare returned no results"
    assert results[0]["model"] == "Qwen2/Qwen2.5"
    assert results[0]["score"] >= 0.9


def test_tokenizer_match_survives_overhead_offset(reference):
    qwen = reference["models"]["Qwen2/Qwen2.5"]["vector"]
    observed = {"vector": _shift(qwen, 7)}  # a chat-template overhead
    results = tokenizer.compare(observed, reference)
    assert results[0]["model"] == "Qwen2/Qwen2.5"
    assert results[0]["score"] >= 0.9, (
        "overhead correction should keep the correct family on top"
    )
