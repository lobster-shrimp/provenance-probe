"""Tests for the shared monitor module (fingerprint + diff).

These lock the drift-detection contract the CLI, the web UI Monitor tab, and
the observatory runner all depend on.
"""
from provenance_probe import monitor


def _bundle(vec, *, fp="fp-a", err="sig-1", jur="UNLIKELY", prov="NO EVIDENCE"):
    return {
        "fingerprint_id": fp,
        "tokenizer": {"vector": vec, "usable": True},
        "errors": {"error_signature": err},
        "score": {"jurisdictional_risk": {"verdict": jur},
                  "provenance_risk": {"verdict": prov}},
    }


VEC = {"a": 10, "b": 12, "c": 15, "d": 11, "e": 13, "f": 14}


def test_identical_runs_no_drift():
    b = _bundle(VEC)
    out = monitor.diff(b, dict(b))
    assert out["drift_detected"] is False
    assert out["changes"] == []


def test_fingerprint_change_is_critical():
    out = monitor.diff(_bundle(VEC, fp="fp-a"), _bundle(VEC, fp="fp-b"))
    assert out["drift_detected"] is True
    crit = [c for c in out["changes"] if c["field"] == "fingerprint_id"]
    assert crit and crit[0]["severity"] == "critical"


def test_tokenizer_shape_change_is_critical():
    shifted = dict(VEC); shifted["c"] = 99      # relative structure changed
    out = monitor.diff(_bundle(VEC), _bundle(shifted, fp="fp-a"))
    tok = [c for c in out["changes"] if c["field"] == "tokenizer_vector"]
    assert tok and tok[0]["severity"] == "critical"
    assert "different model family" in tok[0]["implication"].lower()


def test_constant_overhead_shift_is_not_drift():
    # every probe +7 (a chat-template/accounting change) must NOT read as a swap
    shifted = {k: v + 7 for k, v in VEC.items()}
    out = monitor.diff(_bundle(VEC), _bundle(shifted))   # same fp, err, verdicts
    assert out["drift_detected"] is False


def test_verdict_change_is_high():
    out = monitor.diff(_bundle(VEC, prov="NO EVIDENCE"),
                       _bundle(VEC, prov="CONFIRMED"))
    hi = [c for c in out["changes"] if c["field"] == "provenance_risk"]
    assert hi and hi[0]["severity"] == "high"
    assert "NO EVIDENCE -> CONFIRMED" in hi[0]["detail"]


def test_error_schema_change_is_high():
    out = monitor.diff(_bundle(VEC, err="sig-1"), _bundle(VEC, err="sig-2"))
    assert any(c["field"] == "error_signature" and c["severity"] == "high"
               for c in out["changes"])


def test_fingerprint_stable_and_overhead_invariant():
    b1 = {"tokenizer": {"vector": VEC}, "errors": {"error_signature": "s"}}
    b2 = {"tokenizer": {"vector": {k: v + 100 for k, v in VEC.items()}},
          "errors": {"error_signature": "s"}}
    # deterministic, and a constant shift does not move the fingerprint
    assert monitor.fingerprint(b1) == monitor.fingerprint(b1)
    assert monitor.fingerprint(b1) == monitor.fingerprint(b2)
    # a real structural change does move it
    b3 = {"tokenizer": {"vector": {**VEC, "c": 99}}, "errors": {"error_signature": "s"}}
    assert monitor.fingerprint(b1) != monitor.fingerprint(b3)


# --- degraded confidence when usage/tokenizer is suppressed -----------------

def _no_tok(*, fp="fp-a", err="sig-1"):
    return {"fingerprint_id": fp, "tokenizer": {"usable": False},
            "errors": {"error_signature": err}, "score": {}}


def test_confidence_full_when_both_tokenizers_usable():
    out = monitor.diff(_bundle(VEC), _bundle(VEC))
    assert out["confidence"] == "full"
    assert "confidence_note" not in out


def test_confidence_degraded_when_usage_suppressed():
    out = monitor.diff(_no_tok(), _no_tok())
    assert out["confidence"] == "degraded"
    assert "usage suppressed" in out["confidence_note"]
    assert "not a clean bill" in out["confidence_note"]


def test_degraded_still_detects_wire_drift():
    # tokenizer gone, but error schema changed -> drift still flagged, degraded
    out = monitor.diff(_no_tok(err="s1"), _no_tok(err="s2", fp="fp-b"))
    assert out["drift_detected"] is True
    assert out["confidence"] == "degraded"


def test_degraded_if_only_one_side_suppressed():
    out = monitor.diff(_bundle(VEC), _no_tok(fp="fp-a"))
    assert out["confidence"] == "degraded"
