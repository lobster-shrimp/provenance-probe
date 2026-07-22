"""Provenance verdict calibration: a 'clean' verdict is only given when a
provenance-detecting layer actually returned data. Regression for the real
DeepSeek run where every tokenizer probe 402'd and provenance still read
UNLIKELY (a false 'probably not Chinese')."""
from provenance_probe import scoring

PRC_NET = {"addresses": ["1.2.3.4"],
           "findings": [{"type": "prc_endpoint", "severity": "critical", "detail": "DeepSeek"}]}


def _tok_match(origin, score=1.0, model="X", family="F"):
    return [{"model": model, "family": family, "origin": origin, "score": score,
             "exact_matches": 20, "shared_probes": 20}]


def test_unmeasured_provenance_is_indeterminate_not_unlikely():
    # jurisdiction confirmed, but tokenizer/artifacts/client-source all empty
    b = {"network": PRC_NET, "headers": {}}
    s = scoring.score(b)
    assert s["jurisdictional_risk"]["verdict"] == "CONFIRMED"
    assert s["provenance_risk"]["verdict"] == "INDETERMINATE"      # floored, not UNLIKELY
    assert "not actually measured" in s["provenance_risk"]["note"]


def test_clean_provenance_kept_when_detector_ran():
    # tokenizer fingerprint ran and matched a US family -> a real clean verdict
    b = {"network": PRC_NET, "headers": {}, "tokenizer_match": _tok_match("US")}
    s = scoring.score(b)
    assert s["provenance_risk"]["verdict"] in ("UNLIKELY", "NO EVIDENCE")
    assert "note" not in s["provenance_risk"]                       # legitimately clean


def test_positive_cn_provenance_unaffected_by_floor():
    b = {"network": PRC_NET, "headers": {}, "tokenizer_match": _tok_match("CN")}
    s = scoring.score(b)
    assert s["provenance_risk"]["verdict"] in ("LIKELY", "CONFIRMED")


def test_floor_does_not_touch_jurisdiction():
    b = {"network": {"addresses": [], "findings": []}, "headers": {}}
    s = scoring.score(b)
    # no jurisdiction evidence -> its own low verdict, unchanged by the prov floor
    assert s["jurisdictional_risk"]["verdict"] in ("UNLIKELY", "NO EVIDENCE", "INDETERMINATE")
    assert s["provenance_risk"]["verdict"] == "INDETERMINATE"       # still floored
