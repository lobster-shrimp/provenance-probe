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


# --- WS1 (#113): hard-evidence CEILING — a model's self-report is NOT evidence --
# of what its weights are. Soft/self-report signals may ADD weight but can never
# by themselves reach a CONFIRMED/LIKELY verdict; only a hard measured/artifact
# signal can anchor a positive call.

def test_soft_only_provenance_capped_at_indeterminate():
    # selfid_cn + informative_concession + held_false_persona + persona_mgmt_in_trace
    # would otherwise clear CONFIRMED with ZERO measurement.
    b = {"headers": {},
         "selfid": {"claimed_families": [{"token": "qwen", "family": "Qwen"}]},
         "deception": {
             "confrontation": {"true_backend": "Qwen", "false_backend": "Mistral AI",
                               "true_conceded": True, "false_conceded": False,
                               "informative_concession": True},
             "trace": {"tells": ["explicit persona management"]}}}
    s = scoring.score(b)
    assert s["provenance_risk"]["verdict"] == "INDETERMINATE"
    note = s["provenance_risk"]["note"]
    assert "self-report" in note
    # deterministic, sorted soft-signal listing
    assert "informative_concession" in note and "selfid_cn" in note


def test_held_false_persona_alone_capped():
    b = {"headers": {},
         "deception": {"confrontation": {"true_backend": "Zhipu GLM",
                                         "false_backend": "Mistral AI",
                                         "true_held": True, "true_conceded": False,
                                         "informative_concession": False}}}
    s = scoring.score(b)
    assert s["provenance_risk"]["verdict"] in ("INDETERMINATE", "UNLIKELY", "NO EVIDENCE")
    assert _TIER(s["provenance_risk"]["verdict"]) <= _TIER("INDETERMINATE")


def test_soft_only_jurisdiction_capped_at_indeterminate():
    # false_jurisdiction_assurance (2.4) alone would read LIKELY without any wire signal
    b = {"headers": {},
         "deception": {"correlation": {"misrepresentation": True, "severity": "critical",
                                       "finding": "false compliance assurance"}}}
    s = scoring.score(b)
    assert s["jurisdictional_risk"]["verdict"] == "INDETERMINATE"
    assert "self-report" in s["jurisdictional_risk"]["note"]


def test_hard_provenance_signal_keeps_tier():
    # tokenizer_match_cn (hard) + soft concession -> tier stands, no cap
    b = {"headers": {}, "tokenizer_match": _tok_match("CN", score=1.0),
         "deception": {"confrontation": {"true_backend": "Qwen", "false_backend": "Mistral AI",
                                         "true_conceded": True, "false_conceded": False,
                                         "informative_concession": True}}}
    s = scoring.score(b)
    assert s["provenance_risk"]["verdict"] in ("LIKELY", "CONFIRMED")
    assert "note" not in s["provenance_risk"]


def test_hard_jurisdiction_signal_keeps_tier():
    b = {"network": PRC_NET, "headers": {}}
    s = scoring.score(b)
    assert s["jurisdictional_risk"]["verdict"] in ("LIKELY", "CONFIRMED")
    assert "note" not in s["jurisdictional_risk"]


def test_deception_is_inculpatory_never_exculpatory():
    # A false persona (soft) must only ADD; adding it to a hard-driven verdict must
    # never lower it below the hard-only verdict.
    hard_only = scoring.score({"headers": {}, "tokenizer_match": _tok_match("CN", score=1.0)})
    with_denial = scoring.score({
        "headers": {}, "tokenizer_match": _tok_match("CN", score=1.0),
        "deception": {"confrontation": {"true_backend": "Zhipu GLM", "false_backend": "Mistral AI",
                                        "true_held": True, "true_conceded": False,
                                        "informative_concession": False}}})
    assert (_TIER(with_denial["provenance_risk"]["verdict"])
            >= _TIER(hard_only["provenance_risk"]["verdict"]))


def test_jurisdiction_hard_signal_does_not_anchor_provenance():
    # CRITICAL regression (cross-axis leak): client_prc_endpoint is a HARD signal on
    # BOTH axes but carries a jurisdiction-only WEIGHT (adds zero provenance log-odds).
    # Its presence must NOT unlock a soft-driven provenance verdict: with only
    # self-report provenance signals, provenance MUST cap at INDETERMINATE while
    # jurisdiction (which it actually anchors) may reach CONFIRMED.
    b = {"headers": {},
         "client_source": {"findings": [
             {"type": "client_prc_endpoint",
              "detail": "hardcoded api.some-prc-vendor.cn inference endpoint in client bundle"}]},
         "selfid": {"claimed_families": [{"token": "qwen", "family": "Qwen"}]},
         "deception": {
             "confrontation": {"true_backend": "Qwen", "false_backend": "Mistral AI",
                               "true_conceded": True, "false_conceded": False,
                               "informative_concession": True},
             "trace": {"tells": ["explicit persona management"]}}}
    s = scoring.score(b)
    assert s["provenance_risk"]["verdict"] == "INDETERMINATE"    # NOT a soft-driven CONFIRMED
    assert "self-report" in s["provenance_risk"]["note"]
    # client_prc_endpoint legitimately anchors jurisdiction (its actual axis weight)
    assert s["jurisdictional_risk"]["verdict"] in ("LIKELY", "CONFIRMED")
    assert "note" not in s["jurisdictional_risk"]


def _TIER(v):
    return scoring._TIER_ORDER.index(v)
