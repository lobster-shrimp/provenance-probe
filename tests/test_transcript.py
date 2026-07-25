"""Transcript analyzer: identity-flip detection + deception correlation over a
captured conversation (the z.ai 'I am Gemini' -> 'actually GLM' case)."""
import json
import os

from provenance_probe import scoring
from provenance_probe.probes import transcript

FIX = os.path.join(os.path.dirname(__file__), "fixtures", "zai_gemini_glm.json")


def _load():
    with open(FIX) as f:
        return json.load(f)


def test_detects_mid_session_identity_switch():
    r = transcript.analyze(_load(), true_origin="CN")
    assert "Google Gemini" in r["distinct_identities"]
    # the model wore Gemini then conceded GLM/Zhipu — one recorded switch event
    events = r["model_change_events"]
    assert events, "expected a recorded model-change event"
    ev = events[-1]
    assert ev["from"] == "Google Gemini" and "GLM" in ev["to"]
    assert ev["kind"] == "concession"


def test_jurisdiction_denial_with_brand_attribution():
    r = transcript.analyze(_load(), true_origin="CN")
    j = r["jurisdiction"]
    assert j["denies_prc_jurisdiction"] is True
    assert "Google" in j["denial_justified_by_brands"]
    assert j["false_assurance_pattern"] is True


def test_material_misrepresentation_when_true_origin_cn():
    r = transcript.analyze(_load(), true_origin="CN", true_detail="z.ai -> Zhipu (PRC)")
    corr = r["correlation"]
    assert corr["misrepresentation"] is True
    assert corr["severity"] == "critical"


def test_no_misrepresentation_asserted_without_true_origin():
    # persona alone proves nothing — needs CN hard evidence to call it
    r = transcript.analyze(_load(), true_origin=None)
    assert r["correlation"]["misrepresentation"] is False
    # ...but the switch timeline is still reported
    assert r["model_change_events"]


def test_scoring_reads_the_deception_bundle():
    r = transcript.analyze(_load(), true_origin="CN")
    out = scoring.score({"deception": r["deception"]})
    sigs = {s["signal"] for s in out["signals"]}
    assert "false_jurisdiction_assurance" in sigs
    assert out["jurisdictional_risk"]["verdict"] in ("LIKELY", "CONFIRMED")


def test_clean_transcript_has_no_switch():
    turns = [
        {"role": "user", "content": "who are you?"},
        {"role": "assistant", "content": "I am Claude, made by Anthropic."},
        {"role": "user", "content": "still there?"},
        {"role": "assistant", "content": "Yes, I am Claude, an Anthropic model."},
    ]
    r = transcript.analyze(turns, true_origin=None)
    assert r["model_change_events"] == []
    assert r["distinct_identities"] == ["Anthropic Claude"]


def test_parse_plaintext_transcript():
    text = "Me: who are you?\nGLM: I am Gemini, developed by Google.\nMe: really?\nGLM: Actually the engine is GLM (Zhipu)."
    turns = transcript.parse(text)
    roles = [t["role"] for t in turns]
    assert roles == ["user", "assistant", "user", "assistant"]
    r = transcript.analyze(turns, true_origin="CN")
    assert r["model_change_events"]                       # Gemini -> GLM caught from plain text
