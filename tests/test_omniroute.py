"""Unit tests for the OmniRoute cross-check + calibration gate (P2a).

All pure/injectable — no network. The load-bearing invariants: INCONCLUSIVE is
the default for any uncertainty, CONTRADICTED requires two DISTINCT KNOWN
families, version drift is CORROBORATED, and via-OmniRoute is only trusted once
calibration passes.
"""
from __future__ import annotations

import pytest

from provenance_probe import omniroute as O


# --------------------------------------------------------------------------- #
# Label -> family
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("label,fam", [
    ("oc/deepseek-v4-flash-free", "DeepSeek"),
    ("deepseek-chat", "DeepSeek"),
    ("openrouter/qwen2.5-72b", "Qwen"),
    ("glm-4.6", "GLM"),
    ("zhipu/glm-4", "GLM"),
    ("kimi-k2", "Moonshot"),
    ("gpt-4o-mini", "OpenAI"),
    ("claude-3-5-sonnet", "Claude"),
    ("minimax-m1", "MiniMax"),
])
def test_label_to_family(label, fam):
    assert O.label_to_family(label) == fam


@pytest.mark.unit
def test_label_to_family_unmapped_is_none():
    assert O.label_to_family("some-unknown-model-xyz") is None
    assert O.label_to_family("") is None


@pytest.mark.unit
@pytest.mark.parametrize("label", [
    "proto1-vision",   # 'o1' mid-word must NOT match OpenAI
    "video1",
    "audio1-tts",
    "yixin-chat",      # 'yi' mid-word must NOT match Yi
    "glimmer-7b",      # 'glm'? no; 'gemini/gemma'? no -> unmapped
])
def test_label_to_family_no_midword_false_match(label):
    # HIGH (Claude): unanchored 2-char keys (o1/o3/o4/yi) must not match mid-word,
    # else an incidental substring in a router header becomes a false accusation.
    assert O.label_to_family(label) is None


@pytest.mark.unit
@pytest.mark.parametrize("label,fam", [
    ("o1-preview", "OpenAI"),        # legit o1 route still maps
    ("gpt-4o", "OpenAI"),
    ("yi-1.5-34b", "Yi"),            # legit yi segment still maps
])
def test_label_to_family_boundary_still_matches_legit(label, fam):
    assert O.label_to_family(label) == fam


@pytest.mark.unit
@pytest.mark.parametrize("a,b,rel", [
    ("DeepSeek", "DeepSeek-V3", "same"),        # version drift
    ("Qwen2", "Qwen", "same"),
    ("DeepSeek", "Qwen2", "different"),         # two distinct known families
    ("OpenAI", "Claude", "different"),
    ("DeepSeek", "SomethingExotic", "unclear"), # one side unknown -> unclear
    ("", "DeepSeek", "unclear"),
    ("GPT-NeoX", "GPT-2/OpenAI", "unclear"),    # gpt ⊂ gptneox -> never CONTRADICTED
    ("GLM", "GLM/Zhipu", "same"),               # vendor-suffixed ref name
    ("Claude", "Claude/Anthropic", "same"),
    ("Gemini", "Gemini/Google", "same"),
    ("Yi", "Yi/01.AI", "same"),
])
def test_family_relation(a, b, rel):
    assert O._family_relation(a, b) == rel


@pytest.mark.unit
@pytest.mark.parametrize("fam,root", [
    ("GLM/Zhipu", "glm"), ("Claude/Anthropic", "claude"), ("GPT-2/OpenAI", "gpt"),
    ("GPT-NeoX", "gptneox"), ("DeepSeek-V3", "deepseek"), ("Qwen2/Qwen2.5", "qwen"),
    ("OpenAI", "openai"), ("Yi/01.AI", "yi"), ("Llama-3", "llama"),
])
def test_root_normalization(fam, root):
    assert O._root(fam) == root


@pytest.mark.unit
def test_gpt_neox_label_not_falsely_contradicted():
    # P2 (Codex): 'gpt-neox-20b' must map to GPT-NeoX, and cross-checking against
    # a GPT-NeoX fingerprint must NOT be CONTRADICTED (it was, via gpt->OpenAI).
    assert O.label_to_family("gpt-neox-20b") == "GPT-NeoX"
    cc = O.cross_check("gpt-neox-20b", "GPT-NeoX", calibrated=True)
    assert cc.state == O.CORROBORATED


@pytest.mark.unit
def test_glm_label_corroborates_vendor_suffixed_ref():
    cc = O.cross_check("zhipu/glm-4.6", "GLM/Zhipu", calibrated=True)
    assert cc.state == O.CORROBORATED


@pytest.mark.unit
def test_minimax_without_reference_is_inconclusive_not_contradicted():
    # MEDIUM (Claude): MiniMax has a label→family entry but NO reference vector,
    # so a minimax route can never fingerprint to MiniMax. Calling it CONTRADICTED
    # would be a false accusation; it must stay INCONCLUSIVE.
    cc = O.cross_check("minimax-m1", "Qwen", calibrated=True)
    assert cc.state == O.INCONCLUSIVE


@pytest.mark.unit
def test_known_roots_derived_from_references_excludes_minimax():
    roots = O._known_roots()
    assert "deepseek" in roots and "qwen" in roots and "openai" in roots
    assert "minimax" not in roots        # no MiniMax reference vector ships


# --------------------------------------------------------------------------- #
# Three-state cross-check
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_cross_check_corroborated_with_version_drift():
    cc = O.cross_check("oc/deepseek-v4-flash-free", "DeepSeek-V3", calibrated=True)
    assert cc.state == O.CORROBORATED
    assert cc.mapped_family == "DeepSeek"


@pytest.mark.unit
def test_cross_check_contradicted_only_for_distinct_known():
    cc = O.cross_check("gpt-4o", "DeepSeek-V3", calibrated=True)
    assert cc.state == O.CONTRADICTED
    assert "NOT auto-published" in cc.note        # quarantine reminder in the note


@pytest.mark.unit
def test_cross_check_uncalibrated_is_inconclusive():
    # Even a clean match is withheld until calibration passes (confidence cap).
    cc = O.cross_check("oc/deepseek-v4", "DeepSeek-V3", calibrated=False)
    assert cc.state == O.INCONCLUSIVE
    assert "calibrat" in cc.note.lower()


@pytest.mark.unit
def test_cross_check_unmapped_label_is_inconclusive():
    cc = O.cross_check("mystery-model-9000", "DeepSeek", calibrated=True)
    assert cc.state == O.INCONCLUSIVE


@pytest.mark.unit
def test_cross_check_no_fingerprint_is_inconclusive():
    cc = O.cross_check("deepseek-chat", None, calibrated=True)
    assert cc.state == O.INCONCLUSIVE


@pytest.mark.unit
def test_cross_check_unclear_relation_is_inconclusive_not_contradicted():
    # mapped known family vs an unknown fingerprint family -> never CONTRADICTED.
    cc = O.cross_check("deepseek-chat", "ExoticUnknownFamily", calibrated=True)
    assert cc.state == O.INCONCLUSIVE


# --------------------------------------------------------------------------- #
# Calibration gate
# --------------------------------------------------------------------------- #

# A reference shape (10 probes) to calibrate against.
_REF = {"p1": 2, "p2": 5, "p3": 9, "p4": 4, "p5": 12, "p6": 7,
        "p7": 3, "p8": 6, "p9": 11, "p10": 8}
# A DISTINCT tokenizer that still TRACKS prompt length (correlates) but has
# different absolute counts — the cross-family false-positive Pearson would pass.
_OTHER = {k: round(v * 1.6) + 1 for k, v in _REF.items()}


@pytest.mark.unit
def test_calibration_passes_on_clean_constant_offset():
    # A perfect constant offset (+2000) cancels -> all exact -> calibrated.
    obs = {k: v + 2000 for k, v in _REF.items()}
    cal = O.calibrate(obs, _REF, expected_family="DeepSeek",
                      omniroute_version="1.2.3", route="oc/deepseek-v4")
    assert cal.passed is True
    assert cal.exact_frac == 1.0 and cal.max_residual == 0
    assert cal.template_overhead == 2000 and cal.omniroute_version == "1.2.3"


@pytest.mark.unit
def test_calibration_rejects_wrong_family_that_merely_correlates():
    # CRITICAL (Codex): a different tokenizer that correlates in shape but differs
    # in scale must NOT calibrate. (Pearson would pass this ~0.99; exact-fraction
    # does not.) Offset by a constant so only the SHAPE could match.
    obs = {k: v + 2000 for k, v in _OTHER.items()}
    cal = O.calibrate(obs, _REF, expected_family="DeepSeek")
    assert cal.passed is False
    assert cal.exact_frac < 0.9


@pytest.mark.unit
def test_calibration_fails_on_seam_distortion():
    # Constant offset PLUS distortion on 3/10 probes (BPE seam) -> exact frac 0.7
    # -> NOT calibrated (this is the live OmniRoute v3.8.48 class of result).
    obs = {k: v + 2000 for k, v in _REF.items()}
    obs["p3"] += 79; obs["p5"] += 60; obs["p8"] -= 55
    cal = O.calibrate(obs, _REF, expected_family="DeepSeek")
    assert cal.passed is False
    assert cal.distorted == 3 and cal.exact_frac == 0.7
    assert "NOT calibrated" in cal.note


@pytest.mark.unit
def test_calibration_too_few_shared_probes():
    cal = O.calibrate({"p1": 3, "p2": 5}, _REF, expected_family="DeepSeek")
    assert cal.passed is False
    assert "too few" in cal.note.lower()


@pytest.mark.unit
def test_calibration_tolerance_is_configurable():
    obs = {k: v + 2000 for k, v in _REF.items()}
    obs["p3"] += 8                       # one distorted probe -> exact frac 0.9
    strict = O.calibrate(obs, _REF, tolerance=0.95)
    lenient = O.calibrate(obs, _REF, tolerance=0.85)
    assert strict.passed is False and lenient.passed is True


# --------------------------------------------------------------------------- #
# Header capture + detection
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_omniroute_headers_extracted():
    h = {"content-type": "application/json", "x-omniroute-model": "oc/deepseek-v4",
         "x-omniroute-provider": "combo", "x-omniroute-cache-hit": "false",
         "x-omniroute-version": "1.2.3"}
    got = O.omniroute_headers(h)
    assert got == {"model": "oc/deepseek-v4", "provider": "combo",
                   "cache-hit": "false", "version": "1.2.3"}


@pytest.mark.unit
def test_detect_omniroute_present():
    def fake_get(url):
        return {"status": 200, "json": {"data": [{"id": "auto/best-coding"},
                                                 {"id": "oc/deepseek-v4"}]},
                "headers": {"x-omniroute-version": "1.2.3"}}
    st = O.detect_omniroute(probe=fake_get)
    assert st.present is True
    assert "oc/deepseek-v4" in st.models and st.version == "1.2.3"


@pytest.mark.unit
def test_detect_omniroute_absent_is_graceful():
    def boom(url):
        raise ConnectionError("connection refused")
    st = O.detect_omniroute(probe=boom)
    assert st.present is False and st.error


@pytest.mark.unit
def test_detect_omniroute_non_catalog_json():
    def fake_get(url):
        return {"status": 200, "json": {"message": "hello"}, "headers": {}}
    st = O.detect_omniroute(probe=fake_get)
    assert st.present is False
