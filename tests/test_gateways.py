"""Tests for the pure gateway-knowledge module (provenance_probe/gateways.py).

Covers ET1 (extraction correctness) and ET7 (regression: label_to_family must
behave identically after being extracted out of omniroute.py). The extraction is
load-bearing for the no-egress boundary — gateways.py must stay import-pure.
"""
import pytest

from provenance_probe import gateways as G
from provenance_probe import omniroute as O


# --- ET7 regression: behavior identical after extraction --------------------- #

@pytest.mark.unit
@pytest.mark.parametrize(
    "label,fam",
    [
        ("deepseek-v4-flash", "DeepSeek"),
        ("oc/deepseek-v4-flash-free", "DeepSeek"),
        ("gpt-4o", "OpenAI"),
        ("gpt-neox-20b", "GPT-NeoX"),   # multi-word key must beat the 'gpt' prefix
        ("o1-preview", "OpenAI"),
        ("chatglm3", "GLM"),
        ("kimi-k2", "Moonshot"),
        ("claude-3-5-sonnet", "Claude"),
        ("qwq-32b", "Qwen"),
    ],
)
def test_label_to_family_maps(label, fam):
    assert G.label_to_family(label) == fam


@pytest.mark.unit
def test_label_to_family_unmapped_is_none():
    assert G.label_to_family("some-unknown-model-xyz") is None
    assert G.label_to_family("") is None
    assert G.label_to_family("   ") is None


@pytest.mark.unit
@pytest.mark.parametrize("label", ["proto1-vision", "yixin-7b", "glimmer-3"])
def test_label_to_family_no_midword_false_match(label):
    # short keys (o1, yi, glm) must not match mid-word
    assert G.label_to_family(label) is None


@pytest.mark.unit
def test_omniroute_reexports_are_the_same_objects():
    # Back-compat + no-drift: omniroute must re-export the EXACT gateways objects,
    # so there is exactly one implementation (the regression guarantee for the
    # existing tests/test_omniroute.py suite).
    assert O.label_to_family is G.label_to_family
    assert O.LABEL_FAMILY is G.LABEL_FAMILY
    assert O.DEFAULT_BASE == G.OMNIROUTE_DEFAULT_BASE


# --- ET1 extraction correctness: gateway recognition constants --------------- #

@pytest.mark.unit
def test_known_local_gateways_registry():
    assert G.KNOWN_LOCAL_GATEWAYS["omniroute"] == ("localhost", 20128)
    assert "litellm" in G.KNOWN_LOCAL_GATEWAYS
    assert G.OMNIROUTE_DEFAULT_BASE == "http://localhost:20128/v1"


# --- No-egress boundary: the shared module must stay import-pure -------------- #

@pytest.mark.unit
def test_gateways_module_is_network_pure():
    # gateways.py must never pull in requests or expose network functions — that
    # is the whole reason it exists (plan-eng-review Arch 1). If this fails, the
    # no-egress boundary for the future fleet scanner has been broken.
    assert not hasattr(G, "requests")
    for network_name in ("detect_omniroute", "calibrate", "_default_get"):
        assert not hasattr(G, network_name)
