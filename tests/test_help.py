# -*- coding: utf-8 -*-
"""In-product documentation: the /help page, the single-source LAYERS/VERDICTS
explainers, the report's layer tooltips, and the Help nav link.

The whole point of this feature is DRY: /help, the report tooltips and the form
note all read from explain.LAYERS / explain.VERDICTS. These tests assert that the
rendered surfaces stay in sync with that single source (iterate the source, don't
hardcode copy) and that nothing about auth, gating or the report structure moved.
"""
from __future__ import annotations

import html
import json
import os
import tempfile

import pytest

from provenance_probe import serve, explain, report, scoring


@pytest.fixture
def client():
    return serve.app.test_client()


# --------------------------------------------------------------------------- #
# /help renders, is auth-gated, and covers every layer + verdict tier
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_help_page_renders(client):
    r = client.get("/help")
    assert r.status_code == 200
    assert r.mimetype == "text/html"
    body = r.get_data(as_text=True)
    assert "How provenance-probe works" in body


@pytest.mark.unit
def test_help_page_is_auth_gated(monkeypatch, client):
    # Not allowlisted out of Basic auth: an unauthenticated request 401s, like
    # every route (the global before_request gate).
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("u", "p"))
    assert client.get("/help").status_code == 401


@pytest.mark.unit
def test_help_has_a_section_per_layer(client):
    body = client.get("/help").get_data(as_text=True)
    # Iterate the single source of truth — a new layer must show up automatically.
    for info in explain.LAYERS.values():
        assert html.escape(info.title) in body, info.title
        assert html.escape(info.measures) in body, info.title
        assert html.escape(info.hit_means) in body, info.title


@pytest.mark.unit
def test_help_has_a_section_per_verdict_tier(client):
    body = client.get("/help").get_data(as_text=True)
    for axis in explain.VERDICTS.values():
        assert html.escape(axis.title) in body
        for tier in axis.tiers:
            assert tier.name in body
            assert html.escape(tier.meaning) in body


@pytest.mark.unit
def test_help_explains_the_two_axes_with_the_concrete_example(client):
    body = client.get("/help").get_data(as_text=True)
    # The worked example: a Chinese model on US servers = CONFIRMED provenance +
    # UNLIKELY jurisdiction. Both axes must appear together.
    assert "CONFIRMED provenance" in body
    assert "UNLIKELY" in body and "jurisdiction" in body


@pytest.mark.unit
def test_help_covers_every_flow_and_faq(client):
    body = client.get("/help").get_data(as_text=True)
    for title, blurb in explain.FLOWS:
        assert html.escape(title) in body
        assert html.escape(blurb) in body
    for question, answer in explain.FAQ:
        assert html.escape(question) in body
        assert html.escape(answer) in body
    # The specific FAQ items the product asked for.
    faq_qs = " ".join(q for q, _ in explain.FAQ)
    assert "store my key" in faq_qs
    assert "sent anywhere" in faq_qs
    assert "INDETERMINATE" in faq_qs


# --------------------------------------------------------------------------- #
# Help link is in the poster nav on every page
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("path", ["/", "/help", "/agent", "/wizard", "/wizard/import"])
def test_help_link_in_nav_on_every_page(client, path):
    body = client.get(path).get_data(as_text=True)
    assert '<nav>' in body
    assert 'href="/help"' in body


# --------------------------------------------------------------------------- #
# explain.py single-source contracts (DRY)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_explain_covers_the_eight_engine_layers():
    # The layers named in the README / scoring model.
    for key in ("network", "wire", "tokenizer", "logprob", "behavioral",
                "deception", "latency", "artifacts"):
        assert key in explain.LAYERS


@pytest.mark.unit
def test_tooltip_resolves_signal_layer_aliases():
    # Signals emit "artifact" and "client-source"; both must resolve to a tooltip
    # so the report never shows a bare, unexplained layer for a real signal.
    assert explain.tooltip_for("artifact")
    assert explain.tooltip_for("client-source")
    assert explain.tooltip_for("network").startswith("Network")
    # An unknown layer degrades gracefully to "" (caller renders the bare name).
    assert explain.tooltip_for("nope") == ""


@pytest.mark.unit
def test_every_scoring_layer_has_an_explainer():
    # Every layer string the scorer can attach to a signal must resolve, so the
    # report tooltip is never empty for a signal the engine actually produces.
    layers = set()
    for fn_layers in (
        {"network"}, {"wire"}, {"tokenizer"}, {"behavioral"},
        {"deception"}, {"client-source"}, {"artifact"},
    ):
        layers |= fn_layers
    for layer in layers:
        assert explain.layer_info(layer) is not None, layer


# --------------------------------------------------------------------------- #
# The report renders the layer explainer for a sample bundle
# --------------------------------------------------------------------------- #

def _sample_bundle() -> dict:
    """A minimal bundle that fires one network signal (cn_tld) so the Signals
    table has a real row to hang a tooltip on."""
    b = {
        "target": {"name": "sample", "base_url": "https://api.vendor.cn/v1",
                   "model": "glm-4", "api_style": "openai"},
        "timestamp": "2026-01-01T00:00:00+00:00",
        "network": {"addresses": [{"asn": "AS4808", "country": "CN"}],
                    "findings": [{"type": "cn_tld", "detail": "host ends in .cn"}],
                    "operator": "China Unicom", "jurisdiction": "PRC (mainland)"},
    }
    b["score"] = scoring.score(b)
    return b


@pytest.mark.unit
def test_report_renders_layer_tooltip_from_explain():
    b = _sample_bundle()
    # Sanity: the bundle really produced a signal on the "network" layer.
    assert any(sig["layer"] == "network" for sig in b["score"]["signals"])
    path = os.path.join(tempfile.mkdtemp(), "report.html")
    report.to_html(b, path)
    doc = open(path).read()
    # The layer cell is an <abbr> whose title is the plain-language explainer.
    assert "<abbr" in doc
    assert html.escape(explain.tooltip_for("network")) in doc
    # And the "new here? see help" pointer is present on the report.
    assert 'href="/help"' in doc


@pytest.mark.unit
def test_report_still_has_its_verdict_structure():
    # Additive-only: the report's existing structure/verdict logic is untouched.
    b = _sample_bundle()
    path = os.path.join(tempfile.mkdtemp(), "report.html")
    report.to_html(b, path)
    doc = open(path).read()
    assert "Signals" in doc
    assert "Tokenizer match" in doc
    assert "Network &amp; jurisdiction" in doc
    # verdict words still come straight from the scorer, unchanged.
    assert b["score"]["provenance_risk"]["verdict"] in doc \
        or b["score"]["jurisdictional_risk"]["verdict"] in doc


# --------------------------------------------------------------------------- #
# The probe form points newcomers at /help
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_probe_form_advanced_note_links_help(client):
    body = client.get("/").get_data(as_text=True)
    assert "explained in plain language" in body
    assert 'href="/help"' in body


# --------------------------------------------------------------------------- #
# New demo-GIF slots (files dropped in later by the maintainer)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_probe_page_has_demo_gif_slot(client):
    body = client.get("/").get_data(as_text=True)
    assert "/media/probe-demo.gif" in body
    assert 'class="demo"' in body


@pytest.mark.unit
def test_agent_board_has_demo_gif_slot(client):
    body = client.get("/agent").get_data(as_text=True)
    assert "/media/agent-demo.gif" in body
    assert 'class="demo"' in body
