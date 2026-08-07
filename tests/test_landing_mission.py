# -*- coding: utf-8 -*-
"""P1 (#62): the plain-English mission on the landing, the two named jobs, the
Observatory 'see it live' card, and the two new /help sections.

The whole point is DRY + honesty + no-XSS: the hero and the /help 'Why this
matters' section read from the SAME explain.py constants, every dynamic string is
html.escape'd, and none of the existing routes / form ids / #53 contract move.
"""
from __future__ import annotations

import html

import pytest

from provenance_probe import serve, explain


@pytest.fixture
def client():
    return serve.app.test_client()


# --------------------------------------------------------------------------- #
# Landing: plain-English mission hero (sourced from explain.py)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_landing_renders_mission_hero(client):
    body = client.get("/").get_data(as_text=True)
    # Hero copy is the single source in explain.py — assert against it, don't
    # hardcode a second copy that could drift.
    assert html.escape(explain.MISSION_HEADLINE) in body
    assert html.escape(explain.MISSION_BODY) in body
    # A non-technical reader can restate the mission: the words "swap"/"switch"
    # appear on the first screen, and the first screen carries no engine jargon.
    hero = body.split('class="jobs"')[0]
    assert "swap" in hero.lower() or "switch" in hero.lower()
    for jargon in ("tokenizer", "logprob", "RDAP", "jurisdiction"):
        assert jargon not in hero, f"jargon in hero: {jargon}"


@pytest.mark.unit
def test_landing_names_both_jobs_as_ctas(client):
    body = client.get("/").get_data(as_text=True)
    # Job 1: see what's answering now -> the probe form (anchor on this page).
    assert "See what" in body and "answering right now" in body
    assert 'href="#probe"' in body
    assert 'id=probe' in body                     # the anchor target exists
    # Job 2: watch a service for a silent swap -> the capture/watch path.
    assert "Watch a service for a silent swap" in body
    assert 'href="/wizard"' in body
    # Honest about the tab-bound limit + the real always-on path (the local watch daemon).
    assert "unattended, always-on watching" in body
    assert "watch daemon locally" in body


@pytest.mark.unit
def test_landing_has_observatory_see_it_live_card(client):
    body = client.get("/").get_data(as_text=True)
    # A prominent LINKED card (class .obs), not an iframe, to the public site.
    assert 'class="obs"' in body
    assert "<iframe" not in body
    assert "https://lobster-shrimp.github.io/provenance-observatory/" in body
    assert "See it live" in body
    assert "fingerprinted and watched" in body


# --------------------------------------------------------------------------- #
# /help: the two new plain-language sections, sourced from explain.py
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_help_renders_why_this_matters_and_watching(client):
    body = client.get("/help").get_data(as_text=True)
    assert "Why this matters" in body
    assert "Watching for model swaps" in body
    # Sourced from explain.py — every paragraph of both blocks is present + escaped.
    for para in explain.WHY_THIS_MATTERS + explain.WATCHING_PRIMER:
        assert html.escape(para) in body, para[:40]


# --------------------------------------------------------------------------- #
# No-XSS: every dynamic mission string is escaped, never reflected raw
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_mission_copy_is_escaped_on_landing(client, monkeypatch):
    # Even though the copy is author-controlled, it must land escaped (defense in
    # depth): inject markup into the source and prove it is inert in the response.
    monkeypatch.setattr(explain, "MISSION_HEADLINE", "<script>x</script>&")
    body = client.get("/").get_data(as_text=True)
    assert "<script>x</script>" not in body
    assert "&lt;script&gt;x&lt;/script&gt;&amp;" in body


@pytest.mark.unit
def test_help_prose_sections_are_escaped(client, monkeypatch):
    monkeypatch.setattr(explain, "WHY_THIS_MATTERS", ("<b>boom</b>",))
    body = client.get("/help").get_data(as_text=True)
    # The injected paragraph is neutralised; no raw <b>boom</b> tag is emitted.
    assert "<b>boom</b>" not in body
    assert "&lt;b&gt;boom&lt;/b&gt;" in body


# --------------------------------------------------------------------------- #
# Capture chooser + routes/ids unchanged (regression guard for the UX pass)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_chooser_still_renders_all_methods(client):
    body = client.get("/wizard").get_data(as_text=True)
    assert 'class="chooser"' in body
    assert "I have a plain API address" in body
    assert "It's a website I log into" in body
    assert "I already have a cURL or HAR" in body
    assert 'class="card rec"' in body and "recommended" in body
    # Every downstream route from the chooser is intact.
    assert "/wizard/import" in body
    assert 'href="#add"' in body


@pytest.mark.unit
def test_import_page_leads_with_one_click_extension_and_keeps_contract(client):
    body = client.get("/wizard/import").get_data(as_text=True)
    # The capture extension is presented as the recommended path (load-unpacked, honest
    # about the developer-mode install rather than overselling a store one-click)...
    assert "capture extension (load it unpacked)" in body
    assert "github.com/lobster-shrimp/provenance-probe/tree/main/extension" in body
    # ...without disturbing any form id or the #53 ingest endpoint.
    for token in ("id=har", "id=hint", "id=name", "id=flow",
                  "id=consent", "id=go", "/wizard/capture-import"):
        assert token in body, token


# --------------------------------------------------------------------------- #
# E2E-ish: the "watch" CTA reaches the capture flow; Observatory link resolves
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_watch_cta_reaches_capture_flow(client):
    # Follow the landing's "Watch a service" CTA target (/wizard) and confirm it
    # lands on the capture chooser — a real path from the mission to automation.
    landing = client.get("/").get_data(as_text=True)
    assert 'href="/wizard"' in landing
    wiz = client.get("/wizard")
    assert wiz.status_code == 200
    assert 'class="chooser"' in wiz.get_data(as_text=True)


@pytest.mark.unit
def test_observatory_link_points_at_public_site_and_is_safe(client, monkeypatch):
    monkeypatch.delenv("PROVENANCE_OBSERVATORY_URL", raising=False)
    body = client.get("/").get_data(as_text=True)
    # The card links out to the public GitHub Pages observatory, in a new tab with
    # a noopener/noreferrer guard (no reverse-tabnabbing on an external link).
    assert 'href="https://lobster-shrimp.github.io/provenance-observatory/"' in body
    obs = body.split('class="obs"')[1].split("</a>")[0]
    assert 'target="_blank"' in obs
    assert 'rel="noopener noreferrer"' in obs
