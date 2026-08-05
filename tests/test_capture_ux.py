"""Non-technical capture UX + the /media static route (this PR).

Covers:
  * the /media/<name> read-only static route: serves an existing allowlisted
    file, 404s a missing one, refuses path traversal / non-allowlisted types,
    and stays behind the auth gate;
  * the wizard "which method is right for you?" chooser renders;
  * the /wizard/capture guide and /wizard/import pages render the new
    plain-language step content WITHOUT breaking the existing form ids / the
    #53 capture-import contract;
  * capture_guide.guide() still returns coherent numbered steps.
"""
from __future__ import annotations

import pytest

from provenance_probe import serve, capture_guide


@pytest.fixture
def client():
    return serve.app.test_client()


# --------------------------------------------------------------------------- #
# /media static route  (security-sensitive: classic LFI vector)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_media_serves_existing_placeholder(client):
    r = client.get("/media/placeholder.gif")
    assert r.status_code == 200
    assert r.mimetype == "image/gif"
    body = r.get_data()
    assert body.startswith(b"GIF89a") or body.startswith(b"GIF87a")
    assert r.headers.get("X-Content-Type-Options") == "nosniff"


@pytest.mark.unit
def test_media_missing_file_404s(client):
    assert client.get("/media/does-not-exist.gif").status_code == 404


@pytest.mark.unit
def test_media_non_allowlisted_type_refused(client):
    # __init__.py EXISTS in the media dir but is not an allowlisted media type,
    # so it must never be served (extension allowlist, not just containment).
    r = client.get("/media/__init__.py")
    assert r.status_code == 404
    assert b"Static demo media" not in r.get_data()


@pytest.mark.unit
@pytest.mark.parametrize("path", [
    "/media/../serve.py",
    "/media/..%2fserve.py",
    "/media/%2e%2e%2f%2e%2e%2fpyproject.toml",
    "/media/..%2f..%2f..%2fetc%2fpasswd",
])
def test_media_refuses_path_traversal(client, path):
    r = client.get(path)
    assert r.status_code != 200
    body = r.get_data()
    # Never leak the source or any escaped-dir content.
    assert b"def media_file" not in body
    assert b"tool.setuptools" not in body
    assert b"root:" not in body


@pytest.mark.unit
def test_media_route_is_behind_the_auth_gate(monkeypatch, client):
    # Not allowlisted out of Basic auth: an unauthenticated request 401s.
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("u", "p"))
    assert client.get("/media/placeholder.gif").status_code == 401


# --------------------------------------------------------------------------- #
# Wizard method chooser (front door)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_wizard_renders_method_chooser(client):
    r = client.get("/wizard")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert 'class="chooser"' in html
    # three options, plain-language headings
    assert "I have a plain API address" in html
    assert "It's a website I log into" in html
    assert "I already have a cURL or HAR" in html
    # the log-in path is the recommended/emphasized card
    assert "recommended" in html and 'class="card rec"' in html
    # each card names what it needs + a primary action
    assert "You need:" in html
    assert "/wizard/import" in html          # Option B action
    assert 'href="#add"' in html             # A + C jump to the paste box


# --------------------------------------------------------------------------- #
# /wizard/capture guide — big numbered steps + reassurance + demo slot
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_guide_page_has_plain_language_steps(client):
    r = client.get("/wizard/capture?url=https://chat.app.example")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "What this does" in html
    assert "Is my login safe?" in html
    assert "What happens next" in html
    assert 'class="steps"' in html               # big numbered visual steps
    assert "/media/capture-guide.gif" in html    # embeddable demo-GIF slot
    assert 'class="demo"' in html


# --------------------------------------------------------------------------- #
# /wizard/import — new copy, existing ids + #53 contract intact
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_import_page_has_new_copy(client):
    r = client.get("/wizard/import")
    assert r.status_code == 200
    html = r.get_data(as_text=True)
    assert "What this does" in html
    assert "Is my login safe?" in html
    assert "developer Network panel" in html     # jargon reduced (not "DevTools")
    assert "/media/capture-import.gif" in html
    assert 'class="demo"' in html or "class=demo" in html


@pytest.mark.unit
def test_import_page_preserves_form_ids_and_contract(client):
    # Restyle-only: every form field id and the #53 ingest endpoint stay intact.
    html = client.get("/wizard/import").get_data(as_text=True)
    for token in ("id=har", "id=hint", "id=name", "id=flow",
                  "id=consent", "id=go", "/wizard/capture-import"):
        assert token in html, token


# --------------------------------------------------------------------------- #
# Pure guide generator still coherent
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_guide_generator_still_coherent():
    g = capture_guide.guide("https://chat.app.example", browser="chrome")
    assert [s.n for s in g.steps] == list(range(1, len(g.steps) + 1))
    assert len(g.steps) >= 3
    assert all(s.title and s.detail for s in g.steps)
    assert g.security_note                     # reassurance text present
