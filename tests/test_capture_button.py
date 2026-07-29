"""'/wizard' Capture-for-me proxy flow (child B of #44). The browser+proxy work
needs the [capture] extra and a real browser, so here we monkeypatch
capture_proxy.capture and test the Flask orchestration: the two-phase
run/advance/status state machine, the preview hand-off, and the button render."""
from __future__ import annotations

import time

import pytest

from provenance_probe import serve, capture_proxy


@pytest.fixture
def client():
    return serve.app.test_client()


def _poll(client, rid, want, tries=80):
    for _ in range(tries):
        j = client.get(f"/wizard/capture-run/{rid}").get_json()
        if j.get("status") == want or j.get("state") == want:
            return j
        time.sleep(0.02)
    raise AssertionError(f"status never reached {want!r} (last={j})")


# --------------------------------------------------------------------------- #
# Button rendering (gated on the [capture] extra)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_wizard_shows_capture_button_when_available(client, monkeypatch):
    monkeypatch.setattr(capture_proxy, "proxy_available", lambda: True)
    r = client.get("/wizard")
    assert r.status_code == 200
    assert b"Capture for me" in r.data and b"/wizard/capture-run" in r.data


@pytest.mark.unit
def test_wizard_shows_extra_hint_when_unavailable(client, monkeypatch):
    monkeypatch.setattr(capture_proxy, "proxy_available", lambda: False)
    r = client.get("/wizard")
    assert r.status_code == 200
    assert b"Capture for me" not in r.data
    assert b"[capture]" in r.data or b"playwright install" in r.data


# --------------------------------------------------------------------------- #
# Guards
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_run_requires_url(client):
    r = client.post("/wizard/capture-run", data={"authorized": "1"})
    assert r.status_code == 400


@pytest.mark.unit
def test_capture_run_requires_authorization(client):
    r = client.post("/wizard/capture-run", data={"url": "https://app.example"})
    assert r.status_code == 403


# --------------------------------------------------------------------------- #
# Two-phase happy path -> preview
# --------------------------------------------------------------------------- #

def _fake_ok_capture(url, *, prompt_hint="", login_wait=None, send_wait=None, **kw):
    login_wait()          # block until the browser 'Continue' releases phase 1
    send_wait()           # ...and phase 2
    cap = capture_proxy.flow_to_captured(capture_proxy.Flow(
        url="https://app.example/api/chat", req_headers={"Cookie": "sid=secret"},
        req_body='{"messages":[{"role":"user","content":"hi"}]}',
        resp_body='{"choices":[{"message":{"content":"a longer real reply"}}],'
                  '"usage":{"prompt_tokens":4},"model":"m"}'))
    return capture_proxy.ProxyCaptureResult(ok=True, captured=cap)


@pytest.mark.unit
def test_capture_two_phase_to_preview(client, monkeypatch):
    monkeypatch.setattr(capture_proxy, "capture", _fake_ok_capture)
    rid = client.post("/wizard/capture-run",
                      data={"url": "https://app.example", "name": "app",
                            "message": "hi", "authorized": "1"}).get_json()["run_id"]
    _poll(client, rid, "awaiting_login")
    client.post("/wizard/capture-advance", data={"run_id": rid})
    _poll(client, rid, "awaiting_send")
    client.post("/wizard/capture-advance", data={"run_id": rid})
    _poll(client, rid, "done")

    prev = client.get(f"/wizard/capture-preview/{rid}")
    assert prev.status_code == 200
    assert b"app.example" in prev.data            # synthesized target rendered
    assert b"sid=secret" not in prev.data         # cookie never reflected to the page
    # run is one-shot: gone after preview
    assert client.get(f"/wizard/capture-run/{rid}").status_code == 404


@pytest.mark.unit
def test_capture_error_surfaces_status(client, monkeypatch):
    def fake_fail(url, *, prompt_hint="", login_wait=None, send_wait=None, **kw):
        login_wait(); send_wait()
        return capture_proxy.ProxyCaptureResult(
            ok=False, error="no chat request was captured from this site")
    monkeypatch.setattr(capture_proxy, "capture", fake_fail)
    rid = client.post("/wizard/capture-run",
                      data={"url": "https://app.example", "authorized": "1"}).get_json()["run_id"]
    _poll(client, rid, "awaiting_login")
    client.post("/wizard/capture-advance", data={"run_id": rid})
    _poll(client, rid, "awaiting_send")
    client.post("/wizard/capture-advance", data={"run_id": rid})
    j = _poll(client, rid, "error")
    assert "no chat request" in j["error"]


@pytest.mark.unit
def test_capture_status_and_advance_unknown_run_404(client):
    assert client.get("/wizard/capture-run/nope").status_code == 404
    assert client.post("/wizard/capture-advance", data={"run_id": "nope"}).status_code == 404
    assert client.get("/wizard/capture-preview/nope").status_code == 200  # friendly page, not 500
