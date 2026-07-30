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


# --------------------------------------------------------------------------- #
# Hardening from the ship adversarial pass (#44)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_run_refuses_cross_site_origin(client):
    r = client.post("/wizard/capture-run",
                    data={"url": "https://app.example", "authorized": "1"},
                    headers={"Origin": "https://evil.example"})
    assert r.status_code == 403


@pytest.mark.unit
def test_capture_run_allows_local_origin(client, monkeypatch):
    monkeypatch.setattr(capture_proxy, "capture", _fake_ok_capture)
    r = client.post("/wizard/capture-run",
                    data={"url": "https://app.example", "name": "a", "message": "hi",
                          "authorized": "1"},
                    headers={"Origin": "http://127.0.0.1:8770"})
    assert r.status_code == 200 and "run_id" in r.get_json()


@pytest.mark.unit
def test_capture_run_rejects_non_http_scheme(client):
    r = client.post("/wizard/capture-run",
                    data={"url": "file:///etc/passwd", "authorized": "1"})
    assert r.status_code == 400


@pytest.mark.unit
def test_evict_terminal_runs_preserves_in_flight():
    serve._CAPTURE_RUNS.clear()
    serve._CAPTURE_RUNS["live"] = {"state": "running"}
    for i in range(25):
        serve._CAPTURE_RUNS[f"done{i}"] = {"state": "done"}
    serve._evict_terminal_runs()
    assert "live" in serve._CAPTURE_RUNS            # in-flight run never dropped
    assert not any(k.startswith("done") for k in serve._CAPTURE_RUNS)  # terminal runs evicted
    serve._CAPTURE_RUNS.clear()


@pytest.mark.unit
def test_abandoned_run_times_out_to_error(client, monkeypatch):
    monkeypatch.setattr(serve, "_CAPTURE_WAIT_TIMEOUT", 0.1)   # don't hang the test

    def fake_blocking(url, *, prompt_hint="", login_wait=None, send_wait=None, **kw):
        login_wait()          # operator never clicks Continue -> times out -> raises
        return capture_proxy.ProxyCaptureResult(ok=True, captured=None)
    monkeypatch.setattr(capture_proxy, "capture", fake_blocking)
    rid = client.post("/wizard/capture-run",
                      data={"url": "https://app.example", "authorized": "1"}).get_json()["run_id"]
    j = _poll(client, rid, "error")
    assert "timed out" in j["error"]
