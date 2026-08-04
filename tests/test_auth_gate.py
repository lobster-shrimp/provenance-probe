"""Basic-auth gate for public-hosting mode (#51). OFF by default; when
PROVENANCE_PROBE_BASIC_AUTH="user:pass" is set, every route requires HTTP Basic
auth with a constant-time compare, and a malformed value fails loudly at startup.
"""
from __future__ import annotations

import base64

import pytest

from provenance_probe import serve


def _basic(user: str, password: str) -> dict:
    token = base64.b64encode(f"{user}:{password}".encode()).decode()
    return {"Authorization": f"Basic {token}"}


@pytest.fixture
def client():
    return serve.app.test_client()


# --------------------------------------------------------------------------- #
# Env parsing — malformed fails loud, empty disables, ':' in password kept
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_parse_malformed_value_fails_loud():
    with pytest.raises(RuntimeError):
        serve._parse_basic_auth("nocolonhere")


@pytest.mark.unit
def test_parse_empty_disables_gate():
    assert serve._parse_basic_auth(None) is None
    assert serve._parse_basic_auth("") is None


@pytest.mark.unit
def test_parse_password_may_contain_colon():
    assert serve._parse_basic_auth("user:pa:ss:word") == ("user", "pa:ss:word")


# --------------------------------------------------------------------------- #
# Gate behavior on a real route
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_no_gate_when_unset(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", None)
    r = client.get("/")
    assert r.status_code == 200


@pytest.mark.unit
def test_401_without_credentials(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("alice", "s3cret"))
    r = client.get("/")
    assert r.status_code == 401
    assert r.headers.get("WWW-Authenticate") == 'Basic realm="provenance-probe"'


@pytest.mark.unit
def test_401_with_wrong_credentials(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("alice", "s3cret"))
    r = client.get("/", headers=_basic("alice", "wrong"))
    assert r.status_code == 401
    assert "WWW-Authenticate" in r.headers
    # wrong username too
    r2 = client.get("/", headers=_basic("mallory", "s3cret"))
    assert r2.status_code == 401


@pytest.mark.unit
def test_200_with_correct_credentials(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("alice", "s3cret"))
    r = client.get("/", headers=_basic("alice", "s3cret"))
    assert r.status_code == 200


@pytest.mark.unit
def test_gate_applies_to_all_routes(client, monkeypatch):
    """No allowlist: even a non-index route is gated before its own logic runs."""
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("alice", "s3cret"))
    r = client.get("/wizard")
    assert r.status_code == 401
    r_ok = client.get("/wizard", headers=_basic("alice", "s3cret"))
    assert r_ok.status_code == 200


# --------------------------------------------------------------------------- #
# /api/assess JSON-CSRF hardening: an outbound-triggering route must reject a
# cross-origin form post (non-JSON content-type).
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_api_assess_rejects_non_json_content_type(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", None)
    r = client.post("/api/assess", data="base_url=http://evil&authorized=1",
                    content_type="text/plain")
    assert r.status_code == 415


@pytest.mark.unit
def test_api_assess_accepts_json(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", None)
    # Valid content-type, but missing base_url -> 400 (proves it passed the
    # content-type gate without spawning an assessment).
    r = client.post("/api/assess", json={"authorized": True})
    assert r.status_code == 400


# --------------------------------------------------------------------------- #
# Browser "Capture for me" flow is refused in public-hosting mode (SSRF: it
# drives a real browser to a user URL and can't be IP-pinned).
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_run_refused_when_guard_enabled(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", None)
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    r = client.post("/wizard/capture-run",
                    data={"url": "http://169.254.169.254/latest/", "authorized": "1"})
    assert r.status_code == 403
    assert b"disabled" in r.data.lower()
    r2 = client.post("/wizard/capture-advance", data={"run_id": "x"})
    assert r2.status_code == 403


@pytest.mark.unit
def test_capture_button_hidden_when_guard_enabled(monkeypatch):
    from provenance_probe import capture_proxy
    monkeypatch.setattr(serve, "_BASIC_AUTH", None)
    monkeypatch.setattr(capture_proxy, "proxy_available", lambda: True)
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    r = serve.app.test_client().get("/wizard")
    assert r.status_code == 200
    assert b"Capture for me" not in r.data
