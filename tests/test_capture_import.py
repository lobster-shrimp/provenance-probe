"""Client-side capture import (#53).

The no-install, hosted-safe capture path: the user's OWN browser records the
request, the HAR is parsed client-side, and only the chosen sanitized flow is
POSTed to /wizard/capture-import. The endpoint feeds it to the EXISTING
flow_to_captured -> synthesize -> dry-run pipeline; it runs no browser and makes
no arbitrary fetch, so it is allowed under the egress guard while
/wizard/capture-run stays refused.

Unit tests exercise the pure normalizer and the endpoint guards; the two
integration tests run the real synthesize + dry-run pipeline against a scripted
transport (a z.ai-shaped capture, and a stateful/HTTP-400 one).
"""
from __future__ import annotations

import base64
import json

import pytest
import urllib3.util.connection as u3conn

from provenance_probe import capture_import, serve


# --------------------------------------------------------------------------- #
# Fixtures / helpers
# --------------------------------------------------------------------------- #

@pytest.fixture
def client():
    return serve.app.test_client()


@pytest.fixture(autouse=True)
def _no_auth(monkeypatch):
    # Default every test to no basic-auth gate; the auth test overrides this.
    monkeypatch.setattr(serve, "_BASIC_AUTH", None)


def _zai_response() -> str:
    return json.dumps({
        "id": "c-1", "object": "chat.completion", "model": "glm-4.6",
        "choices": [{"index": 0, "message": {"role": "assistant",
                     "content": "Certainly. Here is a helpful answer."},
                     "finish_reason": "stop"}],
        "usage": {"prompt_tokens": 11, "completion_tokens": 6}})


def _zai_payload(*, cookie: bool = True, host: str = "chat.z.ai") -> dict:
    req_headers = {"Content-Type": "application/json", "x-request-id": "r-1"}
    if cookie:
        req_headers["Cookie"] = "z_session=secret"
    return {
        "name": "zai", "prompt_hint": "fingerprint me",
        "cookie_consent": host if cookie else "",
        "request": {
            "method": "POST",
            "url": f"https://{host}/api/paas/v4/chat/completions",
            "headers": req_headers,
            "body": json.dumps({"model": "glm-4.6",
                                "messages": [{"role": "user", "content": "fingerprint me"}]}),
        },
        "response": {"status": 200,
                     "headers": {"Content-Type": "application/json"},
                     "body": _zai_response()},
    }


class _Resp:
    """Minimal client.Response stand-in for dry_run (ok/text/usage)."""
    def __init__(self, status, n, text="reply"):
        self.status, self._n, self._t = status, n, text

    @property
    def ok(self):
        return 200 <= self.status < 300

    def usage_prompt_tokens(self):
        return self._n

    def text(self):
        return self._t


def _fake_client_factory(script):
    """Build a serve.Client replacement that yields scripted responses."""
    class _FakeClient:
        def __init__(self, target):
            self.target = target
            self.i = -1

        def chat(self, prompt, **kw):
            self.i += 1
            return _Resp(*script[min(self.i, len(script) - 1)])
    return _FakeClient


# --------------------------------------------------------------------------- #
# Unit: normalize() (payload -> Flow), reusing the shared capture primitives
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_normalize_valid_payload_to_flow():
    flow = capture_import.normalize(_zai_payload())
    assert flow.method == "POST"
    assert flow.url.endswith("/api/paas/v4/chat/completions")
    # Cookie stays on the raw flow headers here; flow_to_captured splits it out.
    assert flow.req_headers.get("Cookie") == "z_session=secret"
    assert "fingerprint me" in flow.req_body


@pytest.mark.unit
def test_normalize_missing_request_or_response_errors():
    with pytest.raises(ValueError, match="request"):
        capture_import.normalize({"response": {"status": 200, "body": "{}"}})
    with pytest.raises(ValueError, match="response"):
        capture_import.normalize({"request": {"method": "POST",
                                              "url": "https://x/a", "body": "{}"}})


@pytest.mark.unit
def test_normalize_non_json_body_flows_through_as_template():
    # A form/urlencoded body is not JSON: to_captured -> synthesize should warn
    # but still produce a template target (the adapter of last resort).
    from provenance_probe import wizard
    payload = {"prompt_hint": "hi", "request": {"method": "POST",
               "url": "https://app.example/api/chat", "headers": {}, "body": "q=hi&n=1"},
               "response": {"status": 200, "headers": {}, "body": '{"reply":"ok"}'}}
    cap = capture_import.to_captured(payload)
    syn = wizard.synthesize(cap, "hi", "t")
    assert syn.target["api_style"] == "template"
    assert any("not JSON" in w for w in syn.warnings)


@pytest.mark.unit
def test_normalize_sse_body_is_reassembled():
    sse = ('data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
           'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
           'data: {"usage":{"prompt_tokens":5}}\n\ndata: [DONE]\n\n')
    payload = {"prompt_hint": "hi", "request": {"method": "POST",
               "url": "https://app.example/api/chat", "headers": {},
               "body": '{"messages":[{"role":"user","content":"hi"}]}'},
               "response": {"status": 200,
                            "headers": {"Content-Type": "text/event-stream"},
                            "body": sse}}
    cap = capture_import.to_captured(payload)
    assert cap.content_type == "text/event-stream"
    # sse_reassemble located the per-chunk delta path (no second live replay).
    assert cap.stream_delta_path == "choices.0.delta.content"


@pytest.mark.unit
def test_normalize_picks_chat_flow_via_prompt_hint():
    # A multi-flow payload: select_chat_flow must pick the one whose body carries
    # the prompt hint, not the higher-noise decoy.
    decoy = {"request": {"method": "POST", "url": "https://app.example/api/telemetry",
                         "headers": {}, "body": json.dumps({"event": "x" * 500})},
             "response": {"status": 200, "headers": {}, "body": "{}"}}
    real = {"request": {"method": "POST", "url": "https://app.example/api/chat",
                        "headers": {}, "body": json.dumps({"prompt": "fingerprint me"})},
            "response": {"status": 200, "headers": {}, "body": "{}"}}
    flow = capture_import.normalize({"prompt_hint": "fingerprint me",
                                     "flows": [decoy, real]})
    assert flow.url.endswith("/api/chat")


# --------------------------------------------------------------------------- #
# Unit: endpoint guards
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_import_page_renders_under_guard(client, monkeypatch):
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    r = client.get("/wizard/import")
    assert r.status_code == 200
    assert b"Import a captured request" in r.data
    assert b"/wizard/capture-import" in r.data
    # The HAR is parsed client-side; only the chosen request is uploaded.
    assert b"in your browser" in r.data and b"only the one request you pick" in r.data
    # Server/derived strings are HTML-escaped before hitting innerHTML (no
    # DOM-XSS via echoed warnings/error/host).
    assert b"function esc(" in r.data


@pytest.mark.unit
def test_capture_import_auth_gated(client, monkeypatch):
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("alice", "s3cret"))
    r = client.post("/wizard/capture-import", json=_zai_payload(cookie=False))
    assert r.status_code == 401
    tok = base64.b64encode(b"alice:s3cret").decode()
    monkeypatch.setattr(serve, "Client", _fake_client_factory([(200, 11, "hi"), (200, 11, "ok")]))
    r2 = client.post("/wizard/capture-import", json=_zai_payload(cookie=False),
                     headers={"Authorization": f"Basic {tok}"})
    assert r2.status_code != 401     # passed the gate


@pytest.mark.unit
def test_capture_import_requires_json(client):
    r = client.post("/wizard/capture-import", data="not json", content_type="text/plain")
    assert r.status_code == 415


@pytest.mark.unit
def test_capture_import_refuses_without_cookie_consent(client):
    payload = _zai_payload(cookie=True)
    payload["cookie_consent"] = ""            # cookie present but no consent
    r = client.post("/wizard/capture-import", json=payload)
    assert r.status_code == 403
    assert b"cookie-consent" in r.data or b"session cookie" in r.data


@pytest.mark.unit
def test_capture_import_cookie_origin_bound(client):
    # Consent names a DIFFERENT host than the captured request -> refused (a
    # cookie may only ever be replayed to the host it was captured from).
    payload = _zai_payload(cookie=True, host="chat.z.ai")
    payload["cookie_consent"] = "evil.example"
    r = client.post("/wizard/capture-import", json=payload)
    assert r.status_code == 403
    assert b"captured from" in r.data or b"only ever sent" in r.data


@pytest.mark.unit
def test_capture_import_egress_guard_blocks_private_dry_run(client, monkeypatch):
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    dialed = []
    monkeypatch.setattr(u3conn, "create_connection",
                        lambda address, *a, **k: dialed.append(address))
    # A private target: the guarded dry-run must refuse BEFORE any socket opens.
    payload = {"name": "internal", "prompt_hint": "hi",
               "request": {"method": "POST", "url": "http://10.0.0.5/api/chat",
                           "headers": {"Content-Type": "application/json"},
                           "body": '{"messages":[{"role":"user","content":"hi"}]}'},
               "response": {"status": 200, "headers": {"Content-Type": "application/json"},
                            "body": '{"choices":[{"message":{"content":"x"}}],"usage":{"prompt_tokens":3}}'}}
    r = client.post("/wizard/capture-import", json=payload)
    body = r.get_json()
    assert body["ok"] is False              # dry-run refused
    assert dialed == []                     # no socket opened to the private host


@pytest.mark.unit
def test_capture_import_allowed_while_capture_run_refused(client, monkeypatch):
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    # capture-run (server-side browser) stays refused under the guard...
    run = client.post("/wizard/capture-run",
                      data={"url": "https://chat.z.ai", "authorized": "1"})
    assert run.status_code == 403
    assert b"disabled" in run.data.lower()
    # ...while capture-import (client-side; no browser) is ALLOWED.
    monkeypatch.setattr(serve, "Client",
                        _fake_client_factory([(200, 11, "hi"), (200, 11, "ok")]))
    imp = client.post("/wizard/capture-import", json=_zai_payload(cookie=True))
    assert imp.status_code == 200
    body = imp.get_json()
    assert body["ok"] is True
    # Never persisted on a guarded/public instance; cookie never echoed back.
    assert body["persisted"] is False and body["hosted"] is True
    assert b"secret" not in imp.data


# --------------------------------------------------------------------------- #
# Integration: real synthesize + dry-run over a scripted transport
# --------------------------------------------------------------------------- #

@pytest.mark.integration
def test_import_zai_shaped_capture_yields_usable_target(client, monkeypatch):
    # z.ai-shaped capture -> import -> synthesize -> dry-run -> usable target.
    monkeypatch.setattr(serve, "Client",
                        _fake_client_factory([(200, 11, "hi"), (200, 12, "ok")]))
    r = client.post("/wizard/capture-import", json=_zai_payload(cookie=True))
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is True
    tgt = body["target"]
    assert tgt["api_style"] == "template"
    # synthesize located the reply + usage paths off the captured response.
    assert tgt["response_text_path"] == "choices.0.message.content"
    assert tgt["response_prompt_tokens_path"] == "usage.prompt_tokens"
    # The credential is never reflected back to the caller.
    assert "cookie" not in json.dumps(tgt).lower() or "cookie_env" in tgt


@pytest.mark.integration
def test_import_stateful_400_gives_stale_message_no_false_save(client, monkeypatch):
    # A stateful / signed request that can't replay -> HTTP 400 on dry-run ->
    # the existing "stale, re-capture" message, and NOTHING is saved.
    monkeypatch.setattr(serve, "Client", _fake_client_factory([(400, None, "")]))
    r = client.post("/wizard/capture-import", json=_zai_payload(cookie=True))
    assert r.status_code == 200
    body = r.get_json()
    assert body["ok"] is False
    assert "re-capture" in body["error"].lower() or "stale" in body["error"].lower()
    assert body.get("persisted") in (False, None)   # no false save
