"""z.ai request-signing adapter — the founding-case reactivation.

The golden signatures below were recovered from z.ai's PUBLIC client bundle
(functions ``ane`` + ``sne`` in index-*.js) and CROSS-VERIFIED against the real
``js-sha256`` library the client uses (Node), including a multibyte-UTF-8 message.
Python's stdlib HMAC-SHA256 reproduces js-sha256 byte-for-byte, so these vectors
pin the recovered algorithm: a drift in the key, canonical string, window, or hash
flips them.
"""
import base64

import pytest

from provenance_probe.signers import get_signer
from provenance_probe.signers import zai
from provenance_probe.client import Client
from provenance_probe.config import Target


# --- deterministic golden vectors (fixed timestamp/requestId -> expected token) --

# Vector A: ascii message, empty user_id.
V_A = dict(
    message="Hello",
    timestamp_ms=1750000000000,
    request_id="46daabfa-1cdf-4000-8000-000000000000",
    user_id="",
    expect_b64="SGVsbG8=",
    expect_derived="00a3bb31e434a6f9fa5f74366d775acc9c156bae0c6ef64d702c9dd252a56d54",
    expect_signature="ca8c6d540569961a83bdcf1658a6f96e8796781330281e29015631506c831e66",
)

# Vector B: multibyte UTF-8 message + a non-empty user_id (proves UTF-8 base64
# parity with the browser's TextEncoder path).
V_B = dict(
    message="你好, world 🌏",
    timestamp_ms=1700000123456,
    request_id="322f2d5c-46a6-4111-8222-abcabcabcabc",
    user_id="user-42",
    expect_b64="5L2g5aW9LCB3b3JsZCDwn4yP",
    expect_signature="d160c9593dbf42529233fa63c3feb63eff54f9a04b54f02283fe0aebaf476f8c",
)


def test_secret_key_recovered_verbatim():
    # The constant embedded in the client JS (function sne). A change here means
    # the bundle rotated the key and the adapter must be re-recovered.
    assert zai.SECRET_KEY == "key-@@@@)))()((9))-xxxx&&&%%%%%"


def test_sorted_payload_shape():
    sp = zai.sorted_payload(timestamp_ms=1750000000000,
                            request_id="RID", user_id="UID")
    # keys sorted ascending: requestId < timestamp < user_id
    assert sp == "requestId,RID,timestamp,1750000000000,user_id,UID"


def test_compute_signature_vector_a():
    v = V_A
    assert base64.b64encode(v["message"].encode()).decode() == v["expect_b64"]
    sig = zai.compute_signature(message=v["message"], timestamp_ms=v["timestamp_ms"],
                                request_id=v["request_id"], user_id=v["user_id"])
    assert sig == v["expect_signature"]


def test_compute_signature_vector_b_multibyte():
    v = V_B
    assert base64.b64encode(v["message"].encode()).decode() == v["expect_b64"]
    sig = zai.compute_signature(message=v["message"], timestamp_ms=v["timestamp_ms"],
                                request_id=v["request_id"], user_id=v["user_id"])
    assert sig == v["expect_signature"]


def test_signature_is_deterministic():
    a = zai.compute_signature(message="x", timestamp_ms=1750000000000,
                              request_id="r", user_id="u")
    b = zai.compute_signature(message="x", timestamp_ms=1750000000000,
                              request_id="r", user_id="u")
    assert a == b


def test_signature_changes_with_window():
    # Two timestamps in different 5-minute buckets derive different keys ->
    # different signatures even for the same canonical identity/message.
    base = 1750000000000
    s1 = zai.compute_signature(message="x", timestamp_ms=base,
                               request_id="r", user_id="u")
    s2 = zai.compute_signature(message="x", timestamp_ms=base + zai.WINDOW_MS,
                               request_id="r", user_id="u")
    assert s1 != s2


def test_secret_key_override_changes_signature():
    s = zai.compute_signature(message="x", timestamp_ms=1750000000000,
                              request_id="r", user_id="u")
    s2 = zai.compute_signature(message="x", timestamp_ms=1750000000000,
                               request_id="r", user_id="u", secret_key="other")
    assert s != s2


def test_last_user_message_extraction():
    body = {"messages": [{"role": "system", "content": "sys"},
                         {"role": "user", "content": "first"},
                         {"role": "assistant", "content": "reply"},
                         {"role": "user", "content": "LAST"}]}
    assert zai._last_user_message(body) == "LAST"
    # content-parts array
    body2 = {"messages": [{"role": "user",
                           "content": [{"type": "text", "text": "a"},
                                       {"type": "text", "text": "b"}]}]}
    assert zai._last_user_message(body2) == "ab"
    assert zai._last_user_message({}) == ""


# --- signer entry point (params + headers) ---------------------------------------

def test_build_signed_request_pins_and_matches_vector():
    v = V_A
    body = {"messages": [{"role": "user", "content": v["message"]}]}
    out = zai.build_signed_request(body, {"timestamp_ms": v["timestamp_ms"],
                                          "request_id": v["request_id"],
                                          "user_id": v["user_id"]})
    assert out["signature"] == v["expect_signature"]
    assert out["headers"]["X-Signature"] == v["expect_signature"]
    assert out["headers"]["X-FE-Version"] == zai.FE_VERSION
    p = out["params"]
    assert p["timestamp"] == str(v["timestamp_ms"])
    assert p["requestId"] == v["request_id"]
    assert p["user_id"] == v["user_id"]
    assert p["signature_timestamp"] == str(v["timestamp_ms"])


def test_build_signed_request_merges_telemetry():
    out = zai.build_signed_request(
        {"messages": [{"role": "user", "content": "hi"}]},
        {"timestamp_ms": 1750000000000, "request_id": "r",
         "telemetry": {"platform": "web", "screen_width": 1920}})
    assert out["params"]["platform"] == "web"
    assert out["params"]["screen_width"] == "1920"        # stringified


def test_build_signed_request_defaults_generate_uuid_requestid():
    out = zai.build_signed_request({"messages": [{"role": "user", "content": "hi"}]})
    # a fresh uuid4 (36 chars with dashes) when not pinned
    assert len(out["request_id"]) == 36 and out["request_id"].count("-") == 4


def test_get_signer_unknown_is_none():
    assert get_signer("nope") is None
    assert get_signer("") is None
    assert get_signer("zai") is zai.build_signed_request


# --- transport integration (no live egress; monkeypatch the session) -------------

class _FakeResp:
    def __init__(self):
        self.status_code = 200
        self.headers = {"content-type": "application/json"}
        self.text = '{"choices":[{"message":{"content":"ok"}}]}'

    def json(self):
        import json
        return json.loads(self.text)


def test_client_applies_signer_to_url_and_headers(monkeypatch):
    captured = {}
    t = Target(name="zai", base_url="https://chat.z.ai", api_style="template",
               chat_path=zai.CHAT_PATH,
               request_template={"messages": [{"role": "user", "content": "__PROMPT__"}]},
               response_text_path="choices.0.message.content",
               signer="zai",
               signer_config={"timestamp_ms": 1750000000000,
                              "request_id": "46daabfa-1cdf-4000-8000-000000000000",
                              "user_id": ""})
    c = Client(t)

    def fake_post(url, headers=None, json=None, **kw):
        captured["url"] = url
        captured["headers"] = headers
        captured["json"] = json
        return _FakeResp()

    monkeypatch.setattr(c.s, "post", fake_post)
    r = c.chat("Hello", max_tokens=1)
    assert r.ok
    # URL carries the signed, time-bound query string
    assert "signature_timestamp=1750000000000" in captured["url"]
    assert "requestId=46daabfa-1cdf-4000-8000-000000000000" in captured["url"]
    assert captured["url"].startswith("https://chat.z.ai/api/v2/chat/completions?")
    # header signature equals the golden vector for this exact request
    assert captured["headers"]["X-Signature"] == V_A["expect_signature"]
    assert captured["headers"]["X-FE-Version"] == zai.FE_VERSION
    # body is the verbatim template with the probe prompt substituted
    assert captured["json"]["messages"][0]["content"] == "Hello"


def test_client_unknown_signer_fails_cleanly(monkeypatch):
    t = Target(name="x", base_url="https://x", api_style="template",
               request_template={"messages": [{"role": "user", "content": "__PROMPT__"}]},
               signer="does-not-exist")
    c = Client(t)

    def boom(*a, **k):
        raise AssertionError("must not send when the signer is unknown")

    monkeypatch.setattr(c.s, "post", boom)
    r = c.chat("hi")
    assert not r.ok
    assert "unknown signer" in (r.err or "")


def test_no_signer_leaves_request_unsigned(monkeypatch):
    captured = {}
    t = Target(name="plain", base_url="https://x", api_style="template",
               request_template={"messages": [{"role": "user", "content": "__PROMPT__"}]},
               response_text_path="choices.0.message.content")
    c = Client(t)

    def fake_post(url, headers=None, json=None, **kw):
        captured["url"] = url
        captured["headers"] = headers
        return _FakeResp()

    monkeypatch.setattr(c.s, "post", fake_post)
    c.chat("hi")
    assert "?" not in captured["url"]
    assert "X-Signature" not in captured["headers"]
