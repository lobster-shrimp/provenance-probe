"""z.ai request-signing adapter — the founding-case reactivation.

The golden signatures below pin the RECOVERED ALGORITHM (canonical string, 5-minute
window, double HMAC-SHA256) — the method is public and verified byte-for-byte
against the real ``js-sha256`` library (Node), including a multibyte-UTF-8 message.

They are computed with a deliberately FAKE key (``FAKE_KEY`` below), NOT z.ai's real
embedded key: this repo does not vendor that literal value. The operator recovers
the real key from the current client bundle and passes it via
``signer_config.secret_key`` (see docs/zai-reactivation.md). The signer has no
embedded default and raises when the key is not configured.
"""
import base64

import pytest

from provenance_probe.signers import get_signer
from provenance_probe.signers import zai
from provenance_probe.client import Client
from provenance_probe.config import Target


# A clearly-fake test key. NOT z.ai's real key (which this repo does not ship).
FAKE_KEY = "TEST-KEY-DO-NOT-USE"


# --- deterministic golden vectors (fixed timestamp/requestId + FAKE_KEY -> token) --

# Vector A: ascii message, empty user_id.
V_A = dict(
    message="Hello",
    timestamp_ms=1750000000000,
    request_id="46daabfa-1cdf-4000-8000-000000000000",
    user_id="",
    expect_b64="SGVsbG8=",
    expect_derived="992db111a88286cb70a5d68672e2884d2147bcc19e093f6294c26baae54b5fcf",
    expect_signature="445932babc488914f261537fdbc68ccc8bd3be7b9b32a657d450bf644db70348",
)

# Vector B: multibyte UTF-8 message + a non-empty user_id (proves UTF-8 base64
# parity with the browser's TextEncoder path).
V_B = dict(
    message="你好, world 🌏",
    timestamp_ms=1700000123456,
    request_id="322f2d5c-46a6-4111-8222-abcabcabcabc",
    user_id="user-42",
    expect_b64="5L2g5aW9LCB3b3JsZCDwn4yP",
    expect_signature="68fa422a64d15ed16896f3e1c096068e8f89c4b8153b102ecb6eb95a0f8f1ba5",
)


def test_sorted_payload_shape():
    sp = zai.sorted_payload(timestamp_ms=1750000000000,
                            request_id="RID", user_id="UID")
    # keys sorted ascending: requestId < timestamp < user_id
    assert sp == "requestId,RID,timestamp,1750000000000,user_id,UID"


def test_compute_signature_vector_a():
    v = V_A
    assert base64.b64encode(v["message"].encode()).decode() == v["expect_b64"]
    sig = zai.compute_signature(message=v["message"], timestamp_ms=v["timestamp_ms"],
                                request_id=v["request_id"], user_id=v["user_id"],
                                secret_key=FAKE_KEY)
    assert sig == v["expect_signature"]


def test_compute_signature_vector_b_multibyte():
    v = V_B
    assert base64.b64encode(v["message"].encode()).decode() == v["expect_b64"]
    sig = zai.compute_signature(message=v["message"], timestamp_ms=v["timestamp_ms"],
                                request_id=v["request_id"], user_id=v["user_id"],
                                secret_key=FAKE_KEY)
    assert sig == v["expect_signature"]


def test_missing_secret_key_raises():
    # No embedded default: the operator must supply the key. Both the empty-string
    # and the unset-in-config paths must raise a clear, actionable error.
    with pytest.raises(ValueError, match="secret_key not configured"):
        zai.compute_signature(message="x", timestamp_ms=1750000000000,
                              request_id="r", user_id="u", secret_key="")
    with pytest.raises(ValueError, match="secret_key not configured"):
        zai.build_signed_request({"messages": [{"role": "user", "content": "x"}]},
                                 {"timestamp_ms": 1750000000000, "request_id": "r"})


def test_signature_is_deterministic():
    a = zai.compute_signature(message="x", timestamp_ms=1750000000000,
                              request_id="r", user_id="u", secret_key=FAKE_KEY)
    b = zai.compute_signature(message="x", timestamp_ms=1750000000000,
                              request_id="r", user_id="u", secret_key=FAKE_KEY)
    assert a == b


def test_signature_changes_with_window():
    # Two timestamps in different 5-minute buckets derive different keys ->
    # different signatures even for the same canonical identity/message.
    base = 1750000000000
    s1 = zai.compute_signature(message="x", timestamp_ms=base,
                               request_id="r", user_id="u", secret_key=FAKE_KEY)
    s2 = zai.compute_signature(message="x", timestamp_ms=base + zai.WINDOW_MS,
                               request_id="r", user_id="u", secret_key=FAKE_KEY)
    assert s1 != s2


def test_secret_key_change_changes_signature():
    s = zai.compute_signature(message="x", timestamp_ms=1750000000000,
                              request_id="r", user_id="u", secret_key=FAKE_KEY)
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
                                          "user_id": v["user_id"],
                                          "secret_key": FAKE_KEY})
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
        {"timestamp_ms": 1750000000000, "request_id": "r", "secret_key": FAKE_KEY,
         "telemetry": {"platform": "web", "screen_width": 1920}})
    assert out["params"]["platform"] == "web"
    assert out["params"]["screen_width"] == "1920"        # stringified


def test_build_signed_request_defaults_generate_uuid_requestid():
    out = zai.build_signed_request({"messages": [{"role": "user", "content": "hi"}]},
                                   {"secret_key": FAKE_KEY})
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
                              "user_id": "", "secret_key": FAKE_KEY})
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
