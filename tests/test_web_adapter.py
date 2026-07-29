"""Web-app / platform template adapter: dotted-path extraction, placeholder
substitution, path-based response parsing, and SSE text accumulation."""
from provenance_probe.client import dig, _substitute, Response, Client
from provenance_probe.config import Target


def test_dig_dotted_path_with_indices():
    obj = {"choices": [{"message": {"content": "hello"}}], "usage": {"prompt_tokens": 42}}
    assert dig(obj, "choices.0.message.content") == "hello"
    assert dig(obj, "usage.prompt_tokens") == 42
    assert dig(obj, "choices.9.message.content") is None   # missing index
    assert dig(obj, "nope.here") is None
    assert dig(obj, "") is None


def test_substitute_whole_value_preserves_type():
    tmpl = {"messages": [{"role": "user", "content": "__PROMPT__"}],
            "max_tokens": "__MAX_TOKENS__", "note": "n=__MAX_TOKENS__"}
    out = _substitute(tmpl, {"__PROMPT__": "hi", "__MAX_TOKENS__": 1})
    assert out["messages"][0]["content"] == "hi"
    assert out["max_tokens"] == 1                 # whole-value -> stays int
    assert out["note"] == "n=1"                   # in-string -> stringified


def test_response_uses_configured_paths():
    body = {"reply": {"text": "the answer"}, "meta": {"in_tokens": 7, "engine": "glm-4.6"}}
    paths = {"text": "reply.text", "prompt_tokens": "meta.in_tokens", "model": "meta.engine"}
    r = Response(200, {}, body, "", None, 0.0, paths=paths)
    assert r.text() == "the answer"
    assert r.usage_prompt_tokens() == 7
    assert r.echoed_model() == "glm-4.6"


def test_response_falls_back_to_openai_shape_without_paths():
    body = {"choices": [{"message": {"content": "hi"}}], "usage": {"prompt_tokens": 3}, "model": "m"}
    r = Response(200, {}, body, "", None, 0.0)
    assert r.text() == "hi"
    assert r.usage_prompt_tokens() == 3
    assert r.echoed_model() == "m"


def test_response_stream_text_takes_precedence():
    r = Response(200, {}, "raw sse", "raw sse", None, 0.0, stream_text="streamed reply")
    assert r.text() == "streamed reply"


def test_template_payload_substitution():
    t = Target(name="w", base_url="http://x", api_style="template", model="glm-4.6",
               request_template={"model": "glm-4.6",
                                 "messages": [{"role": "user", "content": "__PROMPT__"}],
                                 "max_tokens": "__MAX_TOKENS__"})
    c = Client(t)
    p = c._payload("probe text", max_tokens=1, temperature=0.0, system=None,
                   logprobs=False, extra={})
    assert p["messages"][0]["content"] == "probe text"
    assert p["max_tokens"] == 1
    assert p["model"] == "glm-4.6"


def test_cookie_auth_header_from_env(monkeypatch):
    monkeypatch.setenv("ZAI_COOKIE", "session=abc123")
    t = Target(name="w", base_url="http://x", api_style="template", cookie_env="ZAI_COOKIE")
    assert t.headers().get("Cookie") == "session=abc123"


# --------------------------------------------------------------------------- #
# JSON-lines streaming runtime (gap #1, #44) — no browser needed
# --------------------------------------------------------------------------- #

class _FakeStreamResp:
    def __init__(self, lines, ct="application/x-ndjson"):
        self._lines = lines
        self.status_code = 200
        self.headers = {"content-type": ct}
        self.text = ""
    def iter_lines(self):
        for l in self._lines:
            yield l.encode()
    def json(self):
        raise ValueError("streamed, not a single JSON object")


def _jl_target(**over):
    from provenance_probe.config import Target
    base = dict(name="jl", base_url="https://app.example", chat_path="/api/chat",
                api_style="template", request_template={"m": "__PROMPT__"},
                stream_mode="jsonlines", stream_delta_path="choices.0.delta.content",
                cookie="s=1")
    base.update(over)
    return Target(**base)


def test_client_jsonlines_stream_reassembles(monkeypatch):
    from provenance_probe.client import Client
    c = Client(_jl_target())
    lines = ['{"choices":[{"delta":{"content":"Hel"}}]}',
             '{"choices":[{"delta":{"content":"lo"}}]}']
    monkeypatch.setattr(c.s, "post", lambda *a, **k: _FakeStreamResp(lines))
    r = c.chat("hi", max_tokens=1)
    assert r.ok and r.text() == "Hello"


def test_client_template_stream_does_not_inject_stream_flag(monkeypatch):
    # Template mode replays the captured body verbatim — must NOT add a `stream`
    # field the app never sent (could break replay on custom apps like v0).
    from provenance_probe.client import Client
    seen = {}
    def fake_post(url, headers=None, json=None, **k):
        seen["json"] = json
        return _FakeStreamResp(['{"choices":[{"delta":{"content":"x"}}]}'])
    c = Client(_jl_target())
    monkeypatch.setattr(c.s, "post", fake_post)
    c.chat("hi")
    assert "stream" not in (seen["json"] or {})
