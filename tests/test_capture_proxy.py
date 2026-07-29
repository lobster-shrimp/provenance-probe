"""Local recording-proxy capture (#44). The pure core is testable with no
mitmproxy/playwright: flow selection + flow->wizard.Captured conversion + SSE
reassembly, plus the two-phase orchestration via an injected driver."""
from __future__ import annotations

import json

import pytest

from provenance_probe import capture_proxy as CX
from provenance_probe import wizard


def _flow(url="https://app.example/api/chat", method="POST",
          req_headers=None, req_body="", resp_headers=None, resp_body="",
          resp_content_type="application/json"):
    return CX.Flow(url=url, method=method, req_headers=req_headers or {},
                   req_body=req_body, resp_headers=resp_headers or {},
                   resp_body=resp_body, resp_content_type=resp_content_type)


# --------------------------------------------------------------------------- #
# Chat-flow selection (shared scorer, lifted from wizard.parse_har)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_select_none_on_empty():
    assert CX.select_chat_flow([], prompt_hint="hi") is None


@pytest.mark.unit
def test_select_prefers_prompt_hint_match():
    noise = _flow(url="https://app.example/api/telemetry", req_body='{"event":"x"}')
    hit = _flow(url="https://app.example/api/chat",
                req_body='{"messages":[{"role":"user","content":"fingerprint me"}]}')
    chosen = CX.select_chat_flow([noise, hit], prompt_hint="fingerprint me")
    assert chosen is hit


@pytest.mark.unit
def test_select_prefers_chatish_json_post_over_random():
    rnd = _flow(url="https://app.example/api/log", req_body='{"a":1}')
    chat = _flow(url="https://app.example/v1/chat/completions",
                 req_body='{"messages":[{"role":"user","content":"x"}]}')
    assert CX.select_chat_flow([rnd, chat]) is chat


@pytest.mark.unit
def test_select_ignores_non_post():
    get = _flow(url="https://app.example/api/chat", method="GET")
    assert CX.select_chat_flow([get]) is None


# --------------------------------------------------------------------------- #
# flow -> wizard.Captured (the hand-off contract to synthesize())
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_flow_to_captured_splits_cookie_out_of_headers():
    f = _flow(req_headers={"Cookie": "sid=secret123", "X-Csrf": "tok", "Host": "app.example"},
              req_body='{"messages":[]}')
    cap = CX.flow_to_captured(f)
    assert isinstance(cap, wizard.Captured)
    assert cap.cookie == "sid=secret123"
    assert "Cookie" not in cap.headers and "cookie" not in {k.lower() for k in cap.headers}
    assert cap.headers.get("X-Csrf") == "tok"          # non-credential header preserved


@pytest.mark.unit
def test_flow_to_captured_json_response_parsed_not_stream():
    body = {"choices": [{"message": {"content": "hello there friend"}}],
            "usage": {"prompt_tokens": 11}, "model": "gpt-4o"}
    f = _flow(req_body='{"messages":[{"role":"user","content":"hi"}]}',
              resp_body=json.dumps(body), resp_content_type="application/json")
    cap = CX.flow_to_captured(f)
    assert cap.response == body                          # parsed JSON, ready for synthesize
    assert "event-stream" not in (cap.content_type or "")


@pytest.mark.unit
def test_proxy_flow_synthesizes_working_target():
    """AC1 core: a captured JSON flow -> Captured -> wizard.synthesize() yields a
    template target with the response paths already located (no hand-typing)."""
    resp = {"choices": [{"message": {"content": "the quick brown fox jumps"}}],
            "usage": {"prompt_tokens": 9}, "model": "gpt-4o"}
    f = _flow(url="https://app.example/api/chat",
              req_headers={"Cookie": "sid=x", "X-Csrf": "t"},
              req_body='{"messages":[{"role":"user","content":"fingerprint me"}],"model":"gpt-4o"}',
              resp_body=json.dumps(resp))
    cap = CX.flow_to_captured(f, prompt_hint="fingerprint me")
    syn = wizard.synthesize(cap, "fingerprint me", "proxied-app")
    t = syn.target
    assert t["api_style"] == "template"
    assert t["base_url"] == "https://app.example"
    assert t["response_text_path"] == "choices.0.message.content"
    assert t["response_prompt_tokens_path"] == "usage.prompt_tokens"
    assert syn.cookie_value == "sid=x"                  # credential held apart


# --------------------------------------------------------------------------- #
# SSE reassembly (AC2)
# --------------------------------------------------------------------------- #

_SSE = (
    'data: {"choices":[{"delta":{"content":"Hel"}}]}\n\n'
    'data: {"choices":[{"delta":{"content":"lo"}}]}\n\n'
    'data: {"choices":[{"delta":{},"finish_reason":"stop"}],'
    '"usage":{"prompt_tokens":7}}\n\n'
    'data: [DONE]\n\n'
)


@pytest.mark.unit
def test_sse_reassemble_helper():
    r = CX.sse_reassemble(_SSE)
    assert r.text == "Hello"                            # deltas concatenated
    assert r.usage_prompt_tokens == 7                   # read off the final chunk
    assert r.delta_path == "choices.0.delta.content"    # per-chunk incremental path


@pytest.mark.unit
def test_flow_to_captured_sse_sets_stream_fields():
    f = _flow(resp_body=_SSE, resp_content_type="text/event-stream")
    cap = CX.flow_to_captured(f)
    assert "event-stream" in cap.content_type
    # detected so synthesize/dry_run don't need a second live replay to learn it.
    assert cap.stream_delta_path == "choices.0.delta.content"


@pytest.mark.unit
def test_sse_flow_synthesizes_sse_target():
    """AC2 core: an SSE flow -> template target with stream_mode=sse and a
    stream_delta_path filled (the cURL-paste path cannot do this)."""
    f = _flow(url="https://app.example/api/chat",
              req_body='{"messages":[{"role":"user","content":"hi"}]}',
              resp_body=_SSE, resp_content_type="text/event-stream")
    cap = CX.flow_to_captured(f)
    syn = wizard.synthesize(cap, "hi", "sse-app")
    assert syn.target["stream_mode"] == "sse"
    assert syn.target["stream_delta_path"] == "choices.0.delta.content"


# --------------------------------------------------------------------------- #
# Ephemeral-CA confdir lifecycle (AC3/AC4)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_proxy_confdir_creates_0700_and_cleans_up():
    import os
    seen = {}
    with CX.proxy_confdir() as d:
        seen["d"] = d
        assert os.path.isdir(d)
        assert (os.stat(d).st_mode & 0o777) == 0o700     # owner-only from creation
    assert not os.path.exists(seen["d"])                 # removed on normal exit


@pytest.mark.unit
def test_proxy_confdir_cleans_up_on_exception():
    import os
    seen = {}
    with pytest.raises(RuntimeError):
        with CX.proxy_confdir() as d:
            seen["d"] = d
            raise RuntimeError("boom")
    assert not os.path.exists(seen["d"])                 # CA never outlives a crash


# --------------------------------------------------------------------------- #
# capture() orchestration via an injected driver (no mitmproxy/playwright)
# --------------------------------------------------------------------------- #

def _driver_returning(flows):
    def drv(url, *, login_wait, send_wait, proxy_port=None):
        login_wait(); send_wait()
        return flows
    return drv


@pytest.mark.unit
def test_capture_happy_path_injected_driver():
    resp = {"choices": [{"message": {"content": "a longer captured reply here"}}],
            "usage": {"prompt_tokens": 4}, "model": "m"}
    flows = [_flow(url="https://app.example/api/chat", req_headers={"Cookie": "s=1"},
                   req_body='{"messages":[{"role":"user","content":"hi"}]}',
                   resp_body=json.dumps(resp))]
    res = CX.capture("https://app.example", prompt_hint="hi",
                     login_wait=lambda: None, send_wait=lambda: None,
                     driver=_driver_returning(flows))
    assert res.ok and res.captured is not None
    assert res.captured.cookie == "s=1"
    assert res.captured.url == "https://app.example/api/chat"


@pytest.mark.unit
def test_capture_no_flows_friendly_error():
    res = CX.capture("https://app.example", login_wait=lambda: None,
                     send_wait=lambda: None, driver=_driver_returning([]))
    assert res.ok is False and "one" in res.error.lower()


@pytest.mark.unit
def test_capture_graceful_without_extra(monkeypatch):
    monkeypatch.setattr(CX, "proxy_available", lambda: False)
    res = CX.capture("https://app.example", login_wait=lambda: None, send_wait=lambda: None)
    assert res.ok is False and res.available is False
    assert "extra" in res.error.lower() or "install" in res.error.lower()


# --------------------------------------------------------------------------- #
# Two-phase session invariants (AC5 login-not-recorded, AC4 teardown)
# --------------------------------------------------------------------------- #

class _FakeProxyRec:
    def __init__(self, flows): self._flows = flows; self.started = self.stopped = self.recording = False
    def start(self, confdir): self.started = True; self.confdir = confdir; return 54321
    def begin_recording(self): self.recording = True
    def flows(self): return list(self._flows) if self.recording else []
    def stop(self): self.stopped = True


class _RecCtx:
    def new_page(self): return type("P", (), {"goto": lambda *a, **k: None})()
    def storage_state(self): return {"cookies": []}
    def close(self): pass


class _RecBrowser:
    def __init__(self): self.contexts = []; self.closed = False
    def new_context(self, **kw): self.contexts.append(kw); return _RecCtx()
    def close(self): self.closed = True


class _RecPW:
    def __init__(self): self.chromium = self; self.browser = _RecBrowser()
    def launch(self, headless=False): return self.browser
    def __enter__(self): return self
    def __exit__(self, *a): return False


@pytest.mark.unit
def test_session_phase1_unproxied_phase2_proxied_and_teardown():
    pw = _RecPW(); proxy = _FakeProxyRec([_flow()])
    flows = CX._run_capture_session("https://app.example", launcher=lambda: pw, proxy=proxy,
                                    login_wait=lambda: None, send_wait=lambda: None, confdir="/tmp/x")
    made = pw.browser.contexts
    assert "proxy" not in made[0]                        # phase 1 (login) is NOT proxied
    assert made[1]["proxy"]["server"].startswith("http://127.0.0.1:")
    assert made[1]["ignore_https_errors"] is True        # throwaway ctx trusts no store
    assert proxy.started and proxy.stopped and proxy.recording
    assert flows                                         # phase-2 flows returned


@pytest.mark.unit
def test_session_stops_proxy_on_abort():
    pw = _RecPW(); proxy = _FakeProxyRec([])
    def boom(): raise RuntimeError("user aborted")
    with pytest.raises(RuntimeError):
        CX._run_capture_session("https://app.example", launcher=lambda: pw, proxy=proxy,
                                login_wait=lambda: None, send_wait=boom, confdir="/tmp/x")
    assert proxy.stopped                                 # torn down even on abort


# --------------------------------------------------------------------------- #
# Gap #1: response body-mode sniffing + JSON-lines (found against v0.app)
# --------------------------------------------------------------------------- #

_JSONL_DELTAS = "\n".join([
    '{"choices":[{"delta":{"content":"Hel"}}]}',
    '{"choices":[{"delta":{"content":"lo"}}]}',
    '{"choices":[{"delta":{}}],"usage":{"prompt_tokens":7}}',
])

# v0.app's real shape: newline-delimited custom diff objects over text/plain.
_V0_JSONL = "\n".join([
    '{"0":[[0,[["AssistantMessageContentPart",{"part":{"taskNameActive":"Getting started..."}}]]]],"_t":"a"}',
    '{"0":{"1":{"1":[["p",{},["text",{},"ok"]]],"_t":"a"},"_t":"a"},"_t":"a"}',
    '{"1":{"1":{"finishReason":["stop"],"creditCost":[0.02]},"_t":"a"},"_t":"a"}',
])


@pytest.mark.unit
@pytest.mark.parametrize("body,ct,mode", [
    ('{"a":1}', "application/json", "json"),
    ('data: {"choices":[{"delta":{"content":"x"}}]}\n\ndata: [DONE]\n', "text/plain", "sse"),
    (_JSONL_DELTAS, "text/plain; charset=utf-8", "jsonlines"),
    (_V0_JSONL, "text/plain; charset=utf-8", "jsonlines"),
    ("just some prose, not json", "text/plain", "none"),
    ("", "application/json", "none"),
])
def test_detect_response_mode(body, ct, mode):
    assert CX.detect_response_mode(body, ct) == mode


@pytest.mark.unit
def test_flow_to_captured_sniffs_sse_under_text_plain():
    # An app that streams SSE but mislabels the content-type as text/plain.
    body = 'data: {"choices":[{"delta":{"content":"hi"}}]}\n\ndata: [DONE]\n'
    cap = CX.flow_to_captured(_flow(resp_body=body, resp_content_type="text/plain; charset=utf-8"))
    assert "event-stream" in cap.content_type            # normalized so synthesize -> sse
    assert cap.stream_delta_path == "choices.0.delta.content"


@pytest.mark.unit
def test_flow_to_captured_jsonlines_deltas():
    cap = CX.flow_to_captured(_flow(resp_body=_JSONL_DELTAS, resp_content_type="text/plain"))
    assert "ndjson" in cap.content_type                  # -> synthesize stream_mode jsonlines
    assert cap.stream_delta_path == "choices.0.delta.content"


@pytest.mark.unit
def test_flow_to_captured_v0_custom_jsonlines_is_honest():
    # v0's custom diff JSON-lines: detected as a stream, but no standard delta path.
    cap = CX.flow_to_captured(_flow(resp_body=_V0_JSONL, resp_content_type="text/plain; charset=utf-8"))
    assert "ndjson" in cap.content_type
    assert cap.stream_delta_path == ""                   # custom shape -> not auto-detectable
    assert cap.response is None


@pytest.mark.unit
def test_synthesize_jsonlines_stream_mode():
    cap = CX.flow_to_captured(_flow(url="https://app.example/api/chat",
                                    req_body='{"messages":[{"role":"user","content":"hi"}]}',
                                    resp_body=_JSONL_DELTAS, resp_content_type="text/plain"))
    syn = wizard.synthesize(cap, "hi", "jl")
    assert syn.target["stream_mode"] == "jsonlines"
    assert syn.target["stream_delta_path"] == "choices.0.delta.content"


@pytest.mark.unit
def test_synthesize_v0_custom_stream_warns_no_delta_path():
    cap = CX.flow_to_captured(_flow(url="https://v0.app/chat/api/chat",
                                    req_body='{"messageContent":{"parts":[{"content":"hi"}]}}',
                                    resp_body=_V0_JSONL, resp_content_type="text/plain"))
    syn = wizard.synthesize(cap, "hi", "v0")
    assert syn.target["stream_mode"] == "jsonlines"
    assert syn.target["stream_delta_path"] == ""
    assert any("delta path" in w.lower() or "by hand" in w.lower() for w in syn.warnings)


# --------------------------------------------------------------------------- #
# Gap #2: widen stateful-key blanking to cover chatId (found against v0.app)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_synthesize_blanks_chatid():
    import json as _json
    cap = CX.flow_to_captured(_flow(
        req_body='{"chatId":"koMTifHbYwZ","messages":[{"role":"user","content":"hi"}]}'))
    syn = wizard.synthesize(cap, "hi", "t")
    assert syn.target["request_template"]["chatId"] == ""     # blanked for replay-safety
    assert any("chatId" in w for w in syn.warnings)


# --------------------------------------------------------------------------- #
# Review fixes (#44 pre-landing review)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_synthesize_prefers_reply_over_echoed_prompt():
    # App echoes the user's own turn in the response; response_text_path must
    # point at the ASSISTANT reply, not the echoed prompt.
    msg = "fingerprint me"
    resp = {"conversation": {"messages": [
        {"role": "user", "content": msg},
        {"role": "assistant", "content": "Sure! Here is a fun fact about llamas and alpacas."}]}}
    cap = CX.flow_to_captured(_flow(req_body='{"m":"' + msg + '"}', resp_body=json.dumps(resp)),
                              prompt_hint=msg)
    syn = wizard.synthesize(cap, msg, "app")
    assert syn.target["response_text_path"] == "conversation.messages.1.content"


@pytest.mark.unit
def test_synthesize_keeps_model_selector_field_but_blanks_chat_id():
    cap = CX.flow_to_captured(_flow(
        req_body='{"chatModelId":"gpt-4o","chatId":"abc","messages":[{"role":"user","content":"hi"}]}'))
    syn = wizard.synthesize(cap, "hi", "t")
    tmpl = syn.target["request_template"]
    assert tmpl["chatModelId"] == "gpt-4o"          # model selector preserved
    assert tmpl["chatId"] == ""                     # conversation id still blanked


@pytest.mark.unit
def test_select_chat_flow_binds_to_target_host():
    third_party = _flow(url="https://analytics.example-ads.com/collect",
                        req_body='{"messages":[{"role":"user","content":"fingerprint me"}],"big":"'
                                 + "x" * 500 + '"}')          # bigger + has the prompt
    real = _flow(url="https://api.app.example/v1/chat",
                 req_body='{"messages":[{"role":"user","content":"fingerprint me"}]}')
    chosen = CX.select_chat_flow([third_party, real], prompt_hint="fingerprint me",
                                 allowed_host="app.example")
    assert chosen is real                            # same registrable domain wins over a bigger 3rd-party


@pytest.mark.unit
def test_select_chat_flow_none_when_only_cross_domain():
    third_party = _flow(url="https://tracker.other.com/x",
                        req_body='{"messages":[{"role":"user","content":"hi"}]}')
    assert CX.select_chat_flow([third_party], allowed_host="app.example") is None


@pytest.mark.unit
def test_detect_response_mode_ignores_heartbeat_comments():
    body = "\n".join([
        ': keep-alive',
        '{"choices":[{"delta":{"content":"Hel"}}]}',
        ': keep-alive',
        '{"choices":[{"delta":{"content":"lo"}}]}',
    ])
    assert CX.detect_response_mode(body, "text/plain") == "jsonlines"


@pytest.mark.unit
def test_capture_binds_to_target_host_via_driver():
    third = _flow(url="https://ads.tracker.io/c",
                  req_body='{"messages":[{"role":"user","content":"hi"}]}',
                  resp_body='{"choices":[{"message":{"content":"a longer reply here"}}]}')
    real = _flow(url="https://app.example/api/chat", req_headers={"Cookie": "sid=real"},
                 req_body='{"messages":[{"role":"user","content":"hi"}]}',
                 resp_body='{"choices":[{"message":{"content":"a longer real reply here"}}]}')
    def drv(url, *, login_wait, send_wait, proxy_port=None):
        return [third, real]
    res = CX.capture("https://app.example", login_wait=lambda: None,
                     send_wait=lambda: None, driver=drv)
    assert res.ok and res.captured.cookie == "sid=real"   # not the tracker's flow


@pytest.mark.unit
def test_session_closes_browser_on_abort():
    pw = _RecPW(); proxy = _FakeProxyRec([])
    def boom(): raise RuntimeError("user aborted")
    with pytest.raises(RuntimeError):
        CX._run_capture_session("https://app.example", launcher=lambda: pw, proxy=proxy,
                                login_wait=lambda: None, send_wait=boom, confdir="/tmp/x")
    assert pw.browser.closed is True                 # browser torn down on abort (no cookie leak)
    assert proxy.stopped
