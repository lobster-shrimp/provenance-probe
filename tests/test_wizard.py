"""Add-a-target wizard: cURL/HAR parse + template synthesis (paste-first v1)."""
import json

import pytest

from provenance_probe import wizard


# --- cURL parsing ------------------------------------------------------------

def test_parse_curl_basic():
    cur = (
        "curl 'https://chat.example.com/api/chat' "
        "-X POST "
        "-H 'content-type: application/json' "
        "-H 'x-csrf-token: abc123' "
        "-H 'cookie: session=secret; other=1' "
        "--data-raw '{\"messages\":[{\"role\":\"user\",\"content\":\"hello\"}]}'"
    )
    c = wizard.parse_curl(cur)
    assert c.url == "https://chat.example.com/api/chat"
    assert c.method == "POST"
    assert c.headers["content-type"] == "application/json"
    assert c.headers["x-csrf-token"] == "abc123"
    assert c.cookie == "session=secret; other=1"      # cookie split out of headers
    assert "cookie" not in {k.lower() for k in c.headers}
    assert json.loads(c.body)["messages"][0]["content"] == "hello"


def test_parse_curl_line_continuations_and_b_flag():
    c = wizard.parse_curl("curl 'https://x.ai/c' \\\n  -b 'sid=9' \\\n  --data '{\"q\":\"hi\"}'")
    assert c.cookie == "sid=9" and c.method == "POST"


def test_parse_curl_empty_raises():
    with pytest.raises(ValueError):
        wizard.parse_curl("   ")


def test_parse_curl_no_url_raises():
    with pytest.raises(ValueError):
        wizard.parse_curl("curl -X POST -H 'a: b'")


# --- HAR parsing -------------------------------------------------------------

def _har(entries):
    return json.dumps({"log": {"entries": entries}})


def test_parse_har_picks_prompt_bearing_post():
    har = _har([
        {"request": {"method": "GET", "url": "https://x.ai/ping", "headers": []}},
        {"request": {"method": "POST", "url": "https://x.ai/api/chat",
                     "headers": [{"name": "cookie", "value": "s=1"},
                                 {"name": "content-type", "value": "application/json"}],
                     "postData": {"text": '{"content":"fingerprint me"}'}},
         "response": {"headers": [{"name": "content-type", "value": "application/json"}],
                      "content": {"text": '{"reply":"ok","usage":{"prompt_tokens":7},"model":"glm-4.6"}'}}},
    ])
    c = wizard.parse_har(har, prompt_hint="fingerprint me")
    assert c.url == "https://x.ai/api/chat" and c.cookie == "s=1"
    assert c.response["usage"]["prompt_tokens"] == 7


def test_parse_har_no_post_raises():
    with pytest.raises(ValueError):
        wizard.parse_har(_har([{"request": {"method": "GET", "url": "https://x.ai/", "headers": []}}]))


# --- dotted-path search ------------------------------------------------------

def test_find_paths_in_nested_response():
    resp = {"choices": [{"message": {"content": "the answer"}}],
            "usage": {"prompt_tokens": 12}, "model": "glm-4.6"}
    assert wizard.find_text_path(resp, "the answer") == "choices.0.message.content"
    assert wizard.find_usage_path(resp) == "usage.prompt_tokens"
    assert wizard.find_model_path(resp) == "model"


def test_find_usage_path_absent_returns_none():
    assert wizard.find_usage_path({"choices": [{"text": "hi"}]}) is None


# --- synthesis ---------------------------------------------------------------

def _cap(body, cookie="sess=abc", response=None, ct=""):
    return wizard.Captured(url="https://chat.example.com/api/v1/chat",
                           method="POST", headers={"x-csrf-token": "t1", "host": "drop"},
                           body=json.dumps(body), cookie=cookie, response=response, content_type=ct)


def test_synthesize_prompt_becomes_placeholder():
    s = wizard.synthesize(_cap({"messages": [{"role": "user", "content": "PROBE"}]}), "PROBE", "lindy")
    assert s.target["request_template"]["messages"][0]["content"] == "__PROMPT__"
    assert s.target["base_url"] == "https://chat.example.com"
    assert s.target["chat_path"] == "/api/v1/chat"
    assert s.target["api_style"] == "template"


def test_synthesize_cookie_never_in_committable_config():
    s = wizard.synthesize(_cap({"content": "PROBE"}), "PROBE", "lindy")
    blob = json.dumps(s.target)
    assert "sess=abc" not in blob                  # the credential is NOT in the config
    assert s.target["cookie_env"] == "LINDY_COOKIE"
    assert s.cookie_value == "sess=abc"            # it is returned separately for env storage


def test_synthesize_strips_stateful_ids_with_warning():
    s = wizard.synthesize(_cap({"conversation_id": "c-99", "content": "PROBE"}), "PROBE", "t")
    assert s.target["request_template"]["conversation_id"] == ""
    assert any("stateful" in w for w in s.warnings)


def test_synthesize_authorized_defaults_false():
    s = wizard.synthesize(_cap({"content": "PROBE"}), "PROBE", "t")
    assert s.target["authorized"] is False          # never auto-authorize probing


def test_synthesize_keeps_csrf_drops_host_header():
    s = wizard.synthesize(_cap({"content": "PROBE"}), "PROBE", "t")
    assert s.target["extra_headers"].get("x-csrf-token") == "t1"
    assert "host" not in s.target["extra_headers"]
    assert any("dynamic" in w for w in s.warnings)  # csrf flagged as dynamic


def test_synthesize_warns_when_usage_absent():
    resp = {"choices": [{"message": {"content": "hi"}}], "model": "m"}  # no usage
    s = wizard.synthesize(_cap({"content": "PROBE"}, response=resp), "PROBE", "t")
    assert any("tokenizer fingerprint will be UNAVAILABLE" in w for w in s.warnings)


def test_synthesize_finds_response_paths_from_har_response():
    resp = {"choices": [{"message": {"content": "PROBE reply"}}],
            "usage": {"prompt_tokens": 5}, "model": "glm-4.6"}
    s = wizard.synthesize(_cap({"content": "PROBE"}, response=resp), "PROBE reply", "t")
    assert s.target["response_prompt_tokens_path"] == "usage.prompt_tokens"
    assert s.target["response_model_path"] == "model"
    assert s.target["response_text_path"] == "choices.0.message.content"


def test_synthesize_detects_sse():
    s = wizard.synthesize(_cap({"content": "PROBE"}, ct="text/event-stream; charset=utf-8"), "PROBE", "t")
    assert s.target["stream_mode"] == "sse"
    assert any("SSE" in w for w in s.warnings)


def test_synthesize_non_json_body_warns():
    cap = wizard.Captured(url="https://x.ai/c", method="POST", headers={},
                          body="q=hi&n=1", cookie="s=1")
    s = wizard.synthesize(cap, "hi", "t")
    assert any("not JSON" in w for w in s.warnings)
