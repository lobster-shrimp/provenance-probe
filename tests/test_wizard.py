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


# --- dry-run -----------------------------------------------------------------

class _Resp:
    def __init__(self, status, n, text="reply"):
        self.status, self._n, self._t = status, n, text
    @property
    def ok(self):                      # mirror client.Response.ok (a property, not a method)
        return 200 <= self.status < 300
    def usage_prompt_tokens(self):
        return self._n
    def text(self):
        return self._t


class _Client:
    def __init__(self, script):
        self.script, self.i = list(script), -1
    def chat(self, prompt, **kw):
        self.i += 1
        return _Resp(*self.script[min(self.i, len(self.script) - 1)])


def test_dry_run_usable_and_replay_safe():
    out = wizard.dry_run(_Client([(200, 7, "hi"), (200, 8, "ok")]))
    assert out["ok"] and out["usage_exposed"] and out["replay_safe"]


def test_dry_run_http_error_is_not_ok():
    out = wizard.dry_run(_Client([(401, None, "")]))
    assert not out["ok"] and "HTTP 401" in out["error"]


def test_dry_run_usage_suppressed_is_degraded_but_replay_safe():
    out = wizard.dry_run(_Client([(200, None, "hi"), (200, None, "ok")]))
    assert out["ok"] and not out["usage_exposed"] and out["replay_safe"]  # stateless, degraded


def test_dry_run_unstable_counts_flag_replay_unsafe():
    out = wizard.dry_run(_Client([(200, 7, "hi"), (200, 900, "ok")]))   # wild drift = stateful
    assert out["usage_exposed"] and not out["replay_safe"]


def test_dry_run_no_reply_is_not_ok():
    out = wizard.dry_run(_Client([(200, 7, ""), (200, 7, "")]))   # HTTP ok but empty replies
    assert not out["ok"] and "no reply" in out["error"]


# --- sanitize (defense-in-depth at the write boundary) -----------------------

def test_sanitize_strips_cookie_and_auth_headers():
    dirty = {"name": "x", "cookie": "sess=SECRET",
             "extra_headers": {"x-csrf-token": "ok", "Cookie": "c=SECRET", "Authorization": "Bearer S"}}
    clean, removed = wizard.sanitize_target(dirty)
    assert "cookie" not in clean
    assert clean["extra_headers"] == {"x-csrf-token": "ok"}
    assert "cookie" in removed and any("Cookie" in r for r in removed) and any("Authorization" in r for r in removed)


# --- save --------------------------------------------------------------------

def test_write_target_appends_list_and_keeps_cookie_out_of_config(tmp_path):
    cfg = tmp_path / "targets.json"
    env = tmp_path / ".env.capture"
    target = {"name": "lindy", "base_url": "https://chat.lindy.ai", "api_style": "template",
              "cookie_env": "LINDY_COOKIE", "authorized": False}
    res = wizard.write_target(target, "sess=SECRET", config_path=str(cfg),
                              env_path=str(env), repo_root=str(tmp_path))
    written = json.loads(cfg.read_text())
    assert isinstance(written, list) and written[0]["name"] == "lindy"   # loader-consumable shape
    assert "SECRET" not in cfg.read_text()               # cookie never in committed config
    assert "LINDY_COOKIE=sess=SECRET" in env.read_text()  # cookie in the env file only
    assert ".env.capture" in (tmp_path / ".gitignore").read_text()   # env file gitignored
    assert res["added"] == "lindy"


def test_write_target_sanitizes_smuggled_cookie_in_edited_target(tmp_path):
    cfg = tmp_path / "targets.json"
    # a hand-edited target that tries to smuggle a cookie into the committed config
    target = {"name": "x", "api_style": "template", "cookie": "sess=SMUGGLED",
              "extra_headers": {"Cookie": "c=SMUGGLED", "x-csrf-token": "keep"}}
    res = wizard.write_target(target, "", config_path=str(cfg),
                              env_path=str(tmp_path / ".env"), repo_root=str(tmp_path))
    text = cfg.read_text()
    assert "SMUGGLED" not in text                        # sanitized at the write boundary
    assert "keep" in text                                # non-secret header preserved
    assert any("stripped credential" in w for w in res["warnings"])


def test_write_target_refuses_name_clobber(tmp_path):
    cfg = tmp_path / "targets.json"
    cfg.write_text(json.dumps([{"name": "lindy"}]))      # loader shape = list
    with pytest.raises(ValueError):
        wizard.write_target({"name": "lindy"}, "", config_path=str(cfg),
                            env_path=str(tmp_path / ".env"), repo_root=str(tmp_path))


def test_ensure_gitignored_idempotent(tmp_path):
    wizard.ensure_gitignored(str(tmp_path), ".env.capture")
    wizard.ensure_gitignored(str(tmp_path), ".env.capture")   # second call no dupe
    assert (tmp_path / ".gitignore").read_text().count(".env.capture") == 1


# --- serve UI routes ---------------------------------------------------------

_CURL = ("curl 'https://chat.example.com/api/chat' -X POST "
         "-H 'content-type: application/json' -H 'cookie: sid=LEAKME' "
         "--data-raw '{\"messages\":[{\"role\":\"user\",\"content\":\"fingerprint me\"}]}'")


def _client():
    from provenance_probe import serve
    return serve.app.test_client()


def test_wizard_get_renders_form():
    r = _client().get("/wizard")
    assert r.status_code == 200 and b"Add-target wizard" in r.data


def test_wizard_post_previews_and_never_reflects_cookie():
    r = _client().post("/wizard", data={"name": "demo", "prompt": "fingerprint me",
                                         "fmt": "curl", "capture": _CURL})
    assert r.status_code == 200 and b"Confirm" in r.data and b"__PROMPT__" in r.data
    assert b"LEAKME" not in r.data          # cookie NOWHERE in the response (no hidden round-trip)
    assert b"name=token" in r.data          # server-side stash token instead


def test_wizard_post_bad_capture_shows_error():
    r = _client().post("/wizard", data={"name": "x", "prompt": "hi", "fmt": "curl",
                                        "capture": "not a curl command"})
    assert r.status_code == 200 and b"Could not parse capture" in r.data


def test_wizard_parse_error_does_not_leak_cookie():
    # a malformed cURL (no URL) that still carries a cookie must not be echoed back
    bad = "curl -X POST -H 'cookie: sid=LEAKME2' -H 'accept: */*'"
    r = _client().post("/wizard", data={"name": "x", "prompt": "hi", "fmt": "curl", "capture": bad})
    assert r.status_code == 200 and b"Could not parse capture" in r.data
    assert b"LEAKME2" not in r.data          # capture (with cookie) not reflected into error HTML


def test_write_target_output_is_loadable_after_unknown_keys_stripped(tmp_path):
    from provenance_probe import config
    cfg = tmp_path / "targets.json"
    target = {"name": "wz", "base_url": "https://x.ai", "api_style": "template",
              "chat_path": "/c", "bogus_field": 1, "another_typo": "z"}   # unknown keys
    wizard.write_target(target, "", config_path=str(cfg),
                        env_path=str(tmp_path / ".env"), repo_root=str(tmp_path))
    loaded = config.load_targets(str(cfg))          # must NOT raise on unknown kwargs
    assert loaded[0].name == "wz" and loaded[0].api_style == "template"


def test_wizard_save_expired_token():
    r = _client().post("/wizard/save", data={"token": "nope", "target": "{}"})
    assert r.status_code == 200 and b"expired" in r.data


def test_wizard_save_rejects_bad_json_with_valid_token():
    import re as _re
    c = _client()
    prev = c.post("/wizard", data={"name": "demo", "prompt": "fingerprint me",
                                   "fmt": "curl", "capture": _CURL})
    token = _re.search(rb'name=token value="([0-9a-f]+)"', prev.data).group(1).decode()
    r = c.post("/wizard/save", data={"token": token, "target": "{not json"})
    assert r.status_code == 200 and b"not valid JSON" in r.data
