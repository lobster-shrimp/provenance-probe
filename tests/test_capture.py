"""Guided web-app capture (E8, P3): the no-dependency guide, the optional
Playwright assist (graceful without it), and the wizard capture page."""
from __future__ import annotations

import pytest

from provenance_probe import capture_guide as G
from provenance_probe import capture_playwright as CP


# --------------------------------------------------------------------------- #
# Guided steps (pure)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_guide_has_five_ordered_steps():
    g = G.guide("https://chat.lindy.ai", browser="chrome")
    assert [s.n for s in g.steps] == [1, 2, 3, 4, 5]
    assert all(s.title and s.detail for s in g.steps)


@pytest.mark.unit
def test_guide_names_known_app_and_host():
    g = G.guide("https://claude.ai/chat", browser="chrome")
    assert g.app == "Claude" and g.host == "claude.ai"


@pytest.mark.unit
def test_guide_unknown_host_is_generic_not_crash():
    g = G.guide("https://some-unknown-app.example/chat")
    assert g.app == "the web app" and g.host == "some-unknown-app.example"


@pytest.mark.unit
def test_guide_bare_host_and_empty_url():
    assert G.guide("chat.z.ai").host == "chat.z.ai"
    assert G.guide("").host == ""            # no crash, generic guide


@pytest.mark.unit
@pytest.mark.parametrize("browser,needle", [
    ("chrome", "Copy as cURL"), ("firefox", "Copy Value"),
    ("safari", "Web Inspector"),
])
def test_guide_tailors_to_browser(browser, needle):
    g = G.guide("https://x.example", browser=browser)
    assert needle in G.as_text(g)


@pytest.mark.unit
def test_guide_always_carries_credential_security_note():
    g = G.guide("https://x.example")
    assert "cookie" in g.security_note.lower() and "never enters" in g.security_note.lower()


@pytest.mark.unit
def test_guide_playwright_hint_reflects_availability():
    assert "provenance-probe capture" in G.guide("https://x", playwright_available=True).playwright_hint
    assert "install" in G.guide("https://x", playwright_available=False).playwright_hint.lower()


# --------------------------------------------------------------------------- #
# Playwright assist — graceful + injected launcher (no real browser)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_capture_graceful_without_playwright(tmp_path):
    # When playwright is absent, capture() must return a clean status, not raise.
    if CP.playwright_available():
        pytest.skip("playwright installed in this env; graceful-absent path not exercised")
    res = CP.capture("https://x.example", str(tmp_path / "none.har"),
                     login_wait=lambda: None, send_wait=lambda: None, launcher=None)
    assert res.ok is False and res.playwright_available is False
    assert "not installed" in res.error.lower()


class _FakeCtx:
    def __init__(self, record_har_path=None): self.har = record_har_path
    def new_page(self): return _FakePage()
    def storage_state(self): return {"cookies": [{"name": "sid", "value": "x"}]}
    def close(self):
        if self.har:                              # only the RECORDED context writes a HAR
            with open(self.har, "w") as f:
                f.write('{"log":{"entries":[]}}')


class _FakePage:
    def goto(self, *a, **k): pass


class _FakeBrowser:
    def __init__(self): self.contexts_made = []
    def new_context(self, record_har_path=None, storage_state=None):
        ctx = _FakeCtx(record_har_path)
        self.contexts_made.append({"har": record_har_path, "storage_state": storage_state})
        return ctx
    def close(self): pass


class _FakePW:
    def __init__(self): self.browser = _FakeBrowser(); self.chromium = self
    def launch(self, headless=False): return self.browser
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _FakeLauncher():
    pw = _FakePW()
    return lambda: pw, pw


@pytest.mark.unit
def test_capture_two_phase_login_not_recorded(tmp_path):
    # HIGH (Codex): the login context must NOT record a HAR; only the second,
    # authenticated context does — so the password/login POST never lands in a file.
    har = str(tmp_path / "cap.har")
    order = []
    make, pw = _FakeLauncher()
    res = CP.capture("https://x.example", har,
                     login_wait=lambda: order.append("login"),
                     send_wait=lambda: order.append("send"),
                     launcher=make)
    assert res.ok and order == ["login", "send"]
    # Exactly two contexts: first (login) with NO har, second recorded + storage_state.
    made = pw.browser.contexts_made
    assert made[0]["har"] is None and made[0]["storage_state"] is None
    assert made[1]["har"] == har and made[1]["storage_state"] is not None
    import os
    assert os.path.exists(har)                    # only the recorded context wrote it


@pytest.mark.unit
def test_capture_har_is_chmod_600(tmp_path):
    import os
    har = str(tmp_path / "cap.har")
    make, _pw = _FakeLauncher()
    CP.capture("https://x.example", har, login_wait=lambda: None,
               send_wait=lambda: None, launcher=make)
    assert (os.stat(har).st_mode & 0o777) == 0o600


# --------------------------------------------------------------------------- #
# CLI + wizard page
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_cli_capture_paste_prints_manual_steps(capsys):
    # --paste is the manual guided flow (default is now proxy capture, #44).
    from provenance_probe import cli
    cli.main(["capture", "https://chat.lindy.ai", "--paste"])
    out = capsys.readouterr().out
    assert "Sign in to Lindy" in out and "Copy as cURL" in out


@pytest.mark.unit
def test_cli_capture_default_missing_extra_prints_message_and_guide(capsys, monkeypatch):
    # AC8: default proxy capture without the [capture] extra prints a clear
    # install message and falls back to the manual steps — never crashes.
    from provenance_probe import cli, capture_proxy
    monkeypatch.setattr(capture_proxy, "proxy_available", lambda: False)
    cli.main(["capture", "https://chat.lindy.ai", "--i-am-authorized"])
    cap = capsys.readouterr()
    assert "extra" in cap.err.lower() or "install" in cap.err.lower()
    assert "Copy as cURL" in cap.out                    # manual fallback shown


@pytest.mark.unit
def test_cli_capture_proxy_saves_target(tmp_path, monkeypatch):
    # AC1 through the CLI: proxy capture -> synthesize -> dry-run -> save, with the
    # cookie held out of the committed config and written 0600 to .env.capture.
    import json
    from provenance_probe import cli, capture_proxy, wizard
    monkeypatch.chdir(tmp_path)
    resp = {"choices": [{"message": {"content": "a captured reply of some length"}}],
            "usage": {"prompt_tokens": 6}, "model": "m"}
    flow = capture_proxy.Flow(url="https://chat.app.com/api/chat",
                              req_headers={"Cookie": "sid=abc"},
                              req_body='{"messages":[{"role":"user","content":"hi"}]}',
                              resp_body=json.dumps(resp))
    cap_obj = capture_proxy.flow_to_captured(flow)
    monkeypatch.setattr(capture_proxy, "capture",
                        lambda url, **k: capture_proxy.ProxyCaptureResult(ok=True, captured=cap_obj))
    monkeypatch.setattr(wizard, "dry_run",
                        lambda *a, **k: {"ok": True, "replay_safe": True, "usage_exposed": True,
                                         "prompt_tokens": [6, 6], "error": None})
    cli.main(["capture", "https://chat.app.com", "--i-am-authorized", "--name", "myapp"])
    import os
    assert os.path.exists("targets.json")
    cfg = json.load(open("targets.json"))
    assert any(t["name"] == "myapp" and t["api_style"] == "template" for t in cfg)
    assert "sid=abc" not in json.dumps(cfg)             # credential never committed
    assert "sid=abc" in open(".env.capture").read()
    assert (os.stat(".env.capture").st_mode & 0o777) == 0o600


@pytest.mark.unit
def test_default_har_path_is_private_not_cwd(monkeypatch, tmp_path):
    # HIGH (Codex): the credential-bearing HAR must NOT default to cwd.
    from provenance_probe import cli
    monkeypatch.setenv("PROVENANCE_PROBE_HOME", str(tmp_path))
    p = cli._default_har_path("https://chat.lindy.ai")
    assert p.startswith(str(tmp_path))
    assert "captures" in p and p.endswith(".har") and "chat.lindy.ai" in p


@pytest.mark.unit
def test_wizard_capture_page_renders():
    from provenance_probe import serve
    c = serve.app.test_client()
    r = c.get("/wizard/capture?url=https://claude.ai&browser=firefox")
    assert r.status_code == 200
    assert b"Capture a request from Claude" in r.data
    assert b"Copy Value" in r.data                 # firefox-tailored
    assert b"gitignored" in r.data or b"never enters" in r.data
