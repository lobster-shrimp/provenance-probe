# -*- coding: utf-8 -*-
"""P2 (#64): the client-side "watch a service for a silent swap".

The whole feature is browser-driven and reuses the EXISTING endpoints
(``/api/assess`` -> ``/api/run`` -> ``/api/monitor``) with NO new detection logic.
These tests lock the security properties the issue calls out:

  * ``/watch`` renders and is auth-gated on hosted like every route;
  * the entry points (landing CTA, "Watch this" on a result, history-row link)
    are present;
  * the re-check defaults to behavioral/deception OFF (fast, cheap);
  * the API key is NEVER stored server-side or in ``localStorage`` — it is only
    ever posted to ``/api/assess``;
  * every probe-derived / user string is escaped before it reaches the DOM
    (no DOM-XSS — the #53 review found one via echoed values);
  * a two-run ``/api/monitor`` diff flags a fingerprint change vs no-change,
    which is the exact contract the client-side loop drives;
  * the ``/help`` "Watching for model swaps" primer describes the client-side
    watch (key stays in the browser, keep the tab open, always-on options).
"""
from __future__ import annotations

import html
import json

import pytest

from provenance_probe import serve, explain


@pytest.fixture
def client():
    return serve.app.test_client()


def _watch_body(client) -> str:
    return client.get("/watch").get_data(as_text=True)


# --------------------------------------------------------------------------- #
# /watch renders and is auth-gated (like every route on hosted)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_watch_page_renders(client):
    r = client.get("/watch")
    assert r.status_code == 200
    assert r.mimetype == "text/html"
    body = r.get_data(as_text=True)
    assert "Watch a service for a silent swap" in body
    # The three honest-limits messages are prominent.
    assert "only while this tab stays open" in body
    assert "background watcher is coming" in body
    assert "Observatory" in body


@pytest.mark.unit
def test_watch_page_is_auth_gated(monkeypatch, client):
    # Not allowlisted out of Basic auth: an unauthenticated request 401s, like
    # every route (the global before_request gate).
    monkeypatch.setattr(serve, "_BASIC_AUTH", ("u", "p"))
    assert client.get("/watch").status_code == 401


# --------------------------------------------------------------------------- #
# Entry points: landing CTA, "Watch this" on a result, history-row link
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_landing_watch_cta_points_at_watch(client):
    body = client.get("/").get_data(as_text=True)
    # The "Set up a watch" job card now opens the client-side watch page.
    assert 'href="/watch"' in body
    assert "Watch a service for a silent swap" in body


@pytest.mark.unit
def test_result_has_watch_this_and_history_row_links_to_watch(client):
    body = client.get("/").get_data(as_text=True)
    # "Watch this" appears on a finished probe result (rendered client-side).
    assert "function watchThis()" in body
    assert "Watch this target for a swap" in body
    # ...and the local-run-history rows carry a per-row "watch" link that
    # pre-fills the target (base_url + name) — never the key.
    assert "/watch?base_url=" in body
    assert "api_key" not in body.split("function watchThis()")[1].split("}")[0]


# --------------------------------------------------------------------------- #
# Reuse the existing endpoints; re-check defaults to behavioral/deception OFF
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_watch_reuses_the_three_endpoints(client):
    body = _watch_body(client)
    assert "/api/assess" in body
    assert "/api/run/" in body
    assert "/api/monitor" in body


@pytest.mark.unit
def test_no_new_watch_endpoint_only_reuse():
    rules = {r.rule for r in serve.app.url_map.iter_rules()}
    assert "/watch" in rules
    # The switch engine is the EXISTING monitor endpoint — no new /api/watch* route.
    assert "/api/assess" in rules
    assert "/api/monitor" in rules
    assert not any(r.startswith("/api/watch") for r in rules), rules


@pytest.mark.unit
def test_recheck_defaults_behavioral_and_deception_off(client):
    body = _watch_body(client)
    # The watch spec turns the slow/costly batteries OFF (fingerprint drift is a
    # tokenizer+wire signal), so re-checks are fast and cheap.
    assert "no_behavioral:true" in body
    assert "no_deception:true" in body


# --------------------------------------------------------------------------- #
# The API key is never persisted server-side or in localStorage
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_key_never_stored_server_side(client, monkeypatch):
    # Stub the worker so /api/assess does no network / thread work; we only assert
    # the endpoint itself never stashes the key.
    monkeypatch.setattr(serve, "_run", lambda rid, spec: None)
    secret = "sk-SECRET-DO-NOT-STORE-123"
    r = client.post("/api/assess", json={"base_url": "https://api.vendor.example/v1",
                                          "api_key": secret, "authorized": True})
    assert r.status_code == 200
    rid = r.get_json()["run_id"]
    try:
        # The server-side run record holds only status + target, never the key.
        assert secret not in json.dumps(serve.RUNS.get(rid, {}))
        # And the polled run state never echoes the key back to the browser.
        run_body = client.get("/api/run/" + rid).get_data(as_text=True)
        assert secret not in run_body
        assert "api_key" not in run_body
    finally:
        serve.RUNS.pop(rid, None)


@pytest.mark.unit
def test_watch_page_never_persists_key_client_side(client):
    body = _watch_body(client)
    # NEVER localStorage/sessionStorage: the word appears only in the privacy
    # note prose, never as a storage WRITE.
    assert ".setItem(" not in body            # no localStorage/sessionStorage.setItem
    assert "localStorage[" not in body
    assert "sessionStorage" not in body
    # The key is collected in-browser and the ONLY fetch that carries it is the
    # per-probe POST to /api/assess; the diff call carries just report filenames.
    assert "JSON.stringify({baseline:baseFile,current:r.file})" in body
    assert "api_key:$('api_key').value" in body


# --------------------------------------------------------------------------- #
# No DOM-XSS: every probe-derived / user value is escaped before the DOM
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_watch_escapes_all_dynamic_values(client):
    body = _watch_body(client)
    # An esc() helper that neutralises the XSS metacharacters is defined and used
    # on every probe-derived field rendered via innerHTML.
    assert "function esc(s)" in body
    for token in ("esc(c.severity)", "esc(c.field)", "esc(c.detail)",
                  "esc((baseFp", "esc(when)"):
        assert token in body, token
    # The Switches log builds nodes with textContent (never innerHTML) for the
    # per-entry summary, so a hostile change field can't inject markup there.
    assert "b.textContent=summary" in body


# --------------------------------------------------------------------------- #
# Integration: the two-run /api/monitor diff the client loop drives
# --------------------------------------------------------------------------- #

def _bundle(fp: str, err: str = "sig-1") -> dict:
    vec = {"a": 10, "b": 12, "c": 15, "d": 11, "e": 13, "f": 14}
    return {
        "target": {"name": "svc", "base_url": "https://api.vendor.example/v1",
                   "model": "m", "api_style": "openai"},
        "timestamp": "2026-01-01T00:00:00+00:00",
        "fingerprint_id": fp,
        "tokenizer": {"vector": vec, "usable": True},
        "errors": {"error_signature": err},
        "score": {"jurisdictional_risk": {"verdict": "UNLIKELY"},
                  "provenance_risk": {"verdict": "NO EVIDENCE"}},
    }


def _write_reports(tmp_path, monkeypatch, baseline: dict, current: dict):
    reports = tmp_path / "reports"
    reports.mkdir()
    (reports / "baseline.json").write_text(json.dumps(baseline))
    (reports / "current.json").write_text(json.dumps(current))
    monkeypatch.setattr(serve, "DATA_DIR", str(tmp_path))


@pytest.mark.unit
def test_monitor_flags_a_fingerprint_change(client, tmp_path, monkeypatch):
    _write_reports(tmp_path, monkeypatch, _bundle("fp-a"), _bundle("fp-b"))
    r = client.post("/api/monitor", json={"baseline": "baseline.json",
                                          "current": "current.json"})
    assert r.status_code == 200
    d = r.get_json()
    assert d["drift_detected"] is True
    assert any(c["field"] == "fingerprint_id" and c["severity"] == "critical"
               for c in d["changes"])
    # The response gives the client exactly what the alert renders.
    assert d["baseline"]["fingerprint_id"] == "fp-a"
    assert d["current"]["fingerprint_id"] == "fp-b"


@pytest.mark.unit
def test_monitor_reports_no_drift_for_identical_runs(client, tmp_path, monkeypatch):
    _write_reports(tmp_path, monkeypatch, _bundle("fp-a"), _bundle("fp-a"))
    r = client.post("/api/monitor", json={"baseline": "baseline.json",
                                          "current": "current.json"})
    d = r.get_json()
    assert d["drift_detected"] is False
    assert d["changes"] == []


@pytest.mark.unit
def test_run_endpoint_exposes_fingerprint_for_baseline_pin():
    # The client pins the baseline by reading fingerprint_id off the completed run;
    # /api/run must surface it (same value /api/history exposes). Drive api_run's
    # done-branch directly with a minimal stored bundle.
    rid = "testfp0000"
    serve.RUNS[rid] = {"state": "done", "progress": 100, "status": "Complete",
                       "files": {"json": "/x/reports/svc_testfp00.json"},
                       "bundle": {"user_warning": {"level": "green", "headline": "ok"},
                                  "score": {}, "fingerprint_id": "fp-baseline-xyz"}}
    try:
        out = serve.app.test_client().get("/api/run/" + rid).get_json()
        assert out["fingerprint_id"] == "fp-baseline-xyz"
    finally:
        serve.RUNS.pop(rid, None)


# --------------------------------------------------------------------------- #
# /help primer describes the client-side watch (single-source explain.py)
# --------------------------------------------------------------------------- #

# --------------------------------------------------------------------------- #
# Credential never leaks into a persisted report via a header-validation error
# (security review of #64). A pasted key with a stray newline/whitespace must not
# make requests raise InvalidHeader with the raw secret in its message, which the
# client swallows into Response.err -> the on-disk report -> GET /report/<name>.
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_header_value_strips_control_chars_and_whitespace():
    from provenance_probe.config import Target
    # A pasted "Bearer sk-…\r\nX-Evil: 1" (CRLF injection / clipboard artifact) is
    # neutralised: no CR/LF survive, so requests never raises InvalidHeader (whose
    # message would echo the raw secret).
    t = Target(name="t", base_url="https://api.example/v1", model="m",
               extra_headers={"Authorization": "Bearer sk-key\r\nX-Evil: 1"},
               cookie="session=abc\n ")
    h = t.headers()
    assert "\r" not in h["Authorization"] and "\n" not in h["Authorization"]
    assert h["Authorization"] == "Bearer sk-keyX-Evil: 1"
    assert h["Cookie"] == "session=abc"


@pytest.mark.unit
def test_env_token_surrounding_whitespace_trimmed(monkeypatch):
    from provenance_probe.config import Target
    monkeypatch.setenv("_PP_TESTTOK", "  sk-abc123  \n")
    t = Target(name="t", base_url="https://api.example/v1", model="m",
               auth_value_env="_PP_TESTTOK")
    assert t.headers()["Authorization"] == "Bearer sk-abc123"


@pytest.mark.unit
def test_transport_error_never_echoes_credential(monkeypatch):
    from provenance_probe.config import Target
    from provenance_probe.client import Client
    secret = "sk-SUPER-SECRET-KEY-XYZ"
    t = Target(name="t", base_url="https://api.example/v1", model="m",
               extra_headers={"Authorization": "Bearer " + secret})
    c = Client(t)
    # Simulate requests embedding the header value in an exception message (as
    # InvalidHeader does via %r). Response.err must be redacted, not the secret.
    def boom(*a, **k):
        raise Exception("Invalid header value: 'Bearer " + secret + "'")
    monkeypatch.setattr(c.s, "post", boom)
    r = c.chat("hi")
    assert r.ok is False
    assert secret not in (r.err or "")
    assert "[redacted]" in (r.err or "")


@pytest.mark.unit
def test_help_primer_describes_client_side_watch(client):
    joined = " ".join(explain.WATCHING_PRIMER)
    # Key stays in the browser; keep the tab open; always-on options.
    assert "API key never leaves your browser" in joined
    assert "while the tab stays open" in joined
    assert "always-on" in joined
    assert "locally" in joined and "Observatory" in joined
    # And it renders, escaped, on /help (single source of truth).
    body = client.get("/help").get_data(as_text=True)
    for para in explain.WATCHING_PRIMER:
        assert html.escape(para) in body, para[:40]
