# -*- coding: utf-8 -*-
"""P3 (#66): the local always-on `watch` daemon.

Locks the contracts the issue calls out:

  * interval parsing (30s/15m/1h), jitter bound + disable;
  * target-name path-traversal defense (slugify + realpath containment);
  * baseline seed-vs-load, and the secret-free switch-record shape;
  * secret hygiene across EVERY alert sink (banner / switches.jsonl / webhook);
  * `assess_target` fingerprint PARITY across CLI-assess / serve / watch for a
    fixed mock response (the whole reason the shared helper exists);
  * integration on a werkzeug mock vendor (like test_sentinel): first-run seed ->
    no-drift -> flip fingerprint -> `--once` exits 2 + writes switches.jsonl;
    `--pin` re-baselines; `--webhook` receives the POST and a failure is non-fatal;
    `--loop` raises on a swap, KEEPS running, and shuts down cleanly;
  * the launchd / systemd generators emit a valid unit that runs `watch --once`.
"""
from __future__ import annotations

import argparse
import json
import os
import shutil
import subprocess
import threading

import pytest

from provenance_probe import watch, assess, serve
from provenance_probe.config import Target


# --------------------------------------------------------------------------- #
# mock vendor: deterministic OpenAI-ish endpoint whose greedy completion (and
# therefore its composite fingerprint) flips when `state["switched"]` is set.
# Only the greedy text changes; tokenizer shape, wire/error/streaming stay put,
# so a flip reads as a clean critical fingerprint drift.
# --------------------------------------------------------------------------- #
def _vendor(state: dict):
    from flask import Flask, jsonify, request, Response
    app = Flask(__name__)

    @app.post("/v1/chat/completions")
    def chat():
        d = request.get_json(force=True, silent=True) or {}
        if isinstance(d.get("temperature"), (int, float)) and d["temperature"] > 2:
            return jsonify({"error": {"message": "bad", "type": "invalid_request_error",
                                      "param": "temperature", "code": None}}), 400
        if isinstance(d.get("max_tokens"), int) and d["max_tokens"] < 0:
            return jsonify({"error": {"message": "bad", "type": "invalid_request_error",
                                      "param": "max_tokens", "code": None}}), 400
        msgs = d.get("messages") or []
        prompt = " ".join(m.get("content", "") for m in msgs if isinstance(m.get("content"), str))
        ptok = len(prompt) + 3                       # deterministic -> stable tokenizer shape
        tag = "GLM-after" if state.get("switched") else "safe-before"
        txt = f"[{tag}] deterministic reply for: {prompt[:40]}"
        if d.get("stream"):
            def gen():
                for w in txt.split():
                    yield "data: " + json.dumps(
                        {"id": "c", "object": "chat.completion.chunk", "model": "m",
                         "choices": [{"delta": {"content": w + " "}, "index": 0,
                                      "finish_reason": None}]}) + "\n\n"
                yield "data: " + json.dumps(
                    {"id": "c", "choices": [{"delta": {}, "index": 0, "finish_reason": "stop"}],
                     "usage": {"prompt_tokens": ptok, "completion_tokens": len(txt.split())}}) + "\n\n"
                yield "data: [DONE]\n\n"
            return Response(gen(), mimetype="text/event-stream")
        return jsonify({"id": "c", "object": "chat.completion", "model": "m",
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": txt}}],
                        "usage": {"prompt_tokens": ptok, "completion_tokens": len(txt.split()),
                                  "total_tokens": ptok + len(txt.split())}})

    @app.get("/v1/models")
    def models():
        return jsonify({"object": "list", "data": [{"id": "m"}]})

    return app


def _serve(app):
    import logging
    import socket
    import time
    from werkzeug.serving import make_server
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    port = srv.server_port
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    return srv, port


def _target(port: int, *, secret: str | None = None) -> Target:
    extra = {"Authorization": f"Bearer {secret}"} if secret else {}
    return Target(name="mock-vendor", base_url=f"http://127.0.0.1:{port}/v1",
                  model="m", api_style="openai", authorized=True, extra_headers=extra)


@pytest.fixture(autouse=True)
def _home(tmp_path, monkeypatch):
    """Redirect the private data root so every test writes into its own tmp dir."""
    monkeypatch.setenv("PROVENANCE_PROBE_HOME", str(tmp_path / "pp"))
    return tmp_path


# =========================================================================== #
# UNIT
# =========================================================================== #
@pytest.mark.unit
def test_parse_interval_forms():
    assert watch.parse_interval("30s") == 30
    assert watch.parse_interval("15m") == 900
    assert watch.parse_interval("1h") == 3600
    assert watch.parse_interval("90") == 90                # bare = seconds
    for bad in ("", "abc", "10x", "-5m", "0s"):
        with pytest.raises(ValueError):
            watch.parse_interval(bad)


@pytest.mark.unit
def test_jitter_bounded_and_disablable():
    # default 10% of interval, capped at 30s
    for _ in range(200):
        j = watch.jitter_seconds(600, 0.10)              # 10% of 600 = 60 -> capped 30
        assert 0.0 <= j <= 30.0
        j2 = watch.jitter_seconds(60, 0.10)              # 10% of 60 = 6 (under cap)
        assert 0.0 <= j2 <= 6.0
    assert watch.jitter_seconds(600, 0) == 0.0            # --jitter 0 disables
    assert watch.jitter_seconds(600, 0.0) == 0.0


@pytest.mark.unit
def test_target_name_path_traversal_is_blocked():
    # Slugify collapses every separator into a single safe segment (dots are an
    # allowed char, but a slug can contain NO slash, so it cannot traverse).
    assert watch.slugify("../../etc/passwd") == "..-..-etc-passwd"
    assert "/" not in watch.slugify("../../etc/passwd")
    assert watch.slugify("a/b\\c") == "a-b-c"
    for bad in ("", ".", ".."):
        with pytest.raises(ValueError):
            watch.slugify(bad)
    # The tokens that slugify to a rejected literal raise outright.
    for bad in ("", ".", ".."):
        with pytest.raises(ValueError):
            watch.target_dir(bad)
    # The security INVARIANT: for ANY crafted name, target_dir either raises or
    # resolves to a path strictly INSIDE the watch root — it can never escape.
    root = os.path.realpath(watch.watch_root())
    for evil in ("..", "../../../../tmp/evil", "/etc/passwd", "a/../../b",
                 "....//....//x", "vendor.prod-1"):
        try:
            d = os.path.realpath(watch.target_dir(evil))
        except ValueError:
            continue
        assert d.startswith(root + os.sep), f"{evil!r} escaped to {d}"


@pytest.mark.unit
def test_colliding_target_names_are_rejected():
    # "a/b" and "a:b" both slugify to "a-b" -> they would share one baseline.
    a = Target(name="a/b", base_url="http://x/v1", model="m", authorized=True)
    b = Target(name="a:b", base_url="http://y/v1", model="m", authorized=True)
    with pytest.raises(ValueError):
        watch.assert_unique_slugs([a, b])
    # distinct, non-colliding names are fine
    watch.assert_unique_slugs([a, Target(name="c-d", base_url="http://z/v1",
                                         model="m", authorized=True)])


@pytest.mark.unit
def test_switch_record_shape_is_secret_free():
    diff = {"changes": [{"severity": "critical", "field": "fingerprint_id",
                         "detail": "changed"}], "drift_detected": True,
            "confidence": "full"}
    rec = watch.switch_record("t", "aaaa", "bbbb", diff)
    assert set(rec) >= {"ts", "target", "baseline_fp", "current_fp", "changes", "confidence"}
    assert rec["baseline_fp"] == "aaaa" and rec["current_fp"] == "bbbb"
    assert rec["changes"] == diff["changes"]
    # NEVER any credential-shaped keys.
    for forbidden in ("api_key", "authorization", "cookie", "headers", "token"):
        assert forbidden not in json.dumps(rec).lower()


@pytest.mark.unit
def test_banner_and_record_never_contain_the_secret():
    secret = "sk-SECRET-TOKEN-abc123"
    tgt = _target(0, secret=secret)
    diff = {"changes": [{"severity": "critical", "field": "fingerprint_id",
                         "detail": "Composite backend fingerprint changed."}],
            "drift_detected": True, "confidence": "full"}
    rec = watch.switch_record(tgt.name, "aaaa", "bbbb", diff)
    banner = watch.render_banner(tgt.name, "aaaa", "bbbb", diff)
    assert "MODEL SWITCH DETECTED" in banner
    assert secret not in banner
    assert secret not in json.dumps(rec)


@pytest.mark.unit
def test_webhook_payload_is_the_secret_free_record(monkeypatch):
    secret = "sk-SECRET-TOKEN-xyz789"
    posts = []

    class _Resp:
        status_code = 200

    def _fake_post(self, url, json=None, timeout=None):
        posts.append(json)
        return _Resp()

    monkeypatch.setattr("requests.Session.post", _fake_post)
    rec = watch.switch_record("t", "aaaa", "bbbb",
                              {"changes": [], "confidence": "full"})
    ok = watch.post_webhook("http://example.invalid/hook", rec,
                            _target(0, secret=secret))
    assert ok is True
    assert posts == [rec]
    assert secret not in json.dumps(posts[0])


@pytest.mark.unit
def test_baseline_seed_then_load_then_drift(monkeypatch):
    """Seed vs load, using a canned bundle (no network): first check seeds and
    reports no drift; an unchanged re-check is clean; a changed fingerprint
    drifts and appends exactly one switches.jsonl record."""
    bundle = {"fingerprint_id": "fp-AAAA", "tokenizer": {"usable": True, "vector": {}},
              "errors": {}, "headers": {}, "greedy": {}, "streaming": {}, "score": {}}
    monkeypatch.setattr("provenance_probe.assess.assess_target",
                        lambda t, o, **k: dict(bundle))
    tgt = Target(name="canned", base_url="http://x/v1", model="m", authorized=True)
    opts = assess.AssessOpts()

    r1 = watch.check_target(tgt, opts)
    assert r1["status"] == "seeded" and r1["drift"] is False
    assert watch.load_baseline("canned")["fingerprint_id"] == "fp-AAAA"

    r2 = watch.check_target(tgt, opts)
    assert r2["status"] == "clean" and r2["drift"] is False

    bundle["fingerprint_id"] = "fp-BBBB"                  # the backend "switched"
    r3 = watch.check_target(tgt, opts)
    assert r3["status"] == "drift" and r3["drift"] is True
    recs = [json.loads(l) for l in
            open(os.path.join(watch.target_dir("canned"), "switches.jsonl"))]
    assert len(recs) == 1
    assert recs[0]["baseline_fp"] == "fp-AAAA" and recs[0]["current_fp"] == "fp-BBBB"


# =========================================================================== #
# INTEGRATION (mock vendor)
# =========================================================================== #
@pytest.mark.unit
def test_once_seed_then_no_drift_then_flip_exits_2_and_pin_resets():
    state = {"switched": False}
    srv, port = _serve(_vendor(state))
    try:
        tgt = _target(port, secret="sk-SECRET-live-001")
        opts = assess.AssessOpts(offline=True)           # tokenizer ON, behavioral/deception OFF

        assert watch.run_once([tgt], opts) == 0          # pass 1: seed -> exit 0
        assert watch.run_once([tgt], opts) == 0          # pass 2: unchanged -> exit 0

        state["switched"] = True
        assert watch.run_once([tgt], opts) == 2          # fingerprint moved -> exit 2

        sw = os.path.join(watch.target_dir("mock-vendor"), "switches.jsonl")
        recs = [json.loads(l) for l in open(sw)]
        assert len(recs) >= 1
        assert recs[-1]["baseline_fp"] != recs[-1]["current_fp"]
        # the live secret never reaches the switch log
        assert "sk-SECRET-live-001" not in open(sw).read()

        # --pin re-baselines to the (now switched) fingerprint; the next check is clean.
        assert watch.pin_targets([tgt], opts) == 0
        assert watch.run_once([tgt], opts) == 0
    finally:
        srv.shutdown()


@pytest.mark.unit
def test_fingerprint_parity_cli_serve_watch(tmp_path, monkeypatch):
    """Criterion 4: CLI-assess, serve, and watch agree byte-for-byte on the
    fingerprint for one fixed mock response (they share assess_target)."""
    state = {"switched": False}
    srv, port = _serve(_vendor(state))
    try:
        tgt = _target(port)

        # watch: seed a baseline, read its fingerprint.
        watch.check_target(tgt, assess.AssessOpts(offline=True))
        fp_watch = watch.load_baseline("mock-vendor")["fingerprint_id"]

        # serve: drive the assess worker directly (its real code path) into a tmp dir.
        monkeypatch.setattr(serve, "DATA_DIR", str(tmp_path / "serve"))
        rid = "rid1"
        serve.RUNS[rid] = {"state": "running", "progress": 0, "status": "…"}
        serve._run(rid, {"base_url": tgt.base_url, "model": "m", "authorized": True,
                         "offline": True, "no_behavioral": True, "no_deception": True})
        assert serve.RUNS[rid]["state"] == "done", serve.RUNS[rid].get("status")
        fp_serve = serve.RUNS[rid]["bundle"]["fingerprint_id"]
        serve.RUNS.pop(rid, None)

        # cli assess: run cmd_assess, read the fingerprint from the report JSON.
        cfg = tmp_path / "targets.json"
        cfg.write_text(json.dumps([{"name": "mock-vendor", "base_url": tgt.base_url,
                                    "model": "m", "authorized": True}]))
        out = tmp_path / "reports"
        ns = argparse.Namespace(
            config=str(cfg), out=str(out), artifacts=None, client_dir=None,
            client_url=None, latency=False, latency_n=12, leak_samples=2,
            no_tokenizer=False, no_behavioral=True, no_deception=True,
            confront_as=None, confront_control="Mistral AI", session_test=False,
            offline=True, i_am_authorized=True, variant_seed=0)
        cli_mod = __import__("provenance_probe.cli", fromlist=["cmd_assess"])
        cli_mod.cmd_assess(ns)
        report = json.load(open(next(p for p in out.iterdir() if p.suffix == ".json")))
        fp_cli = report["fingerprint_id"]

        assert fp_watch == fp_serve == fp_cli, (fp_watch, fp_serve, fp_cli)
    finally:
        srv.shutdown()


@pytest.mark.unit
def test_webhook_receives_post_on_drift_and_failure_is_nonfatal(monkeypatch):
    state = {"switched": False}
    srv, port = _serve(_vendor(state))
    try:
        tgt = _target(port, secret="sk-SECRET-hook-777")
        opts = assess.AssessOpts(offline=True)
        assert watch.run_once([tgt], opts) == 0          # seed
        state["switched"] = True

        posts = []

        class _Resp:
            status_code = 200

        monkeypatch.setattr(
            "requests.Session.post",
            lambda self, url, json=None, timeout=None: posts.append(json) or _Resp())
        rc = watch.run_once([tgt], opts, webhook="http://example.invalid/hook")
        assert rc == 2                                    # drift
        assert len(posts) == 1
        body = posts[0]
        assert body["baseline_fp"] != body["current_fp"]
        assert body["changes"]
        assert "sk-SECRET-hook-777" not in json.dumps(body)

        # A webhook that raises must NOT change the drift exit code or crash —
        # and must not leak the URL path (a Slack/Discord token) into the log.
        def _boom(self, url, json=None, timeout=None):
            raise TimeoutError("connect timed out to https://hooks.example/services/T00/B00/SECRETTOKEN")

        logged = []
        monkeypatch.setattr("requests.Session.post", _boom)
        assert watch.post_webhook("https://hooks.example/services/T00/B00/SECRETTOKEN",
                                  posts[0], tgt, log=logged.append) is False
        assert "SECRETTOKEN" not in " ".join(logged)      # path token never logged
        assert watch.run_once([tgt], opts, webhook="http://example.invalid/hook") == 2
    finally:
        srv.shutdown()


@pytest.mark.unit
def test_loop_raises_then_keeps_running_then_shuts_down():
    """--loop seeds on pass 1, re-checks on the timer, raises on a mid-run swap,
    KEEPS running (does not exit on drift), and shuts down cleanly (rc 0). The
    stop_event is exactly what cmd_watch's SIGINT/SIGTERM handler sets."""
    state = {"switched": False}
    srv, port = _serve(_vendor(state))
    try:
        tgt = _target(port)
        opts = assess.AssessOpts(offline=True)
        stop = threading.Event()

        def on_cycle(n):
            if n == 1:
                state["switched"] = True                 # swap AFTER the baseline pass
            if n >= 3:                                    # ran well past the drift pass
                stop.set()

        rc = watch.run_loop([tgt], opts, interval=0, jitter_frac=0,
                            stop_event=stop, max_passes=6, on_cycle=on_cycle)
        assert rc == 0                                    # clean shutdown
        sw = os.path.join(watch.target_dir("mock-vendor"), "switches.jsonl")
        recs = [json.loads(l) for l in open(sw)]
        assert len(recs) >= 1                             # the swap was recorded
    finally:
        srv.shutdown()


# =========================================================================== #
# UNIT-FILE GENERATORS
# =========================================================================== #
@pytest.mark.unit
def test_launchd_plist_is_valid_and_runs_watch_once(tmp_path):
    plist = watch.launchd_plist(str(tmp_path / "targets.json"), interval=900)
    assert "watch" in plist and "--once" in plist
    assert str((tmp_path / "targets.json").resolve()) in plist or \
        os.path.abspath(str(tmp_path / "targets.json")) in plist
    assert "<key>StartInterval</key>" in plist
    # Strict XML parse EVERYWHERE (catches e.g. an illegal "--" in a comment,
    # which lenient `plutil` would wave through), plus `plutil -lint` on macOS.
    import plistlib
    data = plistlib.loads(plist.encode())
    assert data["Label"] and "--once" in data["ProgramArguments"]
    assert "watch" in data["ProgramArguments"]
    assert int(data["StartInterval"]) == 900
    p = tmp_path / "pp.plist"
    p.write_text(plist)
    if shutil.which("plutil"):                            # macOS
        r = subprocess.run(["plutil", "-lint", str(p)], capture_output=True, text=True)
        assert r.returncode == 0, r.stdout + r.stderr


@pytest.mark.unit
def test_systemd_units_wellformed_and_run_watch_once(tmp_path):
    cfg = str(tmp_path / "targets.json")
    units = watch.systemd_units(cfg, interval=900)
    assert "[Unit]" in units and "[Service]" in units and "[Timer]" in units
    assert "[Install]" in units
    assert "Type=oneshot" in units
    assert "ExecStart=" in units and "watch --once --config" in units
    assert os.path.abspath(cfg) in units
    assert "OnUnitActiveSec=900" in units
    if shutil.which("systemd-analyze"):                   # Linux w/ systemd
        svc = tmp_path / "pp.service"
        svc.write_text(units.split("FILE: provenance-probe-watch.service")[1]
                       .split("# =====")[0].lstrip(" =\n"))
        r = subprocess.run(["systemd-analyze", "verify", str(svc)],
                           capture_output=True, text=True)
        # verify may warn about a user unit path; only fail on a hard parse error.
        assert "Failed to parse" not in (r.stdout + r.stderr)
