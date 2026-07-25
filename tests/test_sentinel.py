"""Real-time sentinel: a proxied upstream that swaps its served model mid-session
must trip an alert + a recorded model-change event, while traffic passes through."""
import threading

from provenance_probe import sentinel


def _upstream(switch_after: int):
    """Serves gpt-4o + a Gemini self-ID; after `switch_after` requests, glm-4 + a
    GLM self-ID (a mid-session swap)."""
    from flask import Flask, jsonify, request
    app = Flask(__name__)
    state = {"n": 0}

    @app.post("/v1/chat/completions")
    def chat():
        request.get_data()
        state["n"] += 1
        switched = state["n"] > switch_after
        model = "glm-4" if switched else "gpt-4o"
        content = ("You caught me — actually the engine is GLM (Zhipu)." if switched
                   else "I am Gemini, developed by Google.")
        return jsonify({"id": "x", "model": model, "object": "chat.completion",
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": content}}],
                        "usage": {"prompt_tokens": 5, "completion_tokens": 3}})

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
    # wait until the socket actually accepts, so the first proxied request
    # doesn't race server startup
    for _ in range(50):
        try:
            with socket.create_connection(("127.0.0.1", port), timeout=0.2):
                break
        except OSError:
            time.sleep(0.05)
    return srv, port


def _post(client, session, msg="hi"):
    return client.post("/v1/chat/completions",
                       json={"model": "m", "messages": [{"role": "user", "content": msg}]},
                       headers={"X-Provenance-Session": session})


def test_detects_mid_session_switch_realtime():
    srv, port = _serve(_upstream(switch_after=2))
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        r1 = _post(c, "s1"); r2 = _post(c, "s1")     # baseline (gpt-4o / Gemini)
        assert r1.status_code == 200
        assert "X-Provenance-Alert" not in r1.headers and "X-Provenance-Alert" not in r2.headers
        r3 = _post(c, "s1")                          # 3rd request -> switched
        assert r3.headers.get("X-Provenance-Alert") == "model-switch"
        evs = c.get("/sentinel/events").get_json()["events"]
        signals = {(e["signal"], e["from"], e["to"]) for e in evs}
        assert ("model_id", "gpt-4o", "glm-4") in signals
        assert any(s == "self_id" and t == "GLM (Zhipu)" for s, _f, t in signals)
        assert c.get("/sentinel/status").get_json()["ok"] is True
    finally:
        srv.shutdown()


def test_passthrough_and_no_false_alert_when_stable():
    srv, port = _serve(_upstream(switch_after=999))   # never switches
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        for _ in range(4):
            r = _post(c, "s1")
            assert r.status_code == 200
            assert r.get_json()["model"] == "gpt-4o"          # body forwarded intact
            assert "X-Provenance-Alert" not in r.headers
        assert c.get("/sentinel/events").get_json()["events"] == []
    finally:
        srv.shutdown()


def test_sessions_are_isolated():
    srv, port = _serve(_upstream(switch_after=1))
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        _post(c, "a")                     # req1: a baseline gpt-4o
        _post(c, "b")                     # req2: b baseline glm-4 (already switched) — no alert (first sight)
        evs = c.get("/sentinel/events").get_json()["events"]
        assert evs == []                  # neither session saw a change *within itself*
    finally:
        srv.shutdown()


# --- Phase 2: SSE tee, fail-open, passthrough, agent report ------------------

def _sse_upstream():
    from flask import Flask, Response
    app = Flask(__name__)

    @app.post("/v1/chat/completions")
    def chat():
        def gen():
            yield 'data: {"model":"glm-4.6","choices":[{"delta":{"content":"Hi"}}]}\n\n'
            yield 'data: {"model":"glm-4.6","choices":[{"delta":{"content":" there"}}]}\n\n'
            yield "data: [DONE]\n\n"
        return Response(gen(), content_type="text/event-stream")

    @app.get("/v1/models")
    def models():
        return {"data": [{"id": "glm-4.6"}]}

    return app


def test_sse_tee_forwards_bytes_and_collects_step():
    srv, port = _serve(_sse_upstream())
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        r = _post(c, "s1")
        assert r.status_code == 200
        body = r.data.decode()
        assert "Hi" in body and "there" in body and "[DONE]" in body   # bytes forwarded
        rep = c.get("/agent/report?session=s1").get_json()
        assert rep["steps"][0]["echoed_model"] == "glm-4.6"            # step collected
        assert rep["steps"][0]["host"]                                # upstream carried for jurisdiction
    finally:
        srv.shutdown()


def test_fail_open_when_accumulator_raises_midstream(monkeypatch):
    # if the SSE parser throws on every line, the agent must STILL get all bytes
    def boom(*a, **k):
        raise RuntimeError("parser exploded")
    monkeypatch.setattr(sentinel, "parse_sse_delta", boom)
    srv, port = _serve(_sse_upstream())
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        r = _post(c, "s1")
        assert r.status_code == 200
        body = r.data.decode()
        assert "Hi" in body and "there" in body and "[DONE]" in body   # UNTOUCHED despite crash
    finally:
        srv.shutdown()


def test_generic_passthrough_non_chat_path():
    srv, port = _serve(_sse_upstream())
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        r = c.get("/v1/models")                                       # not chat/completions
        assert r.status_code == 200
        assert r.get_json()["data"][0]["id"] == "glm-4.6"             # reached upstream
    finally:
        srv.shutdown()


def test_agent_report_404_for_unknown_session():
    srv, port = _serve(_sse_upstream())
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        assert c.get("/agent/report?session=nope").status_code == 404
    finally:
        srv.shutdown()


def _upstream_nomodel_first():
    """req1: an error with NO model field; req2: gpt-4o; req3: glm-4 (a switch)."""
    from flask import Flask, jsonify
    app = Flask(__name__)
    st = {"n": 0}

    @app.post("/v1/chat/completions")
    def chat():
        st["n"] += 1
        if st["n"] == 1:
            return jsonify({"error": {"message": "bad model"}}), 400   # no "model"
        model = "glm-4" if st["n"] >= 3 else "gpt-4o"
        return jsonify({"model": model, "choices": [{"message": {"role": "assistant", "content": "ok"}}]})

    return app


def test_agent_graph_links_subagent_sessions():
    # E6: a child session linked via X-Provenance-Parent nests under its parent
    srv, port = _serve(_sse_upstream())
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        _post(c, "root")
        c.post("/v1/chat/completions",
               json={"model": "m", "messages": [{"role": "user", "content": "hi"}]},
               headers={"X-Provenance-Session": "root/retriever", "X-Provenance-Parent": "root"})
        g = c.get("/agent/graph?session=root").get_json()
        assert g["root"] == "root"
        kids = [n["session"] for n in g["graph"]["children"]]
        assert "root/retriever" in kids
    finally:
        srv.shutdown()


def test_baseline_not_poisoned_by_modelless_first_response():
    # regression: a first response with no model_id must NOT freeze the baseline —
    # a later real switch (gpt-4o -> glm-4) must still be caught (Codex P1).
    srv, port = _serve(_upstream_nomodel_first())
    try:
        app = sentinel.create_app(f"http://127.0.0.1:{port}")
        c = app.test_client()
        _post(c, "s1")                                  # no model -> baseline None
        r2 = _post(c, "s1")                             # gpt-4o -> backfills baseline, no alert
        assert "X-Provenance-Alert" not in r2.headers
        r3 = _post(c, "s1")                             # glm-4 -> switch DETECTED
        assert r3.headers.get("X-Provenance-Alert") == "model-switch"
        sigs = {(e["from"], e["to"]) for e in c.get("/sentinel/events").get_json()["events"]}
        assert ("gpt-4o", "glm-4") in sigs
    finally:
        srv.shutdown()
