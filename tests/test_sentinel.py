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
