"""Session-boundary swap detection: a mock that rotates its served model
mid-session must be caught by session.boundary_check (fingerprint start vs end)."""
import os
import threading

import pytest

from provenance_probe.config import Target
from provenance_probe.client import Client
from provenance_probe.probes import session

VOCABS = os.path.join(os.path.dirname(__file__), "..", "eval", "vocabs")
pytestmark = pytest.mark.skipif(
    not os.path.exists(os.path.join(VOCABS, "qwen2.gguf")),
    reason="vendored eval vocabs not present")


def _switching_app(switch_after: int | None):
    """Serves qwen2 token counts, switching to llama-bpe after `switch_after`
    requests (None = never switch). Genuine GGUF counts, so the fingerprint
    shape actually changes on the swap."""
    from flask import Flask, jsonify, request
    from eval import mock
    qwen = mock.load_tokenizer(os.path.join(VOCABS, "qwen2.gguf"), "qwen2")
    llama = mock.load_tokenizer(os.path.join(VOCABS, "llama-bpe.gguf"), "llama-bpe")
    app = Flask(__name__)
    state = {"n": 0}

    @app.route("/v1/chat/completions", methods=["POST"])
    def chat():
        d = request.get_json(force=True, silent=True) or {}
        if d.get("temperature", 0) > 2 or d.get("max_tokens", 1) < 0:
            return jsonify({"error": {"message": "bad", "type": "invalid_request_error"}}), 400
        state["n"] += 1
        tk = llama if (switch_after is not None and state["n"] > switch_after) else qwen
        prompt = " ".join(m.get("content", "") for m in (d.get("messages") or [])
                          if isinstance(m.get("content"), str))
        n = len(tk.encode(prompt, add_special_tokens=False).ids) + 9
        return jsonify({"id": "x", "model": "blind", "object": "chat.completion",
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": "ok"}}],
                        "usage": {"prompt_tokens": n, "completion_tokens": 1}})

    @app.route("/v1/models")
    def models():
        return jsonify({"data": [{"id": "blind"}]})

    return app


def _serve(app):
    import logging
    from werkzeug.serving import make_server
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_port


def _check(switch_after):
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    srv, port = _serve(_switching_app(switch_after))
    try:
        t = Target(name="x", base_url=f"http://127.0.0.1:{port}/v1", model="blind",
                   authorized=True)
        # gap large enough that the end snapshot is entirely post-switch
        return session.boundary_check(Client(t), gap_probes=60)
    finally:
        srv.shutdown()


def test_detects_mid_session_switch():
    r = _check(switch_after=45)
    assert r["boundary_switch"] is True
    assert r["start_fingerprint"] != r["end_fingerprint"]
    assert any(c["field"] in ("fingerprint_id", "tokenizer_vector") for c in r["changes"])


def test_stable_session_no_switch():
    r = _check(switch_after=None)
    assert r["boundary_switch"] is False
    assert r["start_fingerprint"] == r["end_fingerprint"]
