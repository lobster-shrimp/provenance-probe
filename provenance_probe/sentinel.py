"""Real-time in-line model-switch sentinel (P3).

An OpenAI-compatible reverse proxy. It forwards chat completions to an upstream
endpoint and watches each response for a mid-session identity change — the
echoed model id, a self-ID persona in the reply, or the vendor header shape. The
instant the served model switches WITHIN a session, it records a model-change
event and alerts (log line + an `X-Provenance-Alert` response header). This is
the live guardrail: the boundary check samples start/end, this watches every turn.

    client ──► sentinel ──forward──► upstream
                  │  per session: baseline identity (model id / self-ID / headers)
                  ▼  on change vs baseline -> record event + alert header
              /sentinel/events   /sentinel/status

Passive by design: it inspects the traffic that already flows, it does not inject
probes. Session key = the `X-Provenance-Session` request header (else "default").
"""
from __future__ import annotations
import hashlib
import json
import threading
import time

from .probes import transcript as _tx

# Response headers too volatile to fingerprint (change every request).
_VOLATILE = {"date", "x-request-id", "cf-ray", "x-amzn-requestid", "request-id",
             "openai-processing-ms", "set-cookie", "x-envoy-upstream-service-time",
             "content-length"}


def _header_shape(headers) -> str:
    names = sorted(k.lower() for k in headers.keys() if k.lower() not in _VOLATILE)
    return hashlib.sha256("|".join(names).encode()).hexdigest()[:12]


def identity(resp_json: dict, content: str, headers) -> dict:
    """The identity signals we can read from one live response."""
    idy = _tx._turn_identity(content or "")
    return {"model_id": resp_json.get("model"),
            "self_id": idy.get("conceded") or idy.get("asserted"),
            "header_shape": _header_shape(headers)}


def create_app(upstream: str, *, events_file: str | None = None):
    """Flask proxy app. `upstream` is the real endpoint root (…/v1 is appended)."""
    import requests
    from flask import Flask, request, jsonify, Response

    app = Flask(__name__)
    state = {"sessions": {}, "events": []}
    lock = threading.RLock()   # reentrant: chat() holds it while calling record()
    base_url = upstream.rstrip("/")

    def record(session: str, signal: str, frm, to) -> dict:
        ev = {"session": session, "ts": round(time.time(), 3),
              "signal": signal, "from": frm, "to": to}
        with lock:
            state["events"].append(ev)
        if events_file:
            with open(events_file, "a") as f:
                f.write(json.dumps(ev) + "\n")
        print(f"[sentinel] ALERT session={session} {signal}: {frm} -> {to}", flush=True)
        return ev

    @app.route("/v1/chat/completions", methods=["POST"])
    def chat():
        body = request.get_data()
        fwd = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length", "connection")}
        fwd["Connection"] = "close"   # fresh connection per turn (no pool reuse)
        session = request.headers.get("X-Provenance-Session", "default")
        try:
            r = requests.post(base_url + "/v1/chat/completions", data=body,
                              headers=fwd, timeout=120)
        except requests.RequestException as e:
            return jsonify({"error": {"message": f"sentinel upstream error: {e}"}}), 502

        alerted = False
        if "application/json" in r.headers.get("content-type", ""):
            try:
                j = r.json()
                content = ((j.get("choices") or [{}])[0].get("message") or {}).get("content", "")
                cur = identity(j, content, r.headers)
                with lock:
                    base = state["sessions"].get(session)
                    if base is None:
                        state["sessions"][session] = cur
                    else:
                        for sig in ("model_id", "self_id"):
                            if cur[sig] and base.get(sig) and cur[sig] != base[sig]:
                                record(session, sig, base[sig], cur[sig])
                                base[sig] = cur[sig]
                                alerted = True
            except ValueError:
                pass
        resp = Response(r.content, status=r.status_code,
                        content_type=r.headers.get("content-type"))
        if alerted:
            resp.headers["X-Provenance-Alert"] = "model-switch"
        return resp

    @app.get("/sentinel/events")
    def events_ep():
        with lock:
            return jsonify({"events": list(state["events"])})

    @app.get("/sentinel/status")
    def status_ep():
        with lock:
            return jsonify({"sessions": len(state["sessions"]),
                            "events": len(state["events"]), "upstream": base_url, "ok": True})

    return app


def serve(upstream: str, host: str = "127.0.0.1", port: int = 8900,
          events_file: str | None = None) -> None:
    app = create_app(upstream, events_file=events_file)
    print(f"provenance-probe sentinel  ->  proxying {upstream}  on http://{host}:{port}")
    print("  point your client's base_url at this address; watch /sentinel/events")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("\n  ! Binding to a non-loopback address; this proxy has no auth.\n")
    app.run(host=host, port=port, threaded=True)
