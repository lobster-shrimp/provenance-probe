"""Real-time in-line model-switch sentinel + agent flight recorder (Phase 2/3).

An OpenAI-compatible reverse proxy. The agent under test points its `base_url` at
this proxy; every model call is forwarded to the real upstream and watched. Two
jobs:

  1. SWITCH ALARM (P3): watch each response for a mid-session identity change
     (echoed model id / self-ID persona / header shape) → record a model-change
     event + an `X-Provenance-Alert` header (JSON responses only; for streamed
     responses the headers are already flushed, so the alert lands in
     /sentinel/events).
  2. AGENT FLIGHT RECORDER (Phase 2): accumulate each call as an `AgentStep`
     per session; `/agent/report?session=…` runs `agent.analyze` over the
     collected steps and returns the per-step board.

    agent ──► sentinel ──stream=True──► upstream
                 │ tee: forward each chunk to the agent FIRST (fail-open),
                 │      accumulate the SSE delta in parallel (guarded, capped)
                 ▼ on complete: passive identity (model/self-id/headers) → session store
             /sentinel/events   /sentinel/status   /agent/report

Honesty: this proxy is PASSIVE — it fingerprints the traffic that already flows,
it does NOT inject probes. It therefore cannot produce a tokenizer fingerprint
(`monitor.fingerprint`); it emits a response-IDENTITY (model id / self-ID /
header shape) for SWITCH detection only. CONFIRMED provenance still needs the
active backend probe. Session key = the `X-Provenance-Session` request header
(required for reliable per-step ordering; without it all calls collapse to
"default" and concurrent calls are flagged `unordered`, which withholds switch
claims).
"""
from __future__ import annotations
import hashlib
import json
import threading
import time

from .agent import AgentStep
from .client import parse_sse_delta
from .probes import transcript as _tx

# Response headers too volatile to fingerprint (change every request).
_VOLATILE = {"date", "x-request-id", "cf-ray", "x-amzn-requestid", "request-id",
             "openai-processing-ms", "set-cookie", "x-envoy-upstream-service-time",
             "content-length"}
# Hop-by-hop headers must NOT be forwarded (RFC 7230 §6.1) — everything else is
# end-to-end evidence the agent should see unchanged.
_HOP_BY_HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization",
               "te", "trailers", "transfer-encoding", "upgrade", "content-encoding",
               "content-length"}

MAX_SESSION_STEPS = 1000          # per-session step cap
MAX_ACCUM = 256 * 1024           # per-call accumulation cap (fingerprint needs the head)
MAX_GLOBAL_ACCUM = 16 * 1024 * 1024   # global in-flight accumulation ceiling
MAX_LINE = 64 * 1024             # a single SSE line can't buffer past this (runaway guard)
MAX_SESSIONS = 4096              # cap distinct sessions (evict oldest idle)
MAX_EVENTS = 10000               # cap the retained event log
SESSION_TTL = 3600               # evict idle sessions after 1h


def _header_shape(headers) -> str:
    names = sorted(k.lower() for k in headers.keys() if k.lower() not in _VOLATILE)
    return hashlib.sha256("|".join(names).encode()).hexdigest()[:12]


def _self_id(content: str) -> str | None:
    idy = _tx._turn_identity(content or "")
    return idy.get("conceded") or idy.get("asserted")


def identity(resp_json: dict, content: str, headers) -> dict:
    """The passive identity signals we can read from one live response."""
    return {"model_id": resp_json.get("model"),
            "self_id": _self_id(content),
            "header_shape": _header_shape(headers)}


def _passthrough_headers(up_headers, *, keep_encoding: bool = False) -> list[tuple[str, str]]:
    """Copy end-to-end upstream response headers (drop hop-by-hop). Preserves
    vendor / rate-limit headers — both agent-visible behavior and wire evidence.
    keep_encoding=True keeps `content-encoding` (raw byte passthrough of an
    already-compressed body); the chat path decodes, so it drops it."""
    drop = _HOP_BY_HOP if not keep_encoding else (_HOP_BY_HOP - {"content-encoding"})
    return [(k, v) for k, v in up_headers.items() if k.lower() not in drop]


def _now() -> float:
    return round(time.time(), 3)


def create_app(upstream: str, *, events_file: str | None = None):
    """Flask proxy app. `upstream` is the real endpoint root (…/v1 is appended)."""
    import requests
    from flask import Flask, request, jsonify, Response

    app = Flask(__name__)
    # sessions[key] = {baseline, steps[], last, inflight, accum}
    state = {"sessions": {}, "events": [], "global_accum": 0}
    lock = threading.RLock()   # reentrant: chat() holds it while calling record()
    base_url = upstream.rstrip("/")

    def record(session: str, signal: str, frm, to) -> dict:
        ev = {"session": session, "ts": _now(), "signal": signal, "from": frm, "to": to}
        with lock:
            state["events"].append(ev)
            if len(state["events"]) > MAX_EVENTS:      # bound the retained log
                del state["events"][:len(state["events"]) - MAX_EVENTS]
        if events_file:
            with open(events_file, "a") as f:
                f.write(json.dumps(ev) + "\n")
        print(f"[sentinel] ALERT session={session} {signal}: {frm} -> {to}", flush=True)
        return ev

    def _evict(now: float):
        # never evict a session with an in-flight call (a long stream can outlive
        # the TTL); only idle sessions are removed.
        for k in [k for k, s in state["sessions"].items()
                  if s["inflight"] == 0 and now - s["last"] > SESSION_TTL]:
            del state["sessions"][k]

    def _session(key: str) -> dict:
        s = state["sessions"].get(key)
        if s is None:
            # cap distinct sessions: evict the oldest idle one before adding.
            if len(state["sessions"]) >= MAX_SESSIONS:
                idle = [(v["last"], k) for k, v in state["sessions"].items() if v["inflight"] == 0]
                if idle:
                    del state["sessions"][min(idle)[1]]
            s = {"baseline": None, "steps": [], "last": _now(), "inflight": 0, "parent": None}
            state["sessions"][key] = s
        return s

    def _collect(session: str, model_id, text: str, up_headers, *,
                 unordered: bool, degraded: bool = False, truncated: bool = False) -> bool:
        """Build the passive identity, detect a switch vs baseline, append an
        AgentStep. Returns whether an alert fired. Never raises to the caller."""
        idy = {"model_id": model_id, "self_id": _self_id(text),
               "header_shape": _header_shape(up_headers)}
        alerted = False
        with lock:
            s = _session(session)
            s["last"] = _now()
            base = s["baseline"]
            if base is None:
                s["baseline"] = idy
            else:
                for sig in ("model_id", "self_id"):
                    if not idy[sig]:
                        continue
                    if base.get(sig) is None:
                        base[sig] = idy[sig]           # backfill a never-seen signal (not a switch)
                    elif idy[sig] != base[sig] and not unordered:
                        record(session, sig, base[sig], idy[sig])
                        base[sig] = idy[sig]
                        alerted = True
            if len(s["steps"]) < MAX_SESSION_STEPS:
                idx = len(s["steps"])
                s["steps"].append(AgentStep(
                    index=idx, kind="model", name=f"call#{idx}", echoed_model=model_id,
                    text=text or "", session_id=session, backend_url=base_url,
                    degraded=degraded, unordered=unordered, truncated=truncated))
        return alerted

    def _enter(session: str) -> bool:
        """Mark a call in-flight; return True if it OVERLAPS another call in the
        same session (→ unordered, arrival position unreliable)."""
        with lock:
            _evict(_now())
            s = _session(session)
            s["inflight"] += 1
            s["last"] = _now()               # refresh so a long call isn't evicted
            return s["inflight"] > 1

    def _leave(session: str):
        with lock:
            s = state["sessions"].get(session)
            if s:
                s["inflight"] = max(0, s["inflight"] - 1)

    @app.route("/v1/chat/completions", methods=["POST"])
    def chat():
        body = request.get_data()
        fwd = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length", "connection")}
        fwd["Connection"] = "close"
        session = request.headers.get("X-Provenance-Session", "default")
        parent = request.headers.get("X-Provenance-Parent")   # sub-agent linkage (E6)
        unordered = _enter(session)
        if parent:
            with lock:
                s = _session(session)
                if s["parent"] is None:        # first-writer wins (no silent reparenting)
                    s["parent"] = parent
                _session(parent)               # placeholder so the parent is a reachable root
        try:
            r = requests.post(base_url + "/v1/chat/completions", data=body,
                              headers=fwd, timeout=120, stream=True)
        except requests.RequestException as e:
            _leave(session)
            return jsonify({"error": {"message": f"sentinel upstream error: {e}"}}), 502

        ctype = r.headers.get("content-type", "")
        passthrough = _passthrough_headers(r.headers)

        if "text/event-stream" in ctype:
            # STREAMED: tee — forward each chunk to the agent FIRST (fail-open),
            # accumulate the delta in parallel. Headers are flushed before the
            # body, so a switch alert for a streamed call lands in /sentinel/events.
            def tee():
                buf = b""
                acc, acc_bytes, model = [], 0, None
                truncated = degraded = False
                try:
                    for chunk in r.iter_content(chunk_size=1024):
                        if not chunk:
                            continue
                        yield chunk                       # forward exact bytes FIRST
                        try:                              # accumulation NEVER breaks the yield
                            buf += chunk
                            # runaway-line guard: a line that never terminates can't
                            # buffer past MAX_LINE (bypasses the accumulation cap).
                            if b"\n" not in buf and len(buf) > MAX_LINE:
                                buf = b""
                                truncated = True
                            while b"\n" in buf:
                                line, buf = buf.split(b"\n", 1)
                                s = line.decode("utf-8", "replace").strip()
                                if not s:
                                    continue
                                if model is None and s.startswith("data:"):
                                    p = s[5:].strip()
                                    if p and p != "[DONE]":
                                        try:
                                            model = json.loads(p).get("model")
                                        except Exception:
                                            pass
                                piece = parse_sse_delta(s)
                                if not piece:
                                    continue
                                # atomic: check the per-call + global ceiling AND
                                # reserve the bytes under one lock (no TOCTOU race).
                                with lock:
                                    if (acc_bytes >= MAX_ACCUM
                                            or state["global_accum"] + len(piece) > MAX_GLOBAL_ACCUM):
                                        truncated = True
                                    else:
                                        state["global_accum"] += len(piece)
                                        acc.append(piece)
                                        acc_bytes += len(piece)
                        except Exception:
                            degraded = True                # fail-open: keep streaming
                finally:
                    with lock:
                        state["global_accum"] = max(0, state["global_accum"] - acc_bytes)
                    try:
                        _collect(session, model, "".join(acc), r.headers,
                                 unordered=unordered, degraded=degraded, truncated=truncated)
                    except Exception:
                        pass
                    _leave(session)
                    r.close()                              # release the upstream socket

            resp = Response(tee(), status=r.status_code, content_type=ctype)
            for k, v in passthrough:
                resp.headers[k] = v
            return resp

        # NON-STREAMED JSON: buffer, fingerprint, forward (keeps the P3 alarm's
        # X-Provenance-Alert header working since headers aren't flushed yet).
        content = r.content
        alerted = False
        try:
            j = r.json()
            text = ((j.get("choices") or [{}])[0].get("message") or {}).get("content", "")
            alerted = _collect(session, j.get("model"), text, r.headers, unordered=unordered)
        except ValueError:
            pass
        finally:
            _leave(session)
            r.close()
        resp = Response(content, status=r.status_code, content_type=ctype)
        for k, v in passthrough:
            resp.headers[k] = v
        if alerted:
            resp.headers["X-Provenance-Alert"] = "model-switch"
        return resp

    @app.route("/<path:path>",
               methods=["GET", "POST", "PUT", "DELETE", "PATCH", "HEAD", "OPTIONS"])
    def passthrough(path):
        """Generic transparent passthrough so the proxy is a real base_url
        interposition point — /v1/models, /v1/responses, embeddings, etc. reach
        upstream unchanged. Provenance is only collected on chat/completions.
        Forwards raw bytes and preserves content-encoding (no decode)."""
        fwd = {k: v for k, v in request.headers.items()
               if k.lower() not in ("host", "content-length", "connection")}
        fwd["Connection"] = "close"
        try:
            r = requests.request(request.method, f"{base_url}/{path}", data=request.get_data(),
                                 headers=fwd, params=request.args, timeout=120, stream=True)
        except requests.RequestException as e:
            return jsonify({"error": {"message": f"sentinel upstream error: {e}"}}), 502

        def gen():
            try:
                for chunk in r.iter_content(chunk_size=8192):
                    if chunk:
                        yield chunk
            finally:
                r.close()

        resp = Response(gen(), status=r.status_code,
                        content_type=r.headers.get("content-type"))
        for k, v in _passthrough_headers(r.headers, keep_encoding=True):
            resp.headers[k] = v
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

    @app.get("/agent/report")
    def agent_report_ep():
        """Run the agent analysis over one session's collected steps."""
        from . import agent
        session = request.args.get("session", "default")
        with lock:
            s = state["sessions"].get(session)
            steps = list(s["steps"]) if s else []
        if not steps:
            return jsonify({"error": f"no collected steps for session '{session}'"}), 404
        result = agent.analyze(steps)
        return jsonify({"session": session,
                        "steps": [{k: v for k, v in r.items() if k != "score"} for r in result["steps"]],
                        "verdict": result["verdict"]})

    @app.get("/agent/graph")
    def agent_graph_ep():
        """Sub-agent call graph (E6): the tree of sessions linked by
        X-Provenance-Parent, rooted at `session`. Each node is that agent's board."""
        from . import agent
        root = request.args.get("session", "default")
        with lock:
            children = {}
            snap = {}
            for key, s in state["sessions"].items():
                snap[key] = list(s["steps"])
                children.setdefault(s.get("parent"), []).append(key)
        if root not in snap:
            return jsonify({"error": f"no session '{root}'"}), 404

        # Build the tree ITERATIVELY with a depth cap (deep session chains must not
        # blow the stack or JSON recursion), cycle-guarded.
        MAX_GRAPH_DEPTH = 256

        def make(key):
            steps = snap.get(key, [])
            return {"session": key,
                    "verdict": agent.analyze(steps)["verdict"] if steps else None,
                    "children": []}

        seen = {root}
        root_node = make(root)
        stack = [(root_node, 0)]
        while stack:
            parent_node, depth = stack.pop()
            if depth >= MAX_GRAPH_DEPTH:
                parent_node["truncated"] = True
                continue
            for c in sorted(children.get(parent_node["session"], [])):
                if c in seen:                    # cycle guard
                    parent_node["children"].append({"session": c, "cycle": True})
                    continue
                seen.add(c)
                child_node = make(c)
                parent_node["children"].append(child_node)
                stack.append((child_node, depth + 1))
        return jsonify({"root": root, "graph": root_node})

    return app


def serve(upstream: str, host: str = "127.0.0.1", port: int = 8900,
          events_file: str | None = None) -> None:
    app = create_app(upstream, events_file=events_file)
    print(f"provenance-probe sentinel  ->  proxying {upstream}  on http://{host}:{port}")
    print("  point your client's base_url at this address; watch /sentinel/events")
    print("  agent board: /agent/report?session=<your X-Provenance-Session>")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("\n  ! Binding to a non-loopback address; this proxy has no auth.\n")
    app.run(host=host, port=port, threaded=True)
