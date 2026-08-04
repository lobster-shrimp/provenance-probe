# -*- coding: utf-8 -*-
"""Local web service for provenance-probe.

Binds to 127.0.0.1 by default. Nothing is sent anywhere except to the endpoint
you explicitly ask it to assess. Run history is stored on local disk only.

    provenance-probe serve            # http://127.0.0.1:8770
"""
from __future__ import annotations
import hmac, json, os, threading, datetime, uuid, traceback, html

from flask import Flask, request, jsonify, Response

from .config import Target
from .client import Client
from .probes import network, tokenizer, behavioral, wire, latency, logprob, artifact, clientsrc, deception
from . import scoring, report, userwarn, monitor, egress

RUNS: dict[str, dict] = {}
DATA_DIR = os.path.expanduser(os.environ.get("PROVENANCE_PROBE_HOME", "~/.provenance-probe"))
app = Flask(__name__)


# --------------------------------------------------------------- auth gate ---
# Public-hosting mode only (env-gated, OFF by default). When
# PROVENANCE_PROBE_BASIC_AUTH="user:pass" is set, EVERY route requires HTTP
# Basic auth. Parsed once at import so a malformed value fails loudly at startup
# rather than silently leaving the instance open. Unset -> no gate (local
# single-user behavior is unchanged).
_BASIC_AUTH_ENV = "PROVENANCE_PROBE_BASIC_AUTH"


def _parse_basic_auth(raw: str | None) -> tuple[str, str] | None:
    if not raw:
        return None
    if ":" not in raw:
        raise RuntimeError(
            f"{_BASIC_AUTH_ENV} must be 'user:pass' (missing ':'); refusing to "
            "start with a malformed value that would silently disable auth.")
    user, _, password = raw.partition(":")   # password may itself contain ':'
    return user, password


_BASIC_AUTH = _parse_basic_auth(os.environ.get(_BASIC_AUTH_ENV))


def _auth_challenge() -> Response:
    resp = Response("Authentication required.\n", status=401, mimetype="text/plain")
    resp.headers["WWW-Authenticate"] = 'Basic realm="provenance-probe"'
    return resp


@app.before_request
def _require_basic_auth():
    """Gate ALL routes (no allowlist) before any route logic runs. A 401 is still
    a valid HTTP response, so a liveness probe sees the port answering."""
    if _BASIC_AUTH is None:
        return None
    auth = request.authorization
    if auth is None or (auth.type or "").lower() != "basic":
        return _auth_challenge()
    want_user, want_pass = _BASIC_AUTH
    # Constant-time compares; no boolean short-circuit, so a wrong username and a
    # wrong password take the same path.
    ok_user = hmac.compare_digest((auth.username or "").encode("utf-8"),
                                  want_user.encode("utf-8"))
    ok_pass = hmac.compare_digest((auth.password or "").encode("utf-8"),
                                  want_pass.encode("utf-8"))
    if not (ok_user and ok_pass):
        return _auth_challenge()
    return None


# ------------------------------------------------------------------ engine ---
def _hard_evidence(b):
    src = b.get("client_source") or {}
    if src.get("prc_operators_in_source"):
        return "CN", f"Client source references {', '.join(src['prc_operators_in_source'])}."
    net = b.get("network") or {}
    if (net.get("jurisdiction") or "").startswith("PRC"):
        return "CN", f"Endpoint resolves to {net.get('operator')} ({net.get('jurisdiction')})."
    tm = b.get("tokenizer_match") or []
    if tm and tm[0].get("score", 0) >= 0.75:
        return ("CN" if tm[0].get("origin") == "CN" else "nonCN",
                f"Tokenizer fingerprint matches {tm[0]['model']} (score {tm[0]['score']}).")
    if (b.get("catalog") or {}).get("prc_origin_models"):
        return "CN", "Endpoint catalog offers PRC-origin models."
    return None, ""


def _run(run_id: str, spec: dict):
    st = RUNS[run_id]
    def step(msg, pct):
        st["status"] = msg
        st["progress"] = pct

    try:
        rt = spec.get("request_template") or ""
        if isinstance(rt, str) and rt.strip():
            try:
                rt = json.loads(rt)
            except Exception as e:
                raise ValueError(f"Request template is not valid JSON: {e}")
        elif not isinstance(rt, dict):
            rt = {}
        t = Target(
            name=spec.get("name") or "target",
            base_url=spec["base_url"],
            model=spec.get("model", ""),
            api_style=spec.get("api_style", "openai"),
            chat_path=spec.get("chat_path") or "/chat/completions",
            models_path=spec.get("models_path") or "/models",
            proxy=spec.get("proxy", ""),
            verify_tls=bool(spec.get("verify_tls", True)),
            cookie=spec.get("cookie", ""),
            request_template=rt,
            response_text_path=spec.get("response_text_path", ""),
            response_prompt_tokens_path=spec.get("response_prompt_tokens_path", ""),
            response_model_path=spec.get("response_model_path", ""),
            stream_mode=spec.get("stream_mode", "none"),
            stream_delta_path=spec.get("stream_delta_path", ""),
            authorized=True,
        )
        if spec.get("api_key"):
            # respect the target's auth scheme (anthropic -> x-api-key, no Bearer),
            # not a hardcoded Authorization: Bearer.
            t.extra_headers[t.auth_header] = f"{t.auth_prefix}{spec['api_key']}"

        c = Client(t)
        b = {"target": {"name": t.name, "base_url": t.base_url, "model": t.model,
                        "api_style": t.api_style},
             "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}

        step("Resolving endpoint and jurisdiction…", 8)
        b["network"] = network.analyze_host(t.base_url, do_rdap=not spec.get("offline"))

        step("Fingerprinting API surface…", 20)
        b["headers"] = wire.header_fingerprint(c)
        b["errors"] = wire.error_schema_fingerprint(c)
        b["streaming"] = wire.streaming_fingerprint(c)
        b["catalog"] = wire.model_catalog(c)

        if spec.get("client_url"):
            step("Scanning client source…", 30)
            # Reuse the probe Client's session so this user-supplied URL fetch
            # goes through the SSRF egress guard in public-hosting mode.
            b["client_source"] = clientsrc.scan_url(spec["client_url"], session=c.s)
        elif spec.get("client_dir"):
            step("Scanning client source…", 30)
            b["client_source"] = clientsrc.scan_dir(spec["client_dir"])

        if not spec.get("no_tokenizer"):
            step("Running tokenizer battery…", 45)
            b["tokenizer"] = tokenizer.measure(c)
            if b["tokenizer"]["usable"]:
                b["tokenizer_match"] = tokenizer.compare(b["tokenizer"])

        step("Checking determinism…", 58)
        b["logprobs"] = logprob.logprob_signature(c)
        b["greedy"] = logprob.greedy_signature(c)

        if not spec.get("no_deception"):
            step("Testing persona and jurisdiction claims…", 70)
            d = {"persona": deception.persona_claim(c),
                 "jurisdiction": deception.jurisdiction_claims(c),
                 "trace": deception.reasoning_trace_capture(c)}
            if spec.get("confront_as"):
                step("Paired confrontation with false-premise control…", 80)
                d["confrontation"] = deception.confront(
                    c, spec["confront_as"], spec.get("confront_control") or "Mistral AI")
            if spec.get("session_test"):
                d["session"] = deception.session_resilience(c)
            b["deception"] = d

        if not spec.get("no_behavioral"):
            step("Alignment asymmetry (matched pairs)…", 88)
            b["selfid"] = behavioral.self_identification(c)
            b["alignment"] = behavioral.alignment_asymmetry(c)
            b["leakage"] = behavioral.language_leakage(c, samples=1)

        if spec.get("artifacts_dir"):
            step("Inspecting local model artifacts…", 93)
            b["artifacts"] = artifact.scan_dir(spec["artifacts_dir"])

        if b.get("deception"):
            origin, detail = _hard_evidence(b)
            b["deception"]["correlation"] = deception.correlate(
                b["deception"]["persona"], b["deception"]["jurisdiction"], origin, detail)

        step("Scoring…", 97)
        b["score"] = scoring.score(b)
        b["user_warning"] = userwarn.build(b)
        # Stable backend fingerprint so this run can be diffed against a
        # baseline in the Monitor tab (silent model-swap detection).
        b["fingerprint_id"] = monitor.fingerprint(b)

        os.makedirs(os.path.join(DATA_DIR, "reports"), exist_ok=True)
        base = os.path.join(DATA_DIR, "reports", f"{t.name}_{run_id[:8]}")
        report.to_json(b, base + ".json")
        report.to_html(b, base + ".html")
        userwarn.to_html(b["user_warning"], base + "_USER-WARNING.html")

        st.update(state="done", progress=100, status="Complete",
                  bundle=b, files={"json": base + ".json", "html": base + ".html",
                                   "warning": base + "_USER-WARNING.html"})
    except Exception as e:
        st.update(state="error", status=str(e), traceback=traceback.format_exc())


# ------------------------------------------------------------------- routes --
@app.post("/api/assess")
def api_assess():
    # Require a JSON content-type. This endpoint triggers outbound network
    # activity, so in public-hosting mode it must not be drivable by a
    # cross-origin HTML form (which cannot set application/json without a CORS
    # preflight that this app never answers) — closes the JSON-CSRF vector while
    # the same-origin fetch() UI (which sends application/json) still works.
    if not request.is_json:
        return jsonify({"error": "Content-Type: application/json required"}), 415
    spec = request.get_json(silent=True) or {}
    if not spec.get("base_url"):
        return jsonify({"error": "base_url required"}), 400
    if not spec.get("authorized"):
        return jsonify({"error": "You must confirm you are authorized to test this endpoint."}), 403
    rid = uuid.uuid4().hex
    RUNS[rid] = {"state": "running", "progress": 0, "status": "Starting…",
                 "target": spec.get("base_url")}
    threading.Thread(target=_run, args=(rid, spec), daemon=True).start()
    return jsonify({"run_id": rid})


@app.get("/api/run/<rid>")
def api_run(rid):
    st = RUNS.get(rid)
    if not st:
        return jsonify({"error": "unknown run"}), 404
    out = {k: v for k, v in st.items() if k not in ("bundle",)}
    if st.get("state") == "done":
        b = st["bundle"]
        out["user_warning"] = b["user_warning"]
        out["score"] = b["score"]
        out["deception"] = (b.get("deception") or {}).get("correlation")
        out["confrontation"] = (b.get("deception") or {}).get("confrontation")
        out["tokenizer_match"] = (b.get("tokenizer_match") or [])[:5]
    return jsonify(out)


@app.get("/api/history")
def api_history():
    d = os.path.join(DATA_DIR, "reports")
    if not os.path.isdir(d):
        return jsonify([])
    rows = []
    for f in sorted(os.listdir(d), reverse=True):
        if f.endswith(".json"):
            try:
                b = json.load(open(os.path.join(d, f)))
                rows.append({"file": f, "name": b["target"]["name"],
                             "url": b["target"]["base_url"], "ts": b["timestamp"],
                             "fingerprint_id": b.get("fingerprint_id", ""),
                             "level": b.get("user_warning", {}).get("level"),
                             "headline": b.get("user_warning", {}).get("headline")})
            except Exception:
                pass
    return jsonify(rows[:50])


@app.post("/api/monitor")
def api_monitor():
    """Diff two stored runs (baseline vs current) for silent model-swap detection.

    Reuses the same monitor.diff() the CLI and observatory runner use, so the
    UI verdict cannot drift from the CLI verdict.
    """
    spec = request.get_json(force=True) or {}
    d = os.path.join(DATA_DIR, "reports")
    try:
        base = json.load(open(os.path.join(d, os.path.basename(spec["baseline"]))))
        cur = json.load(open(os.path.join(d, os.path.basename(spec["current"]))))
    except (KeyError, FileNotFoundError):
        return jsonify({"error": "pick a baseline and a current run"}), 400
    result = monitor.diff(base, cur)
    return jsonify({
        "drift_detected": result["drift_detected"],
        "changes": result["changes"],
        "confidence": result["confidence"],
        "confidence_note": result.get("confidence_note", ""),
        "baseline": {"fingerprint_id": base.get("fingerprint_id", ""), "ts": base.get("timestamp")},
        "current": {"fingerprint_id": cur.get("fingerprint_id", ""), "ts": cur.get("timestamp")},
    })


@app.get("/report/<path:name>")
def report_file(name):
    p = os.path.join(DATA_DIR, "reports", os.path.basename(name))
    if not os.path.exists(p):
        return "not found", 404
    if p.endswith(".json"):
        return Response(open(p).read(), mimetype="application/json")
    return Response(open(p).read(), mimetype="text/html")


@app.get("/")
def index():
    obs_url = os.environ.get("PROVENANCE_OBSERVATORY_URL", "http://127.0.0.1:8080")
    return Response(PAGE.replace("__OBSERVATORY_URL__", html.escape(obs_url)), mimetype="text/html")


_AGENT_FORM = """<!doctype html><meta charset=utf-8><title>Agent board · provenance-probe</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>body{{font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;color:#16181d;
background:#f6f7f8;margin:0;padding:26px}}.w{{max-width:940px;margin:0 auto}}
h1{{font-size:21px;margin:0 0 2px}}.sub{{color:#6b7280;font-size:13px;margin-bottom:18px}}
.card{{background:#fff;border:1px solid #e3e5e9;border-radius:11px;padding:20px 22px}}
textarea{{width:100%;min-height:230px;font:13px ui-monospace,monospace;border:1px solid #e3e5e9;
border-radius:8px;padding:11px}}button{{background:#1f4f8b;color:#fff;border:0;border-radius:8px;
padding:11px 20px;font-size:14px;font-weight:600;cursor:pointer;margin-top:10px}}
.chk{{font-size:13px;color:#3d424b;margin:10px 0}}.err{{color:#8b1a1a;font-weight:600;margin:8px 0}}
.topnav{{font-size:11px;letter-spacing:.07em;text-transform:uppercase;margin-bottom:16px}}
.topnav a{{color:#1f4f8b;text-decoration:none;margin-right:14px}}
.eg{{font-size:12px;color:#6b7280}}</style>
<div class=w>
<div class=topnav><a href="/">&larr; Live probe tool</a></div>
<h1>Agent provenance board</h1>
<p class=sub>Paste a captured agent run &mdash; OpenTelemetry GenAI spans, or the minimal
JSON form &mdash; and see per-step model, switch, and egress with hover explanations.</p>
<div class=card>
<form method=post action="/agent">
<label style="font-size:11px;text-transform:uppercase;color:#6b7280;font-weight:650">Agent trace (JSON)</label>
<textarea name=trace placeholder='{{"steps":[{{"model":"gpt-4o","text":"...","backend_url":"https://api.openai.com/v1"}},{{"kind":"tool","tool_host":"data.example.cn"}}]}}'>{trace}</textarea>
<div class=chk><label><input type=checkbox name=resolve {resolve}> Resolve hosts via DNS/RDAP
(off by default &mdash; a pasted trace is untrusted; static hostname signals still fire)</label></div>
{err}
<button type=submit>Analyze agent run</button>
</form></div>
<p class=eg>Tip: from the CLI, <code>provenance-probe agent-trace run.json --html out.html</code> writes the same report.</p>
</div>"""


@app.route("/agent", methods=["GET", "POST"])
def agent_board():
    from . import agent, agent_report
    if request.method == "GET":
        return Response(_AGENT_FORM.format(trace="", resolve="", err=""), mimetype="text/html")
    raw = request.form.get("trace", "")
    resolve = bool(request.form.get("resolve"))
    try:
        steps = agent.parse_trace(raw)
        result = agent.analyze(steps, resolve_hosts=resolve)
    except agent.TraceError as e:
        return Response(_AGENT_FORM.format(
            trace=html.escape(raw), resolve="checked" if resolve else "",
            err=f'<div class="err">Could not parse trace: {html.escape(str(e))}</div>'),
            mimetype="text/html")
    return Response(agent_report.render_html(result, "pasted trace")
                    .replace("</h1>", "</h1><p class='sub'><a href=\"/agent\">&larr; analyze another</a> · "
                                      "<a href=\"/\">live probe tool</a></p>"),
                    mimetype="text/html")


_WIZARD_FORM = """<!doctype html><meta charset=utf-8><title>Add a target · provenance-probe</title>
<style>body{{font:15px system-ui;margin:2rem auto;max-width:760px;color:#16181d}}
textarea{{width:100%;font:12px ui-monospace;min-height:120px}}input{{font:14px system-ui;padding:5px}}
.err{{background:#fdecec;border:1px solid #f5b5b5;padding:.6rem;border-radius:6px}}
.warn{{background:#fff7e6;border:1px solid #ffd591;padding:.5rem;border-radius:6px;margin:.3rem 0}}
label{{display:block;margin:.7rem 0 .2rem;font-weight:600}}.sub{{color:#6b7280}}
.hint{{color:#6b7280;font-size:13px;margin:.2rem 0 0}}</style>
<h1>Add a target</h1>
<p class=sub>One box. Paste whatever you have &mdash; we figure out the rest.
No need to know the API type. Local only; nothing is sent until you approve.
<a href="/">&larr; probe tool</a></p>
{err}
<form method=post action="/wizard">
<label>Target name</label><input name=name value="{name}" placeholder="my-service" required>
<label>Paste an AI service address, a <code>curl</code> command, or a saved HAR</label>
<textarea name=capture required placeholder="https://api.vendor.com/v1
  &mdash; or &mdash;
curl 'https://chat.app.com/api/chat' -H 'cookie: ...' --data '...'">{capture}</textarea>
<p class=hint>A plain address (URL) is identified with a short, consented test.
A <code>curl</code>/HAR capture is for logged-in web apps &mdash;
<a href="/wizard/capture">never captured one? see the step-by-step guide</a>.</p>
<label>If you pasted a capture: the exact message text you sent <span class=sub>(optional for a plain URL)</span></label>
<input name=prompt value="{prompt}" style="width:100%" placeholder="fingerprint me">
<p><button type=submit>Continue &rarr;</button></p></form>"""

_WIZARD_CONSENT = """<!doctype html><meta charset=utf-8><title>Confirm test · provenance-probe</title>
<style>body{{font:15px system-ui;margin:2rem auto;max-width:680px;color:#16181d}}
.box{{background:#f4f7fb;border:1px solid #cdd9ec;padding:1rem 1.2rem;border-radius:8px}}
.sub{{color:#6b7280}}code{{background:#eef;padding:1px 4px;border-radius:3px}}
button{{font:15px system-ui;padding:.5rem 1rem;margin-right:.5rem}}
label{{display:block;margin:.6rem 0}}</style>
<h1>Send a short identify test?</h1>
<div class=box>
<p>To identify <b>{host}</b> I'll send <b>a few short requests</b> (usually 2&ndash;4)
that ask for a single token. A full provenance check afterwards is
<b>~28 requests total</b>.</p>
<p class=sub>Only test services you are authorized to test. Nothing has been sent yet.
{keynote}</p>
</div>
<form method=post action="/wizard/detect">
<input type=hidden name=token value="{token}">
<label><input type=checkbox name=passive_only value=1> Passive only &mdash; just check reachability
(<code>GET /models</code>), send no inference.</label>
<p><button type=submit name=go value=1>Send test &rarr;</button>
<a href="/wizard"><button type=button>Cancel</button></a></p></form>"""

_WIZARD_PREVIEW = """<!doctype html><meta charset=utf-8><title>Confirm target · provenance-probe</title>
<style>body{{font:15px system-ui;margin:2rem auto;max-width:760px;color:#16181d}}
textarea{{width:100%;font:12px ui-monospace;min-height:220px}}
.warn{{background:#fff7e6;border:1px solid #ffd591;padding:.5rem;border-radius:6px;margin:.3rem 0}}
.ok{{background:#eaf7ec;border:1px solid #a3d9a5;padding:.6rem;border-radius:6px}}</style>
<h1>Confirm &amp; save</h1>
<p class=sub>Review the synthesized target. Every field is a best-effort guess &mdash; edit before saving.
Then Save runs a 2-probe dry-run (replay-safety + usage check) and writes the config; the cookie
goes to <code>.env.capture</code> (gitignored). <a href="/wizard">&larr; start over</a></p>
{warnings}
<form method=post action="/wizard/save">
<input type=hidden name=token value="{token}">
<label>Synthesized target (editable JSON)</label>
<textarea name=target>{target_json}</textarea>
<p>{autodetect}<button type=submit>Dry-run &amp; save</button></p></form>"""

# Server-side stash so the captured request (which holds the session COOKIE) is
# NEVER reflected back into the browser between preview and save (Codex). Keyed
# by a one-shot token; single-process local Flask, so an in-memory dict is fine.
_WIZARD_PENDING: dict = {}
# One-shot consent tokens issued by the /wizard endpoint branch. /wizard/detect
# refuses (zero egress) without a valid token, so the consent gate can't be
# bypassed by a direct/CSRF POST, and the endpoint under test comes from here
# (server-side), not a tamperable form field (Codex adversarial, CRITICAL).
_CONSENT_PENDING: dict = {}


def _wiz_warnings(ws):
    return "".join(f'<div class="warn">&#9888; {html.escape(w)}</div>' for w in ws)


def _wiz_page(title, inner):
    return Response(
        f'<!doctype html><meta charset=utf-8><title>{title}</title>'
        '<style>body{font:15px system-ui;margin:2rem auto;max-width:680px;color:#16181d}'
        '.err{background:#fdecec;border:1px solid #f5b5b5;padding:.6rem;border-radius:6px}'
        '.ok{background:#eaf7ec;border:1px solid #a3d9a5;padding:.6rem;border-radius:6px}'
        '.warn{background:#fff7e6;border:1px solid #ffd591;padding:.5rem;margin:.3rem 0}</style>'
        + inner, mimetype="text/html")


def _wiz_form(err="", name="", prompt="", capture=""):
    body = _WIZARD_FORM.format(
        err=f'<div class="err">{html.escape(err)}</div>' if err else "",
        name=html.escape(name), prompt=html.escape(prompt),
        capture=html.escape(capture))
    return Response(body + _capture_ui(), mimetype="text/html")


# Server-side capture runs (the "Capture for me" proxy flow). Each holds the
# two-phase Events and, on success, the synthesized result INCLUDING the session
# cookie — kept server-side only, never reflected to the browser, one-shot.
_CAPTURE_RUNS: dict = {}
# Bound how long a worker blocks waiting for the operator to click Continue, so an
# abandoned run (closed tab) can't leak a thread + browser forever (review #44).
_CAPTURE_WAIT_TIMEOUT = 600


def _same_origin_ok(req) -> bool:
    """CSRF guard for the mutating capture endpoints. The wizard's fetch() carries
    an Origin/Referer for the local page; a cross-site page's differs. This
    endpoint drives a real browser to a caller-supplied URL, so a cross-site POST
    must not be able to start one (review #44). A missing Origin+Referer (curl,
    tests, same-origin no-cors) is allowed — the app binds 127.0.0.1 only."""
    from urllib.parse import urlsplit
    ref = req.headers.get("Origin") or req.headers.get("Referer") or ""
    if not ref:
        return True
    return (urlsplit(ref).hostname or "").lower() in ("127.0.0.1", "localhost", "::1")


def _evict_terminal_runs():
    """Drop finished runs when the map grows, NEVER in-flight ones — clearing a
    running entry would strand its worker on a wait() and lose its cookie."""
    if len(_CAPTURE_RUNS) <= 20:
        return
    for k in [k for k, v in _CAPTURE_RUNS.items() if v.get("state") in ("done", "error")]:
        _CAPTURE_RUNS.pop(k, None)

# Raw HTML+JS for the "Capture for me" section, appended to the wizard form. Kept
# out of the .format() template so its many JS braces need no escaping.
_WIZARD_CAPTURE_JS = """
<hr style="margin:1.6rem 0;border:none;border-top:1px solid #e3e5e9">
<h2 style="font-size:16px">…or capture it for me</h2>
<p class=sub>Opens an isolated browser via a local proxy. You log in and send ONE
message; the login is never recorded. Needs the <code>[capture]</code> extra.</p>
<label>AI service URL</label><input id=cap-url style="width:100%" placeholder="https://chat.app.com">
<label>Target name</label><input id=cap-name style="width:100%" placeholder="my-service">
<label>The exact message you'll send <span class=sub>(optional, improves detection)</span></label>
<input id=cap-msg style="width:100%" placeholder="fingerprint me">
<label style="font-weight:400"><input type=checkbox id=cap-auth> I'm authorized to test this service</label>
<p><button type=button id=cap-go>Capture for me &rarr;</button>
<button type=button id=cap-continue style="display:none"></button></p>
<p id=cap-status class=sub></p>
<script>
(function(){
  var btn=document.getElementById('cap-go'), out=document.getElementById('cap-status'),
      cont=document.getElementById('cap-continue'), rid=null;
  function show(s){
    out.textContent = (s.status||'') + (s.error ? (' \\u2014 '+s.error) : '');
    if(s.status==='awaiting_login'){ cont.style.display='inline-block'; cont.textContent='I have logged in \\u2014 Continue'; }
    else if(s.status==='awaiting_send'){ cont.style.display='inline-block'; cont.textContent='I sent one message \\u2014 Continue'; }
    else { cont.style.display='none'; }
  }
  function poll(){
    fetch('/wizard/capture-run/'+rid).then(function(r){
      if(r.status===404){ out.textContent='capture expired \\u2014 start over'; btn.disabled=false; return null; }
      return r.json();
    }).then(function(s){
      if(!s) return;
      show(s);
      if(s.state==='done'){ window.location='/wizard/capture-preview/'+rid; return; }
      if(s.state==='error'){ btn.disabled=false; return; }
      setTimeout(poll, 800);
    }).catch(function(){ setTimeout(poll,1200); });
  }
  btn.onclick=function(){
    var body=new URLSearchParams({url:document.getElementById('cap-url').value,
      name:document.getElementById('cap-name').value, message:document.getElementById('cap-msg').value,
      authorized:document.getElementById('cap-auth').checked?'1':''});
    btn.disabled=true; out.textContent='starting\\u2026';
    fetch('/wizard/capture-run',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},body:body})
      .then(function(r){return r.json();}).then(function(j){
        if(j.error){ out.textContent=j.error; btn.disabled=false; return; }
        rid=j.run_id; poll();
      }).catch(function(){ out.textContent='could not start capture'; btn.disabled=false; });
  };
  cont.onclick=function(){
    cont.style.display='none';
    fetch('/wizard/capture-advance',{method:'POST',headers:{'Content-Type':'application/x-www-form-urlencoded'},
      body:new URLSearchParams({run_id:rid})});
  };
})();
</script>"""


def _capture_ui() -> str:
    """The 'Capture for me' block, or a one-line note if the extra is missing."""
    # The capture flow drives a real browser to a user-named URL, which cannot be
    # IP-pinned like the requests transport. It is out of scope for the public
    # instance (#51), so it is refused entirely in public-hosting mode — don't
    # advertise it either.
    if egress.guard_enabled():
        return ""
    try:
        from . import capture_proxy
        available = capture_proxy.proxy_available()
    except Exception:
        available = False
    if not available:
        return ('<hr style="margin:1.6rem 0;border:none;border-top:1px solid #e3e5e9">'
                '<p class=sub>Automated capture (a local proxy that records the request '
                "for you) is available with the optional extra: "
                "<code>pip install -e '.[capture]' && playwright install chromium</code>.</p>")
    return _WIZARD_CAPTURE_JS


def _capture_worker(rid: str, url: str, name: str, message: str):
    """Drive proxy capture through its two phases, signaled by the browser UI.
    Runs in a daemon thread; capture_proxy.capture is monkeypatchable in tests."""
    from . import capture_proxy, wizard
    run = _CAPTURE_RUNS[rid]

    def login_wait():
        run["status"] = "awaiting_login"
        if not run["login_evt"].wait(timeout=_CAPTURE_WAIT_TIMEOUT):
            raise TimeoutError("timed out waiting for you to log in and click Continue")

    def send_wait():
        run["status"] = "awaiting_send"
        if not run["send_evt"].wait(timeout=_CAPTURE_WAIT_TIMEOUT):
            raise TimeoutError("timed out waiting for you to send a message and click Continue")

    try:
        res = capture_proxy.capture(url, prompt_hint=message,
                                    login_wait=login_wait, send_wait=send_wait)
        if not res.ok:
            run.update(state="error", status="error", error=res.error)
            return
        run["status"] = "synthesizing"
        syn = wizard.synthesize(res.captured, message, name or "target")
        run.update(state="done", status="done",
                   target=syn.target, cookie=syn.cookie_value,
                   warnings=syn.warnings, prompt=message)
    except Exception as e:                              # never leave the run hanging
        run.update(state="error", status="error",
                   error=f"capture failed: {capture_proxy._redact(str(e))}")


def _effective_host(target: dict) -> str | None:
    """The host the request will ACTUALLY hit — parsed from base_url + chat_path
    together (chat_path is separately editable and can smuggle a host, e.g.
    base_url=good.host + chat_path=@evil.com/…). Returns None if there is no real
    hostname or any userinfo (`@`) is present — both must refuse a cookie replay
    (Claude adversarial, CRITICAL)."""
    from urllib.parse import urlsplit
    base = (target.get("base_url") or "").rstrip("/")
    path = target.get("chat_path") or ""
    u = urlsplit(base + path)
    if "@" in (u.netloc or ""):
        return None
    return (u.hostname or "").lower() or None


def _cookie_origin_ok(pending: dict, target: dict) -> tuple[bool, str]:
    """A stashed cookie may only be sent to the host it was captured from. Refuse
    when the effective host is missing/ambiguous or differs. Applies to every
    cookie-bearing egress (replay AND dry-run-on-save)."""
    if not pending.get("cookie"):
        return True, ""                      # no cookie -> nothing to protect
    captured = pending.get("origin")
    eff = _effective_host(target)
    if eff is None:
        return False, ("the target's effective host is missing or ambiguous (no scheme, or a "
                       "'@' in the URL). The session cookie is only sent to a clear host — "
                       "use an https:// base_url with no userinfo.")
    if eff != captured:
        return False, (f"the request would hit '{eff}' but the captured cookie belongs to "
                       f"'{captured or '—'}'. The session cookie is only replayed to the host "
                       f"it was captured from. Revert base_url/chat_path, or re-capture.")
    return True, ""


def _wiz_preview(target: dict, cookie: str, warnings: list, prompt: str = "") -> Response:
    """Stash the credential server-side, hand the browser a token + editable JSON.

    The editable target carries NO cookie (cookie_env only) and NO key value
    (auth_value_env name only), so nothing sensitive is reflected to the page.
    `prompt` is stashed so the "auto-detect response fields" replay can locate the
    reply in the live response.
    """
    token = uuid.uuid4().hex
    if len(_WIZARD_PENDING) > 20:            # bound the stash
        _WIZARD_PENDING.clear()
    # Bind the stash to the CAPTURED effective host (base_url + chat_path) so the
    # session cookie can never be replayed to an edited/arbitrary host — including
    # via a smuggled chat_path (Codex + Claude adversarial, CRITICAL).
    _WIZARD_PENDING[token] = {"cookie": cookie, "prompt": prompt,
                             "origin": _effective_host(target)}
    # Offer the one-request auto-detect when the response paths aren't known yet
    # (the cURL-paste case) and it's a web-app template target. Same form as save
    # (so the operator's edits are included) via HTML5 formaction — no JS.
    autodetect = ""
    if target.get("api_style") == "template" and not target.get("response_text_path"):
        autodetect = (
            '<button type=submit formaction="/wizard/probe-response" '
            'title="replays your captured request to the same host and reads the reply / usage / '
            'model paths off the real response, so you don\'t hand-type them">'
            '&#128269; Auto-detect response fields (sends a live request)</button> ')
    return Response(_WIZARD_PREVIEW.format(
        warnings=_wiz_warnings(warnings), token=token, autodetect=autodetect,
        target_json=html.escape(json.dumps(target, indent=2))), mimetype="text/html")


@app.post("/wizard/capture-run")
def wizard_capture_run():
    """Start a proxy capture in the background. Returns {run_id}. The heavy work
    (browser + proxy) needs the [capture] extra; capture_proxy reports absence."""
    # SSRF: the capture flow navigates a real browser to a caller-supplied URL and
    # cannot be IP-pinned like the requests transport, so it is refused entirely in
    # public-hosting mode (out of scope for the public instance, #51). _same_origin_ok
    # is NOT a reliable control here — a non-browser client sends no Origin/Referer.
    if egress.guard_enabled():
        return jsonify({"error": "Browser capture is disabled in public-hosting mode "
                                 "(PROVENANCE_PROBE_BLOCK_PRIVATE). Run provenance-probe "
                                 "locally to use the capture flow."}), 403
    if not _same_origin_ok(request):
        return jsonify({"error": "cross-site request refused"}), 403
    url = (request.form.get("url") or "").strip()
    if not url:
        return jsonify({"error": "Enter the AI service URL to capture from."}), 400
    from urllib.parse import urlsplit
    scheme = urlsplit(url if "://" in url else "https://" + url).scheme.lower()
    if scheme not in ("http", "https"):
        return jsonify({"error": "URL must be http(s)."}), 400
    if request.form.get("authorized") != "1":
        return jsonify({"error": "Confirm you are authorized to test this service."}), 403
    _evict_terminal_runs()                             # never drops an in-flight run
    rid = uuid.uuid4().hex
    _CAPTURE_RUNS[rid] = {"state": "running", "status": "starting", "error": "",
                          "login_evt": threading.Event(), "send_evt": threading.Event()}
    threading.Thread(target=_capture_worker, daemon=True,
                     args=(rid, url, request.form.get("name", "").strip(),
                           request.form.get("message", ""))).start()
    return jsonify({"run_id": rid})


@app.post("/wizard/capture-advance")
def wizard_capture_advance():
    """The browser 'Continue' button: release whichever phase the capture waits on.
    Keys off the CURRENT status, so a duplicate/late click can't pre-release the
    next phase (it only sets the event for the phase actually being awaited)."""
    if egress.guard_enabled():                          # capture disabled publicly (#51)
        return jsonify({"error": "Browser capture is disabled in public-hosting mode."}), 403
    if not _same_origin_ok(request):
        return jsonify({"error": "cross-site request refused"}), 403
    run = _CAPTURE_RUNS.get(request.form.get("run_id", ""))
    if run is None:
        return jsonify({"error": "unknown run"}), 404
    if run.get("status") == "awaiting_login":
        run["login_evt"].set()
    elif run.get("status") == "awaiting_send":
        run["send_evt"].set()
    return jsonify({"ok": True})


@app.get("/wizard/capture-run/<rid>")
def wizard_capture_status(rid):
    run = _CAPTURE_RUNS.get(rid)
    if run is None:
        return jsonify({"error": "unknown run"}), 404
    # Never expose the stashed cookie/target to the browser — status only.
    return jsonify({"state": run.get("state"), "status": run.get("status"),
                    "error": run.get("error", "")})


@app.get("/wizard/capture-preview/<rid>")
def wizard_capture_preview(rid):
    """Render the editable preview for a finished capture, then drop the run so
    its server-side cookie doesn't linger."""
    run = _CAPTURE_RUNS.get(rid)
    if run is None or run.get("state") != "done":
        return _wiz_page("Not ready", '<p class="err">That capture is not finished '
                         '(or expired). Start over from the wizard.</p>'
                         '<p><a href="/wizard">&larr; wizard</a></p>')
    _CAPTURE_RUNS.pop(rid, None)                        # one-shot
    return _wiz_preview(run["target"], run.get("cookie", ""),
                        run.get("warnings", []), prompt=run.get("prompt", ""))


@app.route("/wizard", methods=["GET", "POST"])
def wizard_add():
    """One door: classify the paste locally, route curl/HAR to synthesize and a
    plain endpoint to the consent gate. api_style is never asked (E2)."""
    from . import wizard, detect
    if request.method == "GET":
        return _wiz_form()
    name = request.form.get("name", "").strip()
    prompt = request.form.get("prompt", "")
    capture = request.form.get("capture", "")
    kind = detect.classify_input(capture)

    if kind == "empty":
        return _wiz_form("Paste something first — a URL, a curl command, or a HAR.", name, prompt)
    if kind == "unknown":
        return _wiz_form("I couldn't tell what that is. Paste a plain URL "
                         "(https://api.vendor.com/v1), a `curl` command, or a saved HAR file.",
                         name, prompt)
    if kind == "endpoint":
        # No egress yet — show the consent gate. Offer an env key if we know the vendor.
        from . import presets
        preset = presets.match_host(capture)
        key_env = presets.env_key_for(preset)
        keynote = (f"I'll use <code>{html.escape(key_env)}</code> from your environment as the key."
                   if key_env else
                   "No vendor key found in your environment — an authenticated API may return 401.")
        host = ""
        try:
            from urllib.parse import urlsplit
            base, _ = detect._normalize(capture)
            host = urlsplit(base).netloc or base
        except Exception:
            host = capture
        # Issue a one-shot consent token; stash the endpoint server-side so it
        # can't be tampered and so a direct POST can't fake consent.
        token = uuid.uuid4().hex
        if len(_CONSENT_PENDING) > 20:
            _CONSENT_PENDING.clear()
        _CONSENT_PENDING[token] = {"endpoint": capture.strip(), "name": name}
        return Response(_WIZARD_CONSENT.format(
            host=html.escape(host), token=token, keynote=keynote), mimetype="text/html")

    # curl / har — the existing paste path (credential handled apart).
    try:
        cap = wizard.parse_har(capture, prompt) if kind == "har" else wizard.parse_curl(capture)
        syn = wizard.synthesize(cap, prompt, name)
    except (ValueError, KeyError, TypeError) as e:
        # Do NOT echo the capture back — it may hold the session cookie (Codex).
        return _wiz_form(f"Could not parse capture: {e} Re-paste and try again.", name, prompt)
    return _wiz_preview(syn.target, cap.cookie, syn.warnings, prompt=prompt)


@app.route("/wizard/detect", methods=["POST"])
def wizard_detect():
    """Post-consent endpoint identification. Runs detect() with consented=True,
    resolves any env key in memory (never persisted), and hands the operator the
    same editable preview with a plain-language detection card."""
    from . import detect, presets
    # CONSENT GATE (server-side): refuse — and send NOTHING — without a valid
    # one-shot token issued by the /wizard consent step (Codex adversarial).
    token = request.form.get("token", "")
    consent = _CONSENT_PENDING.pop(token, None)
    if consent is None:
        return _wiz_page("Consent expired", '<p class="err">This consent step expired or was '
                         'already used, so no test was sent. Start over from the wizard.</p>'
                         '<p><a href="/wizard">&larr; wizard</a></p>')
    name = consent["name"].strip() or "target"
    endpoint = consent["endpoint"]           # from the server stash, not the form
    passive_only = request.form.get("passive_only") == "1"
    preset = presets.match_host(endpoint)
    key_env = presets.env_key_for(preset)
    key_val = os.environ.get(key_env, "") if key_env else ""   # in-memory only

    d = detect.detect(endpoint, key=key_val or None, consented=True,
                      passive_only=passive_only)
    if not d.base_url and d.error:
        return _wiz_page("Couldn't identify", f'<p class="err">{html.escape(d.error)}</p>'
                         '<p><a href="/wizard">&larr; try again</a></p>')
    if d.route_hint == "capture":
        from urllib.parse import quote
        return _wiz_page("Looks like a web app",
                         f'<p class="warn">{html.escape(d.error)}</p>'
                         f'<p>Web apps need a captured request. '
                         f'<a href="/wizard/capture?url={quote(endpoint, safe="")}">'
                         f'Show me how to capture it &rarr;</a></p>'
                         '<p class=sub><a href="/wizard">&larr; back</a></p>')
    if not d.api_style:
        # Reachable but shape unconfirmed — let the operator pick, don't guess.
        note = d.error or "Reachable, but I couldn't confirm the API type from the response."
        return _wiz_page("Needs a choice", f'<p class="warn">{html.escape(note)}</p>'
                         f'<p class=sub>Confidence: {d.confidence}. Probes sent: {d.probes_used}.</p>'
                         '<p>Set the API style by hand on the '
                         '<a href="/">probe tool</a>, or re-run with an active test.</p>')
    # Build a committable target (key rides auth_value_env NAME only, never value).
    target = {
        "name": name, "base_url": d.base_url, "model": d.model,
        "api_style": d.api_style, "chat_path": d.chat_path or (
            "/v1/messages" if d.api_style == "anthropic" else "/chat/completions"),
        "authorized": False,
    }
    if key_env:
        target["auth_value_env"] = key_env
    conf = {"high": "&#9989; High confidence", "medium": "&#9888; Medium (please confirm)",
            "low": "&#9888; Low (please confirm)"}.get(d.confidence, d.confidence)
    warnings = []
    warnings.append(f"Detected: {d.api_style} API — {conf}. Sent {d.probes_used} probe(s).")
    if d.needs_confirm:
        warnings.append("Ambiguous or partial signal — confirm the api_style/model below before saving.")
    if key_env:
        warnings.append(f"Key: will read {key_env} from your environment at probe time "
                        f"(the value is never written to the config).")
    warnings.append(d.caveat)
    return _wiz_preview(target, "", warnings)


@app.route("/wizard/capture", methods=["GET"])
def wizard_capture():
    """Guided web-app capture (E8): annotated, browser-specific steps for grabbing
    the one chat request the template adapter needs."""
    from . import capture_guide, capture_playwright
    url = request.args.get("url", "")
    browser = request.args.get("browser", "chrome")
    g = capture_guide.guide(url, browser=browser,
                            playwright_available=capture_playwright.playwright_available())
    picker = "".join(
        f'<a href="/wizard/capture?url={html.escape(url)}&browser={b}"'
        f'{" style=font-weight:700" if b == browser else ""}>{b}</a>'
        for b in ("chrome", "firefox", "safari"))
    steps = "".join(
        f'<li><b>{html.escape(s.title)}</b><br>{html.escape(s.detail)}'
        + (f'<br><span class=sub>why: {html.escape(s.why)}</span>' if s.why else "")
        + "</li>" for s in g.steps)
    har = "".join(f"<li>{html.escape(h)}</li>" for h in g.har_alternative)
    inner = (
        f'<h1>Capture a request from {html.escape(g.app)}</h1>'
        f'<p class=sub>Browser: {picker} &nbsp;·&nbsp; <a href="/wizard">&larr; back to Add a target</a></p>'
        f'<ol>{steps}</ol>'
        f'<div class="warn">&#128274; {html.escape(g.security_note)}</div>'
        f'<h3>Prefer a file?</h3><ul>{har}</ul>'
        f'<p class=sub>{html.escape(g.playwright_hint)}</p>'
        f'<p><a href="/wizard">I have my capture &rarr; paste it</a></p>')
    return _wiz_page("Capture guide", inner)


@app.route("/wizard/probe-response", methods=["POST"])
def wizard_probe_response():
    """Auto-detect the response paths for a cURL-derived template target by
    replaying the captured request ONCE and reading the paths off the real
    response — removes the hand-typed-path error the operator hit on cURL paste."""
    from . import wizard
    if not _same_origin_ok(request):                   # defense-in-depth (already token-gated)
        return _wiz_page("Refused", '<p class="err">Cross-site request refused.</p>')
    token = request.form.get("token", "")
    pending = _WIZARD_PENDING.get(token)
    if pending is None:
        return _wiz_page("Expired", '<p class="err">This capture session expired. Start over.'
                         '</p><p><a href="/wizard">&larr; wizard</a></p>')
    try:
        target = json.loads(request.form.get("target", "{}"))
        if not isinstance(target, dict):
            raise ValueError("target must be a JSON object")
    except (json.JSONDecodeError, ValueError) as e:
        return _wiz_page("Invalid", f'<p class="err">Edited target is not valid JSON: '
                         f'{html.escape(str(e))}</p><p><a href="/wizard">&larr; back</a></p>')
    # Origin binding: never replay the captured cookie off its captured host.
    ok, why = _cookie_origin_ok(pending, target)
    if not ok:
        return _wiz_preview(target, pending["cookie"], [f"Refusing to auto-detect: {why}"],
                            prompt=pending.get("prompt", ""))
    try:
        t = Target(name=target.get("name", "target"), base_url=target.get("base_url", ""),
                   chat_path=target.get("chat_path", "/"), api_style="template",
                   request_template=target.get("request_template", {}),
                   stream_mode=target.get("stream_mode", "none"),
                   stream_delta_path=target.get("stream_delta_path", ""),
                   extra_headers=target.get("extra_headers", {}) if isinstance(
                       target.get("extra_headers"), dict) else {},
                   cookie=pending["cookie"])          # cookie from the server-side stash only
        res = wizard.discover_response_paths(Client(t), pending.get("prompt", ""))
    except Exception as e:                            # never 500 the operator
        return _wiz_page("Auto-detect error", f'<p class="err">Could not auto-detect: '
                         f'{html.escape(str(e))}</p><p><a href="/wizard">&larr; re-capture</a></p>')
    if not res["ok"]:
        # Fall back to the manual preview with the reason; keep the pending stash.
        return _wiz_preview(target, pending["cookie"],
                            [f"Auto-detect failed: {res['error']}",
                             "Set response_text_path / response_prompt_tokens_path by hand, "
                             "or paste a HAR instead."],
                            prompt=pending.get("prompt", ""))
    # Merge discovered paths into the target (fill from the real response).
    for k, v in res["paths"].items():
        if v:
            target[k] = v
    if res["stream_mode"] == "sse":
        target["stream_mode"] = "sse"
    notes = ["&#9989; Auto-detected from a live response — review below, then Dry-run &amp; save."]
    if res.get("sample"):
        notes.append(f"reply sample: {res['sample']}")
    if res["stream_mode"] == "sse":
        notes.append("response is SSE — stream_delta_path defaulted; confirm the per-chunk path.")
    if not target.get("response_prompt_tokens_path"):
        notes.append("no prompt-token usage in the response — tokenizer fingerprint will be "
                     "UNAVAILABLE (provenance floors at INDETERMINATE; wire/behavioral only).")
    return _wiz_preview(target, pending["cookie"], notes, prompt=pending.get("prompt", ""))


@app.route("/wizard/save", methods=["POST"])
def wizard_save():
    from . import wizard
    if not _same_origin_ok(request):                   # defense-in-depth (already token-gated)
        return _wiz_page("Refused", '<p class="err">Cross-site request refused.</p>')
    token = request.form.get("token", "")
    pending = _WIZARD_PENDING.get(token)
    if pending is None:
        return _wiz_page("Expired", '<p class="err">This capture session expired or was '
                         'already saved. Start over.</p><p><a href="/wizard">&larr; wizard</a></p>')
    cookie = pending["cookie"]
    try:
        target = json.loads(request.form.get("target", "{}"))
        if not isinstance(target, dict):
            raise ValueError("target must be a JSON object")
    except (json.JSONDecodeError, ValueError) as e:
        return _wiz_page("Invalid", f'<p class="err">Edited target is not valid JSON: '
                         f'{html.escape(str(e))}</p><p><a href="/wizard">&larr; back</a></p>')
    # The dry-run below sends the stashed cookie to base_url+chat_path — apply the
    # SAME origin binding as the replay so an edited host can't exfiltrate it
    # (Claude adversarial, CRITICAL: save had no origin check).
    ok, why = _cookie_origin_ok(pending, target)
    if not ok:
        return _wiz_page("Refusing to save", f'<p class="err">{html.escape(why)}</p>'
                         '<p><a href="/wizard">&larr; re-capture</a></p>')
    # Honor the detected/edited api_style — the endpoint path is openai/anthropic,
    # the paste path is template. Only template carries a cookie.
    api_style = target.get("api_style", "template")
    try:
        if api_style == "template":
            t = Target(name=target.get("name", "target"), base_url=target.get("base_url", ""),
                       chat_path=target.get("chat_path", "/"), api_style="template",
                       request_template=target.get("request_template", {}),
                       response_text_path=target.get("response_text_path", ""),
                       response_prompt_tokens_path=target.get("response_prompt_tokens_path", ""),
                       response_model_path=target.get("response_model_path", ""),
                       stream_mode=target.get("stream_mode", "none"),
                       stream_delta_path=target.get("stream_delta_path", ""),
                       extra_headers=target.get("extra_headers", {}) if isinstance(
                           target.get("extra_headers"), dict) else {},
                       cookie=cookie)                  # cookie from the server-side stash only
            probes = None                              # dry_run's varied-prompt defaults
        else:
            t = Target(name=target.get("name", "target"), base_url=target.get("base_url", ""),
                       model=target.get("model", ""),
                       api_style="anthropic" if api_style == "anthropic" else "openai",
                       chat_path=target.get("chat_path",
                                            "/v1/messages" if api_style == "anthropic"
                                            else "/chat/completions"),
                       auth_value_env=target.get("auth_value_env", ""))
            # Identical prompts: a stateless API returns identical prompt-token
            # counts for identical input, so the replay-safety stability gate
            # (built for web-app replay) doesn't false-fail on a healthy endpoint.
            probes = ["ping", "ping"]
        dr = wizard.dry_run(Client(t), probes=probes)
    except Exception as e:                              # never 500 the operator
        return _wiz_page("Dry-run error", f'<p class="err">Dry-run could not run: '
                         f'{html.escape(str(e))}</p><p><a href="/wizard">&larr; re-capture</a></p>')
    if not dr["ok"]:
        return _wiz_page("Dry-run failed", f'<p class="err">Dry-run failed: '
                         f'{html.escape(dr["error"])}</p><p><a href="/wizard">&larr; re-capture</a></p>')
    if not dr["replay_safe"]:
        # design: refuse to save a stateful/unstable target (replay would fail or
        # spam the operator's real chat). usage-suppressed-but-stable stays safe.
        return _wiz_page("Not replay-safe", '<p class="err">Refusing to save: the two dry-run '
                         'probes did not behave independently (missing reply or unstable '
                         'prompt-token counts). Replaying ~20 probes could fail or append to your '
                         'real chat. Re-capture a single-turn request, or fix the response paths.'
                         '</p><p><a href="/wizard">&larr; re-capture</a></p>')
    try:
        root = os.getcwd()
        res = wizard.write_target(target, cookie, config_path=os.path.join(root, "targets.json"),
                                  env_path=os.path.join(root, ".env.capture"), repo_root=root)
    except ValueError as e:                             # e.g. name clobber
        return _wiz_page("Not saved", f'<p class="err">{html.escape(str(e))}</p>'
                         '<p><a href="/wizard">&larr; back</a></p>')
    except OSError as e:
        return _wiz_page("Write error", f'<p class="err">Could not write config: '
                         f'{html.escape(str(e))}</p>')
    _WIZARD_PENDING.pop(token, None)                    # one-shot
    notes = list(res.get("warnings", []))
    if not dr["usage_exposed"]:
        notes.append("usage.prompt_tokens NOT exposed — tokenizer fingerprint unavailable "
                     "(provenance floors at INDETERMINATE; wire/behavioral only).")
    from urllib.parse import urlencode
    prefill = urlencode({k: v for k, v in {
        "name": target.get("name", ""), "base_url": target.get("base_url", ""),
        "model": target.get("model", ""), "api_style": api_style,
        "chat_path": target.get("chat_path", "")}.items() if v})
    cred_note = ""
    if res.get("env_path"):                             # template path wrote a cookie
        cred_note = (f'Cookie stored in <code>.env.capture</code> (gitignored) as '
                     f'<code>{html.escape(res["cookie_env"])}</code> &mdash; run '
                     f'<code>source .env.capture</code> before probing.')
    elif target.get("auth_value_env"):                  # endpoint path uses an env key
        cred_note = (f'Key read from <code>{html.escape(target["auth_value_env"])}</code> in '
                     f'your environment at probe time (never written to the config).')
    # E5: the payoff — one click to the plain-English verdict card (prefilled;
    # the probe tool renders the existing hero warning). Authorization still
    # required there before any provenance battery runs.
    inner = (f'<h1>Saved: {html.escape(res["added"])}</h1>'
             f'<div class="ok">Target written to <code>{html.escape(res["config_path"])}</code>. '
             f'{cred_note}</div>'
             + "".join(f'<div class="warn">&#9888; {html.escape(n)}</div>' for n in notes)
             + f'<p style="margin-top:1rem"><a href="/?{html.escape(prefill)}">'
             f'<button style="font:15px system-ui;padding:.5rem 1rem">Probe it now &rarr;</button></a></p>'
             + '<p class=sub><a href="/wizard">Add another</a> · <a href="/">probe tool</a></p>')
    return _wiz_page("Saved", inner)


PAGE = r"""<!doctype html><meta charset=utf-8><title>provenance-probe</title>
<meta name=viewport content="width=device-width,initial-scale=1">
<style>
:root{--ink:#16181d;--mut:#6b7280;--line:#e3e5e9;--bg:#f6f7f8;--acc:#1f4f8b}
*{box-sizing:border-box}
body{font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;color:var(--ink);
background:var(--bg);margin:0;padding:26px}
.w{max-width:940px;margin:0 auto}
h1{font-size:21px;margin:0 0 2px;letter-spacing:-.01em}
.sub{color:var(--mut);font-size:13px;margin-bottom:22px}
.card{background:#fff;border:1px solid var(--line);border-radius:11px;padding:20px 22px;margin-bottom:16px}
label{display:block;font-size:11px;letter-spacing:.07em;text-transform:uppercase;
color:var(--mut);font-weight:650;margin:0 0 5px}
input[type=text],input[type=password],select{width:100%;padding:9px 11px;border:1px solid var(--line);
border-radius:7px;font:14px ui-monospace,monospace;background:#fcfcfd}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:14px}
.row{margin-bottom:14px}
button{background:var(--acc);color:#fff;border:0;border-radius:8px;padding:11px 20px;
font-size:14px;font-weight:600;cursor:pointer}
button:disabled{opacity:.5;cursor:default}
.chk{display:flex;gap:9px;align-items:flex-start;font-size:13px;color:#3d424b;
background:#fffdf0;border:1px solid #ece0b0;border-radius:8px;padding:12px 14px}
.adv{font-size:13px;color:var(--acc);cursor:pointer;user-select:none;margin-bottom:12px;display:inline-block}
.hide{display:none}
.bar{height:6px;background:#eceef1;border-radius:99px;overflow:hidden;margin:12px 0 8px}
.bar>i{display:block;height:100%;background:var(--acc);width:0;transition:width .4s}
.stat{font-size:13px;color:var(--mut);font-family:ui-monospace,monospace}
.ban{border-radius:10px;padding:18px 20px;border-left:6px solid;margin-bottom:14px}
.red{background:#fdf2f2;border-color:#8b1a1a;color:#8b1a1a}
.orange{background:#fff8f0;border-color:#a8500f;color:#a8500f}
.yellow{background:#fffdf0;border-color:#7a6a12;color:#7a6a12}
.green{background:#f3faf4;border-color:#2f6b3a;color:#2f6b3a}
.ban h2{font-size:19px;margin:4px 0 4px;letter-spacing:-.01em}
.lvl{font-size:10px;letter-spacing:.11em;text-transform:uppercase;font-weight:700}
ul{margin:8px 0 0;padding-left:20px;color:var(--ink)}li{margin-bottom:7px;font-size:14px}
h3{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);margin:18px 0 8px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.06em;color:var(--mut);
padding:7px 9px;background:#f4f5f7}
td{padding:7px 9px;border-top:1px solid var(--line);vertical-align:top}
.mono{font-family:ui-monospace,monospace;font-size:12px}
a{color:var(--acc)}
.hist{font-size:13px}.hist td{padding:6px 9px}
.dot{display:inline-block;width:8px;height:8px;border-radius:99px;margin-right:7px}
.topnav{display:flex;gap:14px;font-size:11px;letter-spacing:.07em;text-transform:uppercase;
margin:0 0 14px;border-bottom:1px solid var(--line);padding-bottom:8px}
.topnav .active{color:var(--ink);font-weight:700}.topnav a{color:var(--acc);text-decoration:none}
.sev{font-size:10px;letter-spacing:.07em;text-transform:uppercase;font-weight:700;padding:1px 6px;border-radius:4px}
.sev.critical{background:#fdf2f2;color:#8b1a1a}.sev.high{background:#fff8f0;color:#a8500f}.sev.medium{background:#fffdf0;color:#7a6a12}
</style><div class=w>
<div class=topnav><span class=active>Live probe tool</span><a href="/agent">Agent board &rarr;</a><a href="/wizard">Add target &rarr;</a><a href="__OBSERVATORY_URL__">Observatory &rarr;</a></div>
<h1>provenance-probe</h1>
<div class=sub>Local model provenance &amp; jurisdiction assurance · binds to 127.0.0.1 · nothing leaves this machine except requests to the endpoint you name</div>

<div class=card>
 <div class="row grid3">
  <div><label>Endpoint base URL</label>
   <input type=text id=base_url placeholder="https://api.vendor.example/v1"></div>
  <div><label>Model id</label><input type=text id=model placeholder="vendor-flagship-1"></div>
  <div><label>API style</label><select id=api_style onchange="toggleTmpl()">
    <option value=openai>openai</option><option value=anthropic>anthropic</option>
    <option value=template>template (web app)</option></select></div>
 </div>
 <div id=tmpl class=hide>
  <div class=stat style="margin:2px 0 12px">Web app / platform tool: paste one request captured from the app's
   browser traffic (DevTools → Network → the chat request). Use <span class=mono>__PROMPT__</span> where the
   message text goes. Tell it where the reply lives with the response paths below.</div>
  <div class="row grid">
   <div><label>Chat path</label><input type=text id=chat_path placeholder="/api/paas/v4/chat/completions"></div>
   <div><label>Models path (optional)</label><input type=text id=models_path placeholder="/api/paas/v4/models"></div>
  </div>
  <div class=row><label>Request template (JSON, use __PROMPT__)</label>
   <textarea id=request_template rows=7 style="width:100%;padding:9px 11px;border:1px solid var(--line);border-radius:7px;font:13px ui-monospace,monospace;background:#fcfcfd"
    placeholder='{"model":"glm-4.6","messages":[{"role":"user","content":"__PROMPT__"}],"max_tokens":"__MAX_TOKENS__","temperature":"__TEMPERATURE__"}'></textarea></div>
  <div class="row grid3">
   <div><label>Response text path</label><input type=text id=response_text_path placeholder="choices.0.message.content"></div>
   <div><label>Prompt-tokens path (opt)</label><input type=text id=response_prompt_tokens_path placeholder="usage.prompt_tokens"></div>
   <div><label>Model path (opt)</label><input type=text id=response_model_path placeholder="model"></div>
  </div>
  <div class="row grid3">
   <div><label>Session cookie (stays in memory)</label><input type=password id=cookie placeholder="session=…"></div>
   <div><label>Stream mode</label><select id=stream_mode><option value=none>none</option><option value=sse>sse</option></select></div>
   <div><label>SSE delta path</label><input type=text id=stream_delta_path placeholder="choices.0.delta.content"></div>
  </div>
 </div>
 <div class="row grid">
  <div><label>Label</label><input type=text id=name placeholder="vendor-under-test"></div>
  <div><label>API key (optional, stays in memory)</label>
   <input type=password id=api_key placeholder="sk-…"></div>
 </div>
 <span class=adv onclick="document.getElementById('adv').classList.toggle('hide')">Advanced options ▾</span>
 <div id=adv class=hide>
  <div class="row grid">
   <div><label>Client app URL to scan</label><input type=text id=client_url placeholder="https://app.vendor.example"></div>
   <div><label>Client source directory</label><input type=text id=client_dir placeholder="/path/to/unpacked"></div>
  </div>
  <div class="row grid">
   <div><label>Confront as (backend your evidence shows)</label>
    <input type=text id=confront_as placeholder="Zhipu GLM"></div>
   <div><label>False control (sycophancy check)</label>
    <input type=text id=confront_control placeholder="Mistral AI"></div>
  </div>
  <div class="row grid">
   <div><label>Inspecting proxy</label><input type=text id=proxy placeholder="http://127.0.0.1:8080"></div>
   <div><label>Local model dir (self-hosted)</label><input type=text id=artifacts_dir placeholder="/models/x"></div>
  </div>
  <div class=row style="font-size:13px">
   <label><input type=checkbox id=session_test> probe for anti-forensic session termination</label>
   <label><input type=checkbox id=offline> skip RDAP lookups (offline)</label>
   <label><input type=checkbox id=no_behavioral> skip alignment battery (faster)</label>
  </div>
 </div>
 <div class="row chk"><input type=checkbox id=authorized>
  <span>I confirm I am authorized to test this endpoint. The deception and alignment
  probes send politically sensitive prompts and may trip the provider's abuse monitoring.</span></div>
 <button id=go onclick=start()>Run assessment</button>
 <div id=prog class=hide><div class=bar><i id=fill></i></div><div class=stat id=stat></div></div>
</div>

<div id=out></div>

<div class=card><h3>Monitor · compare two runs for a silent model swap</h3>
 <div class=stat style="margin:-2px 0 12px">Same diff the CLI <span class=mono>monitor</span> uses:
  fingerprint, overhead-corrected tokenizer shape, error schema, verdicts, latency.</div>
 <div class="row grid3">
  <div><label>Baseline run</label><select id=mon_base></select></div>
  <div><label>Current run</label><select id=mon_cur></select></div>
  <div style="display:flex;align-items:flex-end"><button id=cmp onclick=compare() style="width:100%">Compare</button></div>
 </div>
 <div id=mon_out class=stat>Run at least two assessments, then compare them here.</div>
</div>

<div class=card><h3>Local run history</h3><div id=hist class=stat>none yet</div></div>
</div>
<script>
const $=i=>document.getElementById(i);
let timer=null;
function toggleTmpl(){$('tmpl').classList.toggle('hide',$('api_style').value!=='template')}
function start(){
 if(!$('authorized').checked){alert('Confirm authorization first.');return}
 const spec={base_url:$('base_url').value.trim(),model:$('model').value.trim(),
  name:$('name').value.trim()||'target',api_style:$('api_style').value,
  api_key:$('api_key').value,client_url:$('client_url').value.trim(),
  client_dir:$('client_dir').value.trim(),confront_as:$('confront_as').value.trim(),
  confront_control:$('confront_control').value.trim(),proxy:$('proxy').value.trim(),
  artifacts_dir:$('artifacts_dir').value.trim(),session_test:$('session_test').checked,
  offline:$('offline').checked,no_behavioral:$('no_behavioral').checked,authorized:true};
 if($('api_style').value==='template'){
  spec.chat_path=$('chat_path').value.trim();
  spec.models_path=$('models_path').value.trim();
  spec.request_template=$('request_template').value.trim();
  spec.response_text_path=$('response_text_path').value.trim();
  spec.response_prompt_tokens_path=$('response_prompt_tokens_path').value.trim();
  spec.response_model_path=$('response_model_path').value.trim();
  spec.cookie=$('cookie').value;
  spec.stream_mode=$('stream_mode').value;
  spec.stream_delta_path=$('stream_delta_path').value.trim();
  if(!spec.request_template){alert('Request template required for web-app (template) mode.');return}
  if(!spec.response_text_path){alert('Response text path required for template mode.');return}
 }
 if(!spec.base_url){alert('Endpoint base URL required.');return}
 $('go').disabled=true;$('prog').classList.remove('hide');$('out').innerHTML='';
 fetch('/api/assess',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify(spec)}).then(r=>r.json()).then(d=>{
   if(d.error){alert(d.error);$('go').disabled=false;return}
   timer=setInterval(()=>poll(d.run_id),900);});
}
function poll(rid){
 fetch('/api/run/'+rid).then(r=>r.json()).then(d=>{
  $('fill').style.width=(d.progress||0)+'%';$('stat').textContent=d.status||'';
  if(d.state==='done'){clearInterval(timer);$('go').disabled=false;render(d,rid);loadHist()}
  if(d.state==='error'){clearInterval(timer);$('go').disabled=false;
   $('out').innerHTML='<div class="card"><b>Error</b><pre class=mono>'+
   (d.status||'')+'</pre></div>'}});
}
function esc(s){return (s||'').replace(/[<>&]/g,c=>({'<':'&lt;','>':'&gt;','&':'&amp;'}[c]))}
function render(d,rid){
 const w=d.user_warning||{},s=d.score||{};
 let h='<div class="ban '+w.level+'"><div class=lvl>'+esc(w.level_label)+'</div>'+
  '<h2>'+esc(w.headline)+'</h2><ul>'+(w.facts||[]).map(f=>'<li>'+esc(f)+'</li>').join('')+
  '</ul></div>';
 h+='<div class=card><h3>What to do</h3><ul>'+(w.actions||[]).map(a=>'<li>'+esc(a)+'</li>').join('')+'</ul></div>';
 h+='<div class=card><h3>Technical verdict</h3><table><tr><th>Risk</th><th>Verdict</th><th>Likelihood</th></tr>'+
  '<tr><td>Jurisdictional (PRC operator/soil)</td><td class=mono>'+s.jurisdictional_risk.verdict+
  '</td><td class=mono>'+s.jurisdictional_risk.likelihood+'</td></tr>'+
  '<tr><td>Provenance (Chinese-origin weights)</td><td class=mono>'+s.provenance_risk.verdict+
  '</td><td class=mono>'+s.provenance_risk.likelihood+'</td></tr></table>'+
  '<div class=stat style="margin-top:9px">Evidence confidence: '+esc(s.confidence)+'</div>';
 if(d.confrontation){const c=d.confrontation;
  h+='<h3>Confrontation (with false-premise control)</h3><table><tr><th>Claim put to model</th>'+
  '<th>Conceded</th></tr><tr><td>'+esc(c.true_backend)+' <span class=stat>(evidence-backed)</span></td><td class=mono>'+
  c.true_conceded+'</td></tr><tr><td>'+esc(c.false_backend)+' <span class=stat>(deliberately false control)</span></td><td class=mono>'+
  c.false_conceded+'</td></tr></table><div class=stat style="margin-top:8px">'+esc(c.verdict)+'</div>'}
 if((d.tokenizer_match||[]).length){
  h+='<h3>Tokenizer fingerprint</h3><table><tr><th>Reference</th><th>Origin</th><th>Score</th><th>Exact</th></tr>'+
  d.tokenizer_match.map(r=>'<tr><td class=mono>'+esc(r.model)+'</td><td>'+esc(String(r.origin))+
  '</td><td class=mono>'+r.score+'</td><td class=mono>'+r.exact_matches+'/'+r.shared_probes+'</td></tr>').join('')+'</table>'}
 h+='<h3>Signals</h3><table><tr><th>Layer</th><th>Signal</th><th>Evidence</th></tr>'+
  (s.signals||[]).map(x=>'<tr><td class=mono>'+esc(x.layer)+'</td><td class=mono>'+esc(x.signal)+
  '</td><td>'+esc(x.evidence)+'</td></tr>').join('')+'</table></div>';
 $('out').innerHTML=h;
}
function loadHist(){
 fetch('/api/history').then(r=>r.json()).then(rows=>{
  fillMon(rows);
  if(!rows.length){$('hist').textContent='none yet';return}
  const col={red:'#8b1a1a',orange:'#a8500f',yellow:'#7a6a12',green:'#2f6b3a'};
  $('hist').innerHTML='<table class=hist>'+rows.map(r=>
   '<tr><td><span class=dot style="background:'+(col[r.level]||'#999')+'"></span>'+
   esc(r.name)+'</td><td class=mono>'+esc(r.url)+'</td><td class=stat>'+esc(r.ts)+
   '</td><td><a href="/report/'+encodeURIComponent(r.file.replace(".json","_USER-WARNING.html"))+
   '" target=_blank>warning</a> · <a href="/report/'+
   encodeURIComponent(r.file.replace(".json",".html"))+'" target=_blank>technical</a></td></tr>'
  ).join('')+'</table>'});
}
function fillMon(rows){
 // rows are newest-first. Default: current = newest, baseline = previous.
 const opt=r=>'<option value="'+esc(r.file)+'">'+esc(r.name)+' · '+esc(r.ts)+
   ' · '+esc((r.fingerprint_id||'—').slice(0,10))+'</option>';
 const b=$('mon_base'),c=$('mon_cur');
 if(!rows.length){b.innerHTML=c.innerHTML='<option value="">no runs yet</option>';return}
 b.innerHTML=c.innerHTML=rows.map(opt).join('');
 c.selectedIndex=0; b.selectedIndex=Math.min(1,rows.length-1);
}
function compare(){
 const baseline=$('mon_base').value,current=$('mon_cur').value;
 if(!baseline||!current){$('mon_out').textContent='Need two runs to compare.';return}
 if(baseline===current){$('mon_out').innerHTML='<span class=sev high>note</span> baseline and current are the same run.';return}
 $('cmp').disabled=true;$('mon_out').textContent='Comparing…';
 fetch('/api/monitor',{method:'POST',headers:{'Content-Type':'application/json'},
  body:JSON.stringify({baseline,current})}).then(r=>r.json()).then(d=>{
   $('cmp').disabled=false;
   if(d.error){$('mon_out').innerHTML='<span class=sev critical>error</span> '+esc(d.error);return}
   const drift=d.drift_detected;
   let h='<div class="ban '+(drift?'red':'green')+'" style="margin:0 0 12px">'+
    '<div class=lvl>'+(drift?'DRIFT DETECTED':'NO DRIFT')+'</div><h2>'+
    (drift?(d.changes.length+' change'+(d.changes.length>1?'s':'')+' since baseline'):'Backend is stable')+'</h2>'+
    '<div class=stat style="color:inherit">baseline '+esc((d.baseline.fingerprint_id||'—').slice(0,12))+
    ' &rarr; current '+esc((d.current.fingerprint_id||'—').slice(0,12))+'</div></div>';
   if(drift){
    h+='<table><tr><th>Severity</th><th>Field</th><th>Detail</th></tr>'+
     d.changes.map(c=>'<tr><td><span class="sev '+esc(c.severity)+'">'+esc(c.severity)+
     '</span></td><td class=mono>'+esc(c.field)+'</td><td>'+esc(c.detail)+
     (c.implication?'<div class=stat>'+esc(c.implication)+'</div>':'')+'</td></tr>').join('')+'</table>';
   }
   if(d.confidence==='degraded'){
    h+='<div class="ban yellow" style="margin-top:10px"><div class=lvl>Degraded confidence</div>'+
     '<div class=stat style="color:inherit">'+esc(d.confidence_note||'')+'</div></div>';
   }
   $('mon_out').innerHTML=h;
  }).catch(e=>{$('cmp').disabled=false;$('mon_out').textContent='Compare failed: '+e});
}
// E5: the add-target wizard hands off here with the target prefilled, so the
// operator lands one click from the plain-English verdict card.
function prefillFromQuery(){
 const q=new URLSearchParams(location.search);
 if(![...q.keys()].length)return;
 const set=(id,k)=>{const v=q.get(k);if(v!=null&&$(id))$(id).value=v};
 set('base_url','base_url');set('model','model');set('name','name');
 const st=q.get('api_style');
 if(st&&$('api_style')){$('api_style').value=st;toggleTmpl();}
 if(q.get('chat_path')&&$('chat_path'))$('chat_path').value=q.get('chat_path');
}
prefillFromQuery();
loadHist();
</script>"""


def serve(host="127.0.0.1", port=8770, debug=False):
    os.makedirs(DATA_DIR, exist_ok=True)
    # The "Capture for me" flow runs a capture in a daemon thread; make sure a
    # process signal/exit tears down any in-flight capture's browser/proxy/CA dir
    # (security sign-off #44) — the daemon thread's own finally won't run.
    try:
        from . import capture_proxy
        capture_proxy.install_process_cleanup()
    except Exception:
        pass
    print(f"provenance-probe  ->  http://{host}:{port}")
    print(f"reports stored in {DATA_DIR}/reports")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("\n  ! Binding to a non-loopback address. This UI has no authentication.\n"
              "    Do not expose it on an untrusted network.\n")
    app.run(host=host, port=port, debug=debug, threaded=True)
