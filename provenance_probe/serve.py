# -*- coding: utf-8 -*-
"""Local web service for provenance-probe.

Binds to 127.0.0.1 by default. Nothing is sent anywhere except to the endpoint
you explicitly ask it to assess. Run history is stored on local disk only.

    provenance-probe serve            # http://127.0.0.1:8770
"""
from __future__ import annotations
import json, os, threading, datetime, uuid, traceback, html

from flask import Flask, request, jsonify, Response

from .config import Target
from .client import Client
from .probes import network, tokenizer, behavioral, wire, latency, logprob, artifact, clientsrc, deception
from . import scoring, report, userwarn

RUNS: dict[str, dict] = {}
DATA_DIR = os.path.expanduser(os.environ.get("PROVENANCE_PROBE_HOME", "~/.provenance-probe"))
app = Flask(__name__)


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
            t.extra_headers["Authorization"] = "Bearer " + spec["api_key"]

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
            b["client_source"] = clientsrc.scan_url(spec["client_url"])
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
    spec = request.get_json(force=True)
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
                             "level": b.get("user_warning", {}).get("level"),
                             "headline": b.get("user_warning", {}).get("headline")})
            except Exception:
                pass
    return jsonify(rows[:50])


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
    return Response(PAGE, mimetype="text/html")


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
</style><div class=w>
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
loadHist();
</script>"""


def serve(host="127.0.0.1", port=8770, debug=False):
    os.makedirs(DATA_DIR, exist_ok=True)
    print(f"provenance-probe  ->  http://{host}:{port}")
    print(f"reports stored in {DATA_DIR}/reports")
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("\n  ! Binding to a non-loopback address. This UI has no authentication.\n"
              "    Do not expose it on an untrusted network.\n")
    app.run(host=host, port=port, debug=debug, threaded=True)
