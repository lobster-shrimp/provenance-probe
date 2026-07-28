#!/usr/bin/env python3
"""provenance-probe CLI."""
from __future__ import annotations
import argparse, json, os, sys, datetime, hashlib, uuid

from .config import load_targets, write_example, Target
from .client import Client
from .probes import (network, tokenizer, behavioral, wire, latency, logprob,
                     artifact, clientsrc, deception, transcript, session)
from . import scoring, report, reference, userwarn, monitor, sentinel

BANNER = """provenance-probe — GenAI model provenance & jurisdiction assurance
Use only against systems you are authorized in writing to test."""


def _assert_scope(t: Target, force: bool):
    if not (t.authorized or force):
        sys.exit(f"[abort] target '{t.name}' has authorized=false. Set it, or pass --i-am-authorized.")


def cmd_assess(a):
    targets = load_targets(a.config)
    ref = tokenizer.load_reference() if not a.no_tokenizer else {}
    if not ref and not a.no_tokenizer:
        print("[warn] no tokenizer reference vectors. Run `build-reference` for the strongest signal.\n")
    bundles = []
    for t in targets:
        _assert_scope(t, a.i_am_authorized)
        print(f"\n>>> {t.name}  {t.base_url}")
        c = Client(t)
        b = {"target": {"name": t.name, "base_url": t.base_url, "model": t.model,
                        "api_style": t.api_style},
             "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")}

        print("  [1/7] network / jurisdiction ...")
        b["network"] = network.analyze_host(t.base_url, do_rdap=not a.offline)

        print("  [2/7] wire fingerprint ...")
        b["headers"] = wire.header_fingerprint(c)
        b["errors"] = wire.error_schema_fingerprint(c)
        b["streaming"] = wire.streaming_fingerprint(c)
        b["catalog"] = wire.model_catalog(c)

        if not a.no_tokenizer:
            print("  [3/7] tokenizer fingerprint ...")
            _seed = getattr(a, "variant_seed", 0) or 0
            _ref_seed = ref.get("variant_seed", 0) if ref else 0
            if _seed != _ref_seed:
                print(f"        ! variant-seed {_seed} != reference seed {_ref_seed}; "
                      f"rebuild the reference with --variant-seed {_seed} or the match is invalid")
            b["tokenizer"] = tokenizer.measure(c, variant_seed=_seed)
            if b["tokenizer"]["usable"]:
                b["tokenizer_match"] = tokenizer.compare(b["tokenizer"], ref)
            else:
                print("        ! endpoint did not return usage.prompt_tokens — "
                      "tokenizer layer unavailable (itself a transparency finding)")

        print("  [4/7] logprob / determinism ...")
        b["logprobs"] = logprob.logprob_signature(c)
        b["greedy"] = logprob.greedy_signature(c)

        if not a.no_behavioral:
            print("  [5/7] self-identification ...")
            b["selfid"] = behavioral.self_identification(c)
            print("  [6/7] alignment asymmetry (matched pairs) ...")
            b["alignment"] = behavioral.alignment_asymmetry(c)
            print("        CJK leakage ...")
            b["leakage"] = behavioral.language_leakage(c, samples=a.leak_samples)

        if a.latency:
            print("  [7/7] latency profile ...")
            b["latency"] = latency.profile(c, n=a.latency_n)

        if not a.no_deception:
            print("  [8/8] deception: persona + jurisdiction claims ...")
            d = {}
            d["persona"] = deception.persona_claim(c)
            d["jurisdiction"] = deception.jurisdiction_claims(c)
            d["trace"] = deception.reasoning_trace_capture(c)
            if a.confront_as:
                print(f"        confrontation vs '{a.confront_as}' (+ false control) ...")
                d["confrontation"] = deception.confront(c, a.confront_as, a.confront_control)
            if a.session_test:
                d["session"] = deception.session_resilience(c)
            b["deception"] = d

        if a.client_dir or a.client_url:
            print("        client-source scan ...")
            b["client_source"] = (clientsrc.scan_dir(a.client_dir) if a.client_dir
                                  else clientsrc.scan_url(a.client_url))

        if a.artifacts:
            print(f"        artifact scan: {a.artifacts}")
            b["artifacts"] = artifact.scan_dir(a.artifacts)

        if b.get("deception"):
            origin, detail = _hard_evidence(b)
            b["deception"]["correlation"] = deception.correlate(
                b["deception"]["persona"], b["deception"]["jurisdiction"], origin, detail)

        b["score"] = scoring.score(b)
        b["user_warning"] = userwarn.build(b)
        b["fingerprint_id"] = monitor.fingerprint(b)
        bundles.append(b)
        print("\n" + report.console(b))
        if b.get("deception", {}).get("correlation", {}).get("finding"):
            print("  DECEPTION: " + b["deception"]["correlation"]["finding"])
        print(userwarn.to_text(b["user_warning"]))

    os.makedirs(a.out, exist_ok=True)
    stamp = datetime.datetime.now().strftime("%Y%m%dT%H%M%S")
    for b in bundles:
        base = os.path.join(a.out, f"{b['target']['name']}_{stamp}")
        report.to_json(b, base + ".json")
        report.to_html(b, base + ".html")
        userwarn.to_html(b["user_warning"], base + "_USER-WARNING.html")
        print(f"\n[+] {base}.json\n[+] {base}.html\n[+] {base}_USER-WARNING.html")


def _hard_evidence(b: dict):
    """Origin per the layers that are hard to fake: source, network, tokenizer."""
    src = b.get("client_source") or {}
    if src.get("prc_operators_in_source"):
        return "CN", f"Client source references {', '.join(src['prc_operators_in_source'])}."
    net = b.get("network") or {}
    if net.get("jurisdiction", "").startswith("PRC"):
        return "CN", f"Endpoint resolves to {net.get('operator')} ({net.get('jurisdiction')})."
    tm = b.get("tokenizer_match") or []
    if tm and tm[0].get("score", 0) >= 0.75:
        return ("CN" if tm[0].get("origin") == "CN" else "nonCN",
                f"Tokenizer fingerprint matches {tm[0]['model']} (score {tm[0]['score']}).")
    cat = b.get("catalog") or {}
    if cat.get("prc_origin_models"):
        return "CN", "Endpoint catalog offers PRC-origin models."
    return None, ""


def cmd_monitor(a):
    """Compare a fresh run against a stored baseline. Detects silent model swaps."""
    base = json.load(open(a.baseline))
    cur = json.load(open(a.current))
    result = monitor.diff(base, cur)
    out = {"baseline": a.baseline, "current": a.current,
           "changes": result["changes"], "drift_detected": result["drift_detected"],
           "confidence": result["confidence"]}
    if result.get("confidence_note"):
        out["confidence_note"] = result["confidence_note"]
    print(json.dumps(out, indent=2))
    if a.json_out:
        json.dump(out, open(a.json_out, "w"), indent=2)
    sys.exit(2 if out["drift_detected"] else 0)


def cmd_artifacts(a):
    r = artifact.scan_dir(a.path)
    crit = [f for f in r["findings"] if f["severity"] == "critical"]
    print(json.dumps(r, indent=2))
    print(f"\n{len(r['findings'])} findings, {len(crit)} critical, "
          f"{r['files_examined']} artifact files examined.")
    sys.exit(2 if crit else 0)


def cmd_serve(a):
    from .serve import serve
    serve(host=a.host, port=a.port, debug=a.debug)


def cmd_clientsrc(a):
    if not (a.dir or a.url):
        sys.exit("provide --dir or --url")
    r = clientsrc.scan_dir(a.dir) if a.dir else clientsrc.scan_url(a.url)
    print(json.dumps(r, indent=2))
    crit = [f for f in r["findings"] if f["severity"] == "critical"]
    if r.get("persona_mismatch"):
        print("\n!! PERSONA MISMATCH: " + r["persona_mismatch"]["detail"])
    sys.exit(2 if crit else 0)


def cmd_network(a):
    hosts = a.host or []
    if a.hosts_file:
        hosts += [l.strip() for l in open(a.hosts_file) if l.strip() and not l.startswith("#")]
    print(json.dumps([network.analyze_host(h, do_rdap=not a.offline) for h in hosts], indent=2))


def cmd_build_reference(a):
    reference.build(hf_token=a.hf_token, overwrite=a.overwrite,
                    allow_remote_code=a.allow_remote_code,
                    only=a.only or None,
                    variant_seed=getattr(a, "variant_seed", 0) or 0)


def cmd_verify_reference(a):
    sys.exit(reference.verify())


def cmd_build_reference_endpoint(a):
    """Measure a reference vector from a live authorized first-party endpoint.

    For families whose tokenizer is not published (Claude, Gemini): the genuine
    first-party API IS the ground truth. Requires --i-am-authorized.
    """
    if not a.i_am_authorized:
        sys.exit("[abort] build-reference-endpoint runs an active probe. Pass "
                 "--i-am-authorized to attest you are authorized to probe this "
                 "endpoint AND that it is the genuine first party for the family.")
    targets = load_targets(a.config)
    t = next((x for x in targets if not a.name or x.name == a.name), None)
    if t is None:
        sys.exit(f"[abort] no target named '{a.name}' in {a.config}.")
    _assert_scope(t, a.i_am_authorized)
    reference.build_from_endpoint(Client(t), label=a.label, family=a.family,
                                  origin=a.origin, overwrite=a.overwrite)


def cmd_transcript(a):
    """Analyze a captured conversation for identity deception + model switches."""
    result = transcript.analyze(transcript.load(a.file),
                                true_origin=a.true_origin, true_detail=a.true_detail or "")
    bundle = {"transcript": {"file": a.file}, "deception": result["deception"]}
    bundle["score"] = scoring.score(bundle)
    corr = result["correlation"]
    print(f"\ntranscript: {a.file}  ({result['turns_analyzed']} assistant turns)")
    print(f"distinct identities claimed: {', '.join(result['distinct_identities']) or 'none'}")
    if result["model_change_events"]:
        print("\nMODEL-CHANGE EVENTS (identity switched mid-session):")
        for e in result["model_change_events"]:
            print(f"  turn {e['turn']}: {e['from']} -> {e['to']}  [{e['kind']}]")
    else:
        print("\nNo mid-session identity change detected.")
    if corr.get("misrepresentation"):
        print(f"\nVERDICT: MATERIAL MISREPRESENTATION ({corr['severity']}) — {corr['finding']}")
    else:
        print(f"\nVERDICT: {corr.get('finding','no misrepresentation asserted')}")
    prov = bundle["score"]["provenance_risk"]["verdict"]
    jur = bundle["score"]["jurisdictional_risk"]["verdict"]
    print(f"provenance: {prov}   jurisdiction: {jur}")
    if a.out:
        json.dump({**result, "score": bundle["score"]}, open(a.out, "w"), indent=2)
        print(f"\n[+] {a.out}")
    # exit 2 when there's something to alert on (a switch or a misrepresentation)
    sys.exit(2 if (result["model_change_events"] or corr.get("misrepresentation")) else 0)


def cmd_session(a):
    """Fingerprint an endpoint at session start + end; detect an intra-session swap."""
    targets = load_targets(a.config)
    switched = False
    for t in targets:
        _assert_scope(t, a.i_am_authorized)
        print(f"\n>>> {t.name}  {t.base_url}  (gap {a.gap_probes} probes)")
        r = session.boundary_check(Client(t), gap_probes=a.gap_probes,
                                   variant_seed=getattr(a, "variant_seed", 0) or 0)
        sf, ef = r["start_fingerprint"][:12], r["end_fingerprint"][:12]
        if r["boundary_switch"]:
            switched = True
            print(f"  MODEL SWITCHED MID-SESSION: {sf} -> {ef}  (confidence {r['confidence']})")
            for c in r["changes"]:
                print(f"    [{c['severity']}] {c['field']}: {c['detail']}")
        else:
            print(f"  stable across the session: {sf}")
        if a.out:
            json.dump(r, open(a.out, "w"), indent=2)
    sys.exit(2 if switched else 0)


def cmd_sentinel(a):
    """Run the real-time in-line model-switch sentinel (reverse proxy)."""
    sentinel.serve(a.upstream, host=a.host, port=a.port, events_file=a.events_file)


def _print_agent_board(result: dict, title: str):
    from . import agent as _agent  # noqa: F401 (kept explicit for clarity)
    print(f"\nagent: {title}   ({len(result['steps'])} steps)")
    _basis = {"PRC": "PRC-soil", "PRC-operator": "PRC-operator",
              "non-PRC-operator": "non-PRC-op", "non-PRC-firstparty": "non-PRC-1p"}
    print(f"  {'#':>2}  {'kind':<5} {'name':<14} {'echoed model':<16} "
          f"{'prov':<13} {'juris (basis)':<26} host")
    for s in result["steps"]:
        b = _basis.get(s.get("jurisdiction_basis") or "", "")
        juris = f"{s['jurisdiction']}" + (f" ({b})" if b else "")
        print(f"  {s['index']:>2}  {s['kind']:<5} {s['name'][:14]:<14} "
              f"{(s['echoed_model'] or '-')[:16]:<16} {s['provenance']:<13} "
              f"{juris:<26} {s['host'] or '-'}")
    v = result["verdict"]
    if v["model_switches"]:
        print("\n  MODEL SWITCHES:")
        for sw in v["model_switches"]:
            print(f"    step {sw['at_step']} [{sw['reason']}]: {sw['from']} -> {sw['to']}")
    else:
        print("\n  No model switch detected across steps.")
    print(f"\n  AGENT VERDICT: {v['label']}  "
          f"(provenance {v['provenance_verdict']} / jurisdiction {v['jurisdiction_verdict']}, "
          f"worst of {v['steps']} steps)")
    if v.get("alert") and not v["model_switches"]:
        print(f"  ALERT: worst step is {v['worst_step_verdict']} (no switch, but a "
              f"LIKELY/CONFIRMED step is present).")
    print("  Note: trace-only provenance floors at INDETERMINATE; CONFIRMED needs an "
          "active backend probe.")


def cmd_agent_trace(a):
    """Ingest a captured agent run (OTel GenAI spans or minimal JSON) and report
    per-step model + switch + egress."""
    from . import agent
    steps = agent.load(a.file)
    result = agent.analyze(steps, offline=a.offline, resolve_hosts=a.resolve_hosts)
    _print_agent_board(result, a.file)
    if a.out:
        json.dump({"steps": [{k: v for k, v in s.items() if k != "score"}
                             for s in result["steps"]],
                   "verdict": result["verdict"]}, open(a.out, "w"), indent=2)
        print(f"\n[+] {a.out}")
    if a.html:
        from . import agent_report
        open(a.html, "w").write(agent_report.render_html(result, a.file))
        print(f"[+] {a.html}  (open in a browser; hover any term to learn what it means)")
    if a.export:
        from . import agent_export
        agent_export.write_bundle(
            a.export, result, target=os.path.splitext(os.path.basename(a.file))[0],
            input_text=open(a.file, encoding="utf-8").read(),
            captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            observation=["trace"])
        print(f"[+] {a.export}  (signed-ready evidence record — drop into the observatory data tree)")
    sys.exit(2 if result["verdict"]["alert"] else 0)


def cmd_agent(a):
    """Config-driven agent assessment: trace ingest + optional active backend probe."""
    from . import agent
    from .config import load_agent
    at = load_agent(a.config)
    if not at.trace_path:
        sys.exit(f"[abort] agent '{at.name}' has no trace_path (Phase 1 needs a captured run).")
    steps = agent.load(at.trace_path)

    overrides: dict[int, dict] = {}
    if "active-probe" in at.observation and at.backends:
        agent.assert_backends_authorized(at.backends, a.i_am_authorized)  # raises if not
        ref = tokenizer.load_reference()
        for bk in at.backends:
            t = bk.to_target(f"{at.name}-backend")
            c = Client(t)
            tok = tokenizer.measure(c)
            if tok.get("usable"):
                match = tokenizer.compare(tok, ref)
                bk_host = agent._host_of(bk.base_url)
                for st in steps:
                    if st.kind == "model" and agent._host_of(st.backend_url) == bk_host:
                        overrides[st.index] = {"tokenizer": tok, "tokenizer_match": match}
    result = agent.analyze(steps, offline=at.offline, resolve_hosts=True, step_overrides=overrides)
    _print_agent_board(result, at.name)
    if a.out:
        json.dump({"agent": at.name, "verdict": result["verdict"]}, open(a.out, "w"), indent=2)
        print(f"\n[+] {a.out}")
    if a.html:
        from . import agent_report
        open(a.html, "w").write(agent_report.render_html(result, at.name))
        print(f"[+] {a.html}  (open in a browser; hover any term to learn what it means)")
    if a.export:
        from . import agent_export
        agent_export.write_bundle(
            a.export, result, target=at.name,
            input_text=open(at.trace_path, encoding="utf-8").read() if at.trace_path else "",
            captured_at=datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
            observation=at.observation)
        print(f"[+] {a.export}  (signed-ready evidence record — drop into the observatory data tree)")
    sys.exit(2 if result["verdict"]["alert"] else 0)


def cmd_redteam(a):
    """Drive an authorized endpoint through the adversarial corpus; alert on a
    model-identity switch under stress."""
    from . import redteam
    if not a.i_am_authorized:
        sys.exit("[abort] redteam sends deliberately adversarial prompts. Pass "
                 "--i-am-authorized to attest written authorization for these targets.")
    targets = load_targets(a.config)
    rc = 0
    for t in targets:
        _assert_scope(t, a.i_am_authorized)
        print(f"\n>>> red-team {t.name}  {t.base_url}  (cap {a.cap})")
        result = redteam.run(Client(t), cap=a.cap)
        for row in result["identities"]:
            if "error" in row:
                print(f"  {row['scenario']:<16} error: {row['error']}")
            else:
                print(f"  {row['scenario']:<16} model={row['model_id'] or '-'}  self-id={row['self_id'] or '-'}")
        if result["switch_detected"]:
            print("\n  SWITCH UNDER STRESS:")
            for s in result["switches"]:
                print(f"    [{s['scenario']}] {s['signal']}: {s['from']} -> {s['to']}")
            rc = 2
        print(f"\n  {result['note']} ({result['scenarios_run']} scenarios)")
        if a.out:
            json.dump(result, open(a.out, "w"), indent=2)
            print(f"  [+] {a.out}")
    sys.exit(rc)


def cmd_omniroute(a):
    """OmniRoute optional accelerator: detect, calibrate, cross-check (P2).

    Fingerprints a route THROUGH a local OmniRoute and cross-checks the router's
    claimed model against the tokenizer fingerprint — but only trusts the result
    once the calibration gate passes for the running OmniRoute version. Until
    then the via-OmniRoute verdict is confidence-capped (honest by construction).
    """
    from . import omniroute as omni
    base = a.base
    st = omni.detect_omniroute(base)
    if not st.present:
        sys.exit(f"[omniroute] not reachable at {base}: {st.error}")
    # Banner to stderr so `--json` stdout stays pure JSON (pipeable).
    print(f"[omniroute] present at {base} (version {st.version or 'unknown'}), "
          f"{len(st.models)} routes", file=sys.stderr)
    if a.list or not a.route:
        for m in st.models:
            print(f"  {m}")
        if not a.route:
            print("\nPass --route <id> [--expect-ref <REFKEY> --i-am-authorized] to fingerprint + cross-check.")
        return
    t = Target(name=f"omniroute:{a.route}", base_url=base, model=a.route,
               api_style="openai", chat_path="/chat/completions",
               authorized=a.i_am_authorized)
    _assert_scope(t, a.i_am_authorized)
    client = Client(t)
    r0 = client.chat("hi", max_tokens=1, temperature=0.0)
    hdrs = omni.omniroute_headers(r0.headers)
    version = st.version or hdrs.get("version", "")   # version rides chat headers, not /models
    obs = tokenizer.measure(client)
    ranked = tokenizer.compare(obs)
    top = ranked[0] if ranked else None
    fam = top["family"] if top else None
    cal = None
    if a.expect_ref:
        ref = tokenizer.load_reference().get("models", {}).get(a.expect_ref)
        if not ref:
            sys.exit(f"[omniroute] unknown --expect-ref '{a.expect_ref}' (not in reference)")
        cal = omni.calibrate(obs.get("vector", {}), ref.get("vector", {}),
                             expected_family=ref.get("family", a.expect_ref),
                             omniroute_version=version, route=a.route)
    # The router's CLAIM is OmniRoute's OWN header, NOT the route the user typed.
    # If x-omniroute-model is absent there is no independent claim -> INCONCLUSIVE
    # (don't corroborate the user's input against the fingerprint) (Codex review).
    router_claim = hdrs.get("model", "")
    calibrated = bool(cal and cal.passed)
    cc = omni.cross_check(router_claim, fam, calibrated=calibrated,
                          router_provider=hdrs.get("provider", ""))
    top_score = (top["score"] if top else 0.0) or 0.0
    # Through a proxy, CONFIRMED requires everything: calibration passed AND a
    # decisive fingerprint match AND the router claim actively CORROBORATES it.
    # An INCONCLUSIVE cross-check (no/unmapped router claim) is not corroboration,
    # so it caps at SUGGESTIVE; CONTRADICTED is quarantined and never published
    # (Codex + Claude adversarial review).
    confirmed = (calibrated and cc.state == omni.CORROBORATED and top_score >= 0.75)
    out = {
        "route": a.route, "measurement_path": "via_omniroute",
        "omniroute_version": version, "router_headers": hdrs,
        "router_claim": router_claim or None,
        "fingerprint": {"family": fam, "origin": top["origin"] if top else None,
                        "score": top["score"] if top else None,
                        "exact": top["exact_matches"] if top else None,
                        "shared": top["shared_probes"] if top else None},
        "calibration": (cal.__dict__ if cal else {"passed": False,
                        "note": "no --expect-ref given; not calibrated -> confidence-capped"}),
        "cross_check": cc.__dict__,
        "quarantined": cc.state == omni.CONTRADICTED,
        "confidence_cap": "CONFIRMED" if confirmed else "SUGGESTIVE",
    }
    if a.json:
        print(json.dumps(out, indent=2, default=str))
    else:
        print(f"\nfingerprint: {fam} (origin {out['fingerprint']['origin']}, "
              f"score {out['fingerprint']['score']}, exact {out['fingerprint']['exact']}/{out['fingerprint']['shared']})")
        if cal:
            print(f"calibration: {'PASSED' if cal.passed else 'FAILED'} "
                  f"(exact {cal.exact_frac}, overhead {cal.template_overhead}, "
                  f"{cal.distorted}/{cal.shared_probes} distorted, max residual {cal.max_residual})")
            print(f"  {cal.note}")
        print(f"cross-check: {cc.state}")
        print(f"  {cc.note}")
        if out["quarantined"]:
            print("  ** QUARANTINED: router claim contradicts the fingerprint. This is an "
                  "analyst-review signal, NOT an auto-published verdict. **")
        print(f"confidence cap: {out['confidence_cap']} "
              f"(via OmniRoute is never CONFIRMED until calibration passes)")


def _default_har_path(url: str) -> str:
    """A private, non-repo captures path for a credential-bearing HAR."""
    from urllib.parse import urlsplit
    home = os.path.expanduser(os.environ.get("PROVENANCE_PROBE_HOME", "~/.provenance-probe"))
    host = (urlsplit(url if "://" in (url or "") else "https://" + (url or "")).hostname or "capture")
    return os.path.join(home, "captures", f"{host}-{uuid.uuid4().hex[:8]}.har")


def _ensure_har_gitignored(har_path: str) -> None:
    """If the HAR landed inside a git repo, make sure it can't be committed."""
    import subprocess
    d = os.path.dirname(os.path.abspath(har_path))
    try:
        top = subprocess.run(["git", "-C", d, "rev-parse", "--show-toplevel"],
                             capture_output=True, text=True, timeout=5)
    except Exception:
        return
    if top.returncode != 0:
        return                                  # not in a repo — private dir, fine
    from . import wizard
    rel = os.path.relpath(os.path.abspath(har_path), top.stdout.strip())
    try:
        wizard.ensure_gitignored(top.stdout.strip(), rel)
    except OSError:
        pass


def cmd_capture(a):
    """Guided web-app capture (E8). Prints annotated steps; with the optional
    Playwright extra installed and --auto, drives a browser to capture for you."""
    from . import capture_guide
    from . import capture_playwright as cap
    avail = cap.playwright_available()
    if a.auto:
        if not avail:
            print("[capture] Playwright not installed — showing the manual steps instead.\n",
                  file=sys.stderr)
            print(capture_guide.as_text(capture_guide.guide(a.url, browser=a.browser,
                                                            playwright_available=False)))
            return
        if not a.i_am_authorized:
            sys.exit("[abort] --auto drives a real browser to the target; pass "
                     "--i-am-authorized to attest you're authorized to test it.")
        har = a.out or _default_har_path(a.url)
        os.makedirs(os.path.dirname(har) or ".", exist_ok=True)
        print(f"[capture] opening a browser at {a.url}. You'll log in first, THEN send one "
              f"message — the login is not recorded.", file=sys.stderr)
        res = cap.capture(a.url, har)
        if not res.ok:
            sys.exit(f"[capture] {res.error}")
        _ensure_har_gitignored(res.har_path)
        print(f"[capture] wrote {res.har_path} (mode 0600). It contains your SESSION COOKIE — "
              f"treat it as a credential; do NOT share or commit it.")
        print(f"[capture] next: run `provenance-probe serve`, open /wizard, and paste the HAR "
              f"contents. The wizard stores the cookie in a gitignored .env.capture and keeps "
              f"it out of the committed config.")
        return
    # Default: print the guided manual steps.
    g = capture_guide.guide(a.url, browser=a.browser, playwright_available=avail)
    print(capture_guide.as_text(g))


def cmd_init(a):
    write_example(a.path)
    print(f"Wrote example config -> {a.path}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="provenance-probe", description=BANNER,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

    s = sub.add_parser("omniroute",
                       help="OmniRoute accelerator: detect, calibrate, cross-check a route")
    s.add_argument("--base", default="http://localhost:20128/v1", help="OmniRoute base URL")
    s.add_argument("--list", action="store_true", help="list available routes and exit")
    s.add_argument("--route", default="", help="route/model id to fingerprint (e.g. oc/deepseek-v4-flash-free)")
    s.add_argument("--expect-ref", dest="expect_ref", default="",
                   help="reference model key of the route's KNOWN family, to run the calibration gate (e.g. DeepSeek-V3)")
    s.add_argument("--i-am-authorized", dest="i_am_authorized", action="store_true",
                   help="attest authorization to actively probe this route")
    s.add_argument("--json", action="store_true", help="emit the full evidence record as JSON")
    s.set_defaults(func=cmd_omniroute)

    s = sub.add_parser("capture",
                       help="guided web-app request capture (E8); --auto uses optional Playwright")
    s.add_argument("url", nargs="?", default="", help="the web app URL to capture from")
    s.add_argument("--browser", default="chrome", choices=["chrome", "firefox", "safari"],
                   help="tailor the DevTools steps to your browser")
    s.add_argument("--auto", action="store_true",
                   help="drive a real browser to capture (needs the [capture] extra)")
    s.add_argument("--out", default="",
                   help="HAR output path for --auto (default: a private 0600 ~/.provenance-probe/captures/ file)")
    s.add_argument("--i-am-authorized", dest="i_am_authorized", action="store_true",
                   help="attest authorization to drive a browser to this target (--auto)")
    s.set_defaults(func=cmd_capture)

    s = sub.add_parser("init", help="write an example target config")
    s.add_argument("--path", default="targets.json")
    s.set_defaults(func=cmd_init)

    s = sub.add_parser("build-reference", help="build local tokenizer reference vectors")
    s.add_argument("--hf-token", default=None, help="or set HF_TOKEN")
    s.add_argument("--overwrite", action="store_true",
                   help="discard existing vectors instead of merging")
    s.add_argument("--allow-remote-code", action="store_true",
                   help="DANGEROUS: executes tokenizer code from the repo. Container only.")
    s.add_argument("--only", action="append",
                   help="build just this repo or label; repeatable")
    s.add_argument("--variant-seed", type=int, default=0,
                   help="build the reference for a rotated probe set (evasion "
                        "hardening); 0 = canonical corpus. Probe with the same seed.")
    s.set_defaults(func=cmd_build_reference)

    s = sub.add_parser("verify-reference", help="self-check the reference file")
    s.set_defaults(func=cmd_verify_reference)

    s = sub.add_parser("build-reference-endpoint",
                       help="measure a reference vector from a live authorized first-party "
                            "endpoint (for families with no published tokenizer, e.g. Claude/Gemini)")
    s.add_argument("--config", required=True, help="target config (JSON) with the endpoint")
    s.add_argument("--name", default=None, help="target name to use (default: first in config)")
    s.add_argument("--label", required=True, help="reference entry label, e.g. 'Claude'")
    s.add_argument("--family", required=True, help="family label, e.g. 'Claude/Anthropic'")
    s.add_argument("--origin", required=True, help="origin tag, e.g. 'US' / 'CN' / 'EU'")
    s.add_argument("--overwrite", action="store_true",
                   help="replace an existing entry even if it came from another source")
    s.add_argument("--i-am-authorized", action="store_true",
                   help="attest written authorization AND that this is the genuine first party")
    s.set_defaults(func=cmd_build_reference_endpoint)

    s = sub.add_parser("assess", help="full multi-layer assessment of configured targets")
    s.add_argument("--config", default="targets.json")
    s.add_argument("--out", default="./reports")
    s.add_argument("--artifacts", help="also scan a local model directory")
    s.add_argument("--client-dir", help="scan unpacked client assets (JS bundle, APK, desktop app)")
    s.add_argument("--client-url", help="fetch a web app and scan its HTML + scripts")
    s.add_argument("--latency", action="store_true", help="run latency profiling")
    s.add_argument("--latency-n", type=int, default=12)
    s.add_argument("--leak-samples", type=int, default=2)
    s.add_argument("--no-tokenizer", action="store_true")
    s.add_argument("--no-behavioral", action="store_true")
    s.add_argument("--no-deception", action="store_true")
    s.add_argument("--confront-as", help="backend your hard evidence shows, e.g. 'Zhipu GLM'")
    s.add_argument("--confront-control", default="Mistral AI",
                   help="deliberately WRONG backend used as a sycophancy control")
    s.add_argument("--session-test", action="store_true",
                   help="probe for anti-forensic session termination")
    s.add_argument("--offline", action="store_true", help="skip RDAP lookups")
    s.add_argument("--i-am-authorized", action="store_true",
                   help="attest you have written authorization to test these targets")
    s.add_argument("--variant-seed", type=int, default=0,
                   help="probe with a rotated probe set (evasion hardening); must "
                        "match the reference's seed (build-reference --variant-seed).")
    s.set_defaults(func=cmd_assess)

    s = sub.add_parser("monitor", help="diff two assessment JSONs; exit 2 on drift")
    s.add_argument("--baseline", required=True)
    s.add_argument("--current", required=True)
    s.add_argument("--json-out")
    s.set_defaults(func=cmd_monitor)

    s = sub.add_parser("artifacts", help="inspect a local/on-prem model directory")
    s.add_argument("path")
    s.set_defaults(func=cmd_artifacts)

    s = sub.add_parser("serve", help="run the local web UI (binds 127.0.0.1)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8770)
    s.add_argument("--debug", action="store_true")
    s.set_defaults(func=cmd_serve)

    s = sub.add_parser("clientsrc", help="scan client-side source for endpoints and persona mismatch")
    s.add_argument("--dir")
    s.add_argument("--url")
    s.set_defaults(func=cmd_clientsrc)

    s = sub.add_parser("network", help="jurisdiction-analyze hosts (e.g. SNI names from a capture)")
    s.add_argument("--host", action="append")
    s.add_argument("--hosts-file")
    s.add_argument("--offline", action="store_true")
    s.set_defaults(func=cmd_network)

    s = sub.add_parser("sentinel",
                       help="real-time in-line model-switch sentinel: reverse-proxy an "
                            "upstream and alert the instant the served model switches")
    s.add_argument("--upstream", required=True, help="upstream endpoint root (…/v1 appended)")
    s.add_argument("--host", default="127.0.0.1")
    s.add_argument("--port", type=int, default=8900)
    s.add_argument("--events-file", help="append model-change events as JSONL here")
    s.set_defaults(func=cmd_sentinel)

    s = sub.add_parser("session",
                       help="fingerprint an endpoint at session start + end; "
                            "exit 2 if the served model switched mid-session")
    s.add_argument("--config", required=True)
    s.add_argument("--gap-probes", type=int, default=5,
                   help="filler turns between the start and end snapshots")
    s.add_argument("--variant-seed", type=int, default=0)
    s.add_argument("--out", help="write the boundary-check JSON here")
    s.add_argument("--i-am-authorized", action="store_true")
    s.set_defaults(func=cmd_session)

    s = sub.add_parser("transcript",
                       help="analyze a captured conversation for identity deception + "
                            "mid-session model switches; exit 2 on a switch/misrepresentation")
    s.add_argument("file", help="transcript file (.json list of {role,content}, or 'Speaker: text')")
    s.add_argument("--true-origin", choices=["CN", "nonCN"], default=None,
                   help="the endpoint's real origin (e.g. z.ai -> CN); needed to assert misrepresentation")
    s.add_argument("--true-detail", default="", help="one line of hard evidence for the origin")
    s.add_argument("--out", help="write full JSON result here")
    s.set_defaults(func=cmd_transcript)

    s = sub.add_parser("agent-trace",
                       help="ingest a captured agent run (OpenTelemetry GenAI spans or "
                            "minimal JSON) and report per-step model + switch + egress; "
                            "exit 2 on a model switch")
    s.add_argument("file", help="agent trace file (OTel spans JSON or {'steps':[...]})")
    s.add_argument("--offline", action="store_true", help="skip RDAP lookups when resolving")
    s.add_argument("--resolve-hosts", action="store_true",
                   help="DNS-resolve trace-supplied hosts (default off: an ingested trace "
                        "is untrusted; static hostname jurisdiction signals still fire)")
    s.add_argument("--out", help="write the per-step board JSON here")
    s.add_argument("--html", help="write a self-contained HTML report with hover "
                                  "tooltips that explain every term and verdict")
    s.add_argument("--export", help="write a deterministic, signed-ready evidence "
                                    "record (drop into the observatory data tree to sign)")
    s.set_defaults(func=cmd_agent_trace)

    s = sub.add_parser("agent",
                       help="config-driven agent assessment: trace ingest + optional "
                            "active backend probe (the only route to CONFIRMED provenance)")
    s.add_argument("--config", required=True, help="AgentTarget JSON (observation, trace_path, backends)")
    s.add_argument("--out", help="write the agent verdict JSON here")
    s.add_argument("--html", help="write a self-contained HTML report with hover "
                                  "tooltips that explain every term and verdict")
    s.add_argument("--export", help="write a deterministic, signed-ready evidence "
                                    "record (drop into the observatory data tree to sign)")
    s.add_argument("--i-am-authorized", action="store_true",
                   help="attest written authorization for EACH backend actively probed")
    s.set_defaults(func=cmd_agent)

    s = sub.add_parser("redteam",
                       help="drive an authorized endpoint through an adversarial corpus; "
                            "exit 2 if the served model identity switches under stress")
    s.add_argument("--config", required=True, help="target config JSON")
    s.add_argument("--cap", type=int, default=8, help="max scenarios to send (quota guard)")
    s.add_argument("--out", help="write the red-team result JSON here")
    s.add_argument("--i-am-authorized", action="store_true",
                   help="attest written authorization to send adversarial prompts")
    s.set_defaults(func=cmd_redteam)

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    main()
