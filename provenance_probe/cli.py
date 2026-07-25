#!/usr/bin/env python3
"""provenance-probe CLI."""
from __future__ import annotations
import argparse, json, os, sys, datetime, hashlib

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


def cmd_init(a):
    write_example(a.path)
    print(f"Wrote example config -> {a.path}")


def main(argv=None):
    p = argparse.ArgumentParser(prog="provenance-probe", description=BANNER,
                                formatter_class=argparse.RawDescriptionHelpFormatter)
    sub = p.add_subparsers(dest="cmd", required=True)

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

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    main()
