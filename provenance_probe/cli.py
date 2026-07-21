#!/usr/bin/env python3
"""provenance-probe CLI."""
from __future__ import annotations
import argparse, json, os, sys, datetime, hashlib

from .config import load_targets, write_example, Target
from .client import Client
from .probes import (network, tokenizer, behavioral, wire, latency, logprob,
                     artifact, clientsrc, deception)
from . import scoring, report, reference, userwarn

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
        b["fingerprint_id"] = _fp(b)
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


def _fp(b: dict) -> str:
    """Stable identity of the serving backend, for drift detection.

    The tokenizer component hashes the overhead-invariant shape of the probe
    vector, not the raw prompt_tokens counts. A constant chat-template /
    token-accounting shift by the endpoint therefore does NOT flip the
    fingerprint (it would otherwise read as a false model swap); a genuine
    change in tokenizer family, which changes the relative structure between
    probes, still does. See tokenizer.shape_vector.
    """
    parts = [
        json.dumps(tokenizer.shape_vector((b.get("tokenizer") or {}).get("vector", {})), sort_keys=True),
        (b.get("errors") or {}).get("error_signature", ""),
        (b.get("headers") or {}).get("header_shape_hash", ""),
        (b.get("greedy") or {}).get("signature", ""),
        json.dumps((b.get("streaming") or {}).get("chunk_fields", [])),
    ]
    return hashlib.sha256("||".join(parts).encode()).hexdigest()[:24]


def cmd_monitor(a):
    """Compare a fresh run against a stored baseline. Detects silent model swaps."""
    base = json.load(open(a.baseline))
    cur = json.load(open(a.current))
    out = {"baseline": a.baseline, "current": a.current, "changes": []}
    if base.get("fingerprint_id") != cur.get("fingerprint_id"):
        out["changes"].append({"severity": "critical", "field": "fingerprint_id",
                               "detail": "Composite backend fingerprint changed — the serving model "
                                         "or stack was altered since baseline."})
    # Compare the overhead-invariant shape, not raw prompt_tokens: a constant
    # chat-template / accounting shift moves every probe by the same amount and
    # is NOT a model change. Only a shift in the relative structure between
    # probes indicates a different tokenizer family. (Same rationale as _fp.)
    bt = tokenizer.shape_vector((base.get("tokenizer") or {}).get("vector", {}))
    ct = tokenizer.shape_vector((cur.get("tokenizer") or {}).get("vector", {}))
    diff = {k: (bt[k], ct[k]) for k in bt if k in ct and bt[k] != ct[k]}
    if diff:
        out["changes"].append({"severity": "critical", "field": "tokenizer_vector",
                               "detail": f"Tokenizer shape changed on {len(diff)} probes (overhead-corrected): "
                                         + ", ".join(f"{k} {v[0]}->{v[1]}" for k, v in list(diff.items())[:6]),
                               "implication": "Different tokenizer => different model family."})
    if (base.get("errors") or {}).get("error_signature") != (cur.get("errors") or {}).get("error_signature"):
        out["changes"].append({"severity": "high", "field": "error_signature",
                               "detail": "Error schema changed — likely a different backend provider."})
    for k in ("jurisdictional_risk", "provenance_risk"):
        bv = (base.get("score") or {}).get(k, {}).get("verdict")
        cv = (cur.get("score") or {}).get(k, {}).get("verdict")
        if bv != cv:
            out["changes"].append({"severity": "high", "field": k,
                                   "detail": f"{k}: {bv} -> {cv}"})
    if base.get("latency") and cur.get("latency"):
        d = latency.drift(base["latency"], cur["latency"])
        if d["drifted"]:
            out["changes"].append({"severity": "medium", "field": "latency",
                                   "detail": json.dumps(d["signals"])})
    out["drift_detected"] = bool(out["changes"])
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

    a = p.parse_args(argv)
    return a.func(a)


if __name__ == "__main__":
    main()
