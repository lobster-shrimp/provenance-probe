"""Single source of truth for "assess one target -> a full bundle".

Historically the per-target assessment was written twice: once in the CLI
(``cli.cmd_assess``) and once in the web service (``serve._run``). The two
drifted — notably ``cmd_assess`` never stored ``fingerprint_id`` while
``serve`` computed it inline (``serve.py``). For the ``watch`` daemon to
produce baselines that are comparable to what ``serve`` / the observatory
produce, all three MUST build the bundle — and above all the
``fingerprint_id`` — the same way.

This module extracts that one flow. ``assess_target(target, opts)`` returns the
FULL bundle including ``score``, ``user_warning`` and ``fingerprint_id``. The
CLI, the web service and the daemon all call it, so there is exactly ONE
definition of what a "bundle" is and how its fingerprint is computed.

The extraction is behavior-preserving: the probe set, their arguments and the
resulting bundle keys are unchanged. Only the human-facing progress messages
are funneled through optional callbacks so each caller can render them its own
way (the CLI prints them; the web service maps them to a progress bar).
"""
from __future__ import annotations

import datetime
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import Target
from .client import Client
from .probes import (network, tokenizer, behavioral, wire, latency, logprob,
                     artifact, clientsrc, deception)
from . import scoring, userwarn, monitor


@dataclass
class AssessOpts:
    """Knobs for a single-target assessment.

    Mirrors the existing ``cmd_assess`` flags one-for-one so the shared helper
    is a straight extraction, not a redesign. The daemon flips ``no_behavioral``
    / ``no_deception`` on for a fast, cheap re-check (matching the P2 default).
    """
    no_tokenizer: bool = False
    no_behavioral: bool = False
    no_deception: bool = False
    latency: bool = False
    latency_n: int = 12
    leak_samples: int = 2
    offline: bool = False
    variant_seed: int = 0
    confront_as: str = ""
    confront_control: str = "Mistral AI"
    session_test: bool = False
    client_dir: str = ""
    client_url: str = ""
    artifacts_dir: str = ""


# Callback types: progress(label, pct) for a progress display, note(msg) for
# incidental warnings (e.g. a variant-seed mismatch). Both optional; default no-op.
Progress = Optional[Callable[[str, int], None]]
Note = Optional[Callable[[str], None]]


def hard_evidence(b: dict) -> tuple[Optional[str], str]:
    """Origin per the layers that are hard to fake: source, network, tokenizer.

    Shared by both former call sites (they held byte-identical copies). Returns
    ``(origin, detail)`` where origin is ``"CN"`` / ``"nonCN"`` / ``None``.
    """
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


def assess_target(target: Target, opts: AssessOpts, *,
                  progress: Progress = None, note: Note = None,
                  client: Optional[Client] = None) -> dict:
    """Full multi-layer bundle incl. ``score``, ``user_warning``, ``fingerprint_id``.

    The single source of truth for what a "bundle" is across the CLI, the web
    service and the daemon. Pure with respect to the filesystem — it does NOT
    write reports; the caller decides where the returned bundle goes.
    """
    def _p(label: str, pct: int) -> None:
        if progress:
            progress(label, pct)

    def _n(msg: str) -> None:
        if note:
            note(msg)

    c = client or Client(target)
    b: dict = {
        "target": {"name": target.name, "base_url": target.base_url,
                   "model": target.model, "api_style": target.api_style},
        "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
    }

    _p("network / jurisdiction", 8)
    b["network"] = network.analyze_host(target.base_url, do_rdap=not opts.offline)

    _p("wire fingerprint", 20)
    b["headers"] = wire.header_fingerprint(c)
    b["errors"] = wire.error_schema_fingerprint(c)
    b["streaming"] = wire.streaming_fingerprint(c)
    b["catalog"] = wire.model_catalog(c)

    if opts.client_dir or opts.client_url:
        _p("client-source scan", 30)
        # Dir-first precedence (matches the pre-refactor CLI). The user-supplied
        # URL fetch is routed through the probe Client's session so it honors the
        # SSRF egress guard in public-hosting mode (and any target proxy);
        # byte-identical to a stock fetch when the guard is unset.
        b["client_source"] = (clientsrc.scan_dir(opts.client_dir) if opts.client_dir
                              else clientsrc.scan_url(opts.client_url, session=c.s))

    if not opts.no_tokenizer:
        _p("tokenizer fingerprint", 45)
        ref = tokenizer.load_reference()
        _ref_seed = ref.get("variant_seed", 0) if ref else 0
        if (opts.variant_seed or 0) != _ref_seed:
            _n(f"        ! variant-seed {opts.variant_seed} != reference seed {_ref_seed}; "
               f"rebuild the reference with --variant-seed {opts.variant_seed} or the match is invalid")
        b["tokenizer"] = tokenizer.measure(c, variant_seed=opts.variant_seed or 0)
        if b["tokenizer"]["usable"]:
            b["tokenizer_match"] = tokenizer.compare(b["tokenizer"], ref)
        else:
            _n("        ! endpoint did not return usage.prompt_tokens — "
               "tokenizer layer unavailable (itself a transparency finding)")

    _p("logprob / determinism", 58)
    b["logprobs"] = logprob.logprob_signature(c)
    b["greedy"] = logprob.greedy_signature(c)

    if not opts.no_deception:
        _p("deception: persona + jurisdiction claims", 70)
        d: dict = {"persona": deception.persona_claim(c),
                   "jurisdiction": deception.jurisdiction_claims(c),
                   "trace": deception.reasoning_trace_capture(c)}
        if opts.confront_as:
            _p(f"confrontation vs '{opts.confront_as}' (+ false control)", 80)
            d["confrontation"] = deception.confront(
                c, opts.confront_as, opts.confront_control or "Mistral AI")
        if opts.session_test:
            d["session"] = deception.session_resilience(c)
        b["deception"] = d

    if not opts.no_behavioral:
        _p("self-identification + alignment asymmetry", 88)
        b["selfid"] = behavioral.self_identification(c)
        b["alignment"] = behavioral.alignment_asymmetry(c)
        b["leakage"] = behavioral.language_leakage(c, samples=opts.leak_samples)

    if opts.latency:
        _p("latency profile", 92)
        b["latency"] = latency.profile(c, n=opts.latency_n)

    if opts.artifacts_dir:
        _p("artifact scan", 94)
        b["artifacts"] = artifact.scan_dir(opts.artifacts_dir)

    if b.get("deception"):
        origin, detail = hard_evidence(b)
        b["deception"]["correlation"] = deception.correlate(
            b["deception"]["persona"], b["deception"]["jurisdiction"], origin, detail)

    _p("scoring", 97)
    b["score"] = scoring.score(b)
    b["user_warning"] = userwarn.build(b)
    # Stable backend fingerprint so this run can be diffed against a baseline
    # (silent model-swap detection). Computed HERE so the CLI, the web service
    # and the daemon are byte-identical.
    b["fingerprint_id"] = monitor.fingerprint(b)
    return b
