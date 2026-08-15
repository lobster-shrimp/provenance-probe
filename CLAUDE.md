# CLAUDE.md — LLM-Provenance

One project, two repos. This file is the combined orientation for both:

| Repo | Role |
|---|---|
| `provenance-probe` | The **engine**: black-box CLI + local Flask web UI that determines which model actually serves an endpoint, and whether it is Chinese-origin or PRC-jurisdiction. Point-in-time, runs 100% local. |
| `provenance-observatory` | The **continuous public layer** built on the probe as a black-box CLI: nightly GitHub-Actions probes of a watch list, a cosign/Rekor-signed append-only evidence log, numbered advisories (MPA-YYYY-NNN), a FastAPI JSON API, and a GitHub Pages site. |

The observatory contains **no fingerprinting logic** — it consumes the probe strictly as a CLI (`assess`, `monitor`'s exit-2 drift contract, `fingerprint_id`) and never imports its internals (decision T7).

## Mission

Vendors can silently swap models, reroute requests, or resell a Chinese-origin model under a Western name — and the customer normally has no way to tell. This project catches it with black-box measurement, no vendor cooperation required, and reports it plain-language-first ("this app uses an AI model built in China"), with the evidence laid out like a lab report underneath. The founding field case: a chat app presenting a Google Gemini persona whose actual backend was GLM (Zhipu), with z.ai endpoints in the client source. Framing used throughout: **Face** (claimed persona) / **Brain** (actual model) / **Pipeline** (where the data actually goes).

## The two verdicts — never collapse them

| Verdict | Question | Hard-to-fake evidence |
|---|---|---|
| **Provenance** | Are the model *weights* Chinese-origin, wherever they run? | Tokenizer fingerprint, embedded persona, catalog |
| **Jurisdiction** | Is inference executed by a PRC-domiciled operator / on PRC soil? | Network/RDAP, TLS/wire, client-source operators |

A vendor can be clean on one and dirty on the other; Chinese open weights inside your own boundary carry zero data-jurisdiction exposure. Every verdict carries an honest confidence label (CONFIRMED / LIKELY / INDETERMINATE / UNLIKELY / NO EVIDENCE) and a measured false-positive rate — never "proof". The showcase target `omniroute-deepseek-local` exists to demonstrate the split: provenance CONFIRMED CN, jurisdiction UNLIKELY (localhost).

## How detection works (core algorithm)

The load-bearing signal is the **tokenizer fingerprint**: ~20 corpus probes (`provenance_probe/data/corpus.py`) sent with `max_tokens=1, temperature=0`; the endpoint's self-reported `usage.prompt_tokens` per probe forms a vector matched against **27 reference vectors spanning 22 model families** (`data/tokenizer_ref.json`). Chat-template overhead is cancelled via the median observed−reference delta; the match score is half continuous closeness (normalized L1, clipped) and half exact-match fraction; a family is called at score ≥ 0.75, and the reference entry's `origin` (CN/US/EU/…) drives the provenance verdict. Han tokens-per-character is a **supporting** signal only (Command-R overlaps the CN families). `usage.prompt_tokens` is self-reported and could be forged — hence the confidence label and the linear-ramp consistency check.

Seven more layers corroborate, each degrading independently (a missing layer lowers confidence, never crashes): network/RDAP jurisdiction, wire fingerprint (headers/error schema/catalog), logprob/determinism, behavioral (self-ID, alignment asymmetry, CJK leakage), latency, deception (persona-vs-jurisdiction confrontation), and client-source/artifacts. `scoring.py` fuses them; `monitor.py` hashes an overhead-invariant shape + wire signature into a `fingerprint_id` and **exits 2 on drift** (the CI/cron primitive for catching a silent swap).

## provenance-probe (engine) — v0.23.1, Python ≥3.10

Package `provenance_probe/`, entry point `provenance-probe` (`cli.py:main`). Deps: requests + flask; extras `[reference]` (build tokenizer refs from HF), `[eval]`, `[capture]` (Playwright/mitmproxy), `[test]`.

Key commands: `serve` (local UI on 127.0.0.1:8770 — probe tool, `/catalog` searchable LLM-API table, `/wizard` add-target, `/agent` board, `/watch` in-tab watcher), `catalog`/`build-catalog` (searchable running table of inference APIs × models × model-card facts, joined with corpus.py provenance — built from models.dev (MIT), observatory refreshes+signs nightly), `assess` (full multi-layer run), `agent-trace`/`agent` (per-step agent flight recorder — OTel GenAI or minimal JSON), `watch` (always-on local daemon: `--once` exit-2-on-drift / `--loop` / `--pin`; launchd/systemd generators), `sentinel` (live reverse-proxy tee + live board), `omniroute`, `capture` (guided or `--auto` two-phase Playwright capture — login never recorded), `redteam`, `monitor` (diff, exit 2 on drift), `build-reference`/`verify-reference`, `init`.

Module map: `probes/*.py` the eight layers; `scoring.py`/`report.py`/`userwarn.py` fuse + render; `detect.py` input classifier + API-probe state machine + consent gate + egress budget; `wizard.py` paste-anything target synthesis, dry-run, secure save; `presets.py` hostname-safe vendor presets; `omniroute.py` calibration gate + cross-check; `client.py`/`config.py` transport (openai/anthropic/raw/template) + `Target`; `assess.py` the single source of truth for a bundle — CLI, serve worker, and watch daemon all call `assess_target()` so baselines are byte-identical everywhere; `catalog.py` the LLM-API catalog (pure build/join/search; models.dev × corpus.py, bundled `data/catalog.json` snapshot); `serve.py` the web UI; `extension/` an MV3 Chrome capture extension (independent versioning, build-only workflow — not store-published).

The mock fixtures at repo root (`mock_real_qwen.py`, `mock_zai.py`, `mock_vendor.py`) power the demo and smoke tests: a fake "US" vendor `northstar-secure-1` fingerprinted as Qwen2, 20/20 exact.

### OmniRoute (proxy measurements are gated)

OmniRoute (local router, ~290 providers, `localhost:20128`) injects a hidden ~2000-token system prompt, so measuring *through* it is gated: `calibrate()` requires ≥0.90 of probes exact after offset (correlation deliberately rejected — Pearson false-passes cross-family). Measured: v3.8.48 lands 15/20 (0.75), so via-OmniRoute DeepSeek is **SUGGESTIVE, not CONFIRMED**. Every record carries `measurement_path: direct | via_omniroute`; CONFIRMED through a proxy needs calibration + a CORROBORATED router-vs-fingerprint cross-check + a decisive score. A **CONTRADICTED** cross-check is an analyst-review signal, **never auto-published** — enforced on both sides (probe + observatory signer).

### Security invariants (hardened by adversarial review — do not regress)

- **No egress before consent** — the wizard endpoint path sends nothing without a valid one-shot server-side consent token.
- **Credential values never reach git** — keys ride env-var *names* (`auth_value_env`); cookies ride a gitignored 0600 `.env.capture`; a write-boundary sanitize strips credential headers even from hand-edited targets.
- **No password handling, ever** — capture is two-phase; the login happens in an unrecorded browser context.
- **Hostname-aware vendor matching** — exact-or-subdomain, never substring (`api.openai.com.evil.test` is rejected).
- **All egress through the one `requests.Session`** (`Client.s`); the public-hosting guard (`PROVENANCE_PROBE_BLOCK_PRIVATE`) fails closed on private/loopback/metadata ranges with a DNS-rebinding pin that must never weaken TLS verification. `Client.chat()` never raises — transport errors return `Response(status=0, err=...)`.
- **`serve` binds 127.0.0.1**, same-origin gate on state-changing POSTs, constant-time basic-auth in `before_request`, no secret ever reflected or logged.
- **Never over-claim, never auto-accuse, authorization gates all active probing** (`authorized` flag per target/backend; behavioral probes send politically sensitive prompts — written authorization must cover that explicitly).

`.claude/agents/provenance-reviewer.md` is the repo-tuned read-only reviewer that checks changes against these invariants — use it for anything touching transport/egress, serve, capture/replay, fingerprint/scoring, or the observatory runner/signing. `.claude/agents/provenance-guide.md` is the repo-tuned interactive **assessment guide** — it walks a user through a passive scan → observatory watch-list entry, then an authorization-gated deep scan (two-phase capture → tokenizer fingerprint) and continuous model-switch monitoring, doing the non-interactive work and handing off only the human login + authorization attestation.

## provenance-observatory — Python ≥3.11

**Approach A (chosen): GitHub-native, zero servers.** Nightly Actions cron → probe CLI → verdicts committed to git (`data/<target>/<date>/verdict.json`) → signed daily manifest → Pages renders from `data/`. Graduate to a hosted service only if target count or probe-schedule privacy forces it. Live site: https://lobster-shrimp.github.io/provenance-observatory/

Layout: `targets.yaml` (watch list; `authorized` gates probing, U2 spend guard: 200 probes/run/target, $50/month ceiling — abort → `no-verdict{budget-exceeded}`); `runner/run.py` (nightly runner; retry once then commit `no-verdict{reason}` — no silent gaps); `runner/advisory.py`/`promote.py` (drift → numbered MPA advisory); `runner/agent_monitor.py` (nightly agent-composition fingerprinting → agent advisories); `lib/` (verdict assembly, canonical readers, cosign/Rekor signing, publish policy, RSS); `api/` (FastAPI: `/api/verdicts`, `/api/targets/{name}`, `/api/advisories`, `/api/model-changes`, `/api/status`, `/api/search`, SSE); `site/build.py` (static renderer).

### Load-bearing decisions (in-repo decision record)

- **Full transparency** (reversal of the original T5 two-tier/disclosure-window design): everything probed is published in full — measurements AND interpreted verdict — as collected. Accuracy comes from controls + published FP rate + confidence labels + prominent corrections/retractions (append-only; retractions are additions, never deletions), not from withholding.
- **P2b publication policy** — the one narrow exception, enforced by the signer (`lib/publish_policy.py`): a `via_omniroute` record is signable only with passing calibration + routing disclosure; CONTRADICTED cross-checks are quarantined (excluded from `entries`/`manifest_root`, filtered from all public verdict loaders, listed with reason in the transparency log). The promote path has a machine guard so a quarantine-worthy advisory can't be numbered as a back door.
- **T9 baseline discipline**: the pinned baseline advances only on a normal advisory close or post-stability blessing — never on an UNSTABLE-triggered close.
- **Controls are the accuracy gate**: `control-deepseek-positive` (must fingerprint CN) + `control-openai-negative` (must not) run nightly; default runs probe controls only. Commercial targets need `authorized:true` AND `OBSERVATORY_PROBE_COMMERCIAL=1`.
- **Probe randomization**: `OBSERVATORY_VARIANT_SEED=N` rotates on-wire probe bytes (defeats exact-string special-casing); the engine reference must be rebuilt for the same seed.

### Watch list state (targets.yaml, as of 2026-08)

Active: both controls, `openai-frontier`, `anthropic-frontier` (US references), `deepseek-direct`, `moonshot-direct` (CN-direct positives). On-demand local only: `omniroute-deepseek-local` (`authorized:false` on purpose — CI can't reach localhost). **`chat-z-ai-webapp` PAUSED 2026-08-05**: z.ai moved chat to a signed per-request API (time-bound signature, not replayable from a static template); last observed served model GLM-5.2 (up from GLM-4.6 — itself the kind of switch this exists to catch); re-enabling needs a z.ai-specific request-signing adapter. Pending capture + written auth + cookie: `lindy-chat-webapp`, `replit-agent-webapp`, `base44-webapp`. Out of scope for the method: ElevenLabs, Runway (no LLM text/prompt-token surface).

## Quality gates & dev workflow

- **Tests**: probe ~319 passing (`python -m pytest -q`; markers `unit` / `integration` — integration needs `[capture]`, skipped in CI). Observatory 121 passing. Lint: ruff.
- **Hermetic eval gates CI** (`python -m eval.run_eval`): consistency tier (11 real GGUF vocabs served blind through a mock — proves matcher/reference internal consistency, NOT live accuracy) + accuracy tier (labeled scoring bundles). Build goes red on **any FP** (a non-CN model flagged CN — the zero-FP launch gate), FN over a ratchet-down-only budget, a verdict-tier regression, or a harness error. CN eval cases stay synthetic in the public repo; named-vendor CN accuracy lives in the observatory.
- **Adversarial review**: every PR reviewed by two independent models (Codex + a Claude subagent); ~20 real issues fixed pre-merge across the project. Use the `provenance-reviewer` agent for security/accuracy-sensitive diffs.
- **CHANGELOG.md discipline**: every change lands with a versioned entry, including security notes.
- **Design system** (`DESIGN.md`): "a lab report you'd trust" — verdict-first, cream paper + deep-green poster band, exactly one hot accent per view (green=clean, coral=flagged, amber=caution), Fraunces display / Geist UI / Geist Mono evidence. Hard anti-slop rules; the serve pages are being unified onto shared CSS tokens.
- **Honesty is a feature**: trace-only provenance floors at INDETERMINATE; suppressed `usage.prompt_tokens` degrades coverage (surfaced as `degraded`), never silently upgrades; copy never oversells (see 0.23.1's "one-click" walk-back).

## Current goals

1. **Gate 1 — legal standing — is the real launch blocker** for named-vendor adverse verdicts: counsel must clear them (Together's ToS benchmarking ban is the sharpest edge; inputs are `DISCLOSURE.md` + `docs/tos-notes.md`; `docs/counsel-brief.md` and the OpenRouter approval request are staged). Gates 2 (published FP rate — done, 0 FP on live controls) and 3 (cosign/Rekor signing — done) are met. `SECURITY_CONTACT_TBD` / PGP key must be set before launch.
2. **Fleet detection — wedge SHIPPED (v0.27.0)** — `provenance-probe fleet-scan` (no-egress, read-only host forensics): discovers agent-CLI `base_url`s in config files + env, resolves localhost gateways to their real upstream via gateway-config parsing (the OmniRoute localhost blind-spot fix), and classifies against an operator allowlist + bundled `corpus.py` attribution as sub-CONFIRMED pointers (never a measured verdict). New pure `provenance_probe/gateways.py` keeps the no-egress boundary structural. Shipped: engine + CLI (#69); **osquery delivery** — `--sqlite` sink + `--print {launchd,systemd,cron,osquery-atc}` (#71); the **fleet host-attribution zero-FP control** wired into the hermetic eval gate (#72); the **prevention posture** — `--print allowlist-template` starter + `docs/fleet-posture.md`, report headlines `allowlist holding: N sanctioned, M drifted` not a rogue list (#73); the **trust-store watch** — `--trust-store` / `--print ca-baseline`, transparent-MITM root-CA detection with a golden baseline (#74); **Tier-2 observed egress** — `--egress` reads the connection table (`lsof -n`, no DNS) for the loopback/wildcard fan-out shape + routed-via-gateway, the `observed` evidence tier (#75); the **signed public provider-attribution registry** — `provenance-probe build-registry`/`verify-registry` generate it deterministically *from* `corpus.py` (probe #76), and the observatory verifies (fail-closed on drift) + cosign-signs + publishes it at `/api/registry` (observatory #28). The host-forensics collectors (`--trust-store`, `--egress`) are gated on `--i-am-authorized` and **refuse (exit 3) rather than report a false-clean** on an unreadable/unsupported/unprivileged host. B-phase remaining: **release the probe to PyPI ≥0.27.0 + bump the observatory's `provenance-probe` pin** to activate the nightly registry publish (currently a documented no-op on the 0.4.1 pin); Intune/Tanium delivery recipes; the Windows collector; and the deeper Tier-2 signals that need the egress/pcap surface (JA3/TLS fingerprint, IP→entity attribution via RDAP).
3. **Reference coverage** — GLM/Yi/InternLM don't ship pre-built (11 of 27 vectors do); closing the CN gap via `build-reference` is what makes z.ai-style cases confirmable. 14 families remain unvalidated by the hermetic eval.
4. **Capture extension** — the MV3 extension is built but not store-published; install is load-unpacked developer mode.
5. **z.ai re-activation** — decide whether a request-signing adapter is worth it, or keep the target paused and documented.

## Skill routing (Claude Code sessions in these repos)

When the user's request matches an available skill, invoke it via the Skill tool. When in doubt, invoke the skill. Product ideas/brainstorming → `/office-hours` · strategy/scope → `/plan-ceo-review` · architecture → `/plan-eng-review` · design system/plan review → `/design-consultation` or `/plan-design-review` · full review pipeline → `/autoplan` · bugs/errors → `/investigate` · QA/testing site behavior → `/qa` or `/qa-only` · code review/diff check → `/review` · visual polish → `/design-review` · ship/deploy/PR → `/ship` or `/land-and-deploy` · save progress → `/context-save` · resume context → `/context-restore` · backlog-ready spec/issue → `/spec`.

## Pointers

Probe: `docs/ARCHITECTURE.md` (math + invariants), `WHITEPAPER.md` (why), `docs/CONOPS.md` (executive/federal agent framing), `QUICKSTART.md`, `RUNNING-LOCALLY.md`, `docs/WIZARD.md`, `docs/EXTENDING.md` / `docs/adding-sources.md`, `docs/PACKAGING.md` (why PyPI + the `llm-provenance-probe` dist-name vs `provenance-probe` command), `DISCLOSURE.md`. Observatory: `docs/ARCHITECTURE.md` (decision record), `docs/adding-targets.md`, `api/README.md` + `api/DEPLOY.md`, `DISCLOSURE.md` (publication policy).
