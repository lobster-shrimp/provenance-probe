# Changelog

## [0.5.0] - 2026-07-25

### Added — Agent Provenance Flight Recorder (Phase 1)
- The unit of assessment can now be an **agent** (a multi-step, multi-model
  workflow), not just one endpoint. `provenance_probe/agent.py` ingests a captured
  agent run and reports a per-step board: which model each step ran on, model
  switches across steps, and tool-call egress jurisdiction.
- `agent-trace <file>` CLI — ingest **OpenTelemetry GenAI spans** (primary) or a
  minimal JSON fallback; prints the board; **exit 2** on a model switch.
- `agent --config a.json` CLI — config-driven assessment: trace ingest + optional
  **active backend probe** (the only route to a CONFIRMED provenance verdict).
- `AgentTarget` / `AgentBackend` config types with **per-backend authorization** —
  active probing aborts on the first unauthorized backend (the consent surface
  widens to the agent operator AND each backend).
- `scoring.combine_agent()` — agent verdict = the worst step, labelled MIXED when
  steps differ; the full per-step board is always shown.
- Honest by design: trace-only provenance floors at INDETERMINATE (no tokenizer
  signal in a post-hoc trace). Egress jurisdiction and model switch are the
  reliable trace signals. `docs/CONOPS.md` = executive/federal concept of ops.
- 26 tests (`tests/test_agent.py`), fixtures for OTel + JSON traces.

### Security / hardening (agent trace ingest)
- **SSRF guard:** an ingested agent trace is untrusted, so `agent-trace` does NOT
  DNS-resolve trace-supplied hosts by default — static hostname jurisdiction
  signals (`.cn`, known PRC endpoints) still fire with zero network I/O. Pass
  `--resolve-hosts` to opt into DNS + RDAP. `network.analyze_host` gained a
  `resolve` flag and a private/reserved/loopback/link-local/metadata IP denylist
  (`_blocked_ip`) applied to both IP-literal hosts and resolved addresses
  (DNS-rebinding defense), plus a distinct-host cap.
- **Self-ID now scores:** a step whose text concedes a CN family feeds `selfid_cn`
  into scoring (previously written to a dead `_self_id` key scoring never read).
- **Switch detection namespaced:** echoed-model-id changes and self-ID brand flips
  are tracked separately (no more spurious `gpt-4o -> OpenAI` cross-namespace hits).
- **Exit-on-worst-verdict:** `agent`/`agent-trace` exit 2 on a LIKELY/CONFIRMED
  worst step even without a switch (CI no longer reads a PRC finding as clean).
- **Malformed-trace hardening:** non-object rows/spans, non-list containers, and
  over-size/over-step traces raise `TraceError`; unknown config keys raise a clear
  `ValueError` instead of a raw `TypeError`.

## [0.4.1] - 2026-07-20

### Fixed
- **`fingerprint_id` no longer flips on a benign chat-template / token-accounting
  change.** `_fp()` hashed the raw tokenizer vector (raw `prompt_tokens`), so a
  constant per-probe overhead shift from an endpoint changing its chat template
  or token accounting produced a new fingerprint — a false "backend changed"
  drift. The fingerprint now hashes the overhead-invariant *shape* of the vector
  (each probe minus the vector's own minimum), which cancels a constant offset
  while preserving the relative structure that distinguishes tokenizer families.
- **`monitor` no longer reports a critical `tokenizer_vector` drift on the same
  benign overhead shift.** Its direct probe-count diff now compares the
  overhead-corrected shape instead of raw counts, matching the fingerprint fix.
  A genuine change in relative token structure still drifts.

### Added
- `tokenizer.shape_vector()` — reference-free overhead-invariant form of a probe
  vector, used by both `_fp()` and `monitor`.
- First automated test suite (`tests/`, `pip install -e '.[test]'`): 12
  characterization tests pinning the three contracts downstream tooling depends
  on — fingerprint overhead-invariance, `monitor` exit-2 drift semantics
  (including no-false-drift on benign overhead), and tokenizer family match
  against the shipped Qwen2 reference.
