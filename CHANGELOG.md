# Changelog

## [0.8.0] - 2026-07-25 — Live agent board (E4)

### Added
- **Live streaming board in the `sentinel` proxy.** `GET /agent/live?session=<id>`
  serves a self-contained page that shows the per-step board **updating in real
  time** as the agent makes calls through the proxy — session picker, animated
  live indicator, pause/resume. It polls a server-rendered report fragment
  (`GET /agent/report.html`), so it reuses the same tooltip-rich `agent_report`
  render (DRY) — hover any term for what it means. `GET /sentinel/sessions` lists
  active sessions. Browser-verified live against a real endpoint (board went
  2 → 3 steps as calls arrived, no reload).

## [0.7.0] - 2026-07-25 — Sub-agent call graph (E6)

### Fixed (pre-merge adversarial review — Codex)
- **No recursion on deep graphs.** `agent_graph.flatten` and the sentinel
  `/agent/graph` builder are now iterative (a 1500-deep acyclic chain — reachable
  under `MAX_STEPS=5000` — no longer `RecursionError`s the report/endpoint);
  `/agent/graph` caps nested-JSON depth.
- **Parent reachable even with no own call:** a child declaring `X-Provenance-Parent`
  creates a placeholder parent session, so `/agent/graph?session=<parent>` works
  even when the parent made no proxied call itself.
- **No silent reparenting** (first-writer wins) and **first-span-wins** on duplicate
  span ids (adversarial traces can't misattach nodes).

### Added
- **Sub-agent call graph.** When a trace carries span parentage (OpenTelemetry
  `spanId`/`parentSpanId`) or the proxy carries `X-Provenance-Parent`, the flat
  per-step board nests into the tree that actually ran — you see *which* step
  spawned the sub-call that switched models or leaked data. `AgentStep` gains
  `span_id`/`parent_id`; `agent_graph.build_tree` is cycle-safe (ancestor-walk
  guard) and drops nothing (a missing/cyclic parent attaches at the root).
- The HTML report renders a **"Sub-agent call graph"** section (indented tree)
  when parentage exists, and documents the blind spot: a sub-agent calling an
  un-proxied backend, or whose spans aren't exported, can't appear.
- **`sentinel` `GET /agent/graph?session=<root>`** returns the tree of sessions
  linked by `X-Provenance-Parent`, each node carrying that agent's verdict.

## [0.6.0] - 2026-07-25 — Agent Flight Recorder Phase 2 (A + E5)

### Fixed (pre-merge adversarial review — Codex)
- **Baseline no longer poisoned by a model-less first response.** A first response
  with no `model_id` (e.g. a 400) set the session baseline to `None` and silently
  swallowed all later switches; the baseline now backfills a never-seen signal
  without alerting, so a real later switch is still caught (regression test added).
- **SSE memory limits are now reliable under concurrency:** the runaway-line guard
  caps `buf` at `MAX_LINE`, and the per-call + global accumulation ceiling is
  checked-and-reserved atomically under one lock (was a TOCTOU race that let
  concurrent streams blow past `MAX_GLOBAL_ACCUM`).
- **Upstream sockets are closed** (`r.close()`) in the tee, JSON, and passthrough
  paths — no socket leak on client disconnect.
- **TTL eviction skips in-flight sessions** (`last` refreshed on entry) so a long
  stream isn't evicted mid-call; distinct sessions capped (evict oldest idle) and
  the event log bounded.
- **Passthrough is fully transparent:** adds `HEAD`/`OPTIONS`, forwards raw bytes,
  and preserves `content-encoding`.

### Added — live proxy interposition (A)
- **`sentinel` is now a live agent flight recorder.** The proxy **tees SSE**
  streams — forwards each chunk to the agent unchanged as it arrives (preserves
  token-streaming), accumulates the delta in parallel (capped per-call + a global
  in-flight ceiling), fingerprints on completion. **Fail-open:** a fingerprinting
  error can never alter or truncate the proxied bytes (tested: raise at mid-stream,
  all chunks still arrive).
- **Generic passthrough** — every path/method reaches upstream unchanged (not just
  `/v1/chat/completions`), so the proxy is a real `base_url` interposition point;
  provenance is collected only on chat completions.
- **Response headers preserved** end-to-end (hop-by-hop denylist) — vendor/rate-limit
  headers are both agent-visible behavior and wire evidence.
- Per-session `AgentStep` accumulation + `GET /agent/report?session=…` runs
  `agent.analyze` over the collected steps. Session key = `X-Provenance-Session`;
  concurrent calls without it are flagged `unordered`, which **withholds** the
  switch verdict. Per-session step cap + byte accounting + TTL eviction.
- Passive by design: the proxy emits a response-IDENTITY (model id / self-ID /
  header shape) for switch detection — NOT a tokenizer fingerprint (that needs the
  active probe). Shared `client.parse_sse_delta` (one SSE parser for client + proxy).

### Added — export pack (E5)
- **`--export` on `agent`/`agent-trace`** writes a deterministic, signed-ready
  evidence record (`agent_export.py`): verdict + per-step board + engine version +
  SHA256 of the input, canonical JSON (`captured_at` isolated so the core is
  reproducible). The record drops under the observatory `data/agents/<target>/<date>/`
  tree and is signed by the existing daily cosign+Rekor manifest — the observatory's
  `build_manifest` now includes agent records. No signing in the engine, no
  duplicated crypto.

### Added — `AgentStep` quality fields
- `degraded` / `unordered` / `truncated` / `session_id`, carried through `analyze`,
  the report (badges + tooltips), and the export. An `unordered` step withholds
  order-dependent switch claims instead of asserting a meaningless one.

## [0.5.2] - 2026-07-25

### Added — the agent report illustrates what happened, and it's in the local UI
- **Bolstered HTML report.** Beyond the per-step board, it now leads with a
  plain-language **"What happened"** narrative (steps, distinct models, each model
  switch, which steps flagged and why, overall verdict), a **"What this tool did"**
  panel naming the observation surfaces that ran (trace ingest / egress mapping /
  active probe — or why the probe didn't run), and an **"Evidence — why each verdict
  fired"** table listing the actual signals per step. So a non-technical reviewer
  sees the reasoning, not just a tier.
- **Agent board in the local `serve` UI.** New `/agent` route + an "Agent board →"
  nav link: paste an agent trace (OTel spans or minimal JSON), get the full
  tooltip-rich report in the browser. Reuses `agent_report.render_html` (DRY);
  untrusted-trace hosts are not DNS-resolved unless you tick the box.
- `render_html(..., fragment=True)` for embedding; +4 tests (112 total).

## [0.5.1] - 2026-07-25

### Added — agent board: operator/soil basis + educational HTML report
- **Jurisdiction basis on the board.** Each step now carries `jurisdiction_basis`
  (the network layer's operator-vs-soil distinction), so the board shows *why* a
  step is flagged: `CONFIRMED (PRC-soil)` vs `CONFIRMED (PRC-operator)` vs
  `UNLIKELY (non-PRC-1p)`. Surfaces that a CDN-fronted PRC vendor (e.g.
  `api.moonshot.ai` → Cloudflare) is caught on operator grounds even when geo-IP
  reads "US".
- **`--html` report** (`provenance_probe/agent_report.py`) — a self-contained HTML
  page for `agent-trace` / `agent` with **hover tooltips on every column, verdict
  tier, and concept** (provenance vs jurisdiction, each tier's meaning, model
  switch, egress, active probe, operator vs soil, …) plus a full glossary. Teaches
  a non-technical reviewer what the tool measured and what each verdict means.
- +3 tests (108 total).

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
