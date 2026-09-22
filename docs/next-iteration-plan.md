# provenance-probe — iteration roadmap

A technical record of the workstreams in the current iteration and their status.
Referenced by the issues that delivered them (#113–#120).

## Theme

One robust, self-explaining detection core, surfaced to two front-ends: a fleet
posture report and a self-service check. Detection must not depend on a model
reporting the truth about itself, and the result must be legible to a
non-technical reader.

## Workstreams

### WS1 — Hard-evidence floor ("don't trust the confession") — DONE (v0.33.0, #114)

A model's self-report is not evidence of what its weights are. The verdict score
now requires at least one hard measured/artifact signal (tokenizer match,
architecture, GGUF/HF-cache artifact, client-source endpoint) before it can reach
a positive provenance or jurisdiction verdict; self-report / persona signals alone
cap at INDETERMINATE. The red-team gained a tokenizer-fingerprint switch signal so
a backend swap behind a constant echoed `model_id` is still caught. `monitor.diff`
fingerprint logic is unchanged. Zero-FP eval gate holds, including a non-CN model
that falsely self-IDs as CN.

### WS2 — Legibility for non-technical readers — DONE (v0.34.1, #116, #117)

`explain.plain_answer(provenance, jurisdiction, confidence)` renders one
deterministic plain-English sentence per verdict tuple (a pure function, so the
served UI and the CLI cannot drift). A static, accessible "how it works" flow
(`explain.flow_html` / `flow_text`, sourced from the single-source `explain.py`)
renders on the landing page, `/help`, and `provenance-probe explain --flow`, using
plain-language layer labels while `/help` keeps the technical names. INDETERMINATE
copy states plainly that it is not a clean bill and not an accusation.

### WS3 — `fleet-scan --rollup` posture report — DONE (v0.35.0, #119)

Aggregates many hosts' fleet-scan findings (a collected SQLite DB or a directory
of per-host JSON) into one report: a headline count, per-classification totals, a
per-machine allowlist holding/drifted/unresolved split, PRC-origin exposure, and a
rogue-upstream table grouped by endpoint. `--format console|json|csv` for SIEM
ingest. The store gained `machine` + `scanned_at` columns and a `fleet_scans`
table so a machine with zero findings is still counted. Pure, no-egress, read-only
host forensics; redaction (POSIX + Windows home paths, URL credentials) holds in
every output format.

### Rollup alerting — `--fail-on-exposure` — DONE (v0.36.0, #121)

`fleet-scan --rollup --fail-on {prc|drift|any|none}` (and the `--fail-on-exposure`
alias) exits **3** when the fleet matches the exposure criterion, so the rollup can
gate cron / CI / a SIEM alert rule. Exit **0** = clean, exit **2** = error (a
broken scan is distinct from found exposure). A deterministic `EXPOSURE:` summary
line appears in every format. Default `none` preserves prior behavior. See
`docs/fleet-rollup.md`.

### WS4 — Self-service check — DEFERRED

The self-serve surfaces (the hosted `serve` wizard, the capture extension, `watch`)
already function and inherit WS2's legibility. Further polish is deferred until
there is a concrete driver for it.

## Notes

- Every workstream shipped via spec → build (isolated worktree, TDD) → external
  quality gate → independent adversarial review → CI-green → merge.
- No scoring/detection change ships without the hermetic eval staying green at
  zero false positives.
