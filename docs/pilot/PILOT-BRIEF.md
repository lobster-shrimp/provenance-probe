# Pilot brief: find where your fleet's AI actually points

*A one-page brief for a security lead / CISO. For the copy-paste run, see
[QUICKSTART.md](QUICKSTART.md). For a real rendered result, see
[sample-report.txt](sample-report.txt).*

## The problem

Your people and your agents are wiring AI into their daily work faster than
policy can keep up. A one-line environment variable or a config file is all it
takes to repoint a coding assistant, an internal tool, or an autonomous agent at
**an unsanctioned model** — or at a **Chinese-built / PRC-jurisdiction endpoint**
(DeepSeek, Qwen, GLM, Kimi, and others). When that happens, your prompts, your
source code, and your customer data leave for an inference provider you never
reviewed, under a jurisdiction you never approved. Most fleets cannot answer the
basic question: *of my N machines, which ones are reaching where, and whose
jurisdiction is on the other end?*

## What the tool does

`provenance-probe` runs a **read-only, no-egress, host-forensics scan** on each
machine. It reads the AI configuration already on disk (config files, environment
variables) to determine **which AI endpoints that machine is set up to reach**,
then attributes each endpoint to its **operator and jurisdiction** using a bundled
corpus. It never sends your prompts anywhere, never makes a network call during
aggregation, and never modifies the host.

This is **own-fleet forensics** — you scanning your own machines' configuration.
The tool reports what a machine is *configured* to reach (honestly labeled
"configured", not "observed traffic"), and it attributes a hostname to who it is
*registered to* — a jurisdiction pointer, not an accusation about any person.

## The setup (~10 minutes)

1. Deliver a scheduled per-machine scan through the tooling you already run
   (osquery ATC / launchd / systemd / Intune / Tanium) — the tool prints the unit
   for you. Each scan writes a small local SQLite file.
2. Gather those per-machine files back into one directory (your MDM/EDR/SIEM
   export, or `scp`).
3. Run one command — `fleet-scan --rollup <dir>` — to get one fleet-wide report.

## What you'll see

One **CISO posture report** across the whole fleet (full example in
[sample-report.txt](sample-report.txt)):

- **A headline**, e.g. *"12 machines scanned; 2 reaching PRC-origin endpoints;
  1 off-allowlist unattributed; allowlist holding on 8/12."*
- **PRC exposure named to the machine** — each PRC-jurisdiction endpoint and the
  exact machines reaching it (`api.deepseek.com → eng-laptop-07`).
- **A rogue-upstream table** — every off-allowlist endpoint grouped by host, with
  operator, jurisdiction (PRC-flagged), and the machines involved.
- **Allowlist holding / drift / freshness** — how many machines are clean, how
  many drifted, and which scans are stale.

## Alerting (cron / CI / SIEM)

The same command is also a **gate**. `--fail-on any` (or `--fail-on prc`) makes it
**exit non-zero when exposure is present**, so a nightly cron job, a CI step, or a
SIEM rule can alert on the exit code instead of a human reading the report. It
cleanly distinguishes *"found shadow AI"* (exit `3`) from *"the scan broke"*
(exit `2`).

## Honest framing

- The scan reads **configuration**, which is not the same as confirmed live
  traffic — findings are labeled accordingly.
- Attribution is a **jurisdiction/operator pointer** from a static corpus, not a
  measured provenance verdict and not an allegation against any employee.
- Results redact usernames and home paths; machine ids are your own inventory
  tags. The sample in this kit is **synthetic demo data**.

## What we need from you to run a pilot

1. A way to run **one command across N machines** (your existing MDM/EDR/RMM, or a
   scheduled unit — the tool generates it).
2. A way to **gather the per-machine result files** into one directory (a SIEM
   export or a file pull).

That's it. From there, one `fleet-scan --rollup` gives you the fleet posture, and
`--fail-on any` turns it into a standing alert. Total lift is a ~10-minute setup
and one command.
