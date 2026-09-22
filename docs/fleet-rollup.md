# Fleet rollup: one CISO posture report across the whole fleet

`fleet-scan` scans and reports **one machine at a time**. A security team running
the pilot needs **one report across the fleet**: "of my N machines, which are
reaching unsanctioned or PRC-origin AI endpoints, and which ones?"
`fleet-scan --rollup` answers that in one command.

It is **pure and no-egress**: it only *reads* already-collected local files (a
SQLite DB, a JSON report, or a directory of per-machine files). It never scans,
never writes, and never touches the network. Aggregation happens on data you
already gathered with the shipped delivery (osquery ATC / launchd / systemd /
Intune / Tanium).

## Terminology (so the numbers are never ambiguous)

- **machine** = a scanned fleet COMPUTER — the thing a CISO counts ("42 machines").
- **endpoint host** = the upstream AI hostname a machine is configured to reach.

The rollup **counts machines** and **groups exposure by endpoint host** — two
different axes, always labeled distinctly (finding totals vs. per-machine holding).

## The one command

```sh
# console posture report (default)
provenance-probe fleet-scan --rollup fleet-rollup/

# machine-by-finding CSV (feeds a spreadsheet / SIEM import)
provenance-probe fleet-scan --rollup fleet-rollup/ --format csv > fleet.csv

# structured JSON (feeds a dashboard / automation)
provenance-probe fleet-scan --rollup fleet-rollup/ --format json
```

`--json` is an alias for `--format json` on the rollup path.

Get this runbook from the CLI at any time:

```sh
provenance-probe fleet-scan --print rollup-quickstart
```

## The three-step flow

### 1. Per machine (already shipped) — schedule a scan that writes its DB

Each scheduled scan writes a local SQLite DB carrying **this machine's id + scan
time**. A clean machine (zero findings) still writes a `fleet_scans` row, so it
is **still counted** in the rollup.

```sh
provenance-probe fleet-scan --allowlist allow.txt \
    --sqlite ~/.provenance-probe/fleet/fleet.db
```

Set the machine id explicitly with `--machine-id <id>` if `socket.gethostname()`
isn't the inventory name you want (e.g. an asset tag). The delivery generators
(`--print launchd|systemd|cron|schtasks|intune|tanium`) already write `--sqlite`.

### 2. Gather one file per machine into a directory

Pull each machine's DB (or a `fleet-scan --json --out report.json` report) back
via your MDM/EDR, a SIEM export, or `scp`, and drop them in one directory. Name
each file for its machine — the filename stem is used as the machine id when a
file doesn't already carry one:

```
fleet-rollup/
  laptop-01.db
  laptop-02.db
  vdi-07.json        # a --json --out report works too
```

Non-recursive: only top-level `*.db` / `*.json` files are read. Malformed or
unreadable files are **skipped and counted** ("N files skipped"), never fatal.

Alternatively, point `--rollup` at a **single collector-merged DB** whose rows
carry the `machine` column (e.g. a SIEM export merged into one table):

```sh
provenance-probe fleet-scan --rollup /siem/fleet-merged.db
```

### 3. Roll it up

The report gives you, in order:

- **The CISO headline:** `42 machines scanned; 3 reaching PRC-origin endpoints;
  5 off-allowlist unattributed; allowlist holding on 34/42.`
- **Machine count + per-machine holding split:** HOLDING (all findings sanctioned
  or zero findings), DRIFTED (>=1 off-allowlist), UNRESOLVED (only an aggregator /
  gateway-unresolved endpoint — needs an active probe, never counted clean or drift).
- **Classification totals (findings)** — the finding axis, labeled distinctly from
  the machine axis so the two are never conflated.
- **PRC-origin exposure** — each PRC endpoint and the named machines reaching it.
- **Rogue-upstream table** — off-allowlist endpoints grouped by host, with operator,
  origin (PRC-flagged), machine count, and the named machines.
- **Freshness** — machines whose latest scan is older than `--stale-days N`
  (default 7). On an old DB with no timestamps this degrades to
  "freshness unavailable" rather than failing.

## Privacy / redaction

The rollup report can leave the security team's control (a CSV in a spreadsheet, a
JSON in a dashboard), so redaction holds in **every** format:

- `source` is redacted — an absolute home path (`/Users/alice/…`, `/home/bob/…`)
  collapses to `~/…`, so a username never leaks.
- `base_url` is sanitized — any embedded credentials (`user:pass@`) and the query
  string are stripped; only scheme + host + path remain.
- `machine` ids are shown as-is — they **are** the inventory the CISO needs, so use
  host identifiers (asset tags / hostnames), never usernames or paths, as machine ids.

## Exit codes

- `0` — any successful report, **including an empty (0-machine) one**.
- `2` — a missing/unreadable path, a corrupt/unopenable SQLite DB, or a directory
  whose only candidate files are all unusable.

## Back-compat

An old DB predating the `machine` / `scanned_at` columns and the `fleet_scans`
table still rolls up: the reader introspects with `PRAGMA table_info` and degrades
— machine count via the best available signal (reported as "unknown" when there's
no machine signal at all), freshness "unavailable" — while still computing
exposures from the findings. No migration is needed; `write_sqlite` recreates its
tables each run.
