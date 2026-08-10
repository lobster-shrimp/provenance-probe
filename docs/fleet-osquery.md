# Fleet delivery: running `fleet-scan` on a fleet via osquery

`fleet-scan` is a single-host, read-only, no-egress scanner. To run it across a
fleet and roll the results into your existing tooling (osquery / Fleet / Tanium /
a SIEM), you do **not** wrap it in an osquery *pack* — an osquery pack runs SQL,
it cannot execute a binary. The delivery pattern is two independent pieces:

1. A **scheduled scan** (launchd / systemd / cron) runs `fleet-scan` on a timer and
   writes its findings to a local **SQLite** database.
2. An **osquery ATC** (Automatic Table Construction) config exposes that SQLite DB
   as an osquery table, so your fleet tooling collects it with a normal query.

The scan itself never makes a network call and writes its DB `0600` with `source`
paths redacted (no username leaks into your SIEM).

```
 timer (launchd/systemd/cron)          osquery daemon (already deployed)
        │ every 12h                            │ scheduled query
        ▼                                      ▼
  fleet-scan --sqlite fleet.db  ──writes──▶  fleet.db  ──ATC──▶  SELECT * FROM fleet_findings
        (no egress, 0600)                                         → your SIEM / Fleet / Tanium
```

## 1. Generate the scheduled-scan unit

Pick your platform. `--allowlist` is optional but recommended (without it every
endpoint reads as drift). `--interval` accepts `30m` / `6h` / `12h` (default `12h`).

**macOS (launchd):**
```sh
provenance-probe fleet-scan --print launchd \
  --allowlist /etc/provenance/allow.txt \
  --sqlite ~/.provenance-probe/fleet/fleet.db \
  --interval 12h > com.provenance-probe.fleet-scan.plist
# then:
cp com.provenance-probe.fleet-scan.plist ~/Library/LaunchAgents/
launchctl load ~/Library/LaunchAgents/com.provenance-probe.fleet-scan.plist
```

**Linux (systemd, user scope):**
```sh
provenance-probe fleet-scan --print systemd \
  --allowlist /etc/provenance/allow.txt \
  --sqlite ~/.provenance-probe/fleet/fleet.db --interval 12h
# split the two FILE sections into:
#   ~/.config/systemd/user/provenance-probe-fleet.service
#   ~/.config/systemd/user/provenance-probe-fleet.timer
systemctl --user daemon-reload
systemctl --user enable --now provenance-probe-fleet.timer
```

**Fallback (cron):**
```sh
provenance-probe fleet-scan --print cron --allowlist /etc/provenance/allow.txt \
  --sqlite ~/.provenance-probe/fleet/fleet.db --interval 12h
# paste the printed line into `crontab -e`
```

The generated unit runs, verbatim, the same interpreter and package you invoked it
with, so it works from a venv or a system install.

## 2. Register the SQLite DB with osquery (ATC)

```sh
provenance-probe fleet-scan --print osquery-atc \
  --sqlite ~/.provenance-probe/fleet/fleet.db > fleet_atc.conf
```

Merge `fleet_atc.conf` into your osquery config (or drop it in
`/etc/osquery/osquery.conf.d/`). It registers a `fleet_findings` table:

```json
{
  "auto_table_construction": {
    "fleet_findings": {
      "query": "SELECT host, base_url, classification, evidence_tier, via_gateway, operator, origin, confidence, source FROM fleet_findings;",
      "path": "/Users/you/.provenance-probe/fleet/fleet.db",
      "columns": ["host","base_url","classification","evidence_tier","via_gateway","operator","origin","confidence","source"],
      "platform": "darwin,linux"
    }
  }
}
```

## 3. Query it

```sql
-- everything that drifted off the allowlist
SELECT host, classification, via_gateway, operator, origin, confidence
FROM fleet_findings
WHERE classification != 'sanctioned';

-- the sharp one: attributed PRC upstreams, including via a local gateway
SELECT host, via_gateway, operator, confidence, source
FROM fleet_findings
WHERE origin LIKE 'PRC%';

-- honest coverage: what still needs an active probe
SELECT COUNT(*) FROM fleet_findings
WHERE classification IN ('aggregator-unresolvable','gateway-upstream-unresolved');
```

## Notes

- **`confidence` is a static-lookup pointer, never a measured provenance verdict.**
  A `PRC` row means the host is *registered to* a PRC operator (corpus.py), not that
  a tokenizer fingerprint confirmed the served model. Treat it as a lead to probe.
- **`evidence_tier` matters.** `configured` means the value was found in a config file
  or env var — it may be stale and is not proof of live traffic.
- **The DB is `0600` and `source` is redacted** (home paths collapse to `~/`). If you
  need full local detail on-box, run the scan with `--no-redact` and read the console
  or JSON output directly instead of collecting the DB.
- **Windows** trust-store/collector support is deferred (macOS + Linux first).
- Direct execution to see it work: `provenance-probe fleet-scan --allowlist allow.txt`
  (console report) or `--json` / `--out report.json`.
