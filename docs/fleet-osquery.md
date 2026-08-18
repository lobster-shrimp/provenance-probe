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

**Windows (Task Scheduler):**
```sh
provenance-probe fleet-scan --print schtasks --interval 12h \
  --sqlite "C:\ProgramData\provenance-probe\fleet.db" > fleet.xml
# then, on the target:  schtasks /Create /XML fleet.xml /TN "com.provenance-probe.fleet-scan"
```

The launchd/systemd/cron units run, verbatim, the same interpreter and package you
invoked the generator with, so they work from a venv or a system install. The
Windows XML uses a bare `python.exe` (resolved on the target's PATH) since it's
usually generated on another host — edit `<Command>`/`<Arguments>` if you pin a path,
or use the Intune script below which installs the probe for you.

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

## MDM delivery: Intune and Tanium

For managed fleets you usually push the scheduled scan through the MDM you already
run, then collect results through the same channel.

**Microsoft Intune** — a PowerShell deploy script (installs the probe + registers the
scheduled task; idempotent, runs as SYSTEM):
```sh
provenance-probe fleet-scan --print intune --interval 12h \
  --allowlist "C:\ProgramData\provenance-probe\allow.txt" > deploy.ps1
```
Add `deploy.ps1` under **Devices → Scripts and remediations → Platform scripts**
(64-bit, run as SYSTEM). For a Win32 app, use it as the install command with a
detection rule of `schtasks /Query /TN "com.provenance-probe.fleet-scan"` (exit 0).

**Tanium** — deploy the scheduled scan as a Package, then read results either via the
osquery ATC table (if you run Tanium's osquery) or a Sensor that runs `fleet-scan
--json`:
```sh
provenance-probe fleet-scan --print tanium --interval 12h   # prints the recipe
```

Both keep the report on the endpoint (`0600`, redacted); the MDM collects the
derived table/JSON, never raw config.

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
- **Windows** is supported: config discovery, the connection table (`netstat -ano`
  + `tasklist`), and the trust-store watch (roots via PowerShell) all run on Windows;
  the ATC `platform` includes `windows`. The one exception is `--ja3` (raw packet
  capture needs npcap/pktmon), which refuses cleanly on Windows rather than
  false-clean.
- Direct execution to see it work: `provenance-probe fleet-scan --allowlist allow.txt`
  (console report) or `--json` / `--out report.json`.
