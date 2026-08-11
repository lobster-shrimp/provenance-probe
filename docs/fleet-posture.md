# Fleet posture: prevention first, `fleet-scan` as the proof

`fleet-scan` detects where local agent CLIs are pointed and flags anything off
your sanctioned list. But **detection is the failure-mode measure, not the
control.** The control is a posture you set; the scan proves the posture is
holding and shows, in one number, where it isn't yet.

Framed that way, this is not "we surveilled your developers and found rogue
tools." It is "here is the sanctioned AI posture; the scan reports
`allowlist holding: N sanctioned, M drifted`, and M is the work left." That is a
much easier thing for a security team to adopt, because it makes them the owner
of a posture, not the subject of a dragnet.

## The posture (two pieces)

1. **An egress allowlist.** The AI inference hosts your org sanctions. Everything
   else is drift by definition. Start from the shipped template and fork it:

   ```sh
   provenance-probe fleet-scan --print allowlist-template > allow.txt
   # edit allow.txt to match your policy, then:
   provenance-probe fleet-scan --allowlist allow.txt
   ```

   Matching is exact-or-subdomain on the hostname — a subdomain of a listed host
   is allowed; a suffix attack (`api.openai.com.evil.test`) is not.

2. **One sanctioned gateway (optional but ideal).** If you route AI traffic
   through a single approved gateway, add just that gateway's host to the
   allowlist. Now the allowlist is tiny and every other endpoint is drift you can
   see.

   **Know the gateway blind spot, though.** `fleet-scan` resolves a gateway to its
   real upstream only when the gateway is on **loopback** (`localhost`/`127.0.0.1`/`::1`)
   AND its config file is on disk at a known path and parseable (OmniRoute,
   LiteLLM). In that case a sanctioned localhost gateway pointed at a PRC backend is
   still caught. But:
   - A **non-loopback** gateway (e.g. `ai-gateway.internal.example.com`) is matched
     against the allowlist directly and its upstream is **not** resolved — if you
     sanction it, a PRC backend behind it is invisible to fleet-scan. Prefer a
     localhost gateway, or actively probe the gateway endpoint itself (the remote
     `assess` path), or don't sanction the gateway host wholesale.
   - A localhost gateway whose config can't be read is surfaced honestly as
     `gateway-upstream-unresolved` (needs an active probe), never as clean.

## The KPI: allowlist-holding, not a rogue list

The report headline is the posture's health, not an accusation:

```
allowlist holding: 38/40 sanctioned, 2 drifted (1 unresolved)
```

- **sanctioned** — on your allowlist. The posture is holding here.
- **drifted** — off the allowlist. Each drift is attributed where the bundled
  corpus can (`off-allowlist-attributed`, e.g. a PRC operator, as a SUB-CONFIRMED
  pointer), left honest where it can't (`off-allowlist-unattributed`), bucketed as
  `aggregator-unresolvable` for neutral aggregators, or
  `gateway-upstream-unresolved` when a local gateway's upstream needs an active
  probe.

Drive M → 0 by either sanctioning an endpoint (add it to the allowlist) or
removing it (fix the config). The number, not the developer, is the target.

## Rollout

- **One host, now:** `fleet-scan --allowlist allow.txt` (add `--json` / `--out` for
  a machine-readable report; `--exit-code` to fail a CI/scheduled run on any drift).
- **Fleet-wide:** schedule the scan and collect the SQLite table through osquery —
  see [fleet-osquery.md](fleet-osquery.md).

## What this is not

- Not a package/registry — the allowlist is your policy, forked from a starter.
- Not surveillance of people — findings are host/config facts, redacted for SIEM
  rollup (home paths collapse to `~/`, `base_url` credentials stripped).
- Not a provenance verdict — attribution is a static corpus pointer, never a
  measured tokenizer-fingerprint verdict. Treat an attributed drift as a lead to
  probe, not a conviction.
