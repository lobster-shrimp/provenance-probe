# Fleet-rollup pilot kit

Hand this folder to a security team to pilot `fleet-scan --rollup` in ~10 minutes.

- **[PILOT-BRIEF.md](PILOT-BRIEF.md)** — one-page brief for a CISO/security lead: the shadow-AI / PRC-exposure problem, what the read-only scan does, and what a pilot needs.
- **[QUICKSTART.md](QUICKSTART.md)** — the copy-paste turnkey run: deliver the per-machine scan, gather results, `fleet-scan --rollup`, exit codes, cron + CI examples.
- **[sample-report.txt](sample-report.txt)** — an actual rendered rollup on synthetic data, so a partner sees exactly what they'll get (regenerate with [make-sample-fixture.py](make-sample-fixture.py)).

Everything here uses the shipped tool — no new features. Deeper reference: [../fleet-rollup.md](../fleet-rollup.md).
