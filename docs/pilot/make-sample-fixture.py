#!/usr/bin/env python3
"""Build the SYNTHETIC multi-machine fixture behind docs/pilot/sample-report.txt.

This is DEMO tooling, not part of the fleet feature. It fabricates a directory of
per-machine SQLite DBs (using the SHIPPED `provenance_probe.fleet.store.write_sqlite`
so the schema is exactly what a real scheduled scan writes), so the pilot sample
report can be regenerated verbatim with the REAL `fleet-scan --rollup`.

All data here is INVENTED for illustration — no real machine, user, or traffic.
Machine ids are fictional inventory tags; the "PRC exposure" is a made-up example of
what a finding would look like, NOT an observation of any real fleet.

Usage:
    python3 docs/pilot/make-sample-fixture.py /tmp/pilot-fixture
    provenance-probe fleet-scan --rollup /tmp/pilot-fixture --fail-on any
"""
from __future__ import annotations

import datetime
import sys

from provenance_probe.fleet.evidence import (
    AGGREGATOR_UNRESOLVABLE,
    Attribution,
    Finding,
    OFF_ALLOWLIST_ATTRIBUTED,
    OFF_ALLOWLIST_UNATTRIBUTED,
    SANCTIONED,
    ScanResult,
)
from provenance_probe.fleet.store import write_sqlite

_NOW = datetime.datetime.now(datetime.timezone.utc)
_FRESH = _NOW.isoformat()
# A fixed old timestamp so the "stale" machine is ALWAYS >7d old, deterministically.
_STALE = datetime.datetime(2025, 1, 1, tzinfo=datetime.timezone.utc).isoformat()

# Sanctioned first-party endpoints (US/EU) — the allowlist "holding" majority.
_OPENAI = Finding(source="~/.config/llm/config.yaml", base_url="https://api.openai.com/v1",
                  host="api.openai.com", evidence_tier="configured", classification=SANCTIONED)
_ANTHROPIC = Finding(source="env:ANTHROPIC_BASE_URL", base_url="https://api.anthropic.com",
                     host="api.anthropic.com", evidence_tier="configured", classification=SANCTIONED)
_MISTRAL = Finding(source="~/.config/llm/config.yaml", base_url="https://api.mistral.ai/v1",
                   host="api.mistral.ai", evidence_tier="configured", classification=SANCTIONED)

# PRC-origin, off-allowlist + attributed (counts as BOTH prc and drift).
_DEEPSEEK = Finding(
    source="~/.codex/config.toml", base_url="https://api.deepseek.com/v1",
    host="api.deepseek.com", evidence_tier="configured",
    classification=OFF_ALLOWLIST_ATTRIBUTED,
    attribution=Attribution(operator="DeepSeek", origin="PRC", confidence=0.99))
_QWEN = Finding(
    source="env:OPENAI_BASE_URL", base_url="https://dashscope.aliyuncs.com/compatible-mode/v1",
    host="dashscope.aliyuncs.com", evidence_tier="configured",
    classification=OFF_ALLOWLIST_ATTRIBUTED,
    attribution=Attribution(operator="Alibaba DashScope (Qwen)", origin="PRC", confidence=0.99))

# Off-allowlist, NOT attributable to any known operator (a shadow relay).
_UNKNOWN = Finding(
    source="~/.config/some-tool/settings.json", base_url="https://llm.shadow-tool.example/v1",
    host="llm.shadow-tool.example", evidence_tier="configured",
    classification=OFF_ALLOWLIST_UNATTRIBUTED)

# A neutral aggregator: jurisdiction resolvable, provenance NOT — never counted
# clean or drift; needs an active probe.
_OPENROUTER = Finding(
    source="~/.config/llm/config.yaml", base_url="https://openrouter.ai/api/v1",
    host="openrouter.ai", evidence_tier="configured", classification=AGGREGATOR_UNRESOLVABLE)


def _result(findings: list[Finding]) -> ScanResult:
    sanctioned = sum(1 for f in findings if f.classification == SANCTIONED)
    unresolved = sum(1 for f in findings if f.classification == AGGREGATOR_UNRESOLVABLE)
    drifted = len(findings) - sanctioned - unresolved
    return ScanResult(findings=findings, sanctioned=sanctioned, drifted=drifted,
                      unresolved=unresolved)


# (machine id, scanned_at, findings) — 12 fictional machines.
_FLEET = [
    ("eng-laptop-01", _FRESH, [_OPENAI, _ANTHROPIC]),
    ("eng-laptop-02", _FRESH, [_OPENAI]),
    ("eng-laptop-03", _FRESH, [_ANTHROPIC, _MISTRAL]),
    ("sales-laptop-04", _FRESH, [_OPENAI]),
    ("design-laptop-05", _FRESH, [_ANTHROPIC]),
    ("data-vdi-06", _FRESH, [_OPENAI, _MISTRAL]),
    ("eng-laptop-07", _FRESH, [_OPENAI, _DEEPSEEK]),          # PRC drift
    ("research-laptop-08", _FRESH, [_QWEN]),                  # PRC drift
    ("contractor-laptop-09", _FRESH, [_UNKNOWN]),             # unattributed drift
    ("eng-laptop-10", _FRESH, [_OPENAI, _OPENROUTER]),        # aggregator/unresolved
    ("ci-runner-11", _STALE, [_OPENAI]),                     # sanctioned but stale
    ("exec-laptop-12", _FRESH, [_ANTHROPIC]),
]


def main() -> int:
    if len(sys.argv) != 2:
        print(__doc__)
        return 2
    out_dir = sys.argv[1]
    import os
    os.makedirs(out_dir, exist_ok=True)
    for machine, scanned_at, findings in _FLEET:
        path = os.path.join(out_dir, f"{machine}.db")
        write_sqlite(_result(findings), path, machine=machine, scanned_at=scanned_at)
    print(f"wrote {len(_FLEET)} synthetic machine DBs to {out_dir}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
