"""SQLite sink for fleet findings, so osquery can read them via ATC.

osquery's Automatic Table Construction (ATC) exposes a SQLite table as an osquery
table — the fleet-delivery path the eng review specified (an osquery *pack* cannot
exec a binary; instead a scheduled scan writes this DB and osquery reads it).

The DB carries internal hostnames/paths and rolls up to a SIEM, so it is written
0600 and `source` is redacted by default (same rule as the JSON report). No egress:
this only writes a local file.
"""
from __future__ import annotations

import os
import sqlite3

from .evidence import OFF_ALLOWLIST_ATTRIBUTED, ScanResult  # noqa: F401 (ScanResult for typing)
from .render import _redact_source

TABLE = "fleet_findings"
COLUMNS = [
    "host", "base_url", "classification", "evidence_tier",
    "via_gateway", "operator", "origin", "confidence", "source",
]


def write_sqlite(result: ScanResult, path: str, *, redact: bool = True) -> str:
    """Write findings to a SQLite DB at `path` (0600) and return the path.

    Idempotent: drops and recreates the table each run so a scheduled scan
    reflects the current state, not an append log.

    Write-boundary posture (mirrors the --out JSON path): the DB carries internal
    hostnames/paths and rolls up to a SIEM, so create it 0600 and refuse to follow
    a symlink at the path (O_NOFOLLOW) — a scheduled root scan writing a predictable
    path must not be redirected into a victim file (CWE-59). The parent dir is
    created so the first unattended run on a fresh host doesn't crash."""
    full = os.path.expanduser(path)
    os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
    # Pre-create the file 0600 and reject a symlink before sqlite opens it.
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    os.close(os.open(full, flags, 0o600))
    con = sqlite3.connect(full)
    try:
        con.execute(f"DROP TABLE IF EXISTS {TABLE}")
        con.execute(
            f"CREATE TABLE {TABLE} ("
            "host TEXT, base_url TEXT, classification TEXT, evidence_tier TEXT, "
            "via_gateway TEXT, operator TEXT, origin TEXT, confidence REAL, source TEXT)"
        )
        con.executemany(
            f"INSERT INTO {TABLE} ({', '.join(COLUMNS)}) "
            f"VALUES ({', '.join('?' for _ in COLUMNS)})",
            [_row(f, redact) for f in result.findings],
        )
        con.commit()
    finally:
        con.close()
    os.chmod(full, 0o600)
    return full


def _row(f, redact: bool) -> tuple:
    a = f.attribution
    return (
        f.host, f.base_url, f.classification, f.evidence_tier, f.via_gateway,
        a.operator if a else "", a.origin if a else "",
        a.confidence if a else None,
        _redact_source(f.source) if redact else f.source,
    )
