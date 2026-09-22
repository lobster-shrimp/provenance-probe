"""SQLite sink for fleet findings, so osquery can read them via ATC.

osquery's Automatic Table Construction (ATC) exposes a SQLite table as an osquery
table — the fleet-delivery path the eng review specified (an osquery *pack* cannot
exec a binary; instead a scheduled scan writes this DB and osquery reads it).

The DB carries internal hostnames/paths and rolls up to a SIEM, so it is written
0600 and `source` is redacted by default (same rule as the JSON report). No egress:
this only writes a local file.

Rollup support (WS3): each row carries the scanning `machine` + a `scanned_at`
UTC timestamp, and a `fleet_scans(machine, scanned_at)` metadata table is written
on EVERY scan — including a zero-finding scan — so a clean machine is still counted
in a fleet rollup. Both additions are additive; old DBs simply lack them and the
rollup reader degrades via `PRAGMA table_info`. `write_sqlite` stays
PER-MACHINE-LOCAL: one machine writes one DB; two machines never write the same DB.
"""
from __future__ import annotations

import datetime
import os
import socket
import sqlite3

from .evidence import OFF_ALLOWLIST_ATTRIBUTED, ScanResult  # noqa: F401 (ScanResult for typing)
from .render import _redact_source

TABLE = "fleet_findings"
SCANS_TABLE = "fleet_scans"
# `machine` + `scanned_at` lead so a rollup/CSV reads machine-first (the axis a
# CISO counts); the rest is the original per-host finding shape.
COLUMNS = [
    "machine", "scanned_at", "host", "base_url", "classification", "evidence_tier",
    "via_gateway", "operator", "origin", "confidence", "source",
]
_COL_TYPES = {"confidence": "REAL"}


def _now_iso() -> str:
    """UTC ISO-8601 timestamp for this scan."""
    return datetime.datetime.now(datetime.timezone.utc).isoformat()


def write_sqlite(result: ScanResult, path: str, *, redact: bool = True,
                 machine: str | None = None, scanned_at: str | None = None) -> str:
    """Write findings to a SQLite DB at `path` (0600) and return the path.

    `machine` defaults to `socket.gethostname()` (operator-overridable via the CLI
    `--machine-id`); `scanned_at` defaults to now (UTC ISO 8601). A
    `fleet_scans(machine, scanned_at)` row is written on EVERY run, including a
    zero-finding scan, so a clean machine still counts in a rollup.

    Idempotent: drops and recreates both tables each run so a scheduled scan
    reflects the current state, not an append log.

    Write-boundary posture (mirrors the --out JSON path): the DB carries internal
    hostnames/paths and rolls up to a SIEM, so create it 0600 and refuse to follow
    a symlink at the path (O_NOFOLLOW) — a scheduled root scan writing a predictable
    path must not be redirected into a victim file (CWE-59). The parent dir is
    created so the first unattended run on a fresh host doesn't crash."""
    machine = machine or socket.gethostname()
    scanned_at = scanned_at or _now_iso()

    full = os.path.expanduser(path)
    os.makedirs(os.path.dirname(full) or ".", exist_ok=True)
    # Pre-create the file 0600 and reject a symlink before sqlite opens it.
    flags = os.O_WRONLY | os.O_CREAT | getattr(os, "O_NOFOLLOW", 0)
    os.close(os.open(full, flags, 0o600))
    con = sqlite3.connect(full)
    try:
        con.execute(f"DROP TABLE IF EXISTS {TABLE}")
        cols_ddl = ", ".join(f"{c} {_COL_TYPES.get(c, 'TEXT')}" for c in COLUMNS)
        con.execute(f"CREATE TABLE {TABLE} ({cols_ddl})")
        con.executemany(
            f"INSERT INTO {TABLE} ({', '.join(COLUMNS)}) "
            f"VALUES ({', '.join('?' for _ in COLUMNS)})",
            [_row(f, redact, machine, scanned_at) for f in result.findings],
        )
        # Metadata table: one row per (machine) reflecting its latest scan, written
        # even when there are zero findings so a clean machine is still countable.
        con.execute(f"DROP TABLE IF EXISTS {SCANS_TABLE}")
        con.execute(f"CREATE TABLE {SCANS_TABLE} (machine TEXT, scanned_at TEXT)")
        con.execute(f"INSERT INTO {SCANS_TABLE} (machine, scanned_at) VALUES (?, ?)",
                    (machine, scanned_at))
        con.commit()
    finally:
        con.close()
    os.chmod(full, 0o600)
    return full


def _row(f, redact: bool, machine: str, scanned_at: str) -> tuple:
    a = f.attribution
    return (
        machine, scanned_at,
        f.host, f.base_url, f.classification, f.evidence_tier, f.via_gateway,
        a.operator if a else "", a.origin if a else "",
        a.confidence if a else None,
        _redact_source(f.source) if redact else f.source,
    )
