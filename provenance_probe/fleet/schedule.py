"""Scheduled-delivery generators for fleet-scan: launchd / systemd / cron units
that run the scan on a timer, plus the osquery ATC config that exposes the
resulting SQLite table.

Pure string generation — no egress, and deliberately NO import of
``provenance_probe.watch`` (which pulls in the network-bearing assessment code):
the fleet package must stay import-clean of the egress path. The interval parser
is inlined here for the same reason.
"""
from __future__ import annotations

import json
import os
import shlex
import sys

from .store import COLUMNS, TABLE


def _xml(v: str) -> str:
    return v.replace("&", "&amp;").replace("<", "&lt;")

DEFAULT_LABEL = "com.provenance-probe.fleet-scan"
DEFAULT_DB = "~/.provenance-probe/fleet/fleet.db"


def parse_interval(s: str) -> int:
    """``30s`` / ``15m`` / ``1h`` / ``12h`` (or bare int seconds) -> seconds."""
    s = (s or "").strip().lower()
    if not s:
        raise ValueError("empty interval")
    unit = {"s": 1, "m": 60, "h": 3600}
    num, mult = (s[:-1], unit[s[-1]]) if s and s[-1] in unit else (s, 1)
    try:
        val = int(num)
    except ValueError:
        raise ValueError(f"bad interval {s!r}: use forms like 30s, 15m, 1h")
    if val <= 0:
        raise ValueError(f"interval must be positive, got {s!r}")
    return val * mult


def fleet_argv(allowlist_path: str, sqlite_path: str) -> list[str]:
    """argv a scheduler runs: this interpreter, this package, a fleet-scan that
    writes the SQLite DB osquery reads. Allowlist is optional."""
    argv = [sys.executable, "-m", "provenance_probe.cli", "fleet-scan",
            "--sqlite", sqlite_path]
    if allowlist_path:
        argv[4:4] = ["--allowlist", allowlist_path]
    return argv


def launchd_plist(allowlist_path: str, sqlite_path: str = DEFAULT_DB, *,
                  interval: int = 43200, label: str = DEFAULT_LABEL) -> str:
    """launchd ``.plist`` running fleet-scan on a StartInterval (default 12h)."""
    args = "\n".join("    <string>" + _xml(a) + "</string>"
                     for a in fleet_argv(allowlist_path, sqlite_path))
    logdir = os.path.expanduser("~/.provenance-probe/fleet/launchd")
    out_log = _xml(os.path.join(logdir, "stdout.log"))
    err_log = _xml(os.path.join(logdir, "stderr.log"))
    plist_path = f"~/Library/LaunchAgents/{label}.plist"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- provenance-probe fleet-scan (scheduled). First create the log dir:
     mkdir -p ~/.provenance-probe/fleet/launchd
     Then save this to {plist_path} and run: launchctl load {plist_path} -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>StartInterval</key>
  <integer>{int(interval)}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{out_log}</string>
  <key>StandardErrorPath</key>
  <string>{err_log}</string>
</dict>
</plist>
"""


def systemd_units(allowlist_path: str, sqlite_path: str = DEFAULT_DB, *,
                  interval: int = 43200) -> str:
    """systemd ``.service`` + ``.timer`` running fleet-scan on a timer."""
    exec_line = " ".join(shlex.quote(a) for a in fleet_argv(allowlist_path, sqlite_path))
    service = f"""[Unit]
Description=provenance-probe fleet-scan (scheduled AI-gateway host scan)

[Service]
Type=oneshot
ExecStart={exec_line}
"""
    timer = f"""[Unit]
Description=Run provenance-probe fleet-scan on a timer

[Timer]
OnBootSec={int(interval)}
OnUnitActiveSec={int(interval)}
AccuracySec=60
Persistent=true

[Install]
WantedBy=timers.target
"""
    return (
        "# provenance-probe fleet-scan — systemd units (user scope).\n"
        "# Split the two sections into ~/.config/systemd/user/provenance-probe-fleet.service\n"
        "# and provenance-probe-fleet.timer, then:\n"
        "#   systemctl --user daemon-reload && systemctl --user enable --now provenance-probe-fleet.timer\n"
        "# ===== FILE: provenance-probe-fleet.service =====\n"
        f"{service}"
        "# ===== FILE: provenance-probe-fleet.timer =====\n"
        f"{timer}"
    )


def cron_line(allowlist_path: str, sqlite_path: str = DEFAULT_DB, *,
              interval: int = 43200) -> str:
    """A crontab line (fallback for hosts without launchd/systemd)."""
    hours = max(1, int(interval) // 3600)
    exec_line = " ".join(shlex.quote(a) for a in fleet_argv(allowlist_path, sqlite_path))
    schedule = f"0 */{hours} * * *" if hours < 24 else "0 3 * * *"
    return (f"# provenance-probe fleet-scan — add to `crontab -e`:\n"
            f"{schedule} {exec_line}\n")


def osquery_atc(sqlite_path: str = DEFAULT_DB, *, table: str = TABLE) -> str:
    """An osquery Automatic Table Construction config exposing the SQLite DB as
    an osquery table `table`. Drop into osquery's config so fleet tooling
    (osqueryd/Fleet/Tanium) can `SELECT * FROM <table>`."""
    cfg = {
        "auto_table_construction": {
            table: {
                "query": f"SELECT {', '.join(COLUMNS)} FROM {TABLE};",
                "path": os.path.expanduser(sqlite_path),
                "columns": list(COLUMNS),
                "platform": "darwin,linux",
            }
        }
    }
    return json.dumps(cfg, indent=2)
