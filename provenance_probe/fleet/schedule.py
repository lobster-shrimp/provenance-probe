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


def _ps(v: str) -> str:
    """Escape a value for a PowerShell double-quoted string literal (backtick, quote,
    and `$` so a path can't inject a variable expansion). CR/LF are stripped — a path
    can't legitimately contain a newline, and leaving one would let it break out of
    the single-line `-Argument`/comment into executable script."""
    v = v.replace("\r", "").replace("\n", "")
    return v.replace("`", "``").replace('"', '`"').replace("$", "`$")

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


def _iso8601_duration(seconds: int) -> str:
    """Seconds -> an ISO-8601 duration (PT12H / PT30M / PT45S) for Task Scheduler."""
    s = max(1, int(seconds))
    if s % 3600 == 0:
        return f"PT{s // 3600}H"
    if s % 60 == 0:
        return f"PT{s // 60}M"
    return f"PT{s}S"


def win_fleet_argv(allowlist_path: str, sqlite_path: str, *, python: str = "python.exe") -> list[str]:
    """argv for a WINDOWS scheduler/MDM: `python.exe -m provenance_probe.cli ...`.

    Uses a bare `python.exe` (resolved on the target's PATH) rather than this host's
    `sys.executable`, since a Windows unit is usually GENERATED on another host — the
    Intune script installs the probe into that Python. Edit if your fleet pins a path.
    """
    argv = [python, "-m", "provenance_probe.cli", "fleet-scan", "--sqlite", sqlite_path]
    if allowlist_path:
        argv[4:4] = ["--allowlist", allowlist_path]
    return argv


def schtasks_xml(allowlist_path: str, sqlite_path: str = DEFAULT_DB, *,
                 interval: int = 43200, label: str = DEFAULT_LABEL) -> str:
    """Windows Task Scheduler XML (register with `schtasks /Create /XML <f> /TN <name>`).
    Windows parity with the launchd/systemd/cron units."""
    argv = win_fleet_argv(allowlist_path, sqlite_path)
    command = _xml(argv[0])
    arguments = _xml(" ".join(argv[1:]))
    every = _iso8601_duration(interval)
    return f"""<?xml version="1.0" encoding="UTF-16"?>
<!-- provenance-probe fleet-scan (scheduled, Windows Task Scheduler).
     Register:  schtasks /Create /XML this.xml /TN "{label}"
     Runs {command} every {every}. Edit <Command>/<Arguments> if python isn't on PATH. -->
<Task version="1.2" xmlns="http://schemas.microsoft.com/windows/2004/02/mit/task">
  <RegistrationInfo>
    <Description>provenance-probe fleet-scan (scheduled AI-gateway host scan)</Description>
  </RegistrationInfo>
  <Triggers>
    <TimeTrigger>
      <Repetition>
        <Interval>{every}</Interval>
        <StopAtDurationEnd>false</StopAtDurationEnd>
      </Repetition>
      <StartBoundary>2020-01-01T03:00:00</StartBoundary>
      <Enabled>true</Enabled>
    </TimeTrigger>
  </Triggers>
  <Principals>
    <Principal id="Author">
      <LogonType>InteractiveToken</LogonType>
      <RunLevel>LeastPrivilege</RunLevel>
    </Principal>
  </Principals>
  <Settings>
    <MultipleInstancesPolicy>IgnoreNew</MultipleInstancesPolicy>
    <StartWhenAvailable>true</StartWhenAvailable>
    <ExecutionTimeLimit>PT10M</ExecutionTimeLimit>
  </Settings>
  <Actions Context="Author">
    <Exec>
      <Command>{command}</Command>
      <Arguments>{arguments}</Arguments>
    </Exec>
  </Actions>
</Task>
"""


def intune_script(allowlist_path: str, sqlite_path: str = DEFAULT_DB, *,
                  interval: int = 43200, label: str = DEFAULT_LABEL) -> str:
    """A PowerShell deployment script for Microsoft Intune (Devices → Scripts, or a
    Win32-app install command). Installs the probe and registers the scheduled task.
    Idempotent: safe to re-run. Runs as SYSTEM in the Intune default context."""
    argv = win_fleet_argv(allowlist_path, sqlite_path)
    inner = " ".join(argv[1:])           # args after python.exe
    every = _iso8601_duration(interval)
    # strip CR/LF so a pathological path can't break out of the `#` comment line.
    allow_note = f"# allowlist: {_ps(allowlist_path)}\n" if allowlist_path else ""
    return f"""# provenance-probe fleet-scan — Intune deployment (PowerShell).
# Intune: Devices > Scripts and remediations > Platform scripts (run as SYSTEM,
# 64-bit). Detection for a Win32 app: `schtasks /Query /TN "{label}"` exit 0.
{allow_note}$ErrorActionPreference = "Stop"

# 1. Ensure the probe is installed for the machine Python (adjust if you pin one).
python.exe -m pip install --upgrade llm-provenance-probe

# 2. Register the scheduled scan (every {every}). Idempotent: recreate cleanly.
$action  = New-ScheduledTaskAction -Execute "python.exe" -Argument "{_ps(inner)}"
$trigger = New-ScheduledTaskTrigger -Once -At 3am `
           -RepetitionInterval (New-TimeSpan -Seconds {int(interval)})
$set     = New-ScheduledTaskSettingsSet -StartWhenAvailable -ExecutionTimeLimit (New-TimeSpan -Minutes 10)
Register-ScheduledTask -TaskName "{label}" -Action $action -Trigger $trigger `
    -Settings $set -Force
Write-Output "registered {label}"
"""


def tanium_recipe(allowlist_path: str, sqlite_path: str = DEFAULT_DB, *,
                  interval: int = 43200) -> str:
    """A Tanium deployment recipe. Tanium consumes fleet-scan two ways: (1) run the
    scheduled scan via a Package (same units above), then (2) read results either
    via the osquery ATC table (`--print osquery-atc`) or a Sensor that runs the CLI."""
    exec_line = " ".join(shlex.quote(a) for a in fleet_argv(allowlist_path, sqlite_path))
    return f"""# provenance-probe fleet-scan — Tanium deployment recipe.
#
# Tanium ingests fleet-scan in two layers:
#
# 1) SCHEDULE the scan on endpoints — deploy a Tanium *Package* whose command runs
#    the platform unit (see `--print launchd|systemd|schtasks`) or, simplest, runs
#    the scan directly on the Package's re-issue interval ({_iso8601_duration(interval)}):
#       {exec_line}
#
# 2) READ results back — two options:
#    a. osquery ATC (recommended if you run Tanium's osquery): deploy the ATC config
#       from `provenance-probe fleet-scan --print osquery-atc` so Tanium can
#         SELECT * FROM {TABLE};
#    b. Sensor: a Tanium Sensor that runs `... fleet-scan --json` and returns the
#       headline / drift count as the sensor value for Interact questions.
#
# Both keep the fleet report on the endpoint (0600, redacted) — Tanium reads the
# derived table/JSON, not raw config. Attribution stays a pointer, never a verdict.
"""


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
                "platform": "darwin,linux,windows",
            }
        }
    }
    return json.dumps(cfg, indent=2)
