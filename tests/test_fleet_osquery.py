"""T6: osquery delivery — SQLite sink, ATC config, scheduled-scan units."""
import json
import sqlite3
import stat

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet import schedule
from provenance_probe.fleet.store import COLUMNS, TABLE, write_sqlite


def _result():
    findings = [
        E.Finding(source="/Users/alice/.codex/config.toml",
                  base_url="https://api.deepseek.com/v1", host="api.deepseek.com",
                  evidence_tier=E.CONFIGURED, classification=E.OFF_ALLOWLIST_ATTRIBUTED,
                  attribution=E.Attribution(operator="DeepSeek", origin="PRC", confidence=0.99)),
        E.Finding(source="env:OPENAI_BASE_URL", base_url="https://api.openai.com/v1",
                  host="api.openai.com", evidence_tier=E.CONFIGURED,
                  classification=E.SANCTIONED),
    ]
    return E.ScanResult(findings=findings, sanctioned=1, drifted=1, unresolved=0)


# --- SQLite sink ------------------------------------------------------------- #

@pytest.mark.unit
def test_write_sqlite_schema_rows_and_redaction(tmp_path):
    db = write_sqlite(_result(), str(tmp_path / "fleet.db"), redact=True)
    con = sqlite3.connect(db)
    cols = [r[1] for r in con.execute(f"PRAGMA table_info({TABLE})")]
    assert cols == COLUMNS
    rows = con.execute(
        f"SELECT host, origin, confidence, source FROM {TABLE} ORDER BY host").fetchall()
    con.close()
    assert rows[0][0] == "api.deepseek.com" and rows[0][1] == "PRC" and rows[0][2] == 0.99
    assert rows[0][3] == "~/.codex/config.toml"          # username redacted
    assert rows[1][0] == "api.openai.com" and rows[1][1] == ""  # sanctioned, no attribution


@pytest.mark.unit
def test_write_sqlite_creates_missing_parent_dir(tmp_path):
    # first unattended run on a fresh host: the default parent dir doesn't exist
    db = write_sqlite(_result(), str(tmp_path / "a" / "b" / "fleet.db"))
    assert (tmp_path / "a" / "b" / "fleet.db").exists()
    con = sqlite3.connect(db)
    assert con.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0] == 2
    con.close()


@pytest.mark.unit
def test_write_sqlite_refuses_symlink(tmp_path):
    # CWE-59: a planted symlink at the DB path must NOT be followed/clobbered
    victim = tmp_path / "victim"
    victim.write_text("do not touch")
    link = tmp_path / "fleet.db"
    link.symlink_to(victim)
    with pytest.raises(OSError):
        write_sqlite(_result(), str(link))
    assert victim.read_text() == "do not touch"   # target untouched


@pytest.mark.unit
def test_write_sqlite_is_0600_and_idempotent(tmp_path):
    p = str(tmp_path / "fleet.db")
    write_sqlite(_result(), p)
    write_sqlite(_result(), p)   # second run must not append/duplicate
    con = sqlite3.connect(p)
    assert con.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0] == 2
    con.close()
    import os
    assert stat.S_IMODE(os.stat(p).st_mode) == 0o600


# --- osquery ATC config ------------------------------------------------------ #

@pytest.mark.unit
def test_osquery_atc_config_shape():
    cfg = json.loads(schedule.osquery_atc("/tmp/fleet.db"))
    atc = cfg["auto_table_construction"]["fleet_findings"]
    assert atc["path"] == "/tmp/fleet.db"
    assert atc["columns"] == COLUMNS
    assert "darwin" in atc["platform"] and "linux" in atc["platform"]
    assert atc["query"].startswith("SELECT ") and TABLE in atc["query"]


# --- scheduled-scan units ---------------------------------------------------- #

@pytest.mark.unit
def test_launchd_plist_runs_fleet_scan_with_sqlite():
    p = schedule.launchd_plist("/etc/allow.txt", "/var/fleet.db", interval=schedule.parse_interval("12h"))
    assert "fleet-scan" in p and "--sqlite" in p and "/var/fleet.db" in p
    assert "<integer>43200</integer>" in p
    assert "--allowlist" in p and "/etc/allow.txt" in p

@pytest.mark.unit
def test_schtasks_xml_is_well_formed_and_runs_fleet_scan():
    import xml.dom.minidom as minidom
    x = schedule.schtasks_xml("C:/allow.txt", "C:/fleet.db", interval=schedule.parse_interval("6h"))
    minidom.parseString(x)  # raises if not well-formed
    assert "<Interval>PT6H</Interval>" in x
    assert "provenance_probe.cli" in x and "fleet-scan" in x
    assert "--sqlite" in x and "C:/fleet.db" in x
    assert "--allowlist" in x and "C:/allow.txt" in x


@pytest.mark.unit
def test_schtasks_xml_escapes_ampersand():
    x = schedule.schtasks_xml("", "C:/a & b/fleet.db", interval=3600)
    import xml.dom.minidom as minidom
    minidom.parseString(x)                 # still well-formed with an & in the path
    assert "&amp;" in x and "a & b" not in x


@pytest.mark.unit
def test_intune_script_installs_and_schedules():
    s = schedule.intune_script("C:/allow.txt", "C:/fleet.db", interval=schedule.parse_interval("12h"))
    assert "pip install --upgrade llm-provenance-probe" in s
    assert "Register-ScheduledTask" in s
    assert "provenance_probe.cli" in s and "fleet-scan" in s
    assert "New-TimeSpan -Seconds 43200" in s


@pytest.mark.unit
def test_tanium_recipe_points_at_osquery_and_cli():
    t = schedule.tanium_recipe("", "/var/fleet.db", interval=3600)
    assert "osquery-atc" in t and TABLE in t
    assert "fleet-scan" in t


@pytest.mark.unit
def test_iso8601_duration_forms():
    assert schedule._iso8601_duration(43200) == "PT12H"
    assert schedule._iso8601_duration(1800) == "PT30M"
    assert schedule._iso8601_duration(45) == "PT45S"


@pytest.mark.unit
def test_cli_print_schtasks_intune_tanium(capsys):
    for choice, needle in (("schtasks", "<Task"), ("intune", "Register-ScheduledTask"),
                           ("tanium", "osquery-atc")):
        assert main(["fleet-scan", "--print", choice]) == 0
        assert needle in capsys.readouterr().out


@pytest.mark.unit
def test_systemd_units_have_timer_and_execstart():
    u = schedule.systemd_units("", "/var/fleet.db", interval=3600)
    assert "ExecStart=" in u and "fleet-scan" in u and "--sqlite" in u
    assert "OnUnitActiveSec=3600" in u
    assert "--allowlist" not in u          # omitted when no allowlist given

@pytest.mark.unit
def test_cron_line_contains_argv():
    c = schedule.cron_line("/etc/allow.txt", "/var/fleet.db", interval=schedule.parse_interval("6h"))
    assert "fleet-scan" in c and "*/6" in c

@pytest.mark.unit
def test_systemd_execstart_quotes_spaces():
    # a sqlite path with a space must be shell-quoted so ExecStart parses correctly
    u = schedule.systemd_units("", "/var/my fleet/fleet.db", interval=3600)
    assert "'/var/my fleet/fleet.db'" in u

@pytest.mark.unit
def test_cli_sqlite_write_error_returns_1(tmp_path, monkeypatch, capsys):
    home = tmp_path
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('base_url = "https://api.deepseek.com/v1"\n')
    monkeypatch.setenv("HOME", str(home))
    for var in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE"):
        monkeypatch.delenv(var, raising=False)
    blocker = home / "blocker"          # a regular file used as a directory -> makedirs fails
    blocker.write_text("x")
    rc = main(["fleet-scan", "--sqlite", str(blocker / "sub" / "fleet.db")])
    assert rc == 1                       # clean error, not an uncaught traceback
    assert "could not write SQLite DB" in capsys.readouterr().err

@pytest.mark.unit
def test_parse_interval():
    assert schedule.parse_interval("12h") == 43200
    assert schedule.parse_interval("30m") == 1800
    with pytest.raises(ValueError):
        schedule.parse_interval("0s")


# --- no-egress invariant extends to the new modules -------------------------- #

@pytest.mark.unit
def test_delivery_modules_do_not_import_requests_or_watch():
    from provenance_probe.fleet import schedule as sch
    from provenance_probe.fleet import store as st
    for mod in (sch, st):
        assert not hasattr(mod, "requests")
        assert not hasattr(mod, "watch")


# --- CLI end-to-end ---------------------------------------------------------- #

@pytest.mark.integration
def test_cli_sqlite_and_atc(tmp_path, monkeypatch, capsys):
    home = tmp_path
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('base_url = "https://api.moonshot.cn/v1"\n')
    monkeypatch.setenv("HOME", str(home))
    for var in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE"):
        monkeypatch.delenv(var, raising=False)
    db = home / "fleet.db"
    rc = main(["fleet-scan", "--sqlite", str(db)])
    assert rc == 0 and db.exists()
    con = sqlite3.connect(str(db))
    hosts = [r[0] for r in con.execute(f"SELECT host FROM {TABLE}")]
    con.close()
    assert "api.moonshot.cn" in hosts

    # --print osquery-atc emits valid JSON and exits without scanning
    capsys.readouterr()
    rc = main(["fleet-scan", "--print", "osquery-atc", "--sqlite", str(db)])
    assert rc == 0
    cfg = json.loads(capsys.readouterr().out)
    assert cfg["auto_table_construction"]["fleet_findings"]["columns"] == COLUMNS

    # --print launchd emits a plist referencing fleet-scan
    rc = main(["fleet-scan", "--print", "launchd", "--interval", "6h"])
    assert rc == 0
    assert "fleet-scan" in capsys.readouterr().out

    # a bad --interval is a clean error, not a traceback
    rc = main(["fleet-scan", "--print", "launchd", "--interval", "12hh"])
    assert rc == 1
    assert "fleet-scan:" in capsys.readouterr().err

    # --print allowlist-template emits a forkable starter (T7)
    rc = main(["fleet-scan", "--print", "allowlist-template"])
    assert rc == 0
    out = capsys.readouterr().out
    assert "api.openai.com" in out and "STARTER" in out
