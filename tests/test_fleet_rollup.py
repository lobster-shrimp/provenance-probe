"""WS3 fleet rollup: one CISO posture report across many scanned machines.

All IO is a real temp file/dir (SQLite + JSON) — no network (the module invariant,
asserted structurally below). Terminology: `machine` = a scanned COMPUTER;
`host` = an upstream ENDPOINT hostname.
"""
import csv
import io
import json
import sqlite3

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet import rollup as R
from provenance_probe.fleet.store import SCANS_TABLE, TABLE, write_sqlite


# --------------------------------------------------------------------------- #
# Fixtures: synthetic ScanResults + per-machine DBs
# --------------------------------------------------------------------------- #

def _sanctioned(host="api.openai.com"):
    return E.Finding(source="env:OPENAI_BASE_URL", base_url=f"https://{host}/v1",
                     host=host, evidence_tier=E.CONFIGURED, classification=E.SANCTIONED)


def _prc_drift(host="api.deepseek.com"):
    return E.Finding(source="/Users/alice/.codex/config.toml",
                     base_url=f"https://user:secret@{host}/v1?token=abc", host=host,
                     evidence_tier=E.CONFIGURED,
                     classification=E.OFF_ALLOWLIST_ATTRIBUTED,
                     attribution=E.Attribution(operator="DeepSeek", origin="PRC",
                                               confidence=0.99))


def _unattr_drift(host="unknown.example.com"):
    return E.Finding(source="/home/bob/.config/x", base_url=f"https://{host}/v1",
                     host=host, evidence_tier=E.CONFIGURED,
                     classification=E.OFF_ALLOWLIST_UNATTRIBUTED)


def _aggregator(host="openrouter.ai"):
    return E.Finding(source="env:OPENAI_BASE_URL", base_url=f"https://{host}/api",
                     host=host, evidence_tier=E.CONFIGURED,
                     classification=E.AGGREGATOR_UNRESOLVABLE)


def _result(findings):
    sanctioned = sum(1 for f in findings if f.classification == E.SANCTIONED)
    unresolved = sum(1 for f in findings if f.classification in
                     (E.AGGREGATOR_UNRESOLVABLE, E.GATEWAY_UPSTREAM_UNRESOLVED))
    return E.ScanResult(findings=findings, sanctioned=sanctioned,
                        drifted=len(findings) - sanctioned, unresolved=unresolved)


def _write_machine(tmp_path, name, findings, scanned_at="2026-09-21T00:00:00+00:00"):
    return write_sqlite(_result(findings), str(tmp_path / f"{name}.db"),
                        machine=name, scanned_at=scanned_at)


# --------------------------------------------------------------------------- #
# store.py: machine + scanned_at + scans row, incl. a zero-finding scan
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_store_writes_machine_scanned_at_and_scans_row(tmp_path):
    db = write_sqlite(_result([_prc_drift()]), str(tmp_path / "m.db"),
                      machine="laptop-01", scanned_at="2026-09-21T12:00:00+00:00")
    con = sqlite3.connect(db)
    m, sat = con.execute(f"SELECT machine, scanned_at FROM {TABLE}").fetchone()
    assert m == "laptop-01" and sat == "2026-09-21T12:00:00+00:00"
    scans = con.execute(f"SELECT machine, scanned_at FROM {SCANS_TABLE}").fetchall()
    con.close()
    assert scans == [("laptop-01", "2026-09-21T12:00:00+00:00")]


@pytest.mark.unit
def test_store_zero_finding_scan_still_writes_scans_row(tmp_path):
    db = write_sqlite(_result([]), str(tmp_path / "clean.db"), machine="clean-01")
    con = sqlite3.connect(db)
    assert con.execute(f"SELECT COUNT(*) FROM {TABLE}").fetchone()[0] == 0
    scans = con.execute(f"SELECT machine FROM {SCANS_TABLE}").fetchall()
    con.close()
    assert scans == [("clean-01",)]      # a clean machine is still counted


@pytest.mark.unit
def test_store_default_machine_is_hostname(tmp_path):
    import socket
    db = write_sqlite(_result([]), str(tmp_path / "d.db"))
    con = sqlite3.connect(db)
    (m,) = con.execute(f"SELECT machine FROM {SCANS_TABLE}").fetchone()
    con.close()
    assert m == socket.gethostname()


# --------------------------------------------------------------------------- #
# Multi-machine aggregation (DB) incl. a zero-finding machine
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_multi_machine_counts_and_headline(tmp_path):
    d = tmp_path / "fleet"
    d.mkdir()
    _write_machine(d, "m-sanctioned", [_sanctioned()])
    _write_machine(d, "m-prc", [_prc_drift()])
    _write_machine(d, "m-unattr", [_unattr_drift()])
    _write_machine(d, "m-clean", [])                    # zero-finding machine still counts
    roll = R.load_rollup(str(d))
    rep = R.build_report(roll)
    assert rep["machines_scanned"] == 4
    # holding = sanctioned + clean = 2; drifted = prc + unattr = 2
    assert rep["allowlist_holding"] == {"holding": 2, "drifted": 2, "unresolved": 0}
    assert "4 machines scanned" in rep["headline"]
    assert "1 reaching PRC-origin endpoints" in rep["headline"]
    assert "1 off-allowlist unattributed" in rep["headline"]
    assert "allowlist holding on 2/4" in rep["headline"]


@pytest.mark.unit
def test_rollup_all_sanctioned(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "a", [_sanctioned()])
    _write_machine(d, "b", [_sanctioned("api.anthropic.com")])
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["allowlist_holding"] == {"holding": 2, "drifted": 0, "unresolved": 0}
    assert rep["prc_exposure"] == [] and rep["rogue_upstreams"] == []


@pytest.mark.unit
def test_rollup_all_drift(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "a", [_prc_drift()])
    _write_machine(d, "b", [_unattr_drift()])
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["allowlist_holding"]["holding"] == 0
    assert rep["allowlist_holding"]["drifted"] == 2


@pytest.mark.unit
def test_rollup_prc_present_grouping(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "a", [_prc_drift()])
    _write_machine(d, "b", [_prc_drift()])              # same endpoint, 2 machines
    rep = R.build_report(R.load_rollup(str(d)))
    assert len(rep["prc_exposure"]) == 1
    e = rep["prc_exposure"][0]
    assert e["endpoint"] == "api.deepseek.com" and e["origin"] == "PRC"
    assert sorted(e["machines"]) == ["a", "b"]


@pytest.mark.unit
def test_rollup_collector_merged_db_with_zero_finding_machine(tmp_path):
    """A single collector-merged DB: fleet_scans lists 3 machines, findings cover 2,
    the clean machine has no finding rows but is still counted."""
    db = str(tmp_path / "merged.db")
    con = sqlite3.connect(db)
    con.execute(f"CREATE TABLE {TABLE} (machine TEXT, scanned_at TEXT, host TEXT, "
                "base_url TEXT, classification TEXT, evidence_tier TEXT, via_gateway "
                "TEXT, operator TEXT, origin TEXT, confidence REAL, source TEXT)")
    con.execute(f"INSERT INTO {TABLE} VALUES "
                "('m1','2026-09-21T00:00:00+00:00','api.deepseek.com',"
                "'https://api.deepseek.com/v1','off-allowlist-attributed','configured',"
                "'','DeepSeek','PRC',0.99,'~/.codex/config.toml')")
    con.execute(f"INSERT INTO {TABLE} VALUES "
                "('m2','2026-09-21T00:00:00+00:00','api.openai.com',"
                "'https://api.openai.com/v1','sanctioned','configured','','','',NULL,'env')")
    con.execute(f"CREATE TABLE {SCANS_TABLE} (machine TEXT, scanned_at TEXT)")
    con.executemany(f"INSERT INTO {SCANS_TABLE} VALUES (?,?)",
                    [("m1", "2026-09-21T00:00:00+00:00"),
                     ("m2", "2026-09-21T00:00:00+00:00"),
                     ("m3", "2026-09-21T00:00:00+00:00")])  # m3 = clean, no findings
    con.commit()
    con.close()
    rep = R.build_report(R.load_rollup(db))
    assert rep["machines_scanned"] == 3                 # scans table authoritative
    assert rep["allowlist_holding"] == {"holding": 2, "drifted": 1, "unresolved": 0}


# --------------------------------------------------------------------------- #
# Directory-of-JSON input + malformed-file skip
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_directory_of_json(tmp_path):
    from provenance_probe.fleet.render import to_json
    d = tmp_path / "reports"
    d.mkdir()
    (d / "vdi-1.json").write_text(json.dumps(
        to_json(_result([_prc_drift()]), machine="vdi-1",
                scanned_at="2026-09-21T00:00:00+00:00")))
    (d / "vdi-2.json").write_text(json.dumps(
        to_json(_result([_sanctioned()]), machine="vdi-2",
                scanned_at="2026-09-21T00:00:00+00:00")))
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["machines_scanned"] == 2
    assert rep["allowlist_holding"] == {"holding": 1, "drifted": 1, "unresolved": 0}
    assert rep["prc_exposure"][0]["machines"] == ["vdi-1"]


@pytest.mark.unit
def test_rollup_directory_malformed_files_skipped(tmp_path):
    from provenance_probe.fleet.render import to_json
    d = tmp_path / "reports"
    d.mkdir()
    (d / "good.json").write_text(json.dumps(
        to_json(_result([_sanctioned()]), machine="good")))
    (d / "broken.json").write_text("{ this is not json ")
    (d / "wrong.json").write_text(json.dumps({"unrelated": "payload"}))
    (d / "corrupt.db").write_text("not a sqlite database at all")
    roll = R.load_rollup(str(d))
    rep = R.build_report(roll)
    assert rep["machines_scanned"] == 1
    assert rep["files_skipped"] == 3


@pytest.mark.unit
def test_rollup_json_machine_id_defaults_to_filename_stem(tmp_path):
    from provenance_probe.fleet.render import to_json
    d = tmp_path / "reports"
    d.mkdir()
    # no "machine" field -> filename stem is the machine id
    (d / "host-42.json").write_text(json.dumps(to_json(_result([_sanctioned()]))))
    roll = R.load_rollup(str(d))
    assert [m.machine for m in roll.machines] == ["host-42"]


# --------------------------------------------------------------------------- #
# Holding / drifted / unresolved incl. an aggregator-only machine
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_aggregator_only_machine_is_unresolved(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "agg", [_aggregator()])
    _write_machine(d, "ok", [_sanctioned()])
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["allowlist_holding"] == {"holding": 1, "drifted": 0, "unresolved": 1}
    assert "openrouter.ai" in rep["unresolved_endpoints"]
    # an aggregator endpoint is NEVER a rogue upstream
    assert rep["rogue_upstreams"] == []


@pytest.mark.unit
def test_rollup_drift_beats_unresolved(tmp_path):
    """A machine with BOTH a drift and an aggregator finding is DRIFTED (precedence)."""
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "mix", [_aggregator(), _unattr_drift()])
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["allowlist_holding"] == {"holding": 0, "drifted": 1, "unresolved": 0}


@pytest.mark.unit
def test_rollup_rogue_upstream_grouping_by_host(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "a", [_prc_drift("api.deepseek.com")])
    _write_machine(d, "b", [_prc_drift("api.deepseek.com")])
    _write_machine(d, "c", [_unattr_drift("weird.example.com")])
    rep = R.build_report(R.load_rollup(str(d)))
    rogue = {r["host"]: r for r in rep["rogue_upstreams"]}
    assert rogue["api.deepseek.com"]["machine_count"] == 2
    assert rogue["api.deepseek.com"]["is_prc"] is True
    assert sorted(rogue["api.deepseek.com"]["machines"]) == ["a", "b"]
    assert rogue["weird.example.com"]["is_prc"] is False
    # PRC rows sort first
    assert rep["rogue_upstreams"][0]["host"] == "api.deepseek.com"


# --------------------------------------------------------------------------- #
# Classification totals AND holding split are both present + distinct
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_classification_totals_and_holding_both_reported(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    # one machine with two findings -> 2 findings but 1 (drifted) machine
    _write_machine(d, "m", [_sanctioned(), _prc_drift()])
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["classification_totals"][E.SANCTIONED] == 1
    assert rep["classification_totals"][E.OFF_ALLOWLIST_ATTRIBUTED] == 1
    assert sum(rep["classification_totals"].values()) == 2        # findings axis
    assert sum(rep["allowlist_holding"].values()) == 1            # machine axis


# --------------------------------------------------------------------------- #
# CSV header/rows + JSON schema
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_csv_header_and_rows(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "m-prc", [_prc_drift()])
    _write_machine(d, "m-clean", [])
    text = R.to_csv(R.load_rollup(str(d)))
    reader = list(csv.reader(io.StringIO(text)))
    assert reader[0] == ["machine", "scanned_at", "host", "base_url", "classification",
                         "evidence_tier", "via_gateway", "operator", "origin",
                         "confidence", "source"]
    rows = {r[0]: r for r in reader[1:]}
    # base_url is sanitized: no creds, no query
    assert rows["m-prc"][3] == "https://api.deepseek.com/v1"
    assert "secret" not in text and "token=abc" not in text
    # the zero-finding machine still gets a row (empty finding columns)
    assert rows["m-clean"][2] == "" and rows["m-clean"][0] == "m-clean"


@pytest.mark.unit
def test_rollup_json_schema(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "a", [_prc_drift()])
    _write_machine(d, "b", [_sanctioned()])
    rep = R.to_json(R.load_rollup(str(d)))
    assert isinstance(rep["headline"], str)
    assert rep["machines_scanned"] == 2
    fr = rep["freshness"]
    assert set(fr) == {"available", "stale_days", "stale_machines", "unknown_machines"}
    assert isinstance(rep["classification_totals"], dict)
    assert set(rep["allowlist_holding"]) == {"holding", "drifted", "unresolved"}
    assert isinstance(rep["prc_exposure"], list) and isinstance(rep["rogue_upstreams"], list)
    ru = rep["rogue_upstreams"][0]
    assert set(ru) >= {"host", "operator", "origin", "is_prc", "machine_count", "machines"}
    assert isinstance(rep["files_skipped"], int)


# --------------------------------------------------------------------------- #
# Redaction: no home-dir path substring, no URL creds, in ALL three formats
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_redaction_no_home_path_or_creds_all_formats(tmp_path):
    from provenance_probe.fleet.render import to_json
    d = tmp_path / "f"
    d.mkdir()
    # a machine DB whose source was NOT redacted at write time (worst case)
    write_sqlite(_result([_prc_drift()]), str(d / "m.db"), redact=False,
                 machine="m", scanned_at="2026-09-21T00:00:00+00:00")
    # and a JSON report carrying an absolute home path + creds in base_url
    (d / "n.json").write_text(json.dumps({
        "findings": [{"source": "/Users/alice/.codex/config.toml",
                      "base_url": "https://user:pw@api.deepseek.com/v1?k=1",
                      "host": "api.deepseek.com", "evidence_tier": "configured",
                      "classification": "off-allowlist-attributed",
                      "attribution": {"operator": "DeepSeek", "origin": "PRC"}}],
        "machine": "n", "scanned_at": "2026-09-21T00:00:00+00:00"}))
    roll = R.load_rollup(str(d))
    for fmt in ("console", "json", "csv"):
        out = R.render(roll, fmt)
        assert "/Users/" not in out, fmt
        assert "/home/" not in out, fmt
        assert "\\Users\\" not in out, fmt
        assert "user:pw@" not in out and "user:secret@" not in out, fmt
        assert "k=1" not in out and "token=abc" not in out, fmt


# --------------------------------------------------------------------------- #
# Back-compat (old DB via PRAGMA), empty / single-machine edges
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_backcompat_old_db_without_new_columns(tmp_path):
    """An old DB (pre-WS3 schema: no machine/scanned_at/scans) must not crash;
    report machine count 'unknown' + freshness unavailable."""
    db = str(tmp_path / "old.db")
    con = sqlite3.connect(db)
    con.execute(f"CREATE TABLE {TABLE} (host TEXT, base_url TEXT, classification TEXT, "
                "evidence_tier TEXT, via_gateway TEXT, operator TEXT, origin TEXT, "
                "confidence REAL, source TEXT)")
    con.execute(f"INSERT INTO {TABLE} VALUES ('api.deepseek.com',"
                "'https://api.deepseek.com/v1','off-allowlist-attributed','configured',"
                "'','DeepSeek','PRC',0.99,'~/.codex/config.toml')")
    con.commit()
    con.close()
    rep = R.build_report(R.load_rollup(db))
    assert rep["machines_scanned"] is None
    assert rep["freshness"]["available"] is False
    assert "unknown" in rep["headline"]
    # exposures still computed from findings
    assert rep["rogue_upstreams"][0]["host"] == "api.deepseek.com"


@pytest.mark.unit
def test_rollup_empty_db(tmp_path):
    db = write_sqlite(_result([]), str(tmp_path / "empty.db"), machine="only")
    rep = R.build_report(R.load_rollup(db))
    assert rep["machines_scanned"] == 1
    assert rep["classification_totals"] == {}


@pytest.mark.unit
def test_rollup_empty_directory_is_zero_machines(tmp_path):
    d = tmp_path / "empty"
    d.mkdir()
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["machines_scanned"] == 0
    assert "0 machines scanned" in rep["headline"]


@pytest.mark.unit
def test_rollup_single_machine(tmp_path):
    db = _write_machine(tmp_path, "solo", [_prc_drift()])
    rep = R.build_report(R.load_rollup(db))
    assert rep["machines_scanned"] == 1
    assert rep["allowlist_holding"]["drifted"] == 1


@pytest.mark.unit
def test_rollup_freshness_stale_detection(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _write_machine(d, "fresh", [_sanctioned()], scanned_at="2026-09-20T00:00:00+00:00")
    _write_machine(d, "stale", [_sanctioned()], scanned_at="2020-01-01T00:00:00+00:00")
    import datetime
    roll = R.load_rollup(str(d), stale_days=7)
    # pin "now" so the test is deterministic
    roll.now = datetime.datetime(2026, 9, 21, tzinfo=datetime.timezone.utc)
    rep = R.build_report(roll)
    assert rep["freshness"]["available"] is True
    assert rep["freshness"]["stale_machines"] == ["stale"]


@pytest.mark.unit
def test_rollup_dir_dedupes_duplicate_machine_id_keeping_latest(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    # two files, SAME machine id, different scan times -> keep the latest
    write_sqlite(_result([_sanctioned()]), str(d / "old.db"),
                 machine="dup", scanned_at="2020-01-01T00:00:00+00:00")
    write_sqlite(_result([_prc_drift()]), str(d / "new.db"),
                 machine="dup", scanned_at="2026-09-21T00:00:00+00:00")
    rep = R.build_report(R.load_rollup(str(d)))
    assert rep["machines_scanned"] == 1
    assert rep["allowlist_holding"]["drifted"] == 1        # the newer (drift) scan won


# --------------------------------------------------------------------------- #
# Exit codes + CLI wiring
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_cli_rollup_missing_path_exit_2(capsys):
    assert main(["fleet-scan", "--rollup", "/no/such/path/xyz"]) == 2
    assert "fleet-scan --rollup" in capsys.readouterr().err


@pytest.mark.unit
def test_cli_rollup_corrupt_db_exit_2(tmp_path, capsys):
    bad = tmp_path / "corrupt.db"
    bad.write_text("this is not sqlite")
    assert main(["fleet-scan", "--rollup", str(bad)]) == 2


@pytest.mark.unit
def test_cli_rollup_dir_all_unusable_exit_2(tmp_path, capsys):
    d = tmp_path / "junk"
    d.mkdir()
    (d / "a.json").write_text("{ broken")
    (d / "b.db").write_text("not sqlite")
    assert main(["fleet-scan", "--rollup", str(d)]) == 2


@pytest.mark.unit
def test_cli_rollup_empty_dir_exit_0(tmp_path, capsys):
    d = tmp_path / "empty"
    d.mkdir()
    assert main(["fleet-scan", "--rollup", str(d)]) == 0
    assert "0 machines scanned" in capsys.readouterr().out


@pytest.mark.unit
def test_cli_rollup_json_alias_and_format(tmp_path, capsys):
    _write_machine(tmp_path, "solo", [_prc_drift()])
    # --json is an alias for --format json on the rollup path
    assert main(["fleet-scan", "--rollup", str(tmp_path / "solo.db"), "--json"]) == 0
    rep = json.loads(capsys.readouterr().out)
    assert rep["machines_scanned"] == 1
    # explicit --format csv
    assert main(["fleet-scan", "--rollup", str(tmp_path / "solo.db"),
                 "--format", "csv"]) == 0
    out = capsys.readouterr().out
    assert out.splitlines()[0].startswith("machine,scanned_at,host")


@pytest.mark.unit
def test_cli_print_rollup_quickstart(capsys):
    assert main(["fleet-scan", "--print", "rollup-quickstart"]) == 0
    out = capsys.readouterr().out
    assert "--rollup" in out and "fleet_scans" in out


# --------------------------------------------------------------------------- #
# No-egress invariant (structural)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rollup_module_makes_no_network_call():
    from provenance_probe.fleet import rollup as mod
    # the rollup module must not import requests or the network-bearing watch path
    assert not hasattr(mod, "requests")
    assert not hasattr(mod, "watch")
    src = open(mod.__file__, encoding="utf-8").read()
    for banned in ("import requests", "urllib.request", "socket.create_connection",
                   "http.client", "urlopen"):
        assert banned not in src, banned
