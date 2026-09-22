"""#120 — `fleet-scan --rollup --fail-on {prc|drift|any|none}` exit gate.

The rollup is a report AND a gate: it EXITS non-zero (3) when the fleet has
shadow-AI exposure so cron / a CI job / a SIEM rule can alert on it, while the full
report still prints. Exit codes: 0 = clean/no-match, 2 = error (outranks exposure),
3 = exposure matched. `--fail-on none` (the default) preserves WS3 behavior exactly,
adding only the trailing deterministic `EXPOSURE:` summary line.

No network (rollup is a pure, no-egress reader). Terminology: `machine` = a scanned
COMPUTER; `host` = an upstream ENDPOINT hostname.
"""
import json

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet import rollup as R
from provenance_probe.fleet.store import write_sqlite


# --------------------------------------------------------------------------- #
# Fixtures
# --------------------------------------------------------------------------- #

def _sanctioned(host="api.openai.com"):
    return E.Finding(source="env:OPENAI_BASE_URL", base_url=f"https://{host}/v1",
                     host=host, evidence_tier=E.CONFIGURED, classification=E.SANCTIONED)


def _prc_drift(host="api.deepseek.com"):
    return E.Finding(source="/Users/alice/.codex/config.toml",
                     base_url=f"https://{host}/v1", host=host,
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


def _db(tmp_path, name, findings):
    return write_sqlite(_result(findings), str(tmp_path / f"{name}.db"),
                        machine=name, scanned_at="2026-09-21T00:00:00+00:00")


def _clean(tmp_path):
    return _db(tmp_path, "clean", [_sanctioned()])


def _prc(tmp_path):
    return _db(tmp_path, "prc", [_prc_drift()])


def _drift(tmp_path):
    return _db(tmp_path, "drift", [_unattr_drift()])


def _unresolved(tmp_path):
    return _db(tmp_path, "agg", [_aggregator()])


# --------------------------------------------------------------------------- #
# Exit-code matrix: none/prc/drift/any × {clean, prc, drift, unresolved-only}
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("mode,fixture,expected", [
    # --fail-on none: never gates (exit 0 regardless of exposure).
    ("none", _clean, 0),
    ("none", _prc, 0),
    ("none", _drift, 0),
    # --fail-on prc: only PRC-origin findings gate.
    ("prc", _clean, 0),
    ("prc", _prc, 3),
    ("prc", _drift, 0),          # non-PRC drift ignored by a PRC-only gate
    # --fail-on drift: any off-allowlist finding gates.
    ("drift", _clean, 0),
    ("drift", _drift, 3),
    # --fail-on any: prc OR drift gates; unresolved does NOT.
    ("any", _clean, 0),
    ("any", _prc, 3),
    ("any", _drift, 3),
    ("any", _unresolved, 0),     # unresolved is not exposure
])
def test_exit_code_matrix(tmp_path, capsys, mode, fixture, expected):
    db = fixture(tmp_path)
    rc = main(["fleet-scan", "--rollup", db, "--fail-on", mode])
    capsys.readouterr()
    assert rc == expected


# --------------------------------------------------------------------------- #
# Error (2) OUTRANKS exposure — a corrupt DB with --fail-on any still exits 2
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_error_outranks_exposure(tmp_path, capsys):
    bad = tmp_path / "corrupt.db"
    bad.write_text("this is not sqlite")
    assert main(["fleet-scan", "--rollup", str(bad), "--fail-on", "any"]) == 2
    assert "fleet-scan --rollup" in capsys.readouterr().err


@pytest.mark.unit
def test_error_missing_path_outranks_exposure(capsys):
    assert main(["fleet-scan", "--rollup", "/no/such/xyz", "--fail-on", "any"]) == 2


# --------------------------------------------------------------------------- #
# Report body STILL prints in full on exit 3
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_report_body_printed_on_exit_3(tmp_path, capsys):
    rc = main(["fleet-scan", "--rollup", _prc(tmp_path), "--fail-on", "any"])
    out = capsys.readouterr().out
    assert rc == 3
    # the full report body is present, not just the gate line
    assert "PRC-ORIGIN EXPOSURE" in out
    assert "machines scanned" in out
    # ...and the trailing EXPOSURE summary line reads FAIL
    assert out.rstrip().splitlines()[-1] == \
        "EXPOSURE: prc=1 drift=1 (fail-on=any -> FAIL)"


# --------------------------------------------------------------------------- #
# Deterministic summary line: console (all modes) + json exposure object
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_console_summary_line_none_has_no_verdict(tmp_path, capsys):
    main(["fleet-scan", "--rollup", _prc(tmp_path), "--fail-on", "none"])
    last = capsys.readouterr().out.rstrip().splitlines()[-1]
    assert last == "EXPOSURE: prc=1 drift=1 (fail-on=none)"
    assert "->" not in last


@pytest.mark.unit
def test_console_summary_line_default_is_none(tmp_path, capsys):
    # omitting --fail-on == --fail-on none (backward-compatible default)
    rc = main(["fleet-scan", "--rollup", _prc(tmp_path)])
    last = capsys.readouterr().out.rstrip().splitlines()[-1]
    assert rc == 0
    assert last == "EXPOSURE: prc=1 drift=1 (fail-on=none)"


@pytest.mark.unit
def test_console_summary_line_ok_when_clean(tmp_path, capsys):
    main(["fleet-scan", "--rollup", _clean(tmp_path), "--fail-on", "any"])
    last = capsys.readouterr().out.rstrip().splitlines()[-1]
    assert last == "EXPOSURE: prc=0 drift=0 (fail-on=any -> ok)"


@pytest.mark.unit
def test_json_exposure_object_matched(tmp_path, capsys):
    main(["fleet-scan", "--rollup", _prc(tmp_path), "--fail-on", "prc", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert rep["exposure"] == {"prc": 1, "drift": 1, "unresolved": 0,
                               "fail_on": "prc", "matched": True, "exit_code": 3}


@pytest.mark.unit
def test_json_exposure_object_clean(tmp_path, capsys):
    main(["fleet-scan", "--rollup", _clean(tmp_path), "--fail-on", "any", "--json"])
    rep = json.loads(capsys.readouterr().out)
    assert rep["exposure"] == {"prc": 0, "drift": 0, "unresolved": 0,
                               "fail_on": "any", "matched": False, "exit_code": 0}


@pytest.mark.unit
def test_csv_exposure_trailing_comment(tmp_path, capsys):
    main(["fleet-scan", "--rollup", _prc(tmp_path), "--fail-on", "any",
          "--format", "csv"])
    out = capsys.readouterr().out
    last = out.rstrip().splitlines()[-1]
    assert last.startswith("# EXPOSURE:")
    assert "prc=1 drift=1" in last and "fail-on=any -> FAIL" in last


# --------------------------------------------------------------------------- #
# --fail-on-exposure == --fail-on any (byte-identical) + precedence
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_fail_on_exposure_alias_equals_any(tmp_path, capsys):
    db = _prc(tmp_path)
    rc_alias = main(["fleet-scan", "--rollup", db, "--fail-on-exposure"])
    out_alias = capsys.readouterr().out
    rc_any = main(["fleet-scan", "--rollup", db, "--fail-on", "any"])
    out_any = capsys.readouterr().out
    assert rc_alias == rc_any == 3
    assert out_alias == out_any


@pytest.mark.unit
def test_explicit_fail_on_wins_over_alias(tmp_path, capsys):
    # both given: explicit --fail-on prc wins; a non-PRC drift fleet then exits 0
    rc = main(["fleet-scan", "--rollup", _drift(tmp_path),
               "--fail-on-exposure", "--fail-on", "prc"])
    last = capsys.readouterr().out.rstrip().splitlines()[-1]
    assert rc == 0
    assert last == "EXPOSURE: prc=0 drift=1 (fail-on=prc -> ok)"


# --------------------------------------------------------------------------- #
# Counts match the report's own tallies
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_counts_match_report_tallies(tmp_path):
    d = tmp_path / "f"
    d.mkdir()
    _db(d, "a", [_prc_drift()])                    # prc + drift
    _db(d, "b", [_unattr_drift()])                 # drift only
    _db(d, "c", [_aggregator()])                   # unresolved only
    _db(d, "d", [_sanctioned()])                   # clean
    roll = R.load_rollup(str(d))
    rep = R.build_report(roll)
    exp = R.exposure_summary(roll, "any")
    # drift count == the two off-allowlist classification totals
    tot = rep["classification_totals"]
    assert exp["drift"] == (tot.get(E.OFF_ALLOWLIST_ATTRIBUTED, 0)
                            + tot.get(E.OFF_ALLOWLIST_UNATTRIBUTED, 0)) == 2
    assert exp["prc"] == 1
    assert exp["unresolved"] == 1
    assert exp["matched"] is True and exp["exit_code"] == 3


@pytest.mark.unit
def test_prc_off_allowlist_counts_both(tmp_path):
    # a single PRC-origin off-allowlist finding counts toward BOTH prc and drift
    exp = R.exposure_summary(R.load_rollup(_prc(tmp_path)), "any")
    assert exp["prc"] == 1 and exp["drift"] == 1


# --------------------------------------------------------------------------- #
# Scope: --fail-on / --fail-on-exposure require --rollup (argparse error)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_fail_on_without_rollup_is_argparse_error(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["fleet-scan", "--fail-on", "any", "--print", "rollup-quickstart"])
    assert ei.value.code == 2
    assert "--rollup" in capsys.readouterr().err


@pytest.mark.unit
def test_fail_on_exposure_without_rollup_is_argparse_error(capsys):
    with pytest.raises(SystemExit) as ei:
        main(["fleet-scan", "--fail-on-exposure"])
    assert ei.value.code == 2
    assert "--rollup" in capsys.readouterr().err
