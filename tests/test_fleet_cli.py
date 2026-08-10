"""fleet-scan CLI + report rendering tests (T5)."""
import json

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet.render import render_console, to_json


def _result(findings):
    sanctioned = sum(1 for f in findings if f.classification == E.SANCTIONED)
    unresolved = sum(1 for f in findings if f.classification in
                     (E.GATEWAY_UPSTREAM_UNRESOLVED, E.AGGREGATOR_UNRESOLVABLE))
    return E.ScanResult(findings=findings, sanctioned=sanctioned,
                        drifted=len(findings) - sanctioned, unresolved=unresolved)


@pytest.mark.unit
def test_redaction_collapses_home_path():
    f = E.Finding(source="/Users/alice/.codex/config.toml",
                  base_url="https://api.deepseek.com/v1", host="api.deepseek.com",
                  evidence_tier=E.CONFIGURED, classification=E.OFF_ALLOWLIST_UNATTRIBUTED)
    out = to_json(_result([f]), redact=True)
    assert out["findings"][0]["source"] == "~/.codex/config.toml"  # username gone
    # no-redact keeps it
    assert to_json(_result([f]), redact=False)["findings"][0]["source"].startswith("/Users/alice")


@pytest.mark.unit
def test_attribution_renders_as_sub_confirmed():
    a = E.Attribution(operator="DeepSeek", origin="PRC", confidence=0.99)
    f = E.Finding(source="~/.codex/config.toml", base_url="https://api.deepseek.com/v1",
                  host="api.deepseek.com", evidence_tier=E.CONFIGURED,
                  classification=E.OFF_ALLOWLIST_ATTRIBUTED, attribution=a)
    text = render_console(_result([f]))
    assert "DeepSeek (PRC)" in text
    assert "NOT a measured provenance verdict" in text
    assert to_json(_result([f]))["findings"][0]["attribution"]["measured"] is False


@pytest.mark.integration
def test_cli_end_to_end(tmp_path, monkeypatch, capsys):
    home = tmp_path
    codex = home / ".codex"
    codex.mkdir()
    (codex / "config.toml").write_text('base_url = "https://api.deepseek.com/v1"\n')
    allow = home / "allow.txt"
    allow.write_text("api.openai.com\n")
    monkeypatch.setenv("HOME", str(home))
    for var in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE"):
        monkeypatch.delenv(var, raising=False)

    rc = main(["fleet-scan", "--allowlist", str(allow), "--json"])
    assert rc == 0
    out = json.loads(capsys.readouterr().out)
    hosts = {f["host"]: f for f in out["findings"]}
    assert "api.deepseek.com" in hosts
    assert hosts["api.deepseek.com"]["classification"] == E.OFF_ALLOWLIST_ATTRIBUTED
    assert hosts["api.deepseek.com"]["attribution"]["origin"] == "PRC"
    assert out["drifted"] >= 1


@pytest.mark.integration
def test_cli_exit_code_on_drift(tmp_path, monkeypatch):
    home = tmp_path
    (home / ".codex").mkdir()
    (home / ".codex" / "config.toml").write_text('base_url = "https://api.moonshot.cn/v1"\n')
    monkeypatch.setenv("HOME", str(home))
    for var in ("ANTHROPIC_BASE_URL", "OPENAI_BASE_URL", "OPENAI_API_BASE"):
        monkeypatch.delenv(var, raising=False)
    rc = main(["fleet-scan", "--exit-code"])
    assert rc == 2   # drift present → exit 2
