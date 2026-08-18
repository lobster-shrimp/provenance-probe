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
def test_egress_rdap_attribution_wiring(monkeypatch, capsys):
    """--egress --rdap resolves upstream IPs to a pointer + exits 2 on a PRC flag,
    with NO real network (default_connections + attribute_ip both faked)."""
    from provenance_probe.fleet import connections
    from provenance_probe.probes import network

    conns = [connections.Conn("codex", "1", "192.168.1.9", 54000, "1.2.3.4", 443, "ESTABLISHED")]
    monkeypatch.setattr(connections, "default_connections", lambda: conns)
    monkeypatch.setattr(connections, "is_privileged", lambda: True)

    def fake_attr_ip(ip, *, session=None, do_rdap=True):
        return {"ip": ip, "ptr": "api.deepseek.com", "country": "CN", "asn_name": "Aliyun",
                "jurisdiction": "PRC", "confidence": 0.95, "prc_hint": False, "skipped": False}
    monkeypatch.setattr(network, "attribute_ip", fake_attr_ip)

    rc = main(["fleet-scan", "--egress", "--rdap", "--i-am-authorized", "--json", "--exit-code"])
    payload = json.loads(capsys.readouterr().out)
    assert "attribution" in payload
    a = payload["attribution"]["attributions"][0]
    assert a["ip"] == "1.2.3.4" and a["flagged"] is True
    assert a["measured"] is False
    assert rc == 2  # PRC-pointing upstream is drift


@pytest.mark.unit
def test_egress_without_rdap_makes_no_attribution(monkeypatch, capsys):
    """Bare --egress stays no-egress: no attribution block, attribute_ip never called."""
    from provenance_probe.fleet import connections
    from provenance_probe.probes import network

    conns = [connections.Conn("codex", "1", "192.168.1.9", 54000, "1.2.3.4", 443, "ESTABLISHED")]
    monkeypatch.setattr(connections, "default_connections", lambda: conns)
    monkeypatch.setattr(connections, "is_privileged", lambda: True)

    def boom(*a, **k):
        raise AssertionError("bare --egress must not RDAP")
    monkeypatch.setattr(network, "attribute_ip", boom)

    rc = main(["fleet-scan", "--egress", "--i-am-authorized", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert "attribution" not in payload
    assert rc == 0


@pytest.mark.unit
def test_ja3_refuses_without_authorization(capsys):
    rc = main(["fleet-scan", "--ja3"])
    assert rc == 1
    assert "i-am-authorized" in capsys.readouterr().err


@pytest.mark.unit
def test_ja3_refuses_exit3_when_capture_unavailable(monkeypatch, capsys):
    from provenance_probe.fleet import ja3
    monkeypatch.setattr(ja3, "capture_ja3",
                        lambda **k: (_ for _ in ()).throw(ja3.Ja3Unavailable("not root")))
    rc = main(["fleet-scan", "--ja3", "--i-am-authorized"])
    assert rc == 3  # refuse, never a false-clean
    assert "not root" in capsys.readouterr().err


@pytest.mark.unit
def test_ja3_capture_renders_observations(monkeypatch, capsys):
    from provenance_probe.fleet import ja3
    obs = [ja3.Ja3Observation("192.168.1.9", "1.2.3.4", 443, "771,,,,", "deadbeef")]
    monkeypatch.setattr(ja3, "capture_ja3", lambda **k: obs)
    rc = main(["fleet-scan", "--ja3", "--i-am-authorized", "--json"])
    payload = json.loads(capsys.readouterr().out)
    assert rc == 0  # unknown JA3 is not auto-suspicious
    assert payload["measured"] is False
    assert payload["observations"][0]["dst_ip"] == "1.2.3.4"
    assert payload["observations"][0]["known"] is None


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
