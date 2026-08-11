"""Fleet-scan core tests: collectors, gateway resolution, classification.

Covers the localhost blind-spot fix (T1), evidence tiers (ET5), attribution via
corpus.py (ET2), and the guardrail-5 zero-FP edge cases. All IO is injected — no
filesystem, no network (the module invariant).
"""
import pytest

from provenance_probe.fleet import run_scan
from provenance_probe.fleet import attribute as A
from provenance_probe.fleet import evidence as E
from provenance_probe.fleet.allowlist import is_sanctioned, load_allowlist


def _reader(mapping):
    return lambda path: mapping.get(path)


# --- attribution unit (ET2, corpus.py direct import) ------------------------- #

@pytest.mark.unit
def test_attribute_prc_host():
    a = A.attribute("api.deepseek.com")
    assert a is not None and a.origin == "PRC" and a.operator.startswith("DeepSeek")
    assert a.measured is False and 0 < a.confidence <= 1

@pytest.mark.unit
def test_attribute_first_party_us():
    a = A.attribute("api.openai.com")
    assert a is not None and a.origin == "US" and a.measured is False

@pytest.mark.unit
def test_attribute_aggregator_is_not_attributed():
    assert A.attribute("openrouter.ai") is None      # aggregators are unresolvable, not attributed
    assert A.is_aggregator("openrouter.ai") == "OpenRouter"

@pytest.mark.unit
def test_attribute_unknown_host_is_none():
    assert A.attribute("example.com") is None

@pytest.mark.unit
def test_attribute_subdomain_matches_but_evil_suffix_does_not():
    # subdomain of a PRC host IS attributed...
    assert A.attribute("foo.bigmodel.cn") is not None
    # ...but a suffix-attack host is NOT (guardrail 5 zero-FP)
    assert A.attribute("api.deepseek.com.evil.test") is None


# --- allowlist exact-or-subdomain (guardrail 5) ------------------------------ #

@pytest.mark.unit
def test_allowlist_exact_and_subdomain():
    al = load_allowlist("api.openai.com\n# comment\nhttps://api.anthropic.com/v1\n")
    assert is_sanctioned("api.openai.com", al)
    assert is_sanctioned("eu.api.openai.com", al)          # subdomain sanctioned
    assert is_sanctioned("api.anthropic.com", al)          # URL entry parsed to host
    assert not is_sanctioned("api.openai.com.evil.test", al)  # suffix attack rejected
    assert not is_sanctioned("openai.com", al)             # parent not sanctioned


# --- end-to-end: direct hosts ----------------------------------------------- #

@pytest.mark.unit
def test_direct_prc_host_off_allowlist_is_attributed():
    files = {"~/.codex/config.toml": 'base_url = "https://api.deepseek.com/v1"'}
    r = run_scan("api.openai.com", environ={}, read_text=_reader(files))
    f = next(f for f in r.findings if f.host == "api.deepseek.com")
    assert f.classification == E.OFF_ALLOWLIST_ATTRIBUTED
    assert f.attribution.origin == "PRC" and f.attribution.measured is False
    assert f.evidence_tier == E.CONFIGURED

@pytest.mark.unit
def test_sanctioned_host():
    files = {"~/.codex/config.toml": 'base_url = "https://api.openai.com/v1"'}
    r = run_scan("api.openai.com", environ={}, read_text=_reader(files))
    assert all(f.classification == E.SANCTIONED for f in r.findings)
    assert r.drifted == 0 and r.sanctioned == 1

@pytest.mark.unit
def test_evil_suffix_is_unattributed_not_sanctioned():
    files = {"~/.codex/config.toml": 'base_url = "https://api.deepseek.com.evil.test/v1"'}
    r = run_scan("api.deepseek.com", environ={}, read_text=_reader(files))
    f = r.findings[0]
    assert f.classification == E.OFF_ALLOWLIST_UNATTRIBUTED  # neither matched nor faked

@pytest.mark.unit
def test_aggregator_bucket():
    files = {"~/.codex/config.toml": 'base_url = "https://openrouter.ai/api/v1"'}
    r = run_scan("api.openai.com", environ={}, read_text=_reader(files))
    assert r.findings[0].classification == E.AGGREGATOR_UNRESOLVABLE
    assert r.unresolved == 1


# --- the localhost blind-spot fix (T1) -------------------------------------- #

@pytest.mark.unit
def test_localhost_gateway_resolves_to_prc_upstream():
    files = {"~/.codex/config.toml": 'base_url = "http://localhost:20128/v1"'}
    gw_cfg = {"providers": [{"api_base": "https://api.deepseek.com/v1"}]}
    r = run_scan("api.openai.com", environ={}, read_text=_reader(files),
                 gateway_config_loader=lambda name: gw_cfg if name == "omniroute" else None)
    f = next(f for f in r.findings if f.via_gateway == "omniroute")
    assert f.host == "api.deepseek.com"
    assert f.classification == E.OFF_ALLOWLIST_ATTRIBUTED and f.attribution.origin == "PRC"
    assert any("resolved through omniroute" in n for n in f.notes)

@pytest.mark.unit
def test_localhost_gateway_unresolved_when_no_config():
    files = {"~/.codex/config.toml": 'base_url = "http://localhost:20128/v1"'}
    r = run_scan("api.openai.com", environ={}, read_text=_reader(files),
                 gateway_config_loader=lambda name: None)
    f = r.findings[0]
    assert f.classification == E.GATEWAY_UPSTREAM_UNRESOLVED and f.via_gateway == "omniroute"
    assert r.unresolved == 1


# --- env collector (Codex #3 caveat) ---------------------------------------- #

@pytest.mark.unit
def test_env_collector_flags_and_caveats():
    r = run_scan("api.openai.com",
                 environ={"OPENAI_BASE_URL": "https://api.moonshot.cn/v1"},
                 read_text=_reader({}))
    f = next(f for f in r.findings if f.source == "env:OPENAI_BASE_URL")
    assert f.attribution.origin == "PRC"
    assert any("scanner-process env only" in n for n in f.notes)


# --- report headline --------------------------------------------------------- #

@pytest.mark.unit
def test_headline_counts():
    files = {
        "~/.codex/config.toml": 'base_url = "https://api.openai.com/v1"',
        "~/.continue/config.json": '"base_url": "https://api.deepseek.com/v1"',
    }
    r = run_scan("api.openai.com", environ={}, read_text=_reader(files))
    assert r.sanctioned == 1 and r.drifted == 1
    assert "1/2 sanctioned" in r.headline


# --- no-egress invariant ----------------------------------------------------- #

@pytest.mark.unit
def test_fleet_modules_do_not_import_requests():
    import provenance_probe.fleet.scan as scan
    import provenance_probe.fleet.resolve as resolve
    import provenance_probe.fleet.attribute as attr
    for mod in (scan, resolve, attr):
        assert not hasattr(mod, "requests"), f"{mod.__name__} must not import requests"


# --- provenance-reviewer HIGH: credentials must never enter a finding -------- #

@pytest.mark.unit
def test_strip_userinfo_unit():
    from provenance_probe.fleet.collectors import strip_userinfo
    assert strip_userinfo("https://user:sk-tok@api.evil.example/v1") == "https://api.evil.example/v1"
    assert strip_userinfo("https://user:pw@host:8080/v1") == "https://host:8080/v1"
    assert strip_userinfo("https://api.openai.com/v1") == "https://api.openai.com/v1"  # unchanged
    assert "sk-tok" not in strip_userinfo("http://x:sk-tok@h/v1")
    # IPv6 literal keeps its brackets and drops the creds
    assert strip_userinfo("http://user:pw@[::1]:20128/v1") == "http://[::1]:20128/v1"


@pytest.mark.unit
def test_credential_in_env_base_url_never_reaches_report():
    r = run_scan("api.openai.com",
                 environ={"OPENAI_BASE_URL": "https://user:sk-secrettoken123@api.deepseek.com/v1"},
                 read_text=_reader({}))
    blob = repr([(f.base_url, f.source, f.notes) for f in r.findings])
    assert "sk-secrettoken123" not in blob
    # classification still works off the stripped host
    f = next(f for f in r.findings if f.host == "api.deepseek.com")
    assert f.classification == E.OFF_ALLOWLIST_ATTRIBUTED

@pytest.mark.unit
def test_credential_in_config_base_url_never_reaches_report():
    files = {"~/.codex/config.toml": 'base_url = "https://u:sk-leak999@api.moonshot.cn/v1"'}
    r = run_scan("api.openai.com", environ={}, read_text=_reader(files))
    from provenance_probe.fleet.render import to_json
    assert "sk-leak999" not in repr(to_json(r, redact=True))
    assert "sk-leak999" not in repr(to_json(r, redact=False))  # not gated on redact


# --- provenance-reviewer LOW: bare host:port allowlist entry sanctions ------- #

@pytest.mark.unit
def test_bare_host_port_allowlist_entry_sanctions():
    al = load_allowlist("localhost:20128\napi.openai.com\n")
    assert is_sanctioned("localhost", al)   # port stripped, still matches
    assert is_sanctioned("api.openai.com", al)


# --- T7: the starter allowlist template ------------------------------------- #

@pytest.mark.unit
def test_allowlist_template_parses_to_a_usable_starter():
    from provenance_probe.fleet.allowlist import TEMPLATE
    al = load_allowlist(TEMPLATE)
    assert is_sanctioned("api.openai.com", al)
    assert is_sanctioned("api.anthropic.com", al)
    # commented placeholders (cloud tenants, the gateway) are NOT active
    assert not is_sanctioned("tenant.openai.azure.com", al)
    # the starter never sanctions a PRC host, and ships no PRC/aggregator hosts
    assert not is_sanctioned("api.deepseek.com", al)
    assert all("deepseek" not in h and "moonshot" not in h and "bigmodel" not in h
               for h in al)
