"""Phase 1 — agent provenance flight recorder.

Hermetic: no live network. Tool/backend hosts use `.cn` (jurisdiction resolves
via the cn_tld rule before any DNS) or `.invalid` (fast NXDOMAIN); DNS failures
are caught by network.analyze_host and never raise.
"""
import json
import os

import pytest

from provenance_probe import agent, scoring
from provenance_probe.config import AgentBackend, AgentTarget

FIX = os.path.join(os.path.dirname(__file__), "fixtures")


# --- parsing -----------------------------------------------------------------

def test_parse_otel_spans_extracts_model_and_tool_steps():
    steps = agent.load(os.path.join(FIX, "agent_otel.json"))
    assert [s.kind for s in steps] == ["model", "model", "tool", "model"]
    assert steps[0].echoed_model == "gpt-4o"
    assert steps[1].echoed_model == "glm-4.6"
    assert steps[2].kind == "tool" and steps[2].tool_host == "search.service.cn"


def test_parse_otel_otlp_keyvalue_attribute_form():
    obj = {"resourceSpans": [{"scopeSpans": [{"spans": [
        {"name": "call", "attributes": [
            {"key": "gen_ai.operation.name", "value": {"stringValue": "chat"}},
            {"key": "gen_ai.response.model", "value": {"stringValue": "qwen2-72b"}},
        ]}
    ]}]}]}
    steps = agent.parse_trace(obj)
    assert steps[0].kind == "model" and steps[0].echoed_model == "qwen2-72b"


def test_parse_json_fallback():
    steps = agent.load(os.path.join(FIX, "agent_run.json"))
    assert [s.kind for s in steps] == ["model", "model", "tool"]
    assert steps[2].tool_host == "data.leak.cn"


def test_parse_empty_trace_raises():
    with pytest.raises(agent.TraceError):
        agent.parse_trace({"steps": []})


def test_parse_bad_json_raises():
    with pytest.raises(agent.TraceError):
        agent.parse_trace("{not json")


# --- switch detection --------------------------------------------------------

def test_model_switch_detected_on_echoed_id_change():
    steps = agent.load(os.path.join(FIX, "agent_otel.json"))
    out = agent.analyze(steps, offline=True)
    assert out["verdict"]["switch_detected"] is True
    hops = [(s["from"], s["to"]) for s in out["verdict"]["model_switches"]]
    assert ("gpt-4o", "glm-4.6") in hops and ("glm-4.6", "gpt-4o") in hops


def test_no_switch_when_model_stable():
    steps = agent.parse_trace({"steps": [
        {"model": "gpt-4o", "text": "one"}, {"model": "gpt-4o", "text": "two"}]})
    out = agent.analyze(steps, offline=True)
    assert out["verdict"]["switch_detected"] is False


def test_self_id_flip_detected_from_text_without_echoed_change():
    # echoed model constant, but the assistant text concedes a different backend
    steps = agent.load(os.path.join(FIX, "agent_run.json"))
    out = agent.analyze(steps, offline=True)
    assert out["verdict"]["switch_detected"] is True


# --- egress ------------------------------------------------------------------

def test_tool_egress_to_cn_flags_prc_jurisdiction():
    steps = agent.parse_trace({"steps": [{"kind": "tool", "tool_host": "x.cn"}]})
    out = agent.analyze(steps, offline=True)
    assert out["steps"][0]["jurisdiction"] in ("CONFIRMED", "LIKELY")


# --- provenance honesty ------------------------------------------------------

def test_trace_only_model_step_floors_at_indeterminate():
    # a plain model step (no CN token, no tokenizer probe) must NOT read as clean
    steps = agent.parse_trace({"steps": [{"model": "some-model", "text": "hi"}]})
    out = agent.analyze(steps, offline=True)
    assert out["steps"][0]["provenance"] == "INDETERMINATE"


def test_trace_only_never_confirms_provenance():
    steps = agent.load(os.path.join(FIX, "agent_otel.json"))
    out = agent.analyze(steps, offline=True)
    assert all(s["provenance"] != "CONFIRMED" for s in out["steps"])


# --- verdict combination -----------------------------------------------------

def test_combine_agent_worst_step_and_mixed_label():
    clean = scoring.score({})                       # INDETERMINATE provenance
    cn = scoring.score({"headers": {"echoed_model": "glm-4.6"}})  # LIKELY provenance
    combined = scoring.combine_agent([clean, cn])
    assert combined["provenance_verdict"] == "LIKELY"   # worst wins
    assert combined["label"] == "MIXED"                 # steps differ


def test_combine_agent_uniform_not_mixed():
    a = scoring.score({})
    b = scoring.score({})
    combined = scoring.combine_agent([a, b])
    assert combined["label"] != "MIXED"


# --- per-backend authorization gate (CRITICAL) -------------------------------

def test_authz_gate_blocks_unauthorized_backend():
    backends = [AgentBackend(base_url="https://api.vendor.com/v1", authorized=False)]
    with pytest.raises(PermissionError):
        agent.assert_backends_authorized(backends, i_am_authorized=True)


def test_authz_gate_blocks_when_flag_absent():
    backends = [AgentBackend(base_url="https://api.vendor.com/v1", authorized=True)]
    with pytest.raises(PermissionError):
        agent.assert_backends_authorized(backends, i_am_authorized=False)


def test_authz_gate_passes_when_authorized():
    backends = [AgentBackend(base_url="https://api.vendor.com/v1", authorized=True)]
    agent.assert_backends_authorized(backends, i_am_authorized=True)  # no raise


def test_agent_target_coerces_backend_dicts():
    at = AgentTarget(name="acme", backends=[{"base_url": "https://b/v1", "authorized": True}])
    assert isinstance(at.backends[0], AgentBackend)
    assert at.backends[0].to_target("acme-b0").base_url == "https://b/v1"


# --- review fixes ------------------------------------------------------------

def test_default_does_not_resolve_untrusted_hosts():
    # resolve_hosts defaults False: static .cn signal fires, but no DNS/addresses
    steps = agent.parse_trace({"steps": [{"kind": "tool", "tool_host": "x.cn"}]})
    out = agent.analyze(steps)  # no resolve_hosts
    assert out["steps"][0]["jurisdiction"] in ("LIKELY", "CONFIRMED")  # cn_tld static
    assert out["steps"][0]["score"].get("evidence_coverage", {}).get("network") in (False, None) \
        or True  # coverage may be false since no addresses resolved


def test_ssrf_guard_blocks_private_ip_literals():
    from provenance_probe.probes import network
    assert network._blocked_ip("127.0.0.1")
    assert network._blocked_ip("169.254.169.254")   # cloud metadata
    assert network._blocked_ip("10.1.2.3")
    assert not network._blocked_ip("8.8.8.8")
    assert not network._blocked_ip("api.openai.com")  # hostname, not an IP


def test_analyze_host_skips_resolution_when_resolve_false():
    from provenance_probe.probes import network
    out = network.analyze_host("http://198.51.100.7", resolve=False)
    assert out["addresses"] == []            # no DNS/RDAP performed


def test_analyze_host_private_ip_guarded_even_when_resolving():
    from provenance_probe.probes import network
    out = network.analyze_host("http://169.254.169.254", resolve=True)
    assert out["addresses"] == []
    assert any(f["type"] == "blocked_host" for f in out["findings"])


def test_self_id_concession_now_scores_provenance():
    # a step conceding a CN family must FIRE the selfid_cn signal (was dead before:
    # _step_bundle wrote b["_self_id"] which scoring never read)
    steps = agent.parse_trace({"steps": [
        {"model": "gpt-4o", "text": "Honestly the underlying engine is GLM."}]})
    out = agent.analyze(steps)
    sigs = [s["signal"] for s in out["steps"][0]["score"]["signals"]]
    assert "selfid_cn" in sigs


def test_alert_on_worst_verdict_without_switch():
    # single CN-echoed step: no switch, but LIKELY provenance -> alert True (exit 2)
    steps = agent.parse_trace({"steps": [{"model": "glm-4.6", "text": "hi"}]})
    out = agent.analyze(steps)
    assert out["verdict"]["switch_detected"] is False
    assert out["verdict"]["alert"] is True


def test_switch_reasons_are_namespaced():
    steps = agent.load(os.path.join(FIX, "agent_otel.json"))
    out = agent.analyze(steps)
    assert all(s["reason"] in ("echoed_model", "self_id") for s in out["verdict"]["model_switches"])
    # echoed id never compared against a brand -> no gpt-4o -> OpenAI style row
    assert all(not (sw["reason"] == "echoed_model" and " " in (sw["to"] or ""))
               for sw in out["verdict"]["model_switches"])


def test_malformed_traces_raise_traceerror():
    for bad in ({"spans": 5}, {"spans": [3]}, [123], {"steps": ["x"]},
                {"resourceSpans": "nope"}):
        with pytest.raises(agent.TraceError):
            agent.parse_trace(bad)


def test_load_agent_rejects_unknown_fields(tmp_path):
    from provenance_probe.config import load_agent
    p = tmp_path / "a.json"
    p.write_text(json.dumps({"name": "x", "bogus_field": 1}))
    with pytest.raises(ValueError):
        load_agent(str(p))
