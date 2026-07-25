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
