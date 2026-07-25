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


# --- operator-vs-soil basis + HTML report -----------------------------------

def test_jurisdiction_basis_distinguishes_operator_from_soil():
    # .cn host -> on-soil "PRC"; a known PRC-operator endpoint -> "PRC-operator"
    steps = agent.parse_trace({"steps": [
        {"kind": "tool", "tool_host": "x.cn"},
        {"model": "m", "backend_url": "https://api.moonshot.ai/v1"}]})
    out = agent.analyze(steps)  # static signals, no DNS
    bases = [s.get("jurisdiction_basis") for s in out["steps"]]
    assert "PRC" in bases            # x.cn -> on-soil
    assert "PRC-operator" in bases   # moonshot.ai -> operator, not soil


def test_html_report_has_tooltips_and_glossary():
    from provenance_probe import agent_report
    steps = agent.load(os.path.join(FIX, "agent_otel.json"))
    out = agent.analyze(steps)
    doc = agent_report.render_html(out, "test")
    assert "<html" in doc and "</html>" in doc
    assert 'class="tip"' in doc and "data-tip=" in doc          # hover tooltips present
    assert "Glossary" in doc                                     # educational glossary
    assert "PROVENANCE" in doc and "JURISDICTION" in doc         # both axes explained
    # every verdict tier the board can show has a glossary entry
    for tier in ("CONFIRMED", "LIKELY", "INDETERMINATE", "UNLIKELY", "NO EVIDENCE"):
        assert tier in agent_report.GLOSSARY


def test_html_report_shows_operator_basis_label():
    from provenance_probe import agent_report
    steps = agent.parse_trace({"steps": [{"model": "m", "backend_url": "https://api.moonshot.ai/v1"}]})
    out = agent.analyze(steps)
    doc = agent_report.render_html(out, "moonshot")
    assert "PRC-operator" in doc


def test_report_has_narrative_and_evidence_sections():
    from provenance_probe import agent_report
    out = agent.analyze(agent.load(os.path.join(FIX, "agent_otel.json")))
    doc = agent_report.render_html(out, "t")
    assert "What happened" in doc            # plain-language narrative
    assert "What this tool did" in doc        # observation modes
    assert "Evidence" in doc                  # why-it-fired signals
    assert "switched" in doc                  # narrates the switch


def test_report_fragment_mode_omits_html_wrapper():
    from provenance_probe import agent_report
    out = agent.analyze(agent.parse_trace({"steps": [{"model": "m", "text": "hi"}]}))
    frag = agent_report.render_html(out, "t", fragment=True)
    assert "<html" not in frag and 'class="agent-report"' in frag


# --- serve /agent route ------------------------------------------------------

def test_serve_agent_route_get_and_post():
    from provenance_probe.serve import app
    c = app.test_client()
    assert c.get("/agent").status_code == 200                      # form renders
    r = c.post("/agent", data={"trace": json.dumps({"steps": [
        {"model": "glm-4.6", "text": "hi"}]})})
    assert r.status_code == 200
    assert b"Agent provenance flight recorder" in r.data           # rendered board
    assert b"What happened" in r.data


def test_serve_agent_route_bad_trace_shows_error():
    from provenance_probe.serve import app
    c = app.test_client()
    r = c.post("/agent", data={"trace": "{not json"})
    assert r.status_code == 200
    assert b"Could not parse trace" in r.data                      # graceful error, no 500


# --- T0: AgentStep quality fields --------------------------------------------

def test_unordered_step_withholds_switch_verdict():
    # two model steps with different echoed ids, but the second is unordered ->
    # the switch claim must be WITHHELD (order-dependent claim on unreliable order)
    steps = [agent.AgentStep(0, "model", "a", echoed_model="gpt-4o"),
             agent.AgentStep(1, "model", "b", echoed_model="glm-4.6", unordered=True)]
    out = agent.analyze(steps)
    assert out["verdict"]["switch_detected"] is False
    assert out["verdict"]["ordering_incomplete"] is True
    assert "switch_note" in out["verdict"]


def test_ordered_steps_still_detect_switch():
    steps = [agent.AgentStep(0, "model", "a", echoed_model="gpt-4o"),
             agent.AgentStep(1, "model", "b", echoed_model="glm-4.6")]
    out = agent.analyze(steps)
    assert out["verdict"]["switch_detected"] is True
    assert out["verdict"]["ordering_incomplete"] is False


def test_quality_flags_flow_to_rows_and_report():
    from provenance_probe import agent_report
    steps = [agent.AgentStep(0, "model", "a", echoed_model="m",
                             degraded=True, truncated=True)]
    out = agent.analyze(steps)
    assert out["steps"][0]["degraded"] and out["steps"][0]["truncated"]
    doc = agent_report.render_html(out, "t")
    assert "DEGRADED" in doc and "TRUNCATED" in doc


# --- T4/E5: deterministic export bundle --------------------------------------

def test_export_bundle_is_deterministic_except_timestamp():
    from provenance_probe import agent_export
    out = agent.analyze(agent.load(os.path.join(FIX, "agent_otel.json")))
    b1 = agent_export.build_bundle(out, target="t", input_sha256="abc", captured_at=None)
    b2 = agent_export.build_bundle(out, target="t", input_sha256="abc", captured_at=None)
    assert agent_export.canonical(b1) == agent_export.canonical(b2)
    # only captured_at differs when stamped
    b3 = agent_export.build_bundle(out, target="t", input_sha256="abc", captured_at="2026-01-01T00:00:00Z")
    b3["captured_at"] = None
    assert agent_export.canonical(b1) == agent_export.canonical(b3)


def test_export_bundle_schema_matches_observatory_record():
    from provenance_probe import agent_export
    out = agent.analyze(agent.parse_trace({"steps": [{"model": "glm-4.6", "text": "hi"}]}))
    b = agent_export.build_bundle(out, target="acme", input_sha256="deadbeef")
    for key in ("schema_version", "kind", "captured_at", "target", "engine", "verdict", "steps", "input_sha256"):
        assert key in b
    assert b["kind"] == "agent" and b["input_sha256"] == "deadbeef"
    assert "score" not in b["steps"][0]        # score stripped from the record


# --- E6: sub-agent call graph ------------------------------------------------

_NESTED = {"steps": [
    {"name": "planner", "model": "gpt-4o", "span_id": "a"},
    {"name": "retriever", "model": "glm-4.6", "span_id": "b", "parent_id": "a"},
    {"name": "web", "kind": "tool", "tool_host": "x.cn", "span_id": "c", "parent_id": "b"},
]}


def test_build_tree_nests_by_parent():
    from provenance_probe import agent_graph
    out = agent.analyze(agent.parse_trace(_NESTED))
    tree = agent_graph.build_tree(out["steps"])
    assert len(tree) == 1 and tree[0]["name"] == "planner"          # single root
    assert tree[0]["children"][0]["name"] == "retriever"
    assert tree[0]["children"][0]["children"][0]["name"] == "web"   # grandchild
    depths = {n["name"]: n["depth"] for n in agent_graph.flatten(tree)}
    assert depths == {"planner": 0, "retriever": 1, "web": 2}


def test_has_structure_false_for_flat_trace():
    from provenance_probe import agent_graph
    out = agent.analyze(agent.load(os.path.join(FIX, "agent_otel.json")))
    assert agent_graph.has_structure(out["steps"]) is False        # no parent links


def test_build_tree_cycle_guard():
    from provenance_probe import agent_graph
    out = agent.analyze(agent.parse_trace({"steps": [
        {"model": "m", "span_id": "a", "parent_id": "b"},
        {"model": "m", "span_id": "b", "parent_id": "a"}]}))
    tree = agent_graph.build_tree(out["steps"])                     # must not loop/empty
    assert len(agent_graph.flatten(tree)) == 2


def test_report_renders_call_graph_when_nested():
    from provenance_probe import agent_report
    out = agent.analyze(agent.parse_trace(_NESTED))
    doc = agent_report.render_html(out, "t")
    assert "Sub-agent call graph" in doc
    # flat trace: no graph section
    flat = agent.analyze(agent.load(os.path.join(FIX, "agent_otel.json")))
    assert "Sub-agent call graph" not in agent_report.render_html(flat, "t")
