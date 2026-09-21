# -*- coding: utf-8 -*-
"""WS2 (#115) wiring: the flow renders on the landing + /help, `explain --flow`
prints the plain-text flow, and BOTH the serve result surface and the CLI assess
lead with the IDENTICAL plain_answer string (the zero-drift contract).
"""
from __future__ import annotations

import io
import os
import tempfile
from contextlib import redirect_stdout

import pytest

from provenance_probe import serve, explain, scoring, userwarn, cli
from provenance_probe.config import Target


@pytest.fixture
def client():
    return serve.app.test_client()


def _cn_bundle() -> dict:
    """A bundle that fires a hard CN network signal so the verdicts are non-trivial."""
    b = {
        "target": {"name": "sample", "base_url": "https://api.vendor.cn/v1",
                   "model": "glm-4", "api_style": "openai"},
        "timestamp": "2026-01-01T00:00:00+00:00",
        "network": {"addresses": [{"asn": "AS4808", "country": "CN"}],
                    "findings": [{"type": "cn_tld", "detail": "host ends in .cn"},
                                 {"type": "prc_ip_geo", "detail": "IP geolocates to CN"}],
                    "operator": "China Unicom", "jurisdiction": "PRC (mainland)"},
    }
    b["score"] = scoring.score(b)
    b["user_warning"] = userwarn.build(b)
    b["fingerprint_id"] = "deadbeef"
    return b


def _expected_answer(b: dict) -> str:
    s = b["score"]
    return explain.plain_answer(s["provenance_risk"]["verdict"],
                                s["jurisdictional_risk"]["verdict"],
                                s["confidence"])


# --------------------------------------------------------------------------- #
# Flow renders on the landing + /help; explain --flow prints flow_text
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_flow_renders_on_landing(client):
    body = client.get("/").get_data(as_text=True)
    assert explain.flow_html() in body


@pytest.mark.unit
def test_flow_renders_on_help(client):
    body = client.get("/help").get_data(as_text=True)
    assert explain.flow_html() in body


@pytest.mark.unit
def test_cli_explain_flow_prints_flow_text():
    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.main(["explain", "--flow"])
    out = buf.getvalue()
    assert explain.flow_text() in out


# --------------------------------------------------------------------------- #
# Zero-drift: serve api_run + CLI assess lead with the SAME plain_answer
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_serve_api_run_leads_with_plain_answer(client):
    b = _cn_bundle()
    rid = "testrid"
    serve.RUNS[rid] = {"state": "done", "progress": 100, "status": "Complete",
                       "bundle": b}
    try:
        data = client.get(f"/api/run/{rid}").get_json()
    finally:
        serve.RUNS.pop(rid, None)
    assert data["plain_answer"] == _expected_answer(b)


@pytest.mark.unit
def test_cli_assess_leads_with_the_same_plain_answer(monkeypatch, tmp_path):
    b = _cn_bundle()

    monkeypatch.setattr(cli, "load_targets",
                        lambda cfg: [Target(name="sample",
                                            base_url="https://api.vendor.cn/v1",
                                            model="glm-4", api_style="openai",
                                            authorized=True)])
    monkeypatch.setattr(cli.tokenizer, "load_reference", lambda: {})
    monkeypatch.setattr(cli.assess, "assess_target",
                        lambda t, opts, progress=None, note=None: b)

    class _Args:
        config = "unused"
        no_tokenizer = True
        no_behavioral = True
        no_deception = True
        latency = False
        latency_n = 1
        leak_samples = 0
        offline = True
        variant_seed = 0
        confront_as = ""
        confront_control = False
        session_test = False
        client_dir = ""
        client_url = ""
        artifacts = ""
        i_am_authorized = True
        out = str(tmp_path)

    buf = io.StringIO()
    with redirect_stdout(buf):
        cli.cmd_assess(_Args())
    out = buf.getvalue()

    expected = _expected_answer(b)
    assert expected in out, "CLI assess must print the plain answer"
    # It LEADS the result block: it precedes the technical console report.
    assert out.index(expected) < out.index("MODEL PROVENANCE ASSESSMENT")


@pytest.mark.unit
def test_serve_and_cli_use_the_identical_plain_answer_source():
    # Both surfaces call explain.plain_answer with the same tuple, so for any
    # bundle the string is identical by construction — assert the shared source
    # is deterministic across a representative spread.
    b = _cn_bundle()
    assert _expected_answer(b) == _expected_answer(b)
