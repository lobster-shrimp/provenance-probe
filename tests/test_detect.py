"""Unit tests for the auto-detect state machine (detect.py) and presets (E2/E3/E4/E6).

A fake probe records every call and returns scripted ProbeResults, so the whole
state machine is tested with zero network. The CRITICAL invariant under test:
detect() sends NOTHING unless consented=True.
"""
from __future__ import annotations

import pytest

from provenance_probe import detect as D
from provenance_probe import presets as P


# --------------------------------------------------------------------------- #
# Fake transport
# --------------------------------------------------------------------------- #

class FakeProbe:
    """Records (method, url, headers, body) and replays scripted responses.

    `script` maps a substring-of-url -> ProbeResult (or a callable(url)->result).
    Any unmatched call returns a 404 so tests fail loudly on unexpected egress.
    """

    def __init__(self, script):
        self.script = script
        self.calls = []

    def __call__(self, method, url, headers, body):
        self.calls.append((method, url, dict(headers), body))
        for frag, resp in self.script.items():
            if frag in url:
                return resp(url) if callable(resp) else resp
        return D.ProbeResult(404, {"error": "no route"}, {})


def _openai_ok(model="gpt-4o-mini"):
    return D.ProbeResult(200, {
        "model": model, "usage": {"prompt_tokens": 3, "completion_tokens": 1},
        "choices": [{"message": {"role": "assistant", "content": "ok"}}]}, {})


def _anthropic_ok(model="claude-3-haiku-20240307"):
    return D.ProbeResult(200, {
        "model": model, "usage": {"input_tokens": 3, "output_tokens": 1},
        "content": [{"type": "text", "text": "ok"}]}, {})


def _catalog(ids=("gpt-4o-mini", "gpt-4o")):
    return D.ProbeResult(200, {"data": [{"id": i} for i in ids]}, {})


# --------------------------------------------------------------------------- #
# Input classifier (LOCAL, no network)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("text,expected", [
    ("", "empty"),
    ("   ", "empty"),
    ("curl 'https://api.x.com/v1/chat/completions' -H 'a: b'", "curl"),
    ("CURL https://api.x.com", "curl"),
    ('{"log": {"entries": []}}', "har"),
    ("[1,2,3]", "har"),
    ("https://api.openai.com/v1", "endpoint"),
    ("api.deepseek.com", "endpoint"),
    ("api.vendor.com/v1/chat/completions", "endpoint"),
    ("this is a sentence not a url", "unknown"),
    ("not a url with spaces", "unknown"),
])
def test_classify_input(text, expected):
    assert D.classify_input(text) == expected


# --------------------------------------------------------------------------- #
# Consent gate — the CRITICAL invariant: no egress without consent
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_no_egress_without_consent():
    fp = FakeProbe({"": _openai_ok()})
    d = D.detect("https://api.openai.com/v1", key="sk-x", consented=False, probe=fp)
    assert d.ok is False
    assert d.needs_confirm is True
    assert "consent" in d.error.lower()
    assert fp.calls == []            # NOTHING was sent
    assert d.probes_used == 0


@pytest.mark.unit
def test_consent_gate_mentions_real_volume():
    d = D.detect("https://api.openai.com/v1", consented=False)
    # Consent honesty (outside-voice #3): state the real request volume.
    assert "28" in d.error or "requests" in d.error.lower()


# --------------------------------------------------------------------------- #
# Shape detection — openai / anthropic / catalog
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_detect_openai_shape():
    fp = FakeProbe({"/models": _catalog(), "/chat/completions": _openai_ok(),
                    "/v1/messages": D.ProbeResult(404, {"error": "nope"}, {})})
    d = D.detect("https://api.openai.com/v1", key="sk-x", consented=True, probe=fp)
    assert d.ok and d.llm_positive
    assert d.api_style == "openai"
    assert d.confidence == "high"
    assert d.needs_confirm is False
    assert d.model == "gpt-4o-mini"


@pytest.mark.unit
def test_detect_anthropic_shape():
    fp = FakeProbe({"/models": D.ProbeResult(404, {"error": "nope"}, {}),
                    "/chat/completions": D.ProbeResult(404, {"error": "nope"}, {}),
                    "/v1/messages": _anthropic_ok()})
    d = D.detect("https://api.anthropic.com", key="sk-ant", consented=True, probe=fp)
    assert d.ok and d.llm_positive
    assert d.api_style == "anthropic"
    assert d.confidence == "high"
    assert d.chat_path == "/v1/messages"


@pytest.mark.unit
def test_anthropic_without_catalog_sets_usable_model():
    # MEDIUM (Codex): a positive anthropic detection with no /models catalog must
    # still yield a usable model id (from the echoed response), else save writes "".
    fp = FakeProbe({"/models": D.ProbeResult(404, {}, {}),
                    "/chat/completions": D.ProbeResult(404, {}, {}),
                    "/v1/messages": _anthropic_ok(model="claude-3-5-sonnet-20241022")})
    d = D.detect("https://api.anthropic.com", key="k", consented=True, probe=fp)
    assert d.api_style == "anthropic" and d.model == "claude-3-5-sonnet-20241022"


@pytest.mark.unit
def test_active_probe_transport_error_is_surfaced():
    # MEDIUM (Codex): /models answers but the chat POSTs fail at transport — the
    # real error must surface, not a misleading "not recognizable".
    net_err = D.ProbeResult(0, None, {}, error="the endpoint's TLS certificate could not be verified")
    fp = FakeProbe({"/models": _catalog(), "/chat/completions": net_err, "/v1/messages": net_err})
    d = D.detect("https://api.vendor.com/v1", key="k", consented=True, probe=fp)
    assert d.llm_positive is False
    assert "tls" in d.error.lower() or "certificate" in d.error.lower()


@pytest.mark.unit
def test_ambiguous_both_shapes_confirms():
    fp = FakeProbe({"/models": _catalog(), "/chat/completions": _openai_ok(),
                    "/v1/messages": _anthropic_ok()})
    d = D.detect("https://api.proxy.com/v1", key="k", consented=True, probe=fp)
    assert d.ok and d.needs_confirm is True        # never silently pick
    assert d.confidence == "medium"


# --------------------------------------------------------------------------- #
# LLM-positive requires the FULL combination
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_non_llm_json_is_not_positive():
    # A 200 with JSON but no assistant content / usage / model -> INDETERMINATE.
    junk = D.ProbeResult(200, {"status": "healthy", "version": "1.2"}, {})
    fp = FakeProbe({"/models": junk, "/chat/completions": junk, "/v1/messages": junk})
    d = D.detect("https://api.thing.com", key="k", consented=True, probe=fp)
    assert d.llm_positive is False
    assert d.ok is False
    assert d.needs_confirm is True
    assert "recognizable" in d.error.lower() or "not an llm" in d.error.lower()


@pytest.mark.unit
def test_partial_openai_shape_confirms_low_confidence():
    # content + model but no usage -> 2/3 fields -> partial -> confirm, not positive.
    partial = D.ProbeResult(200, {
        "model": "x", "choices": [{"message": {"content": "ok"}}]}, {})
    fp = FakeProbe({"/models": D.ProbeResult(404, {}, {}),
                    "/chat/completions": partial,
                    "/v1/messages": D.ProbeResult(404, {}, {})})
    d = D.detect("https://api.thing.com", key="k", consented=True, probe=fp)
    assert d.llm_positive is False
    assert d.needs_confirm is True
    assert d.confidence == "low"
    assert d.api_style == "openai"


# --------------------------------------------------------------------------- #
# HTML / login wall, 401, 429
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_html_routes_to_capture():
    html = D.ProbeResult(200, None, {"content-type": "text/html"}, text="<!doctype html><html>login</html>")
    fp = FakeProbe({"/models": html})
    d = D.detect("https://chat.vendor.com", consented=True, probe=fp)
    assert d.route_hint == "capture"
    assert "web app" in d.error.lower()


@pytest.mark.unit
def test_401_without_key_asks_for_key():
    un = D.ProbeResult(401, {"error": "unauthorized"}, {})
    fp = FakeProbe({"/models": un, "/chat/completions": un, "/v1/messages": un})
    d = D.detect("https://api.vendor.com/v1", key=None, consented=True, probe=fp)
    assert d.needs_confirm is True
    assert "401" in d.error and "key" in d.error.lower()


@pytest.mark.unit
def test_429_is_explained():
    rl = D.ProbeResult(429, {"error": "slow down"}, {})
    fp = FakeProbe({"/models": rl, "/chat/completions": rl, "/v1/messages": rl})
    d = D.detect("https://api.vendor.com/v1", key="k", consented=True, probe=fp)
    assert "429" in d.error
    assert d.needs_confirm is True


# --------------------------------------------------------------------------- #
# passive_only sends no inference
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_passive_only_no_inference():
    fp = FakeProbe({"/models": _catalog()})
    d = D.detect("https://api.openai.com/v1", key="k", consented=True,
                 passive_only=True, probe=fp)
    # Only GET /models should have been called; no POST.
    assert all(m == "GET" for (m, *_rest) in fp.calls)
    assert d.needs_confirm is True          # shape not confirmed by inference
    assert d.models == ["gpt-4o-mini", "gpt-4o"]


# --------------------------------------------------------------------------- #
# Egress budget
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_egress_budget_caps_requests():
    b = D.EgressBudget(max_requests=1)
    b.spend(1)
    with pytest.raises(D.EgressBudgetExceeded):
        b.spend(1)
    assert b.remaining() == 0


@pytest.mark.unit
def test_detect_respects_session_budget():
    fp = FakeProbe({"/models": _catalog(), "/chat/completions": _openai_ok(),
                    "/v1/messages": _anthropic_ok()})
    tiny = D.EgressBudget(max_requests=1)     # only the passive GET fits
    d = D.detect("https://api.openai.com/v1", key="k", consented=True,
                 probe=fp, budget=tiny)
    assert d.needs_confirm is True
    assert "stopped early" in d.error.lower() or "budget" in d.error.lower()
    assert len(fp.calls) <= 1                 # budget stopped further egress


# --------------------------------------------------------------------------- #
# Forged-usage caveat + friendly errors
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_every_detection_carries_usage_caveat():
    d = D.detect("https://api.openai.com/v1", consented=False)
    assert "self-reported" in d.caveat.lower()


@pytest.mark.unit
@pytest.mark.parametrize("exc,frag", [
    (TimeoutError("timed out"), "timeout"),
    (ConnectionError("connection refused"), "connect"),
])
def test_friendly_net_errors(exc, frag):
    assert frag in D._friendly_net_error(exc).lower()


@pytest.mark.unit
def test_network_error_is_friendly_not_stacktrace():
    def boom(method, url, headers, body):
        return D.ProbeResult(0, None, {}, error=D._friendly_net_error(ConnectionError("refused")))
    fp = boom
    d = D.detect("https://api.dead.local", key="k", consented=True, probe=fp)
    assert d.needs_confirm is True
    assert "connect" in d.error.lower()


# --------------------------------------------------------------------------- #
# URL normalization — no path doubling (regression)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("text,base,full", [
    ("https://api.openai.com/v1", "https://api.openai.com/v1", ""),
    ("api.deepseek.com", "https://api.deepseek.com", ""),
    ("https://api.x.com/v1/chat/completions", "https://api.x.com/v1",
     "https://api.x.com/v1/chat/completions"),
    # anthropic: /v1/messages is the whole suffix; base excludes /v1 (matches the
    # anthropic base_url convention), full is the exact endpoint.
    ("https://api.x.com/v1/messages", "https://api.x.com",
     "https://api.x.com/v1/messages"),
])
def test_normalize_no_doubling(text, base, full):
    assert D._normalize(text) == (base, full)


@pytest.mark.unit
def test_v1_base_does_not_double_models_path():
    seen = []

    def rec(method, url, headers, body):
        seen.append(url)
        if url.endswith("/v1/models"):
            return _catalog()
        if url.endswith("/chat/completions"):
            return _openai_ok()
        return D.ProbeResult(404, {}, {})

    d = D.detect("https://api.openai.com/v1", key="k", consented=True, probe=rec)
    assert "https://api.openai.com/v1/v1/models" not in seen   # no doubling
    assert d.api_style == "openai"


@pytest.mark.unit
def test_anthropic_cross_probe_no_v1_doubling():
    # LOW (Claude): a full openai-suffixed URL must not make the anthropic
    # cross-probe hit .../v1/v1/messages.
    seen = []

    def rec(method, url, headers, body):
        seen.append(url)
        return D.ProbeResult(404, {}, {})   # force fall-through to both cross-probes

    D.detect("https://api.x.com/v1/chat/completions", key="k", consented=True, probe=rec)
    assert not any("/v1/v1/messages" in u for u in seen)


@pytest.mark.unit
def test_full_endpoint_probed_as_given():
    seen = []

    def rec(method, url, headers, body):
        seen.append(url)
        if url == "https://api.x.com/v1/chat/completions":
            return _openai_ok()
        return D.ProbeResult(404, {}, {})

    d = D.detect("https://api.x.com/v1/chat/completions", key="k", consented=True, probe=rec)
    assert "https://api.x.com/v1/v1/chat/completions" not in seen   # no doubling
    assert d.api_style == "openai"


# --------------------------------------------------------------------------- #
# Presets (E4) + env key (E3) — value NEVER leaks
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("url,slug", [
    ("https://api.openai.com/v1", "openai"),
    ("https://api.anthropic.com", "anthropic"),
    ("https://api.deepseek.com", "deepseek"),
    ("https://api.moonshot.ai/v1", "moonshot"),
])
def test_preset_host_match(url, slug):
    p = P.match_host(url)
    assert p is not None and p.slug == slug


@pytest.mark.unit
def test_preset_unknown_host():
    assert P.match_host("https://api.totally-unknown-vendor.example") is None


@pytest.mark.unit
@pytest.mark.parametrize("evil", [
    "https://api.openai.com.evil.test/v1",     # suffix attack
    "https://api.openai.com.attacker.io",
    "https://evil.test/api.openai.com",        # host in path, not host
    "https://notopenai.com",
])
def test_preset_host_match_rejects_lookalikes(evil):
    # CRITICAL (Codex): substring matching would exfiltrate OPENAI_API_KEY to a
    # look-alike host. Hostname-aware matching must reject these.
    assert P.match_host(evil) is None


@pytest.mark.unit
def test_preset_host_match_allows_real_subdomain():
    # A legitimate subdomain of a preset host still matches.
    assert P.match_host("https://api.moonshot.cn/v1").slug == "moonshot"


@pytest.mark.unit
def test_env_key_returns_name_never_value():
    p = P.match_slug("openai")
    env = {"OPENAI_API_KEY": "sk-secret-value"}
    name = P.env_key_for(p, environ=env)
    assert name == "OPENAI_API_KEY"          # the NAME
    assert name != "sk-secret-value"         # never the value


@pytest.mark.unit
def test_env_key_absent_returns_none():
    p = P.match_slug("openai")
    assert P.env_key_for(p, environ={}) is None
    assert P.env_key_for(p, environ={"OPENAI_API_KEY": ""}) is None
