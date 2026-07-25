"""E8: adversarial red-team corpus — detect a model-identity switch under stress."""
from provenance_probe import redteam


class _Resp:
    def __init__(self, model, content, status=200):
        self._model, self._content, self.status = model, content, status
    def echoed_model(self):
        return self._model
    def text(self):
        return self._content
    def ok(self):
        return 200 <= self.status < 300


class _Client:
    """Returns a scripted (model, content) per call; can swap identity after N."""
    def __init__(self, script):
        self.script = list(script)
        self.i = -1

    def chat(self, prompt, **kw):
        self.i += 1
        return _Resp(*self.script[min(self.i, len(self.script) - 1)])


def test_stable_identity_no_switch():
    c = _Client([("gpt-4o", "I am ChatGPT by OpenAI.")] * 8)
    out = redteam.run(c, cap=8)
    assert out["switch_detected"] is False
    assert out["scenarios_run"] == 8
    assert "stable" in out["note"]


def test_switch_under_stress_detected():
    # stable for 2, then the backend swaps to glm-4 (a cheaper fallback under load)
    script = [("gpt-4o", "I am ChatGPT.")] * 2 + [("glm-4", "Actually I'm GLM.")] * 6
    out = redteam.run(_Client(script), cap=8)
    assert out["switch_detected"] is True
    hops = {(s["signal"], s["from"], s["to"]) for s in out["switches"]}
    assert ("model_id", "gpt-4o", "glm-4") in hops


def test_cap_bounds_volume():
    c = _Client([("m", "x")] * 20)
    out = redteam.run(c, cap=3)                       # quota guard
    assert out["scenarios_run"] == 3


def test_transport_error_is_not_a_clean_scenario():
    # a non-2xx Response must NOT count as a successful no-identity scenario
    c = _Client([("gpt-4o", "hi", 200), ("", "", 500), ("gpt-4o", "hi", 200)])
    out = redteam.run(c, cap=3)
    assert out["scenarios_run"] == 2                       # the 500 didn't count
    assert any("transport" in r.get("error", "") for r in out["identities"])


def test_self_id_change_is_advisory_not_hard_switch():
    # echoed model stable, only the self-ID text changes (e.g. a refusal/negation)
    c = _Client([("gpt-4o", "I am ChatGPT."), ("gpt-4o", "Actually I'm GLM.")] + [("gpt-4o", "x")] * 6)
    out = redteam.run(c, cap=8)
    assert out["switch_detected"] is False                 # NOT a hard switch (exit 0)
    assert out["self_id_flags"]                            # but flagged for review


def test_self_id_backfills_when_first_response_has_no_selfid():
    # first response: model id only; later a self-ID appears then changes -> flagged
    c = _Client([("router", "ok."), ("router", "I am ChatGPT."), ("router", "Actually GLM.")]
                + [("router", "x")] * 5)
    out = redteam.run(c, cap=8)
    # the self-ID went ChatGPT(OpenAI) -> GLM; backfill means the change is seen
    assert any(f["signal"] == "self_id" for f in out["self_id_flags"])


def test_one_scenario_error_does_not_abort():
    class _Boom(_Client):
        def chat(self, prompt, **kw):
            self.i += 1
            if self.i == 1:
                raise RuntimeError("rate limited")
            return _Resp("gpt-4o", "I am ChatGPT.")
    out = redteam.run(_Boom([]), cap=4)
    assert any("error" in r for r in out["identities"])   # the failure is recorded
    assert out["switch_detected"] is False                # and the run continued
