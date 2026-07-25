"""E8: adversarial red-team corpus — detect a model-identity switch under stress."""
from provenance_probe import redteam


class _Resp:
    def __init__(self, model, content):
        self.body = {"model": model,
                     "choices": [{"message": {"role": "assistant", "content": content}}]}
        self.stream_text = None


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
