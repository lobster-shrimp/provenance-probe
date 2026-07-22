"""Reasoning models (Moonshot kimi, OpenAI o-series) reject temperature=0 with a
400. Since prompt_tokens is temperature-independent, the client retries once
without temperature. Regression for the real kimi-k2.6 fingerprint failure."""
from provenance_probe.client import Client
from provenance_probe.config import Target


class _Resp:
    def __init__(self, status, body, text):
        self.status_code = status
        self._body = body
        self.text = text
        self.headers = {}
    def json(self):
        import json as _j
        return _j.loads(self.text)


class _Session:
    """Fake session: first POST 400s on temperature, retry (no temperature) 200s."""
    def __init__(self):
        self.calls = []
    def post(self, url, headers=None, json=None, **kw):
        self.calls.append(json)
        if "temperature" in json:
            return _Resp(400, None, '{"error":{"message":"invalid temperature: only 1 is allowed"}}')
        return _Resp(200, None, '{"usage":{"prompt_tokens":42},"choices":[{"message":{"content":"ok"}}]}')


def test_retries_without_temperature_on_400():
    c = Client(Target(name="k", base_url="http://x", model="kimi-k2.6"))
    c.s = _Session()
    r = c.chat("probe", max_tokens=1, temperature=0.0)
    assert r.status == 200
    assert r.usage_prompt_tokens() == 42
    assert len(c.s.calls) == 2                       # original + one retry
    assert "temperature" in c.s.calls[0]             # first attempt had it
    assert "temperature" not in c.s.calls[1]         # retry dropped it


def test_no_retry_when_400_is_unrelated():
    class S(_Session):
        def post(self, url, headers=None, json=None, **kw):
            self.calls.append(json)
            return _Resp(400, None, '{"error":{"message":"model not found"}}')
    c = Client(Target(name="k", base_url="http://x", model="m"))
    c.s = S()
    c.chat("probe", max_tokens=1, temperature=0.0)
    assert len(c.s.calls) == 1                       # no temperature retry


def test_no_retry_on_success():
    class S(_Session):
        def post(self, url, headers=None, json=None, **kw):
            self.calls.append(json)
            return _Resp(200, None, '{"usage":{"prompt_tokens":7}}')
    c = Client(Target(name="k", base_url="http://x", model="m"))
    c.s = S()
    r = c.chat("probe", max_tokens=1, temperature=0.0)
    assert r.usage_prompt_tokens() == 7
    assert len(c.s.calls) == 1
