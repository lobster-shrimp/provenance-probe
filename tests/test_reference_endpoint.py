"""build-reference-endpoint: measure a reference vector from a live first-party API.

For families whose tokenizer is not published (Claude, Gemini), the genuine
first-party endpoint is the ground truth. These tests use a fake client so no
network is touched.
"""
import json

import pytest

from provenance_probe import reference


class _T:
    base_url = "https://api.anthropic.com"


class _Resp:
    def __init__(self, n, err=None):
        self._n, self.err = n, err

    def usage_prompt_tokens(self):
        return self._n

    def echoed_model(self):
        return "claude-x"


class _Client:
    """Deterministic prompt_tokens per probe so measure() yields a usable vector."""
    t = _T()

    def chat(self, prompt, **kw):
        return _Resp(len(prompt) // 2 + 3)


def _seed_ref(tmp_path, models=None):
    out = tmp_path / "ref.json"
    out.write_text(json.dumps({"corpus_version": reference.CORPUS_VERSION,
                               "synthetic": False, "variant_seed": 0,
                               "models": models or {}}))
    return str(out)


def test_build_from_endpoint_merges_measured_vector(tmp_path):
    out = _seed_ref(tmp_path)
    reference.build_from_endpoint(_Client(), label="Claude", family="Claude/Anthropic",
                                  origin="US", out=out)
    e = json.loads(open(out).read())["models"]["Claude"]
    assert e["origin"] == "US" and e["family"] == "Claude/Anthropic"
    assert e["source"] == "live-first-party-api"                 # distinct, auditable provenance
    assert e["endpoint"] == "https://api.anthropic.com"
    assert len(e["vector"]) >= 6


def test_build_from_endpoint_refuses_unusable(tmp_path):
    class _Empty:
        t = _T()
        def chat(self, prompt, **kw):
            return _Resp(None, err="no usage")     # endpoint suppresses prompt_tokens
    with pytest.raises(SystemExit):
        reference.build_from_endpoint(_Empty(), label="X", family="X", origin="US",
                                      out=_seed_ref(tmp_path))


def test_build_from_endpoint_protects_foreign_source(tmp_path):
    out = _seed_ref(tmp_path, models={"Claude": {"source": "tiktoken", "vector": {}}})
    with pytest.raises(SystemExit):                 # won't clobber a GGUF/tiktoken entry
        reference.build_from_endpoint(_Client(), label="Claude", family="C", origin="US", out=out)


def test_build_from_endpoint_reruns_over_own_source(tmp_path):
    out = _seed_ref(tmp_path, models={"Claude": {"source": "live-first-party-api", "vector": {}}})
    reference.build_from_endpoint(_Client(), label="Claude", family="Claude/Anthropic",
                                  origin="US", out=out)                # re-measure is allowed
    assert len(json.loads(open(out).read())["models"]["Claude"]["vector"]) >= 6
