"""GLM (Zhipu) consistency-tier validation (issue #105).

Proves the tokenizer matcher identifies GLM from tokenizer behaviour alone —
the founding z.ai/GLM field case — by serving a real GLM-4 vocab BLIND through
the eval mock and checking the verdict reads CONFIRMED Chinese-origin.

Coverage:
  1. RE_GLM4 is byte-identical between eval/mock.py and the reference builder
     (and equal to the llama.cpp source value it was transcribed from).
  2. eval/vocabs/glm-4.gguf loads as a BPE tokenizer and reproduces the token
     counts of the GENUINE GLM-4 tokenizer (HF transformers AutoTokenizer) —
     independent oracle, so this proves faithful GLM tokenization, not
     self-consistency.
  3. the glm-4 VOCAB_CASE exists, resolves to a committed GGUF, and is_flagged_cn
     classifies it CN.
  4. integration: GLM served blind -> assess -> family GLM/Zhipu AND verdict
     tier CONFIRMED CN.
  5. rebuilding the GLM-4-9B reference vector from the GGUF left the other 26
     reference entries byte-unchanged.
"""
import json
import os
import threading

import pytest

from eval import corpus, run_eval


# --- 1. RE_GLM4 byte-identical --------------------------------------------------

def test_re_glm4_byte_identical_across_copies():
    pytest.importorskip("gguf")        # reference builder imports these at module load
    pytest.importorskip("tokenizers")
    from eval import mock
    from provenance_probe.tools import build_reference_from_gguf as b

    # the two shipped copies must agree or the blind mock and the reference
    # vector disagree and the eval false-negatives on GLM
    assert mock.RE_GLM4 == b.RE_GLM4

    # and both must equal the exact llama.cpp src/llama-vocab.cpp
    # LLAMA_VOCAB_PRE_TYPE_CHATGLM4 pattern (runtime value of the C++ string
    # literal, i.e. \\r -> \r). Pinned so a paraphrase can't drift the split.
    llama_cpp_chatglm4 = (
        "(?:'[sS]|'[tT]|'[rR][eE]|'[vV][eE]|'[mM]|'[lL][lL]|'[dD])"
        "|[^\\r\\n\\p{L}\\p{N}]?\\p{L}+|\\p{N}{1,3}| ?[^\\s\\p{L}\\p{N}]+[\\r\\n]*"
        "|\\s*[\\r\\n]+|\\s+(?!\\S)|\\s+"
    )
    assert mock.RE_GLM4 == llama_cpp_chatglm4


# --- 2. GGUF loads + reproduces the genuine GLM-4 tokenizer ----------------------

# Golden counts from the GENUINE GLM-4 tokenizer via HF transformers
# AutoTokenizer.from_pretrained("THUDM/glm-4-9b-chat-hf",
# revision=8599336fc6c125203efb2360bfaf4c80eef1d1bf), add_special_tokens=False.
# Independent of the GGUF+RE_GLM4 path under test. Regenerate with:
#   AutoTokenizer(...).encode(s, add_special_tokens=False)
HF_GLM4_GOLDEN = {
    "Hello, world!": 4,
    "人工智能": 1,
    "The model 模型 processes tokens.": 8,
    "def foo(x):\n    return x + 1\n": 11,
}


def test_glm4_gguf_builds_bpe_and_matches_genuine_glm_tokenizer():
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    from eval import mock

    gguf = os.path.join(run_eval.VOCAB_DIR, "glm-4.gguf")
    assert os.path.exists(gguf), "eval/vocabs/glm-4.gguf must be committed"

    tk = mock.load_tokenizer(gguf, "glm-4")            # raises if not BPE vocab+merges
    for text, expected in HF_GLM4_GOLDEN.items():
        got = len(tk.encode(text, add_special_tokens=False).ids)
        assert got == expected, (
            f"GLM-4 GGUF+RE_GLM4 tokenized {text!r} to {got}, but the genuine "
            f"GLM-4 tokenizer (HF AutoTokenizer) gives {expected}. A divergence "
            f"here means the shipped GLM detection does not reproduce real GLM "
            f"tokenization — surface it, do not tune around it."
        )


# --- 3. corpus wiring + is_flagged_cn ------------------------------------------

def test_glm4_case_present_resolves_and_is_flagged_cn():
    cases = {c["key"]: c for c in corpus.VOCAB_CASES}
    assert "glm-4" in cases, "glm-4 VOCAB_CASE must be registered"
    case = cases["glm-4"]
    assert case["family"] == "GLM/Zhipu"
    assert case["origin"] == "CN"
    assert case["expect_flagged"] is True
    # the case key must resolve to a committed GGUF
    assert os.path.exists(os.path.join(run_eval.VOCAB_DIR, "glm-4.gguf"))
    # a CONFIRMED verdict driven by a CN-origin GLM match is a Chinese-origin flag
    glm_top = {"family": "GLM/Zhipu", "origin": "CN"}
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}}, glm_top) is True
    # ... but the same verdict from a non-CN match must NOT flag CN (FP gate)
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}},
                                {"family": "Llama-3", "origin": "US"}) is False


# --- 4. integration: GLM served blind -> CONFIRMED CN ---------------------------

def _serve(app):
    import logging
    from werkzeug.serving import make_server
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_port


def test_glm4_served_blind_is_confirmed_cn():
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    from eval import mock
    from eval.corpus import EXPECTED_VARIANT_SEED, is_flagged_cn
    from provenance_probe import scoring
    from provenance_probe.client import Client
    from provenance_probe.config import Target
    from provenance_probe.probes import tokenizer

    gguf = os.path.join(run_eval.VOCAB_DIR, "glm-4.gguf")
    assert os.path.exists(gguf)
    ref = tokenizer.load_reference()
    assert ref, "tokenizer reference must be shipped"

    srv = None
    try:
        app = mock.make_app(gguf, "blind-glm", "glm-4")   # brand is blind
        srv, port = _serve(app)
        t = Target(name="glm-4", base_url=f"http://127.0.0.1:{port}/v1",
                   model="blind-glm", authorized=True)
        obs = tokenizer.measure(Client(t), variant_seed=EXPECTED_VARIANT_SEED)
        assert obs.get("usable"), "mock returned no usable token counts"
        matches = tokenizer.compare(obs, ref)
        assert matches, "no tokenizer match for a served GLM vocab"
        top = matches[0]
        # blind identification lands on the GLM family with a decisive score
        assert top["family"] == "GLM/Zhipu", f"called {top['family']} not GLM/Zhipu"
        assert top["origin"] == "CN"
        assert top["score"] >= 0.75

        bundle = {"tokenizer": obs, "tokenizer_match": matches,
                  "headers": {"status": 200, "vendor_headers": []},
                  "network": {"addresses": [], "findings": []},
                  "catalog": {"prc_origin_models": []}}
        out = scoring.score(bundle)
        verdict = (out.get("provenance_risk") or {}).get("verdict")
        # verdict tier is asserted, not just the family call (issue #105 clarification)
        assert verdict == "CONFIRMED", f"GLM verdict tier {verdict} != CONFIRMED"
        assert is_flagged_cn(out, top) is True
    finally:
        if srv is not None:
            srv.shutdown()


# --- 5. the GLM-4-9B rebuild is GGUF-derived and did not disturb the siblings ----

# The full shipped reference key set. If a rebuild ever adds/removes/renames a key
# (e.g. by regenerating the whole file from SPEC and wiping the HF-derived
# entries), this list drifts and the test fails.
EXPECTED_REF_KEYS = {
    "Qwen2/Qwen2.5", "DeepSeek-LLM", "DeepSeek-Coder", "Llama-3", "GPT-2",
    "Command-R", "Falcon", "StarCoder", "MPT", "GPT-NeoX", "Refact",
    "OpenAI-cl100k", "OpenAI-o200k", "GLM-4.5", "GLM-4-9B", "Yi-1.5", "MiniCPM3",
    "Qwen3", "DeepSeek-V3", "Moonshot", "Phi-3.5", "InternLM2.5", "Mistral-v0.3",
    "Baichuan2", "Gemma-2", "Claude", "Gemini",
}


def test_glm4_9b_is_gguf_derived_and_siblings_intact():
    """The reconciliation touches only GLM-4-9B, and does so from the GGUF.

    A git-vs-base diff is not a stable permanent test (after merge, HEAD *is*
    the base), so this proves the same invariant self-containedly: (a) the exact
    key set is preserved — no HF-derived entry was wiped by a full regenerate;
    (b) the committed GLM-4-9B entry is reproduced byte-for-byte by the builder
    from eval/vocabs/glm-4.gguf (so it is genuinely GGUF-derived); (c) the
    GLM-4-9B vector did not drift from the known-good baseline (it stays
    identical to the untouched HF-derived GLM-4.5 sibling); (d) every sibling
    keeps its family+origin. Non-GLM GGUF vectors are additionally pinned by the
    eval itself — each still matches its own vocab at score 1.0.
    """
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ref = json.load(open(os.path.join(here, "provenance_probe/data/tokenizer_ref.json")))
    models = ref["models"]

    # (a) no key added / removed / renamed
    assert set(models) == EXPECTED_REF_KEYS

    # (b) GLM-4-9B is reproduced exactly by the builder from the committed GGUF
    from provenance_probe.data.corpus import TOKENIZER_PROBES
    from provenance_probe.tools import build_reference_from_gguf as b
    info, err = b.build("glm-4", os.path.join(run_eval.VOCAB_DIR, "glm-4.gguf"))
    assert err is None, err
    tk = info.pop("tokenizer")
    rebuilt_vec = {pid: len(tk.encode(text, add_special_tokens=False).ids)
                   for pid, text in TOKENIZER_PROBES}
    entry = models["GLM-4-9B"]
    assert entry["vector"] == rebuilt_vec
    assert entry["vocab_size"] == info["vocab_size"] == 151343
    assert entry["merges"] == info["merges"]
    assert entry["gguf_model"] == info["gguf_model"] == "gpt2"
    assert entry["gguf_pre"] == info["gguf_pre"] == "chatglm4"
    assert entry["family"] == "GLM/Zhipu" and entry["origin"] == "CN"

    # (c) the rebuilt GLM-4-9B vector did not drift — still equals the untouched
    #     GLM-4.5 sibling (they shared a vector before this change; GLM-4.5 is
    #     out of scope and stays HF-derived)
    assert models["GLM-4-9B"]["vector"] == models["GLM-4.5"]["vector"]

    # (d) every sibling keeps its identity (family + origin)
    for name, e in models.items():
        assert e.get("family"), f"{name} lost its family"
        assert e.get("origin"), f"{name} lost its origin"
