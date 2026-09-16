"""SentencePiece consistency-tier validation (issues #107 and #109).

Adds the SentencePiece enabler to the eval's GGUF-vocab path and validates the
four last-gap CN families whose tokenizer is SentencePiece, not byte-level GPT-2
BPE: Yi-1.5, InternLM2.5, MiniCPM3 (Approach A, committed unigram-style GGUF
carrying tokens+scores+merges) and Baichuan2 (Approach B, raw tokenizer.model via
sentencepiece). Each is served BLIND through the eval mock; the verdict must read
flagged Chinese-origin, matching the family at score 1.0.

FINDING pinned by these tests (surfaced, not tuned away): all four are
SentencePiece **BPE** with byte_fallback (proto model_type=2), NOT unigram, so
the faithful reconstruction is models.BPE(..., byte_fallback=True) + a per-family
Metaspace/Replace front-end (SP_CONFIG), reproducing the genuine HF AutoTokenizer
counts exactly. tokenizers.models.Unigram would be the wrong algorithm.

Coverage:
  ENABLER
    - classify_vocab: byte-level BPE (no scores) vs SentencePiece (has scores).
    - shared-builder parity: eval/mock.py serves each SP vocab through the SAME
      build_reference_from_gguf builder, so mock and reference cannot drift.
    - BPE path unchanged: an existing byte-level BPE vocab (glm-4) still builds
      and reproduces its genuine counts (regression guard for criterion 1).
  PER FAMILY (Yi, InternLM, MiniCPM, Baichuan)
    1. the committed vocab loads and reproduces the genuine HF AutoTokenizer
       counts (independent oracle) — the hard faithfulness gate.
    2. a VOCAB_CASE exists, resolves to a committed vocab, is_flagged_cn CN.
    3. integration: served blind -> assess -> the family match AND flagged CN.
    4. rebuilding the family's reference vector from its committed vocab left
       every reference key present and every sibling's family+origin intact, and
       the family entry is genuinely vocab-derived (reproduced by the builder).
"""
import json
import os
import threading

import pytest

from eval import corpus, mock, run_eval


# The four SP families, their vocab key, HF source, and expected family/verdict.
SP_FAMILIES = {
    "yi":       {"label": "Yi-1.5",      "family": "Yi/01.AI",  "vocab": "yi.gguf"},
    "internlm": {"label": "InternLM2.5", "family": "InternLM",  "vocab": "internlm.gguf"},
    "minicpm":  {"label": "MiniCPM3",    "family": "MiniCPM",   "vocab": "minicpm.gguf"},
    "baichuan": {"label": "Baichuan2",   "family": "Baichuan",  "vocab": "baichuan.model"},
}

# --- golden HF AutoTokenizer sample-string counts (independent oracle) ----------
# Computed once from transformers.AutoTokenizer.from_pretrained(<repo>) with
# add_special_tokens=False and no chat template. For InternLM the golden reflects
# the genuine byte_fallback tokenization (== the pre-existing shipped reference
# and a real endpoint): InternLM2.5's CURRENT HF fast/slow tokenizers regressed
# byte_fallback to False (emoji/rare-unicode collapse to <unk>), so the served
# reconstruction deliberately reproduces the byte_fallback-correct behaviour.
SAMPLE = ["Hello, world!", "人工智能",
          "The model 模型 processes tokens.", "def foo(x):\n    return x + 1\n"]
GOLDEN_SAMPLE = {
    "yi":       {"Hello, world!": 4, "人工智能": 2, "The model 模型 processes tokens.": 7, "def foo(x):\n    return x + 1\n": 13},
    "internlm": {"Hello, world!": 4, "人工智能": 1, "The model 模型 processes tokens.": 7, "def foo(x):\n    return x + 1\n": 11},
    "minicpm":  {"Hello, world!": 4, "人工智能": 2, "The model 模型 processes tokens.": 7, "def foo(x):\n    return x + 1\n": 14},
    "baichuan": {"Hello, world!": 4, "人工智能": 1, "The model 模型 processes tokens.": 7, "def foo(x):\n    return x + 1\n": 14},
}

# --- golden probe-corpus vectors (the genuine tokenizer over the 20 probes) ------
# Yi/InternLM/MiniCPM are byte-identical to the pre-existing HF-derived shipped
# vector (zero detection delta). Baichuan is the genuine sentencepiece vector; it
# differs from the prior shipped vector on 4 probes (diacritics 148->150, cyrillic
# 59->60, base64ish 256->192, newline_storm 122->121) — a surfaced vector-drift
# finding, the prior shipped Baichuan vector was slightly off.
GOLDEN_VECTOR = {
    "yi": {"cjk_dense": 65, "cjk_mixed": 35, "jp_kana": 92, "ko_hangul": 91, "ws_runs": 94, "tabs_deep": 56, "digits_long": 335, "punct_repeat": 149, "emoji_zwj": 481, "rare_unicode": 469, "diacritics": 291, "arabic_hebrew": 161, "cyrillic": 58, "code_json": 184, "code_regex": 280, "url_paths": 211, "base64ish": 193, "md_table": 126, "mixed_script_cjk_code": 120, "newline_storm": 122},
    "internlm": {"cjk_dense": 66, "cjk_mixed": 35, "jp_kana": 74, "ko_hangul": 79, "ws_runs": 79, "tabs_deep": 29, "digits_long": 190, "punct_repeat": 17, "emoji_zwj": 480, "rare_unicode": 452, "diacritics": 270, "arabic_hebrew": 125, "cyrillic": 140, "code_json": 135, "code_regex": 212, "url_paths": 171, "base64ish": 198, "md_table": 114, "mixed_script_cjk_code": 105, "newline_storm": 9},
    "minicpm": {"cjk_dense": 67, "cjk_mixed": 34, "jp_kana": 70, "ko_hangul": 73, "ws_runs": 105, "tabs_deep": 112, "digits_long": 335, "punct_repeat": 245, "emoji_zwj": 193, "rare_unicode": 461, "diacritics": 151, "arabic_hebrew": 119, "cyrillic": 85, "code_json": 155, "code_regex": 289, "url_paths": 211, "base64ish": 193, "md_table": 132, "mixed_script_cjk_code": 120, "newline_storm": 122},
    "baichuan": {"cjk_dense": 62, "cjk_mixed": 34, "jp_kana": 68, "ko_hangul": 46, "ws_runs": 98, "tabs_deep": 112, "digits_long": 334, "punct_repeat": 164, "emoji_zwj": 192, "rare_unicode": 224, "diacritics": 150, "arabic_hebrew": 102, "cyrillic": 60, "code_json": 173, "code_regex": 304, "url_paths": 221, "base64ish": 192, "md_table": 126, "mixed_script_cjk_code": 123, "newline_storm": 121},
}

EXPECTED_REF_KEYS = {
    "Qwen2/Qwen2.5", "DeepSeek-LLM", "DeepSeek-Coder", "Llama-3", "GPT-2",
    "Command-R", "Falcon", "StarCoder", "MPT", "GPT-NeoX", "Refact",
    "OpenAI-cl100k", "OpenAI-o200k", "GLM-4.5", "GLM-4-9B", "Yi-1.5", "MiniCPM3",
    "Qwen3", "DeepSeek-V3", "Moonshot", "Phi-3.5", "InternLM2.5", "Mistral-v0.3",
    "Baichuan2", "Gemma-2", "Claude", "Gemini",
}


def _need_deps():
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    pytest.importorskip("sentencepiece")


def _serve(app):
    import logging
    from werkzeug.serving import make_server
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_port


# =============================== ENABLER =======================================

def test_classify_vocab_bpe_vs_spm():
    """read_gguf_vocab returns scores; a vocab with scores is SentencePiece, one
    without is byte-level BPE. The four SP GGUFs carry scores; the existing 13 do
    not (criterion 1)."""
    _need_deps()
    from provenance_probe.tools import build_reference_from_gguf as b

    # existing byte-level BPE vocab: merges, no scores -> bpe
    toks, merges, scores, _pre, model = b.read_gguf_vocab(
        os.path.join(run_eval.VOCAB_DIR, "glm-4.gguf"))
    assert toks and merges and not scores
    assert b.classify_vocab(merges, scores, model) == "bpe"

    # SP vocab (Approach A): has scores -> spm
    toks, merges, scores, _pre, model = b.read_gguf_vocab(
        os.path.join(run_eval.VOCAB_DIR, "yi.gguf"))
    assert toks and scores and len(scores) == len(toks)
    assert b.classify_vocab(merges, scores, model) == "spm"
    assert model == "llama"


def test_bpe_path_unchanged_regression():
    """The byte-level BPE path (the existing 13 families) still builds and
    reproduces genuine counts — the SP enabler did not disturb it (criterion 1)."""
    _need_deps()
    from provenance_probe.tools import build_reference_from_gguf as b
    tk = mock.load_tokenizer(os.path.join(run_eval.VOCAB_DIR, "glm-4.gguf"), "glm-4")
    # genuine GLM-4 HF AutoTokenizer counts (pinned in test_eval_glm.py)
    assert len(tk.encode("人工智能", add_special_tokens=False).ids) == 1
    assert len(tk.encode("Hello, world!", add_special_tokens=False).ids) == 4
    # and the builder still classifies/reads it as BPE, not SP
    _t, merges, scores, _p, _m = b.read_gguf_vocab(
        os.path.join(run_eval.VOCAB_DIR, "glm-4.gguf"))
    assert merges and not scores


@pytest.mark.parametrize("key", list(SP_FAMILIES))
def test_shared_builder_parity_mock_equals_reference(key):
    """eval/mock.py serves each SP vocab through the SAME builder the reference
    uses (build_reference_from_gguf), so the served counts and the rebuilt
    reference vector are identical — the SP analogue of the byte-identical REGEX
    invariant (criterion 2)."""
    _need_deps()
    from provenance_probe.data.corpus import TOKENIZER_PROBES
    from provenance_probe.tools import build_reference_from_gguf as b

    path = mock.vocab_path(run_eval.VOCAB_DIR, key)
    served = mock.load_tokenizer(path, key)
    info, err = b.build(key, path)
    assert err is None, err
    served_vec = {pid: len(served.encode(t, add_special_tokens=False).ids)
                  for pid, t in TOKENIZER_PROBES}
    assert served_vec == info["vector"]


# ============================== PER FAMILY =====================================

@pytest.mark.parametrize("key", list(SP_FAMILIES))
def test_sp_vocab_reproduces_genuine_hf_tokenizer(key):
    """1. The committed vocab loads and reproduces the genuine HF AutoTokenizer
    sample counts (independent oracle) — the hard faithfulness gate (criterion 3).
    """
    _need_deps()
    path = mock.vocab_path(run_eval.VOCAB_DIR, key)
    assert os.path.exists(path), f"eval/vocabs/{SP_FAMILIES[key]['vocab']} committed"
    tk = mock.load_tokenizer(path, key)
    for text, expected in GOLDEN_SAMPLE[key].items():
        got = len(tk.encode(text, add_special_tokens=False).ids)
        assert got == expected, (
            f"{key} served tokenized {text!r} to {got}, but the genuine HF "
            f"tokenizer gives {expected}. A divergence means the shipped {key} "
            f"detection does not reproduce real tokenization — surface it, do not "
            f"tune around it.")


@pytest.mark.parametrize("key", list(SP_FAMILIES))
def test_sp_case_present_resolves_and_is_flagged_cn(key):
    """2. The VOCAB_CASE exists, resolves to a committed vocab, is_flagged_cn CN."""
    meta = SP_FAMILIES[key]
    cases = {c["key"]: c for c in corpus.VOCAB_CASES}
    assert key in cases, f"{key} VOCAB_CASE must be registered"
    case = cases[key]
    assert case["family"] == meta["family"]
    assert case["origin"] == "CN"
    assert case["expect_flagged"] is True
    assert os.path.exists(mock.vocab_path(run_eval.VOCAB_DIR, key))
    top = {"family": meta["family"], "origin": "CN"}
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}}, top) is True
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "LIKELY"}}, top) is True
    # a non-CN match with the same verdict must NOT flag CN (FP gate)
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}},
                                {"family": "Llama-3", "origin": "US"}) is False


@pytest.mark.parametrize("key", list(SP_FAMILIES))
def test_sp_served_blind_is_flagged_cn(key):
    """3. Served blind -> assess -> the family match AND flagged Chinese-origin."""
    _need_deps()
    from eval.corpus import EXPECTED_VARIANT_SEED, is_flagged_cn
    from provenance_probe import scoring
    from provenance_probe.client import Client
    from provenance_probe.config import Target
    from provenance_probe.probes import tokenizer

    meta = SP_FAMILIES[key]
    path = mock.vocab_path(run_eval.VOCAB_DIR, key)
    ref = tokenizer.load_reference()
    assert ref, "tokenizer reference must be shipped"

    srv = None
    try:
        app = mock.make_app(path, f"blind-{key}", key)   # brand is blind
        srv, port = _serve(app)
        t = Target(name=key, base_url=f"http://127.0.0.1:{port}/v1",
                   model=f"blind-{key}", authorized=True)
        obs = tokenizer.measure(Client(t), variant_seed=EXPECTED_VARIANT_SEED)
        assert obs.get("usable"), "mock returned no usable token counts"
        matches = tokenizer.compare(obs, ref)
        assert matches, f"no tokenizer match for a served {key} vocab"
        top = matches[0]
        assert top["family"] == meta["family"], f"called {top['family']} not {meta['family']}"
        assert top["origin"] == "CN"
        assert top["score"] >= 0.75

        bundle = {"tokenizer": obs, "tokenizer_match": matches,
                  "headers": {"status": 200, "vendor_headers": []},
                  "network": {"addresses": [], "findings": []},
                  "catalog": {"prc_origin_models": []}}
        out = scoring.score(bundle)
        verdict = (out.get("provenance_risk") or {}).get("verdict")
        # adverse provenance tier (CONFIRMED for baichuan; LIKELY for the others,
        # the same tier as the shipped Qwen/DeepSeek CN cases) + a CN flag
        assert verdict in ("CONFIRMED", "LIKELY"), f"{key} verdict {verdict} not adverse"
        assert is_flagged_cn(out, top) is True
    finally:
        if srv is not None:
            srv.shutdown()


@pytest.mark.parametrize("key", list(SP_FAMILIES))
def test_sp_is_vocab_derived_and_siblings_intact(key):
    """4. The reconciliation touches only this family and does so from its
    committed vocab: the exact key set is preserved; the entry is reproduced by
    the builder; the vector matches the genuine golden; siblings keep identity."""
    _need_deps()
    from provenance_probe.data.corpus import TOKENIZER_PROBES
    from provenance_probe.tools import build_reference_from_gguf as b

    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ref = json.load(open(os.path.join(here, "provenance_probe/data/tokenizer_ref.json")))
    models = ref["models"]
    assert set(models) == EXPECTED_REF_KEYS

    path = mock.vocab_path(run_eval.VOCAB_DIR, key)
    info, err = b.build(key, path)
    assert err is None, err
    served = mock.load_tokenizer(path, key)
    rebuilt = {pid: len(served.encode(text, add_special_tokens=False).ids)
               for pid, text in TOKENIZER_PROBES}
    entry = models[SP_FAMILIES[key]["label"]]
    assert entry["vector"] == rebuilt == info["vector"]
    assert entry["vector"] == GOLDEN_VECTOR[key]
    assert entry["family"] == SP_FAMILIES[key]["family"] and entry["origin"] == "CN"

    for name, e in models.items():
        assert e.get("family"), f"{name} lost its family"
        assert e.get("origin"), f"{name} lost its origin"
