"""Moonshot (Moonlight/Kimi) consistency-tier validation (issue #107).

Proves the tokenizer matcher identifies Moonshot from tokenizer behaviour alone
by serving a real Moonlight-16B-A3B vocab BLIND through the eval mock and checking
the verdict reads CONFIRMED Chinese-origin.

Moonshot ships a *tiktoken* tokenizer (not an HF tokenizer.json). llama.cpp's
matching pre-type (LLAMA_VOCAB_PRE_TYPE_KIMI_K2) delegates the split to a custom
unicode.cpp handler, so the faithful pre-tokenizer regex is the model's own
`pat_str` from tokenization_moonshot.py; RE_MOONSHOT is that value.

Coverage:
  1. RE_MOONSHOT is byte-identical between eval/mock.py and the reference builder
     (and equal to the Moonlight tokenization_moonshot.py pat_str value it was
     transcribed from).
  2. eval/vocabs/moonshot.gguf loads as a BPE tokenizer and reproduces the token
     counts of the GENUINE Moonlight tokenizer (tiktoken oracle) — independent of
     the GGUF+RE_MOONSHOT path, so this proves faithful Moonshot tokenization, not
     self-consistency.
  3. the moonshot VOCAB_CASE exists, resolves to a committed GGUF, and
     is_flagged_cn classifies it CN.
  4. integration: Moonshot served blind -> assess -> family Moonshot AND verdict
     tier CONFIRMED CN.
  5. rebuilding the Moonshot reference vector from the GGUF left every reference
     key present and every sibling's family+origin intact, and the Moonshot
     entry is genuinely GGUF-derived (reproduced byte-for-byte by the builder).
"""
import json
import os
import threading

import pytest

from eval import corpus, run_eval


# --- 1. RE_MOONSHOT byte-identical ---------------------------------------------

def test_re_moonshot_byte_identical_across_copies():
    pytest.importorskip("gguf")        # reference builder imports these at module load
    pytest.importorskip("tokenizers")
    from eval import mock
    from provenance_probe.tools import build_reference_from_gguf as b

    # the two shipped copies must agree or the blind mock and the reference
    # vector disagree and the eval false-negatives on Moonshot
    assert mock.RE_MOONSHOT == b.RE_MOONSHOT

    # and both must equal the exact Moonlight tokenization_moonshot.py pat_str
    # (the authoritative source; runtime value of the joined pattern). Pinned so a
    # paraphrase can't drift the split.
    moonlight_pat_str = "|".join([
        r"[\p{Han}]+",
        r"[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
        r"[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?",
        r"\p{N}{1,3}",
        r" ?[^\s\p{L}\p{N}]+[\r\n]*",
        r"\s*[\r\n]+",
        r"\s+(?!\S)",
        r"\s+",
    ])
    assert mock.RE_MOONSHOT == moonlight_pat_str


# --- 2. GGUF loads + reproduces the genuine Moonshot tokenizer ------------------

# Golden counts from the GENUINE Moonlight tokenizer via tiktoken:
#   ranks = load_tiktoken_bpe(hf_hub_download("moonshotai/Moonlight-16B-A3B",
#           "tiktoken.model", revision="476b36a4..."))
#   tiktoken.Encoding(pat_str=<pat_str>, mergeable_ranks=ranks, special_tokens={})
#   .encode(s, disallowed_special=())
# Independent of the GGUF+RE_MOONSHOT path under test.
HF_MOONSHOT_GOLDEN = {
    "Hello, world!": 4,
    "人工智能": 1,
    "The model 模型 processes tokens.": 7,
    "def foo(x):\n    return x + 1\n": 11,
}


def test_moonshot_gguf_builds_bpe_and_matches_genuine_tokenizer():
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    from eval import mock

    gguf = os.path.join(run_eval.VOCAB_DIR, "moonshot.gguf")
    assert os.path.exists(gguf), "eval/vocabs/moonshot.gguf must be committed"

    tk = mock.load_tokenizer(gguf, "moonshot")         # raises if not BPE vocab+merges
    for text, expected in HF_MOONSHOT_GOLDEN.items():
        got = len(tk.encode(text, add_special_tokens=False).ids)
        assert got == expected, (
            f"Moonshot GGUF+RE_MOONSHOT tokenized {text!r} to {got}, but the "
            f"genuine Moonlight tokenizer (tiktoken) gives {expected}. A "
            f"divergence here means the shipped Moonshot detection does not "
            f"reproduce real Moonshot tokenization — surface it, do not tune "
            f"around it."
        )


# --- 3. corpus wiring + is_flagged_cn ------------------------------------------

def test_moonshot_case_present_resolves_and_is_flagged_cn():
    cases = {c["key"]: c for c in corpus.VOCAB_CASES}
    assert "moonshot" in cases, "moonshot VOCAB_CASE must be registered"
    case = cases["moonshot"]
    assert case["family"] == "Moonshot"
    assert case["origin"] == "CN"
    assert case["expect_flagged"] is True
    # the case key must resolve to a committed GGUF
    assert os.path.exists(os.path.join(run_eval.VOCAB_DIR, "moonshot.gguf"))
    # a CONFIRMED verdict driven by a CN-origin Moonshot match is a CN flag
    moon_top = {"family": "Moonshot", "origin": "CN"}
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}}, moon_top) is True
    # ... but the same verdict from a non-CN match must NOT flag CN (FP gate)
    assert corpus.is_flagged_cn({"provenance_risk": {"verdict": "CONFIRMED"}},
                                {"family": "Llama-3", "origin": "US"}) is False


# --- 4. integration: Moonshot served blind -> CONFIRMED CN ---------------------

def _serve(app):
    import logging
    from werkzeug.serving import make_server
    logging.getLogger("werkzeug").setLevel(logging.ERROR)
    srv = make_server("127.0.0.1", 0, app, threaded=True)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv, srv.server_port


def test_moonshot_served_blind_is_confirmed_cn():
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    from eval import mock
    from eval.corpus import EXPECTED_VARIANT_SEED, is_flagged_cn
    from provenance_probe import scoring
    from provenance_probe.client import Client
    from provenance_probe.config import Target
    from provenance_probe.probes import tokenizer

    gguf = os.path.join(run_eval.VOCAB_DIR, "moonshot.gguf")
    assert os.path.exists(gguf)
    ref = tokenizer.load_reference()
    assert ref, "tokenizer reference must be shipped"

    srv = None
    try:
        app = mock.make_app(gguf, "blind-moonshot", "moonshot")   # brand is blind
        srv, port = _serve(app)
        t = Target(name="moonshot", base_url=f"http://127.0.0.1:{port}/v1",
                   model="blind-moonshot", authorized=True)
        obs = tokenizer.measure(Client(t), variant_seed=EXPECTED_VARIANT_SEED)
        assert obs.get("usable"), "mock returned no usable token counts"
        matches = tokenizer.compare(obs, ref)
        assert matches, "no tokenizer match for a served Moonshot vocab"
        top = matches[0]
        # blind identification lands on the Moonshot family with a decisive score
        assert top["family"] == "Moonshot", f"called {top['family']} not Moonshot"
        assert top["origin"] == "CN"
        assert top["score"] >= 0.75

        bundle = {"tokenizer": obs, "tokenizer_match": matches,
                  "headers": {"status": 200, "vendor_headers": []},
                  "network": {"addresses": [], "findings": []},
                  "catalog": {"prc_origin_models": []}}
        out = scoring.score(bundle)
        verdict = (out.get("provenance_risk") or {}).get("verdict")
        # verdict tier is asserted, not just the family call
        assert verdict == "CONFIRMED", f"Moonshot verdict tier {verdict} != CONFIRMED"
        assert is_flagged_cn(out, top) is True
    finally:
        if srv is not None:
            srv.shutdown()


# --- 5. the Moonshot rebuild is GGUF-derived and did not disturb the siblings ---

# The full shipped reference key set. If a rebuild ever adds/removes/renames a key
# this list drifts and the test fails.
EXPECTED_REF_KEYS = {
    "Qwen2/Qwen2.5", "DeepSeek-LLM", "DeepSeek-Coder", "Llama-3", "GPT-2",
    "Command-R", "Falcon", "StarCoder", "MPT", "GPT-NeoX", "Refact",
    "OpenAI-cl100k", "OpenAI-o200k", "GLM-4.5", "GLM-4-9B", "Yi-1.5", "MiniCPM3",
    "Qwen3", "DeepSeek-V3", "Moonshot", "Phi-3.5", "InternLM2.5", "Mistral-v0.3",
    "Baichuan2", "Gemma-2", "Claude", "Gemini",
}

# The known-good Moonshot vector — the genuine Moonlight tiktoken counts over the
# probe corpus (byte-identical to the pre-existing HF-derived reference vector, so
# rebuilding from the GGUF is zero detection delta).
MOONSHOT_GOLDEN_VECTOR = {
    "cjk_dense": 60, "cjk_mixed": 33, "jp_kana": 64, "ko_hangul": 38,
    "ws_runs": 79, "tabs_deep": 27, "digits_long": 184, "punct_repeat": 13,
    "emoji_zwj": 279, "rare_unicode": 413, "diacritics": 210, "arabic_hebrew": 63,
    "cyrillic": 43, "code_json": 143, "code_regex": 224, "url_paths": 171,
    "base64ish": 174, "md_table": 110, "mixed_script_cjk_code": 111,
    "newline_storm": 11,
}


def test_moonshot_is_gguf_derived_and_siblings_intact():
    """The reconciliation touches only Moonshot, and does so from the GGUF.

    Self-contained (no git-vs-base diff, which is unstable after merge): (a) the
    exact key set is preserved — no HF-derived entry was wiped by a full
    regenerate; (b) the committed Moonshot entry is reproduced byte-for-byte by
    the builder from eval/vocabs/moonshot.gguf (so it is genuinely GGUF-derived);
    (c) the Moonshot vector did not drift from the known-good baseline (the
    genuine Moonlight tiktoken counts); (d) every sibling keeps its
    family+origin. Non-Moonshot GGUF vectors are additionally pinned by the eval
    itself — each still matches its own vocab at score 1.0.
    """
    pytest.importorskip("gguf")
    pytest.importorskip("tokenizers")
    here = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    ref = json.load(open(os.path.join(here, "provenance_probe/data/tokenizer_ref.json")))
    models = ref["models"]

    # (a) no key added / removed / renamed
    assert set(models) == EXPECTED_REF_KEYS

    # (b) Moonshot is reproduced exactly by the builder from the committed GGUF
    from provenance_probe.data.corpus import TOKENIZER_PROBES
    from provenance_probe.tools import build_reference_from_gguf as b
    info, err = b.build("moonshot", os.path.join(run_eval.VOCAB_DIR, "moonshot.gguf"))
    assert err is None, err
    tk = info.pop("tokenizer")
    rebuilt_vec = {pid: len(tk.encode(text, add_special_tokens=False).ids)
                   for pid, text in TOKENIZER_PROBES}
    entry = models["Moonshot"]
    assert entry["vector"] == rebuilt_vec
    assert entry["vocab_size"] == info["vocab_size"] == 163584
    assert entry["merges"] == info["merges"] == 163328
    assert entry["gguf_model"] == info["gguf_model"] == "gpt2"
    assert entry["gguf_pre"] == info["gguf_pre"] == "kimi-k2"
    assert entry["family"] == "Moonshot" and entry["origin"] == "CN"

    # (c) the rebuilt Moonshot vector did not drift — still equals the genuine
    #     Moonlight tiktoken counts
    assert models["Moonshot"]["vector"] == MOONSHOT_GOLDEN_VECTOR

    # (d) every sibling keeps its identity (family + origin)
    for name, e in models.items():
        assert e.get("family"), f"{name} lost its family"
        assert e.get("origin"), f"{name} lost its origin"
