#!/usr/bin/env python3
"""Build REAL tokenizer reference vectors from llama.cpp's bundled GGUF vocabs.

These are the actual production vocabularies and merge tables, not surrogates.
Pre-tokenizer regexes are taken from llama.cpp's llama-vocab.cpp so the split
behaviour matches the real tokenizer rather than a generic ByteLevel default.
"""
import json, os, sys
from gguf import GGUFReader
from tokenizers import Tokenizer, models, pre_tokenizers, normalizers, decoders, Regex

from provenance_probe.data.corpus import TOKENIZER_PROBES, CORPUS_VERSION

# --- pre-tokenizer regexes, transcribed from llama.cpp -----------------------
RE_LLAMA3 = (r"(?i:'s|'t|'re|'ve|'m|'ll|'d)|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}"
             r"| ?[^\s\p{L}\p{N}]+[\r\n]*|\s*[\r\n]+|\s+(?!\S)|\s+")
RE_GPT2 = (r"'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+| ?[^\s\p{L}\p{N}]+"
           r"|\s+(?!\S)|\s+")
RE_DEEPSEEK_LLM = (r"[\r\n]|\p{N}|[^\s\p{L}\p{N}]?[\p{L}\p{M}]+|\s*[\r\n]+"
                   r"|\s+(?!\S)|\s+")
RE_DEEPSEEK_CODER = (r"[\r\n]|\p{N}{1,3}|[^\s\p{L}\p{N}]?[\p{L}\p{M}]+"
                     r"|\s*[\r\n]+|\s+(?!\S)|\s+")
RE_FALCON = (r"[\p{P}\$\+<=>\^~\|]+|'s|'t|'re|'ve|'m|'ll|'d| ?\p{L}+| ?\p{N}+"
             r"| ?[^\s\p{L}\p{N}]+|\s+(?!\S)|\s+")
# GLM-4 (Zhipu). Transcribed byte-for-byte from llama.cpp
# src/llama-vocab.cpp, case LLAMA_VOCAB_PRE_TYPE_CHATGLM4 (commit
# 7ceed8737fdb4eb09b4760e77bd12d38012de5a8). Differs from RE_LLAMA3 only in the
# contraction alternation: GLM-4 spells the case-folding out explicitly
# ((?:'[sS]|...)) instead of (?i:'s|...). Kept byte-identical to eval/mock.py.
RE_GLM4 = (r"(?:'[sS]|'[tT]|'[rR][eE]|'[vV][eE]|'[mM]|'[lL][lL]|'[dD])"
           r"|[^\r\n\p{L}\p{N}]?\p{L}+|\p{N}{1,3}| ?[^\s\p{L}\p{N}]+[\r\n]*"
           r"|\s*[\r\n]+|\s+(?!\S)|\s+")
# Moonshot (Moonlight/Kimi). This family ships a *tiktoken* tokenizer, not an HF
# tokenizer.json; the authoritative pre-tokenizer split is the model's own
# `pat_str` (moonshotai/Moonlight-16B-A3B `tokenization_moonshot.py`, revision
# 476b36a4). llama.cpp's matching pre-type LLAMA_VOCAB_PRE_TYPE_KIMI_K2 (commit
# 7ceed8737fdb4eb09b4760e77bd12d38012de5a8) does NOT carry a single-regex
# transcription — it triggers on `\p{Han}+` and delegates the split to a custom
# handler in unicode.cpp — so the model's own pat_str is the faithful source.
# Kept byte-identical to eval/mock.py (pinned by a test). Because `[\p{Han}]+`
# is the first alternative, Han is consumed before the `&&[^\p{Han}]` class
# intersections, which Oniguruma (the tokenizers Regex engine) supports.
RE_MOONSHOT = (
    r"[\p{Han}]+"
    r"|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?"
    r"|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?"
    r"|\p{N}{1,3}"
    r"| ?[^\s\p{L}\p{N}]+[\r\n]*"
    r"|\s*[\r\n]+"
    r"|\s+(?!\S)"
    r"|\s+")

# vocab file -> (label, family, origin, regex)
SPEC = {
    "qwen2":           ("Qwen2/Qwen2.5",   "Qwen",          "CN", RE_LLAMA3),
    "deepseek-llm":    ("DeepSeek-LLM",    "DeepSeek",      "CN", RE_DEEPSEEK_LLM),
    "deepseek-coder":  ("DeepSeek-Coder",  "DeepSeek",      "CN", RE_DEEPSEEK_CODER),
    "glm-4":           ("GLM-4",           "GLM/Zhipu",     "CN", RE_GLM4),
    "moonshot":        ("Moonshot",        "Moonshot",      "CN", RE_MOONSHOT),
    "llama-bpe":       ("Llama-3",         "Llama-3",       "US", RE_LLAMA3),
    "gpt-2":           ("GPT-2",           "GPT-2/OpenAI",  "US", RE_GPT2),
    "command-r":       ("Command-R",       "Cohere",        "CA", RE_GPT2),
    "falcon":          ("Falcon",          "Falcon/TII",    "AE", RE_FALCON),
    "starcoder":       ("StarCoder",       "StarCoder",     "EU", RE_GPT2),
    "mpt":             ("MPT",             "MPT",           "US", RE_GPT2),
    "gpt-neox":        ("GPT-NeoX",        "GPT-NeoX",      "US", RE_GPT2),
    "refact":          ("Refact",          "Refact",        "EU", RE_GPT2),
}
# published vocab sizes, for extraction self-check
EXPECT = {"qwen2": 151936, "deepseek-llm": 102400, "deepseek-coder": 32256,
          "llama-bpe": 128256, "gpt-2": 50257, "command-r": 256000, "falcon": 65024}

# --- SentencePiece (SP) families ---------------------------------------------
# The last CN gap after GLM (#106) and Moonshot (#108): four families whose
# tokenizer is SentencePiece, not byte-level GPT-2 BPE, so the RE_*/ByteLevel
# path in the existing SPEC cannot serve them.
#
# FINDING (surfaced, not tuned away): all four are SentencePiece **BPE**
# (proto model_type=2) with `byte_fallback`, NOT unigram — they carry piece
# scores AND a merge table, and their front-end is Metaspace ("▁") + ByteFallback
# rather than GPT-2 ByteLevel. So the faithful `tokenizers` reconstruction is
# `models.BPE(..., byte_fallback=True)` + a per-family SP front-end, reproducing
# the genuine HF `AutoTokenizer` counts exactly. (`tokenizers.models.Unigram`
# would be the wrong algorithm and does NOT reproduce them.)
#
# Three land via **Approach A** (committed vocab GGUF carrying tokens+scores+
# merges, `tokenizer.ggml.model="llama"`, reconstructed here). The fourth,
# Baichuan2, is a *slow* custom SP tokenizer with no fast backend whose
# `_tokenize` is literally `sp_model.encode`; it lands via **Approach B**
# (committed raw `tokenizer.model` served through `sentencepiece`), which
# reproduces its oracle exactly. `SP_CONFIG` is the SP analogue of `REGEX`: the
# per-family front-end, mirrored byte-identically into eval/mock.py and pinned by
# a test. `build_sp_tokenizer` is the ONE shared builder both call.
SP_CONFIG = {
    # key -> label, family, origin, source, and the per-family SP front-end.
    #   norm/pre: which normalizer / pre-tokenizer reproduces the HF fast counts
    #   dec:      decoder (does not affect prompt-token counts; set for round-trip)
    #   approach: "gguf" (A) or "sentencepiece" (B, raw .model)
    "yi": {
        "label": "Yi-1.5", "family": "Yi/01.AI", "origin": "CN",
        "source": "01-ai/Yi-1.5-9B-Chat", "approach": "gguf",
        "byte_fallback": True, "fuse_unk": False, "unk": None,
        "pre": "metaspace_always", "dec": "sp_default",
    },
    "minicpm": {
        "label": "MiniCPM3", "family": "MiniCPM", "origin": "CN",
        "source": "openbmb/MiniCPM3-4B", "approach": "gguf",
        "byte_fallback": True, "fuse_unk": False, "unk": None,
        "norm": "prepend_replace", "dec": "sp_default",
    },
    "internlm": {
        "label": "InternLM2.5", "family": "InternLM", "origin": "CN",
        "source": "internlm/internlm2_5-7b-chat", "approach": "gguf",
        # InternLM2.5's CURRENT HF fast/slow tokenizers regressed byte_fallback
        # to False (emoji/rare-unicode collapse to <unk>); the genuine model and
        # the shipped reference use byte_fallback=True with add_dummy_prefix=False.
        # We reproduce the genuine byte-fallback behaviour (byte_fallback=True +
        # Replace(" "→"▁"), no prepend) — a real endpoint's tokenization and the
        # pre-existing shipped vector, byte-for-byte.
        "byte_fallback": True, "fuse_unk": False, "unk": None,
        "norm": "replace", "dec": "sp_default",
    },
    "baichuan": {
        "label": "Baichuan2", "family": "Baichuan", "origin": "CN",
        "source": "baichuan-inc/Baichuan2-7B-Chat", "approach": "sentencepiece",
    },
}

SP_METASPACE = "▁"   # ▁


def build_sp_tokenizer(toks, merges_pairs, cfg):
    """The ONE shared SentencePiece-BPE builder (Approach A).

    Used byte-identically by this reference builder AND eval/mock.py so a served
    vocab reproduces its own reference vector. `cfg` is an SP_CONFIG entry.
    """
    vocab = {t: i for i, t in enumerate(toks)}
    tk = Tokenizer(models.BPE(vocab=vocab, merges=merges_pairs,
                              unk_token=cfg.get("unk"),
                              fuse_unk=cfg.get("fuse_unk", False),
                              byte_fallback=cfg.get("byte_fallback", False)))
    norm = cfg.get("norm")
    if norm == "prepend_replace":
        tk.normalizer = normalizers.Sequence([
            normalizers.Prepend(SP_METASPACE),
            normalizers.Replace(" ", SP_METASPACE)])
    elif norm == "replace":
        tk.normalizer = normalizers.Replace(" ", SP_METASPACE)
    pre = cfg.get("pre")
    if pre == "metaspace_always":
        tk.pre_tokenizer = pre_tokenizers.Metaspace(
            replacement=SP_METASPACE, prepend_scheme="always", split=False)
    if cfg.get("dec") == "sp_default":
        tk.decoder = decoders.Sequence([
            decoders.Replace(SP_METASPACE, " "),
            decoders.ByteFallback(), decoders.Fuse()])
    return tk


class _Ids:
    __slots__ = ("ids",)

    def __init__(self, ids):
        self.ids = ids


class SPMTokenizer:
    """Approach B adapter: serve a raw SentencePiece `.model` via `sentencepiece`.

    Exposes the same `.encode(text, add_special_tokens=False).ids` surface the
    tokenizers.Tokenizer path uses, so eval/mock.py stays uniform. Baichuan2's
    `BaichuanTokenizer._tokenize` is `sp_model.encode`, so this reproduces its HF
    `AutoTokenizer` counts exactly.
    """

    def __init__(self, model_path):
        import sentencepiece as spm
        self._sp = spm.SentencePieceProcessor(model_file=model_path)

    def encode(self, text, add_special_tokens=False):
        return _Ids(self._sp.encode(text))


def sp_tokenizer_from_gguf(path, key):
    """Build the shared SP tokenizer for `key` from its committed GGUF vocab."""
    toks, merges, scores, _pre, model = read_gguf_vocab(path)
    if not scores:
        raise ValueError(f"{path}: not a SentencePiece vocab (no scores)")
    pairs = [tuple(m.split(" ")) for m in merges if len(m.split(" ")) == 2]
    return build_sp_tokenizer(toks, pairs, SP_CONFIG[key])


def load_sp_tokenizer(path, key):
    """Serve an SP family: GGUF (Approach A) or raw `.model` (Approach B)."""
    if SP_CONFIG[key].get("approach") == "sentencepiece" or path.endswith(".model"):
        return SPMTokenizer(path)
    return sp_tokenizer_from_gguf(path, key)


def classify_vocab(merges, scores, model):
    """bpe (byte-level GPT-2) vs spm (SentencePiece).

    The load-bearing signal is `tokenizer.ggml.scores`: llama.cpp's byte-level
    BPE vocabs (the existing 13) ship tokens+merges and NO scores; a
    SentencePiece vocab ships piece scores. (These SP families are SP-BPE, so
    they carry merges too — hence the classifier keys on scores, not the
    absence of merges.)
    """
    if scores:
        return "spm"
    return "bpe"


def read_gguf_vocab(path):
    r = GGUFReader(path)
    f = {x.name: x for x in r.fields.values()}

    def strs(key):
        fld = f.get(key)
        if fld is None:
            return []
        out = []
        for i in fld.data:
            p = fld.parts[i]
            out.append(bytes(p).decode("utf-8", "replace"))
        return out

    def floats(key):
        fld = f.get(key)
        if fld is None:
            return []
        # a GGUF numeric-array element is a length-1 memmap, not a scalar
        return [float(fld.parts[i][0]) for i in fld.data]

    toks = strs("tokenizer.ggml.tokens")
    merges = strs("tokenizer.ggml.merges")
    scores = floats("tokenizer.ggml.scores")
    pre = strs("tokenizer.ggml.pre")
    model = strs("tokenizer.ggml.model")
    return toks, merges, scores, (pre[0] if pre else None), (model[0] if model else None)


def _sp_vector(tk):
    return {pid: len(tk.encode(text, add_special_tokens=False).ids)
            for pid, text in TOKENIZER_PROBES}


def build_sp(name, path):
    """Build a SentencePiece-family reference entry (Approach A or B)."""
    cfg = SP_CONFIG[name]
    if cfg.get("approach") == "sentencepiece" or path.endswith(".model"):
        tk = SPMTokenizer(path)
        info = {"label": cfg["label"], "family": cfg["family"], "origin": cfg["origin"],
                "source": cfg["source"], "gguf_model": "sentencepiece",
                "gguf_pre": None, "vector": _sp_vector(tk), "note": "raw .model (Approach B)"}
        return info, None
    toks, merges, scores, pre, model = read_gguf_vocab(path)
    if not toks or not scores:
        return None, f"{name}: not a SentencePiece vocab (model={model}, scores={len(scores)})"
    pairs = [tuple(m.split(" ")) for m in merges if len(m.split(" ")) == 2]
    tk = build_sp_tokenizer(toks, pairs, cfg)
    info = {"label": cfg["label"], "family": cfg["family"], "origin": cfg["origin"],
            "source": cfg["source"], "vocab_size": len(toks), "merges": len(pairs),
            "gguf_model": model, "gguf_pre": pre, "vector": _sp_vector(tk), "note": ""}
    return info, None


def build(name, path):
    if name in SP_CONFIG:
        return build_sp(name, path)
    label, family, origin, rex = SPEC[name]
    toks, merges, scores, pre, model = read_gguf_vocab(path)
    if not toks or not merges:
        return None, f"{name}: no BPE vocab/merges (model={model})"

    vocab = {t: i for i, t in enumerate(toks)}
    pairs = []
    for m in merges:
        parts = m.split(" ")
        if len(parts) == 2:
            pairs.append((parts[0], parts[1]))
    tk = Tokenizer(models.BPE(vocab=vocab, merges=pairs,
                              fuse_unk=False, byte_fallback=False))
    tk.pre_tokenizer = pre_tokenizers.Sequence([
        pre_tokenizers.Split(Regex(rex), behavior="isolated", invert=False),
        pre_tokenizers.ByteLevel(add_prefix_space=False, use_regex=False),
    ])
    tk.decoder = decoders.ByteLevel()

    note = ""
    if name in EXPECT and len(toks) != EXPECT[name]:
        note = f"vocab {len(toks)} != published {EXPECT[name]}"
    return {"label": label, "family": family, "origin": origin,
            "vocab_size": len(toks), "merges": len(pairs),
            "gguf_pre": pre, "gguf_model": model, "tokenizer": tk,
            "note": note}, None


def main():
    # NOTE: this standalone regen emits ONLY the byte-level-BPE SPEC families from
    # $GGUF_VOCAB_DIR. The SentencePiece families (SP_CONFIG) and the HF/tiktoken
    # families are reconciled INTO the shipped tokenizer_ref.json separately (each
    # SP entry is rebuilt from its committed eval/vocabs vocab via build_sp(); the
    # rebuild is pinned by tests/test_eval_sentencepiece.py). Do not run this as a
    # full regenerate or it will drop those entries.
    ref = {"corpus_version": CORPUS_VERSION, "synthetic": False,
           "provenance": "llama.cpp bundled GGUF vocabs (real production tokenizers)",
           "models": {}}
    report = []
    for name in SPEC:
        p = os.path.join(os.environ.get("GGUF_VOCAB_DIR", "/tmp"), f"v_{name}.gguf")
        if not os.path.exists(p):
            continue
        try:
            info, err = build(name, p)
        except Exception as e:
            report.append((name, "ERROR", str(e)[:70], "", ""))
            continue
        if err:
            report.append((name, "SKIP", err[:70], "", ""))
            continue
        tk = info.pop("tokenizer")
        vec = {}
        for pid, text in TOKENIZER_PROBES:
            vec[pid] = len(tk.encode(text, add_special_tokens=False).ids)
        info["vector"] = vec
        ref["models"][info["label"]] = info
        report.append((name, "OK", f"vocab={info['vocab_size']}",
                       f"han_tok/char={round(vec['cjk_dense']/126,3)}",
                       info["note"] or "vocab size matches"))

    print(f"{'vocab':<18}{'st':<7}{'detail':<24}{'discriminator':<22}{'check'}")
    print("-" * 96)
    for row in report:
        print(f"{row[0]:<18}{row[1]:<7}{row[2]:<24}{row[3]:<22}{row[4]}")

    out = os.path.join(os.path.dirname(os.path.dirname(os.path.abspath(__file__))),
                       "data", "tokenizer_ref.json")
    json.dump(ref, open(out, "w"), indent=2)
    print(f"\nWrote {len(ref['models'])} REAL reference vectors -> {out}")


if __name__ == "__main__":
    main()
