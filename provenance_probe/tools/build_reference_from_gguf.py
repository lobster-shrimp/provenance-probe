#!/usr/bin/env python3
"""Build REAL tokenizer reference vectors from llama.cpp's bundled GGUF vocabs.

These are the actual production vocabularies and merge tables, not surrogates.
Pre-tokenizer regexes are taken from llama.cpp's llama-vocab.cpp so the split
behaviour matches the real tokenizer rather than a generic ByteLevel default.
"""
import json, os, sys
from gguf import GGUFReader
from tokenizers import Tokenizer, models, pre_tokenizers, decoders, Regex

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

# vocab file -> (label, family, origin, regex)
SPEC = {
    "qwen2":           ("Qwen2/Qwen2.5",   "Qwen",          "CN", RE_LLAMA3),
    "deepseek-llm":    ("DeepSeek-LLM",    "DeepSeek",      "CN", RE_DEEPSEEK_LLM),
    "deepseek-coder":  ("DeepSeek-Coder",  "DeepSeek",      "CN", RE_DEEPSEEK_CODER),
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

    toks = strs("tokenizer.ggml.tokens")
    merges = strs("tokenizer.ggml.merges")
    pre = strs("tokenizer.ggml.pre")
    model = strs("tokenizer.ggml.model")
    return toks, merges, (pre[0] if pre else None), (model[0] if model else None)


def build(name, path):
    label, family, origin, rex = SPEC[name]
    toks, merges, pre, model = read_gguf_vocab(path)
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
