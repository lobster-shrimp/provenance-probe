"""Canonical GGUF-vocab blind endpoint for the eval harness.

Serves genuine `usage.prompt_tokens` counts computed from a real open-weights
GGUF vocabulary, behind an OpenAI-compatible `/v1/chat/completions` surface.
The brand it reports is intentionally uninformative ("blind-N"): the tokenizer
layer must do the identification with no help from the model id.

WHY PER-FAMILY REGEX (the load-bearing fix):
    llama.cpp uses a *different* pre-tokenizer split regex per model family.
    The shipped reference vectors (tools/build_reference_from_gguf.py) are built
    with the correct per-family regex, so a mock that served every vocab through
    one hardcoded regex (as the earlier observatory mock did) would produce token
    counts that do NOT match that vocab's own reference vector — a false negative
    for exactly the models we care about. `SPEC` below mirrors the reference
    builder so a served vocab reproduces its own reference counts.

    ┌── served vocab ──┐   pick regex from SPEC   ┌── genuine BPE encode ──┐
    │ eval/vocabs/X.gguf│ ───────────────────────▶│ prompt_tokens over probes│
    └───────────────────┘   (same as reference)   └────────────┬───────────┘
                                                                ▼
                                             OpenAI-compat usage.prompt_tokens

The provenance-observatory controls self-test is intended to reuse this module
(pointed at a provenance-probe checkout) instead of keeping its own copy, so the
two repos share ONE mock implementation (DRY). Run standalone:

    python -m eval.mock <gguf_path> <port> <brand> [regex_key]
"""
from __future__ import annotations

# Pre-tokenizer regexes, transcribed from llama.cpp's llama-vocab.cpp — kept
# byte-identical to tools/build_reference_from_gguf.py so mock and reference
# agree. If you change one, change both (there is a test that pins this).
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
# GLM-4 (Zhipu). Byte-for-byte from llama.cpp src/llama-vocab.cpp, case
# LLAMA_VOCAB_PRE_TYPE_CHATGLM4 (commit 7ceed8737fdb4eb09b4760e77bd12d38012de5a8).
# MUST stay byte-identical to build_reference_from_gguf.py (pinned by a test).
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
# Kept byte-identical to build_reference_from_gguf.py (pinned by a test). Because
# `[\p{Han}]+` is the first alternative, Han is consumed before the `&&[^\p{Han}]`
# class intersections, which Oniguruma (the tokenizers Regex engine) supports.
RE_MOONSHOT = (
    r"[\p{Han}]+"
    r"|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+(?i:'s|'t|'re|'ve|'m|'ll|'d)?"
    r"|[^\r\n\p{L}\p{N}]?[\p{Lu}\p{Lt}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]+[\p{Ll}\p{Lm}\p{Lo}\p{M}&&[^\p{Han}]]*(?i:'s|'t|'re|'ve|'m|'ll|'d)?"
    r"|\p{N}{1,3}"
    r"| ?[^\s\p{L}\p{N}]+[\r\n]*"
    r"|\s*[\r\n]+"
    r"|\s+(?!\S)"
    r"|\s+")

# vocab key -> pre-tokenizer regex. Mirrors SPEC in build_reference_from_gguf.py.
REGEX = {
    "qwen2": RE_LLAMA3, "llama-bpe": RE_LLAMA3,
    "deepseek-llm": RE_DEEPSEEK_LLM, "deepseek-coder": RE_DEEPSEEK_CODER,
    "gpt-2": RE_GPT2, "command-r": RE_GPT2, "starcoder": RE_GPT2,
    "mpt": RE_GPT2, "gpt-neox": RE_GPT2, "refact": RE_GPT2,
    "falcon": RE_FALCON, "glm-4": RE_GLM4, "moonshot": RE_MOONSHOT,
}

# Chat-template / accounting overhead a real endpoint adds on top of the raw
# prompt token count. Constant per endpoint; the matcher is overhead-invariant
# (tokenizer._overhead_correct) so the exact value does not change the verdict —
# it only proves the correction works.
TEMPLATE_OVERHEAD = 9


def load_tokenizer(gguf_path: str, regex_key: str):
    """Build a served tokenizer for one vocab key.

    Byte-level BPE families (the existing 13) use the per-family pre-tokenizer
    REGEX below. SentencePiece families (Yi, MiniCPM, InternLM, Baichuan) are
    served through the ONE shared SP builder in build_reference_from_gguf.py
    (`SP_CONFIG` — the SP analogue of REGEX), so a served vocab reproduces its own
    reference vector. Imported lazily so the harness module stays importable
    without the heavy optional deps (gguf, tokenizers, sentencepiece) installed —
    only running a vocab case needs them.
    """
    # SentencePiece path: the shared builder (mock == reference builder).
    from provenance_probe.tools.build_reference_from_gguf import (
        SP_CONFIG, load_sp_tokenizer)
    if regex_key in SP_CONFIG or gguf_path.endswith(".model"):
        return load_sp_tokenizer(gguf_path, regex_key)

    from gguf import GGUFReader
    from tokenizers import Tokenizer, models, pre_tokenizers, Regex

    regex = REGEX.get(regex_key)
    if regex is None:
        raise ValueError(f"no pre-tokenizer regex for vocab key {regex_key!r}; "
                         f"known: {sorted(REGEX)}")
    reader = GGUFReader(gguf_path)
    fields = {x.name: x for x in reader.fields.values()}

    def strs(key):
        fld = fields.get(key)
        if fld is None:
            return []
        return [bytes(fld.parts[i]).decode("utf-8", "replace") for i in fld.data]

    toks = strs("tokenizer.ggml.tokens")
    merges = [tuple(m.split(" ")) for m in strs("tokenizer.ggml.merges")
              if len(m.split(" ")) == 2]
    if not toks or not merges:
        raise ValueError(f"{gguf_path}: no BPE vocab/merges")
    tk = Tokenizer(models.BPE(vocab={t: i for i, t in enumerate(toks)},
                              merges=merges, fuse_unk=False))
    tk.pre_tokenizer = pre_tokenizers.Sequence([
        pre_tokenizers.Split(Regex(regex), behavior="isolated"),
        pre_tokenizers.ByteLevel(add_prefix_space=False, use_regex=False),
    ])
    return tk


def vocab_path(vocab_dir: str, key: str) -> str:
    """Resolve a vocab key to its committed file: `<key>.gguf` (byte-level BPE or
    Approach-A SentencePiece) or `<key>.model` (Approach-B raw SentencePiece)."""
    import os
    gguf = os.path.join(vocab_dir, key + ".gguf")
    if os.path.exists(gguf):
        return gguf
    return os.path.join(vocab_dir, key + ".model")


def make_app(gguf_path: str, brand: str, regex_key: str, overhead: int = TEMPLATE_OVERHEAD):
    """Flask app serving genuine token counts for one vocab, branded blind."""
    from flask import Flask, jsonify, request

    tk = load_tokenizer(gguf_path, regex_key)
    app = Flask(__name__)

    @app.route("/v1/chat/completions", methods=["POST"])
    def chat():
        d = request.get_json(force=True, silent=True) or {}
        # mirror a real endpoint's parameter validation (used by the wire layer)
        if d.get("temperature", 0) > 2 or d.get("max_tokens", 1) < 0:
            return jsonify({"error": {"message": "Invalid value", "param": "temperature",
                                      "type": "invalid_request_error", "code": None}}), 400
        prompt = " ".join(m.get("content", "") for m in (d.get("messages") or [])
                          if isinstance(m.get("content"), str))
        n = len(tk.encode(prompt, add_special_tokens=False).ids) + overhead
        return jsonify({"id": "eval", "model": brand, "object": "chat.completion",
                        "choices": [{"index": 0, "finish_reason": "stop",
                                     "message": {"role": "assistant", "content": "ok"}}],
                        "usage": {"prompt_tokens": n, "completion_tokens": 1}})

    @app.route("/v1/models")
    def models_list():
        return jsonify({"data": [{"id": brand}]})

    return app


def main(argv=None):
    import sys
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 3:
        print("usage: python -m eval.mock <gguf_path> <port> <brand> [regex_key]",
              file=sys.stderr)
        return 2
    gguf_path, port, brand = argv[0], int(argv[1]), argv[2]
    # default the regex key from the vocab filename (e.g. eval/vocabs/qwen2.gguf)
    import os
    regex_key = argv[3] if len(argv) > 3 else os.path.basename(gguf_path).replace(".gguf", "")
    make_app(gguf_path, brand, regex_key).run(port=port, threaded=True)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
