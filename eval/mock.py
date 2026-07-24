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

# vocab key -> pre-tokenizer regex. Mirrors SPEC in build_reference_from_gguf.py.
REGEX = {
    "qwen2": RE_LLAMA3, "llama-bpe": RE_LLAMA3,
    "deepseek-llm": RE_DEEPSEEK_LLM, "deepseek-coder": RE_DEEPSEEK_CODER,
    "gpt-2": RE_GPT2, "command-r": RE_GPT2, "starcoder": RE_GPT2,
    "mpt": RE_GPT2, "gpt-neox": RE_GPT2, "refact": RE_GPT2,
    "falcon": RE_FALCON,
}

# Chat-template / accounting overhead a real endpoint adds on top of the raw
# prompt token count. Constant per endpoint; the matcher is overhead-invariant
# (tokenizer._overhead_correct) so the exact value does not change the verdict —
# it only proves the correction works.
TEMPLATE_OVERHEAD = 9


def load_tokenizer(gguf_path: str, regex_key: str):
    """Build a tokenizers.Tokenizer from a GGUF vocab using the family regex.

    Imported lazily so the harness module stays importable without the heavy
    optional deps (gguf, tokenizers) installed — only running a vocab case
    needs them.
    """
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
