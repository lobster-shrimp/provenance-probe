#!/usr/bin/env python3
"""Build a vocab-only, byte-level-BPE GGUF from a tiktoken vocabulary.

Some CN families (e.g. Moonshot's Moonlight/Kimi line) ship a *tiktoken*
tokenizer (`tiktoken.model`, a base64 `bytes -> rank` table + a `pat_str`
pre-tokenizer regex in the model's `tokenization_*.py`) rather than an HF
`tokenizer.json`. llama.cpp ships no bundled vocab for them, and its converter's
Kimi-K2 path delegates the split to a custom C++ handler in `unicode.cpp` (the
`LLAMA_VOCAB_PRE_TYPE_KIMI_K2` case is only a `\\p{Han}+` trigger), so there is
no single-regex transcription to lift from `src/llama-vocab.cpp`.

This tool reconstructs the equivalent GPT-2 byte-level BPE (tokens + merges) from
the tiktoken ranks — the standard OpenAI/llama.cpp reconstruction — and writes a
vocab-only GGUF the eval harness (`eval/mock.py` `load_tokenizer`) can serve
blind. The authoritative pre-tokenizer regex is the model's own `pat_str`; it is
transcribed into `eval/mock.py` / `build_reference_from_gguf.py` (`RE_MOONSHOT`)
and pinned byte-identical by a test.

Usage:
    python -m scripts.build_tiktoken_vocab_gguf <hf_repo> <out.gguf> [revision]

e.g. moonshot:
    python -m scripts.build_tiktoken_vocab_gguf \
        moonshotai/Moonlight-16B-A3B eval/vocabs/moonshot.gguf \
        476b36a473d4467f94469414bef6cee75c9c8172
"""
from __future__ import annotations

import sys


def bytes_to_unicode() -> dict[int, str]:
    """GPT-2 reversible byte -> unicode map (identical to HF ByteLevel)."""
    bs = (list(range(ord("!"), ord("~") + 1))
          + list(range(ord("¡"), ord("¬") + 1))
          + list(range(ord("®"), ord("ÿ") + 1)))
    cs = bs[:]
    n = 0
    for b in range(256):
        if b not in bs:
            bs.append(b)
            cs.append(256 + n)
            n += 1
    return {b: chr(c) for b, c in zip(bs, cs)}


def _reconstruct_merges(ranks: dict[bytes, int]):
    """Reconstruct BPE merges from tiktoken ranks (OpenAI standard algorithm).

    For each multi-byte token, re-run BPE over its bytes stopping just before its
    own rank; the final two parts are the merge that produced it.
    """
    def bpe(token: bytes, max_rank: int):
        parts = [bytes([b]) for b in token]
        while True:
            min_idx = min_rank = None
            for i in range(len(parts) - 1):
                rank = ranks.get(parts[i] + parts[i + 1])
                if rank is not None and (min_rank is None or rank < min_rank):
                    min_idx, min_rank = i, rank
            if min_rank is None or min_rank >= max_rank:
                break
            parts = parts[:min_idx] + [parts[min_idx] + parts[min_idx + 1]] + parts[min_idx + 2:]
        return parts

    merges = []
    for tok, rank in ranks.items():
        if len(tok) == 1:
            continue
        parts = bpe(tok, rank)
        if len(parts) == 2:
            merges.append((parts[0], parts[1]))
    return merges


def build(hf_repo: str, out_path: str, revision: str | None = None) -> None:
    from huggingface_hub import hf_hub_download
    from tiktoken.load import load_tiktoken_bpe
    import gguf

    vocab_file = hf_hub_download(hf_repo, "tiktoken.model", revision=revision)
    ranks = load_tiktoken_bpe(vocab_file)          # bytes -> rank

    b2u = bytes_to_unicode()
    def enc(bb: bytes) -> str:
        return "".join(b2u[x] for x in bb)

    items = sorted(ranks.items(), key=lambda kv: kv[1])
    tokens = [enc(tok) for tok, _ in items]
    merges = [f"{enc(a)} {enc(b)}" for a, b in _reconstruct_merges(ranks)]

    w = gguf.GGUFWriter(out_path, "gpt2")
    w.add_tokenizer_model("gpt2")
    w.add_tokenizer_pre("kimi-k2")                 # llama.cpp pre-type for this family
    w.add_token_list(tokens)
    w.add_token_merges(merges)
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.close()
    print(f"wrote {out_path}: {len(tokens)} tokens, {len(merges)} merges "
          f"(from {hf_repo}@{revision or 'main'})")


def main(argv=None) -> int:
    argv = argv if argv is not None else sys.argv[1:]
    if len(argv) < 2:
        print(__doc__)
        return 2
    build(argv[0], argv[1], argv[2] if len(argv) > 2 else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
