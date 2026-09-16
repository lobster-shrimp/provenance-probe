#!/usr/bin/env python3
"""Build a vocab-only SentencePiece GGUF from an HF SentencePiece tokenizer.

Three of the four last-gap CN families — Yi, InternLM2.5, MiniCPM3 — ship a
*SentencePiece* tokenizer rather than a byte-level GPT-2 BPE. Empirically all
three are SentencePiece **BPE** with `byte_fallback` (model_type=2 in the proto),
NOT unigram: they carry piece scores AND a merge table, and their front-end is
Metaspace (`▁`) + ByteFallback, not GPT-2 ByteLevel. So the byte-level-BPE mock
path (`RE_*` + ByteLevel) cannot serve them — this is the wall #108 documented
for Yi/MiniCPM3/InternLM. (Baichuan2, the fourth family, is a *slow* custom
SentencePiece tokenizer with no fast backend; it is served from its raw
`tokenizer.model` via `sentencepiece` — Approach B — not from a GGUF.)

This tool writes a vocab-only GGUF carrying the id-ordered token list, the piece
`scores`, and the merge table, tagged `tokenizer.ggml.model = "llama"` and
`tokenizer.ggml.pre = <key>`. The eval harness (`eval/mock.py` `load_tokenizer`)
and the reference builder (`build_reference_from_gguf.py`) both reconstruct the
served tokenizer from it via the SHARED `build_sp_tokenizer`, using the per-family
front-end in `SP_CONFIG` (the SentencePiece analogue of the byte-identical `REGEX`
copies). Presence of `tokenizer.ggml.scores` is the classifier: a vocab with
scores is served through the SP path, a vocab without through the byte-level path.

Faithfulness is the landing gate: the served reconstruction must reproduce the
genuine HF `AutoTokenizer` counts per probe (see tests/test_eval_<fam>.py). The
tokens+merges are lifted from the model's own HF fast tokenizer (its
`tokenizer.json` / backend), so the reconstruction IS that tokenizer.

Usage:
    python -m scripts.build_spm_vocab_gguf <key> <hf_repo> <out.gguf> [revision] [--trust-remote-code]

e.g.:
    python -m scripts.build_spm_vocab_gguf yi 01-ai/Yi-1.5-9B-Chat eval/vocabs/yi.gguf
    python -m scripts.build_spm_vocab_gguf internlm internlm/internlm2_5-7b-chat \
        eval/vocabs/internlm.gguf --trust-remote-code
"""
from __future__ import annotations

import json
import sys


def _proto_scores(repo: str, revision: str | None) -> dict[str, float]:
    """piece -> score from the model's SentencePiece proto (informational)."""
    try:
        from huggingface_hub import hf_hub_download
        from transformers.convert_slow_tokenizer import import_protobuf
        mpath = hf_hub_download(repo, "tokenizer.model", revision=revision)
        pb = import_protobuf()
        m = pb.ModelProto()
        m.ParseFromString(open(mpath, "rb").read())
        return {p.piece: float(p.score) for p in m.pieces}
    except Exception:
        return {}


def build(key: str, repo: str, out_path: str, trust_remote_code: bool = False,
          revision: str | None = None) -> None:
    from transformers import AutoTokenizer
    import gguf

    hf = AutoTokenizer.from_pretrained(repo, revision=revision,
                                       trust_remote_code=trust_remote_code)
    if not hasattr(hf, "backend_tokenizer"):
        raise SystemExit(f"{repo}: no fast tokenizer backend; this family needs "
                         f"the raw-.model (Approach B) path, not a GGUF")
    tj = json.loads(hf.backend_tokenizer.to_str())
    model = tj["model"]
    merges = ["{} {}".format(*m) if isinstance(m, (list, tuple)) else m
              for m in model.get("merges", [])]

    # full id-ordered token list, including added/special tokens and any holes
    full = hf.get_vocab()                       # token -> id
    max_id = max(full.values())
    id2tok: list[str | None] = [None] * (max_id + 1)
    for tok, i in full.items():
        id2tok[i] = tok
    tokens = [t if t is not None else f"<placeholder_{i}>"
              for i, t in enumerate(id2tok)]

    score_of = _proto_scores(repo, revision)
    scores = [score_of.get(t, 0.0) for t in tokens]

    w = gguf.GGUFWriter(out_path, "llama")
    w.add_tokenizer_model("llama")              # SP marker (vs "gpt2" byte-level)
    w.add_tokenizer_pre(key)
    w.add_token_list(tokens)
    w.add_token_scores(scores)                  # presence of scores = SP path
    w.add_token_merges(merges)
    w.write_header_to_file()
    w.write_kv_data_to_file()
    w.close()
    print(f"wrote {out_path}: {len(tokens)} tokens, {len(merges)} merges "
          f"(from {repo}@{revision or 'main'})")


def main(argv=None) -> int:
    argv = list(argv if argv is not None else sys.argv[1:])
    trc = False
    if "--trust-remote-code" in argv:
        trc = True
        argv.remove("--trust-remote-code")
    if len(argv) < 3:
        print(__doc__)
        return 2
    build(argv[0], argv[1], argv[2], trust_remote_code=trc,
          revision=argv[3] if len(argv) > 3 else None)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
