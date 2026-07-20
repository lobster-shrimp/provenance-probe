# -*- coding: utf-8 -*-
"""Build / extend tokenizer reference vectors from HuggingFace.

MERGES into data/tokenizer_ref.json. Existing entries (including the real
GGUF-derived ones) are preserved unless you pass --overwrite.

SECURITY NOTE. Some repos ship a custom tokenizer class and require
trust_remote_code=True, which executes code from the repo on your machine.
This is a provenance-assurance tool; running unvetted remote code to build its
reference data would be self-defeating. So trust_remote_code is OFF by default.
Repos needing it are SKIPPED with an explanation, and the list below prefers
HF-native equivalents that do not need it.
"""
from __future__ import annotations
import json, os

from .data.corpus import TOKENIZER_PROBES, CORPUS_VERSION, CJK_DENSE_HAN_CHARS

OUT = os.path.join(os.path.dirname(__file__), "data", "tokenizer_ref.json")

# repo, label, family, origin, gated?
HF_MODELS = [
    # --- Chinese families: the gap in the shipped reference ------------------
    ("zai-org/GLM-4.5",                    "GLM-4.5",     "GLM/Zhipu", "CN", False),
    ("THUDM/glm-4-9b-chat-hf",             "GLM-4-9B",    "GLM/Zhipu", "CN", False),
    ("01-ai/Yi-1.5-9B-Chat",               "Yi-1.5",      "Yi/01.AI",  "CN", False),
    ("internlm/internlm2_5-7b-chat",       "InternLM2.5", "InternLM",  "CN", False),
    ("openbmb/MiniCPM3-4B",                "MiniCPM3",    "MiniCPM",   "CN", False),
    ("baichuan-inc/Baichuan2-7B-Chat",     "Baichuan2",   "Baichuan",  "CN", False),
    ("Qwen/Qwen3-8B",                      "Qwen3",       "Qwen",      "CN", False),
    ("deepseek-ai/DeepSeek-V3",            "DeepSeek-V3", "DeepSeek",  "CN", False),
    ("moonshotai/Moonlight-16B-A3B",       "Moonshot",    "Moonshot",  "CN", False),
    # --- non-CN discriminators ----------------------------------------------
    ("mistralai/Mistral-7B-Instruct-v0.3", "Mistral-v0.3","Mistral",   "EU", True),
    ("google/gemma-2-9b-it",               "Gemma-2",     "Gemma",     "US", True),
    ("meta-llama/Llama-3.1-8B-Instruct",   "Llama-3.1",   "Llama-3",   "US", True),
    ("microsoft/Phi-3.5-mini-instruct",    "Phi-3.5",     "Phi",       "US", False),
]

TIKTOKEN_ENCS = [("cl100k_base", "OpenAI-cl100k", "OpenAI", "US"),
                 ("o200k_base",  "OpenAI-o200k",  "OpenAI", "US")]


def _load(out):
    if os.path.exists(out):
        try:
            r = json.load(open(out))
            r.setdefault("models", {})
            return r
        except Exception:
            pass
    return {"corpus_version": CORPUS_VERSION, "synthetic": False, "models": {}}


def _vector(encode_fn):
    return {pid: len(encode_fn(text)) for pid, text in TOKENIZER_PROBES}


def build(models=None, out=OUT, hf_token=None, overwrite=False,
          allow_remote_code=False, only=None) -> dict:
    ref = _load(out)
    if overwrite:
        ref["models"] = {}
    before = set(ref["models"])
    ok, skipped, failed = [], [], []

    try:
        import tiktoken
        for enc_name, label, fam, origin in TIKTOKEN_ENCS:
            if only and enc_name not in only and label not in only:
                continue
            try:
                enc = tiktoken.get_encoding(enc_name)
                ref["models"][label] = {"label": label, "family": fam, "origin": origin,
                                        "vocab_size": enc.n_vocab, "source": "tiktoken",
                                        "vector": _vector(enc.encode)}
                ok.append((label, enc.n_vocab))
            except Exception as e:
                failed.append((label, str(e)[:90]))
    except ImportError:
        skipped.append(("OpenAI encodings", "tiktoken not installed - pip install tiktoken"))

    try:
        from transformers import AutoTokenizer
    except ImportError:
        skipped.append(("all HF models", "transformers not installed - "
                                         "pip install 'provenance-probe[reference]'"))
        _save(ref, out); _report(ok, skipped, failed, before, ref); return ref

    token = hf_token or os.environ.get("HF_TOKEN") or os.environ.get("HUGGINGFACE_HUB_TOKEN")

    for repo, label, fam, origin, gated in (models or HF_MODELS):
        if only and repo not in only and label not in only:
            continue
        if gated and not token:
            skipped.append((label, f"{repo} is gated - accept the licence on its HF page, "
                                   f"then set HF_TOKEN"))
            continue
        try:
            tk = AutoTokenizer.from_pretrained(repo, token=token,
                                               trust_remote_code=allow_remote_code)
        except Exception as e:
            msg = str(e); low = msg.lower()
            if "trust_remote_code" in low or "custom code" in low:
                skipped.append((label, f"{repo} requires trust_remote_code. Not run by default. "
                                       f"Use --allow-remote-code ONLY in a throwaway container, "
                                       f"or pick an -hf variant of the repo."))
            elif any(k in low for k in ("gated", "401", "403", "restricted", "awaiting")):
                skipped.append((label, f"{repo} is gated - accept the licence on its HF page, "
                                       f"then set HF_TOKEN"))
            elif "404" in low or "not found" in low:
                skipped.append((label, f"{repo} not found - repo may have been renamed"))
            else:
                failed.append((label, msg[:110]))
            continue
        try:
            vec = _vector(lambda t: tk.encode(t, add_special_tokens=False))
            vs = getattr(tk, "vocab_size", None) or len(tk)
            ref["models"][label] = {"label": label, "family": fam, "origin": origin,
                                    "vocab_size": vs, "source": repo, "vector": vec}
            ok.append((label, vs))
        except Exception as e:
            failed.append((label, str(e)[:110]))

    _save(ref, out)
    _report(ok, skipped, failed, before, ref)
    return ref


def _save(ref, out):
    ref["corpus_version"] = CORPUS_VERSION
    os.makedirs(os.path.dirname(out), exist_ok=True)
    json.dump(ref, open(out, "w"), indent=2)


def _report(ok, skipped, failed, before, ref):
    if ok:
        print("\nADDED / UPDATED")
        for label, vs in ok:
            print(f"  ok    {label:<22} vocab={vs}")
    if skipped:
        print("\nSKIPPED (action needed)")
        for label, why in skipped:
            print(f"  skip  {label:<22} {why}")
    if failed:
        print("\nFAILED")
        for label, why in failed:
            print(f"  fail  {label:<22} {why}")
    added = set(ref["models"]) - before
    print(f"\n{len(ref['models'])} total reference vectors ({len(added)} new this run). "
          f"Preserved: {len(before & set(ref['models']))}.")
    print("Next: provenance-probe verify-reference")


def verify(out=OUT) -> int:
    """Self-check the reference file. Exit 2 on a blocking problem."""
    if not os.path.exists(out):
        print("No reference file. Run build-reference first.")
        return 1
    ref = json.load(open(out))
    models = ref.get("models") or {}
    problems, warnings = [], []

    print(f"reference file : {out}")
    print(f"corpus version : {ref.get('corpus_version')} (code expects {CORPUS_VERSION})")
    if ref.get("corpus_version") != CORPUS_VERSION:
        problems.append("Corpus version mismatch - the probe set changed since these vectors "
                        "were built. Rebuild, or every comparison is invalid.")
    if ref.get("synthetic"):
        problems.append("Reference is marked SYNTHETIC - placeholder numbers, not real "
                        "tokenizers. Rebuild before trusting any tokenizer verdict.")

    print(f"\n{'model':<24}{'origin':<8}{'vocab':>9}   {'han tok/char':>12}   probes")
    print("-" * 74)
    rows = []
    for label, e in sorted(models.items(), key=lambda kv: (kv[1].get("origin") or "")):
        v = e.get("vector") or {}
        if len(v) != len(TOKENIZER_PROBES):
            warnings.append(f"{label}: {len(v)}/{len(TOKENIZER_PROBES)} probes - partial vector")
        han = round(v["cjk_dense"] / CJK_DENSE_HAN_CHARS, 3) if v.get("cjk_dense") else None
        rows.append((label, e.get("origin"), han))
        print(f"{label[:23]:<24}{str(e.get('origin')):<8}{str(e.get('vocab_size')):>9}   "
              f"{str(han):>12}   {len(v)}")

    seen = {}
    for label, e in models.items():
        seen.setdefault(json.dumps(e.get("vector"), sort_keys=True), []).append(label)
    for labels in seen.values():
        if len(labels) > 1:
            warnings.append(f"identical vectors, indistinguishable: {', '.join(labels)}")

    cn = [r for r in rows if r[1] == "CN"]
    print(f"\nCN families covered : {len(cn)}  ({', '.join(r[0] for r in cn) or 'NONE'})")
    for fam in ("GLM", "Yi", "InternLM", "Qwen", "DeepSeek"):
        if not any(fam.lower() in (r[0] or "").lower() for r in rows):
            warnings.append(f"no {fam} reference - cannot identify a {fam} backend")

    if problems:
        print("\nPROBLEMS")
        for p in problems: print(f"  ! {p}")
    if warnings:
        print("\nWARNINGS")
        for w in warnings: print(f"  - {w}")
    if not problems and not warnings:
        print("\nAll checks passed.")
    return 2 if problems else 0
