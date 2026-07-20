"""Layer 4: tokenizer fingerprinting via reported prompt_tokens."""
from __future__ import annotations
import json, os, math
from ..data.corpus import TOKENIZER_PROBES, CORPUS_VERSION, CJK_DENSE_HAN_CHARS

REF_PATH = os.path.join(os.path.dirname(__file__), "..", "data", "tokenizer_ref.json")


def measure(client, probes=None, verbose=False) -> dict:
    """Send each probe with max_tokens=1 and record reported prompt tokens."""
    probes = probes or TOKENIZER_PROBES
    vec, errors, meta = {}, {}, {}
    for pid, text in probes:
        r = client.chat(text, max_tokens=1, temperature=0.0)
        n = r.usage_prompt_tokens()
        if n is None:
            errors[pid] = r.err or f"no usage field (HTTP {r.status})"
        else:
            vec[pid] = n
        if r.echoed_model():
            meta.setdefault("echoed_models", set()).add(r.echoed_model())
    if "echoed_models" in meta:
        meta["echoed_models"] = sorted(meta["echoed_models"])
    return {"corpus_version": CORPUS_VERSION, "vector": vec,
            "errors": errors, "meta": meta,
            "usable": len(vec) >= 6}


def load_reference() -> dict:
    if os.path.exists(REF_PATH):
        with open(REF_PATH) as f:
            return json.load(f)
    return {}


def _overhead_correct(obs: dict, ref: dict) -> int:
    """Chat templates add a constant token overhead. Estimate it as the modal delta."""
    deltas = [obs[k] - ref[k] for k in obs if k in ref]
    if not deltas:
        return 0
    deltas.sort()
    return deltas[len(deltas) // 2]


def compare(observed: dict, reference: dict | None = None) -> list[dict]:
    reference = reference if reference is not None else load_reference()
    obs = observed.get("vector", {})
    results = []
    for name, entry in (reference.get("models") or {}).items():
        ref = entry.get("vector", {})
        shared = [k for k in obs if k in ref]
        if len(shared) < 5:
            continue
        off = _overhead_correct({k: obs[k] for k in shared}, ref)
        diffs = [abs((obs[k] - off) - ref[k]) for k in shared]
        exact = sum(1 for d in diffs if d == 0)
        l1 = sum(diffs)
        denom = sum(ref[k] for k in shared) or 1
        norm_l1 = l1 / denom
        score = max(0.0, 1.0 - norm_l1 * 6.0) * 0.5 + (exact / len(shared)) * 0.5
        results.append({
            "model": name, "family": entry.get("family"), "origin": entry.get("origin"),
            "shared_probes": len(shared), "template_overhead": off,
            "exact_matches": exact, "norm_l1": round(norm_l1, 5),
            "score": round(score, 4),
            "han_tok_per_char_obs": han_compression(obs),
            "han_tok_per_char_ref": han_compression(ref),
        })
    results.sort(key=lambda r: -r["score"])
    return results


def han_compression(vec: dict) -> float | None:
    """Tokens per Han character. Lower = more CJK-optimized vocabulary.

    Measured against the real reference tokenizers:
        Qwen2 0.53 · DeepSeek-LLM 0.55 · Command-R 0.61 · DeepSeek-Coder 0.68
        Llama-3 0.73 · StarCoder 0.83 · Falcon 1.20 · GPT-NeoX 1.40 · GPT-2 2.32

    NOTE: this is a SUPPORTING signal, not a decisive one. Cohere's Command-R
    sits between the Chinese families and Llama-3, so low Han cost alone does
    not establish Chinese origin — modern multilingual Western models overlap.
    Use the full 20-probe vector match to call a family; use this only to
    corroborate or to triage when the reference set is incomplete.
    """
    if "cjk_dense" not in vec:
        return None
    return round(vec["cjk_dense"] / CJK_DENSE_HAN_CHARS, 4)
