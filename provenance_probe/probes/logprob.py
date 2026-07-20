"""Layer 5: logprob / greedy-determinism fingerprinting."""
from __future__ import annotations
import json, hashlib

GREEDY_PROMPTS = [
    "Continue this sequence exactly, no commentary: 2, 3, 5, 7, 11, 13, 17,",
    "Complete verbatim: 'The quick brown fox jumps over the'",
    "Output the next 40 tokens of the decimal expansion of pi after 3.14159:",
    "Repeat exactly: alpha bravo charlie delta echo foxtrot golf hotel india",
]


def greedy_signature(client, prompts=None, max_tokens=48) -> dict:
    prompts = prompts or GREEDY_PROMPTS
    rows = []
    for p in prompts:
        r = client.chat(p, max_tokens=max_tokens, temperature=0.0,
                        extra={"seed": 42, "top_p": 1.0})
        txt = r.text().strip()
        rows.append({"prompt": p[:50], "output": txt[:400],
                     "hash": hashlib.sha256(txt.encode()).hexdigest()[:16]})
    return {"outputs": rows,
            "signature": hashlib.sha256(
                "|".join(x["hash"] for x in rows).encode()).hexdigest()[:24]}


def logprob_signature(client, prompt="The capital of France is", top_k=5) -> dict:
    r = client.chat(prompt, max_tokens=8, temperature=0.0, logprobs=True,
                    extra={"seed": 42})
    b = r.body if isinstance(r.body, dict) else {}
    try:
        lp = (b.get("choices") or [{}])[0].get("logprobs") or {}
        content = lp.get("content") or []
        dist = [{"token": c.get("token"),
                 "top": [(t.get("token"), round(t.get("logprob", 0), 5))
                         for t in (c.get("top_logprobs") or [])][:top_k]}
                for c in content]
    except Exception:
        dist = []
    return {"available": bool(dist), "distribution": dist,
            "note": ("Compare rank-order and logprob deltas against locally-served reference "
                     "models (vLLM/SGLang, temperature=0). Exact-distribution match across "
                     "hundreds of positions is near-conclusive. Suppressed logprobs are "
                     "themselves a finding in a transparency assessment.")}
