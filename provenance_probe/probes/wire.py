"""Layer 3: API surface fingerprinting - headers, error schema, streaming shape."""
from __future__ import annotations
import json, hashlib
from ..data.corpus import ERROR_PROBES, PRC_MODEL_TOKENS

VENDOR_HEADER_HINTS = {
    "openai-organization": "OpenAI", "openai-processing-ms": "OpenAI",
    "x-request-id": "generic", "anthropic-ratelimit-requests-limit": "Anthropic",
    "x-amzn-requestid": "AWS", "x-amz-cf-id": "AWS CloudFront",
    "x-ms-region": "Azure", "azureml-model-session": "Azure ML",
    "x-goog-": "Google", "x-openrouter": "OpenRouter",
    "x-together-": "Together", "fireworks-": "Fireworks",
    "x-groq-region": "Groq", "x-vercel-": "Vercel",
    "x-tt-logid": "ByteDance", "x-tt-trace-id": "ByteDance",
    "x-acs-request-id": "Alibaba Cloud", "x-oss-request-id": "Alibaba Cloud",
    "x-ca-request-id": "Alibaba API Gateway",
    "x-tc-requestid": "Tencent Cloud", "x-bce-request-id": "Baidu Cloud",
    "x-ds-": "DeepSeek", "x-cache-status": "generic-cdn",
}


def header_fingerprint(client) -> dict:
    r = client.chat("ping", max_tokens=1)
    hdrs = r.headers
    hits = []
    for k in hdrs:
        for pat, vendor in VENDOR_HEADER_HINTS.items():
            if k.startswith(pat) or k == pat:
                hits.append({"header": k, "implies": vendor, "value": str(hdrs[k])[:120]})
    server = hdrs.get("server") or hdrs.get("x-powered-by")
    return {"status": r.status, "server": server,
            "echoed_model": r.echoed_model(),
            "vendor_headers": hits,
            "header_names": sorted(hdrs.keys()),
            "header_shape_hash": hashlib.sha256(
                "|".join(sorted(hdrs.keys())).encode()).hexdigest()[:16]}


def error_schema_fingerprint(client) -> dict:
    rows = []
    for name, mutation in ERROR_PROBES:
        payload = {"model": client.t.model,
                   "messages": [{"role": "user", "content": "hi"}],
                   "max_tokens": 1}
        payload.update(mutation)
        r = client.raw_post(client.t.chat_path, payload)
        shape = _shape(r.body)
        rows.append({"probe": name, "status": r.status, "schema": shape,
                     "excerpt": (r.raw or "")[:300]})
    sig = hashlib.sha256(json.dumps([(x["probe"], x["status"], x["schema"])
                                     for x in rows], sort_keys=True).encode()).hexdigest()[:16]
    return {"probes": rows, "error_signature": sig}


def _shape(obj, depth=0):
    if depth > 3:
        return "..."
    if isinstance(obj, dict):
        return {k: _shape(v, depth + 1) for k, v in sorted(obj.items())}
    if isinstance(obj, list):
        return [_shape(obj[0], depth + 1)] if obj else []
    return type(obj).__name__


def streaming_fingerprint(client) -> dict:
    r = client.chat("Count from one to ten.", max_tokens=60, stream=True)
    lines = [l for l in (r.raw or "").splitlines() if l.strip()]
    fields, finish, has_usage = set(), None, False
    for l in lines:
        if not l.startswith("data:"):
            continue
        payload = l[5:].strip()
        if payload == "[DONE]":
            fields.add("__DONE_sentinel__")
            continue
        try:
            o = json.loads(payload)
        except Exception:
            continue
        fields.update(o.keys())
        if "usage" in o and o["usage"]:
            has_usage = True
        try:
            fr = (o.get("choices") or [{}])[0].get("finish_reason")
            if fr:
                finish = fr
        except Exception:
            pass
    return {"chunk_count": len(lines), "chunk_fields": sorted(fields),
            "final_usage_chunk": has_usage, "finish_reason": finish,
            "ttft_s": round(r.ttft, 4) if r.ttft else None}


def model_catalog(client) -> dict:
    r = client.list_models()
    ids = []
    b = r.body
    if isinstance(b, dict):
        for m in b.get("data", b.get("models", [])) or []:
            if isinstance(m, dict):
                ids.append(m.get("id") or m.get("name") or "")
            elif isinstance(m, str):
                ids.append(m)
    flagged = []
    for i in ids:
        low = (i or "").lower()
        for tok, fam in PRC_MODEL_TOKENS.items():
            if tok in low:
                flagged.append({"id": i, "family": fam, "origin": "CN"})
                break
    return {"status": r.status, "count": len(ids), "ids": ids[:200],
            "prc_origin_models": flagged}
