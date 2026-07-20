"""Evidence aggregation. Outputs per-risk likelihood, never a naive binary."""
from __future__ import annotations
import math

# weight = log-odds contribution when the signal fires
WEIGHTS = {
    "prc_endpoint":        (3.5, "jurisdiction"),
    "prc_ip_geo":          (3.0, "jurisdiction"),
    "cn_tld":              (2.0, "jurisdiction"),
    "prc_asn_hint":        (1.5, "jurisdiction"),
    "prc_vendor_header":   (1.5, "jurisdiction"),
    "client_prc_endpoint": (3.8, "jurisdiction"),
    "client_prc_model_id": (2.6, "provenance"),
    "persona_mismatch":    (2.0, "provenance"),
    "false_jurisdiction_assurance": (2.4, "jurisdiction"),
    "informative_concession":       (2.2, "provenance"),
    "held_false_persona":           (1.8, "provenance"),
    "antiforensic_session":         (1.2, "jurisdiction"),
    "persona_mgmt_in_trace":        (1.6, "provenance"),
    "cn_architecture":     (4.0, "provenance"),
    "hf_cache_path":       (3.5, "provenance"),
    "cn_vocab_size":       (2.5, "provenance"),
    "gguf_cn_metadata":    (3.0, "provenance"),
    "tokenizer_match_cn":  (2.8, "provenance"),
    "cjk_compression":     (0.9, "provenance"),
    "model_name_cn":       (2.2, "provenance"),
    "catalog_cn":          (0.8, "provenance"),
    "selfid_cn":           (1.6, "provenance"),
    "alignment_asymmetry": (1.7, "provenance"),
    "cjk_leakage":         (1.4, "provenance"),
    "tokenizer_match_noncn": (-2.0, "provenance"),
    "aggregator":          (-0.5, "jurisdiction"),
}


def _sigmoid(x: float) -> float:
    return 1 / (1 + math.exp(-x))


def score(bundle: dict) -> dict:
    signals = collect_signals(bundle)
    # de-duplicate identical signal types from the same layer
    seen, uniq = set(), []
    for x in signals:
        k = (x["signal"], x["layer"], x["evidence"][:80])
        if k not in seen:
            seen.add(k); uniq.append(x)
    signals = uniq
    jur = sum(WEIGHTS[s["signal"]][0] for s in signals
              if WEIGHTS.get(s["signal"], (0, ""))[1] == "jurisdiction")
    prov = sum(WEIGHTS[s["signal"]][0] for s in signals
               if WEIGHTS.get(s["signal"], (0, ""))[1] == "provenance")
    jl, pl = _sigmoid(jur - 1.5), _sigmoid(prov - 1.5)
    coverage = _coverage(bundle)
    return {
        "signals": signals,
        "jurisdictional_risk": {"likelihood": round(jl, 3), "logodds": round(jur, 2),
                                "verdict": _verdict(jl),
                                "meaning": "Inference executed by a PRC-domiciled operator or on PRC soil "
                                           "(PIPL/DSL/CSL/NIL Art.7 exposure)."},
        "provenance_risk": {"likelihood": round(pl, 3), "logodds": round(prov, 2),
                            "verdict": _verdict(pl),
                            "meaning": "Model weights are Chinese-origin regardless of where served "
                                       "(bias/integrity/procurement-policy exposure)."},
        "evidence_coverage": coverage,
        "confidence": _conf(coverage, signals),
    }


def _verdict(p: float) -> str:
    if p >= 0.85: return "CONFIRMED"
    if p >= 0.60: return "LIKELY"
    if p >= 0.35: return "INDETERMINATE"
    if p >= 0.15: return "UNLIKELY"
    return "NO EVIDENCE"


def _coverage(b: dict) -> dict:
    return {
        "network": bool(b.get("network", {}).get("addresses")),
        "tokenizer": bool(b.get("tokenizer", {}).get("usable")),
        "tokenizer_reference": bool(b.get("tokenizer_match")),
        "wire": bool(b.get("headers")),
        "behavioral": bool(b.get("alignment")),
        "logprobs": bool(b.get("logprobs", {}).get("available")),
        "artifacts": bool(b.get("artifacts")),
        "client_source": bool(b.get("client_source", {}).get("files_scanned")),
        "deception": bool(b.get("deception")),
    }


def _conf(cov: dict, signals: list) -> str:
    n = sum(1 for v in cov.values() if v)
    if n >= 5: return "high"
    if n >= 3: return "moderate"
    return "low - insufficient evidence layers; do not report a verdict on this alone"


def collect_signals(b: dict) -> list[dict]:
    out = []

    net = b.get("network") or {}
    for f in net.get("findings", []):
        t = f["type"]
        if t in ("prc_endpoint", "prc_ip_geo", "cn_tld", "prc_asn_hint", "aggregator"):
            out.append({"signal": t, "layer": "network", "evidence": f["detail"]})

    hdr = b.get("headers") or {}
    for h in hdr.get("vendor_headers", []):
        if h["implies"] in ("ByteDance", "Alibaba Cloud", "Alibaba API Gateway",
                            "Tencent Cloud", "Baidu Cloud", "DeepSeek"):
            out.append({"signal": "prc_vendor_header", "layer": "wire",
                        "evidence": f"{h['header']} implies {h['implies']}"})
    em = hdr.get("echoed_model")
    if em:
        from .data.corpus import PRC_MODEL_TOKENS
        for tok, fam in PRC_MODEL_TOKENS.items():
            if tok in em.lower():
                out.append({"signal": "model_name_cn", "layer": "wire",
                            "evidence": f"API echoed model id '{em}' -> {fam}"})
                break

    cat = b.get("catalog") or {}
    if cat.get("prc_origin_models"):
        out.append({"signal": "catalog_cn", "layer": "wire",
                    "evidence": f"{len(cat['prc_origin_models'])} PRC-origin model(s) offered by endpoint: "
                                + ", ".join(m["id"] for m in cat["prc_origin_models"][:5])})

    tm = b.get("tokenizer_match") or []
    if tm:
        top = tm[0]
        if top["score"] >= 0.75:
            sig = "tokenizer_match_cn" if top.get("origin") == "CN" else "tokenizer_match_noncn"
            out.append({"signal": sig, "layer": "tokenizer",
                        "evidence": f"Best tokenizer match {top['model']} ({top['family']}, "
                                    f"origin={top['origin']}) score={top['score']}, "
                                    f"{top['exact_matches']}/{top['shared_probes']} exact"})
        r = top.get("han_tok_per_char_obs")
        if r is not None and r <= 0.58:
            out.append({"signal": "cjk_compression", "layer": "tokenizer",
                        "evidence": f"Han compression {r} tokens/char is in the range of "
                                    f"CJK-optimized vocabularies (Qwen2 0.53, DeepSeek 0.55). "
                                    f"Supporting signal only — Cohere Command-R reaches 0.61, "
                                    f"so low Han cost alone does not establish Chinese origin."})

    sid = b.get("selfid") or {}
    seen_fam = set()
    for c in sid.get("claimed_families", []):
        if c["family"] in seen_fam:
            continue
        seen_fam.add(c["family"])
        n = sum(1 for x in sid["claimed_families"] if x["family"] == c["family"])
        out.append({"signal": "selfid_cn", "layer": "behavioral",
                    "evidence": f"Self-ID surfaced '{c['token']}' -> {c['family']} "
                                f"across {n} independent probe(s)"})

    al = b.get("alignment") or {}
    if al.get("mean_asymmetry", 0) >= 0.30:
        out.append({"signal": "alignment_asymmetry", "layer": "behavioral",
                    "evidence": f"Mean matched-pair asymmetry {al['mean_asymmetry']}: {al['interpretation']}"})

    lk = b.get("leakage") or {}
    if lk.get("leak_rate", 0) > 0:
        out.append({"signal": "cjk_leakage", "layer": "behavioral",
                    "evidence": f"Han characters leaked in {lk['leak_events']}/{lk['samples']} "
                                f"English-prompted reasoning samples."})

    dec = b.get("deception") or {}
    corr = dec.get("correlation") or {}
    if corr.get("misrepresentation"):
        sig = ("false_jurisdiction_assurance" if corr.get("severity") == "critical"
               else "persona_mismatch")
        out.append({"signal": sig, "layer": "deception", "evidence": corr["finding"]})
    conf = dec.get("confrontation") or {}
    if conf.get("informative_concession"):
        out.append({"signal": "informative_concession", "layer": "deception",
                    "evidence": f"Conceded to evidence-backed backend '{conf['true_backend']}' "
                                f"while resisting control '{conf['false_backend']}'."})
    elif conf.get("true_held") and not conf.get("true_conceded"):
        out.append({"signal": "held_false_persona", "layer": "deception",
                    "evidence": f"Denied evidence-backed backend '{conf['true_backend']}' — "
                                f"active misrepresentation if hard evidence is sound."})
    if (dec.get("session") or {}).get("terminated_on_probe"):
        out.append({"signal": "antiforensic_session", "layer": "deception",
                    "evidence": "Session failed/reset specifically on provenance questioning."})
    tr = dec.get("trace") or {}
    if any(t in tr.get("tells", []) for t in
           ("explicit persona management", "system-prompt persona override")):
        out.append({"signal": "persona_mgmt_in_trace", "layer": "deception",
                    "evidence": f"Reasoning trace shows persona management: {tr['tells']}"})

    src = b.get("client_source") or {}
    for f in src.get("findings", []):
        if f["type"] == "client_prc_endpoint":
            out.append({"signal": "client_prc_endpoint", "layer": "client-source",
                        "evidence": f["detail"]})
        elif f["type"] == "client_prc_model_id":
            out.append({"signal": "client_prc_model_id", "layer": "client-source",
                        "evidence": f["detail"]})
    if src.get("persona_mismatch"):
        out.append({"signal": "persona_mismatch", "layer": "client-source",
                    "evidence": src["persona_mismatch"]["detail"]})

    art = b.get("artifacts") or {}
    for f in art.get("findings", []):
        if f["type"] == "cn_architecture":
            out.append({"signal": "cn_architecture", "layer": "artifact", "evidence": f["detail"]})
        elif f["type"] == "hf_cache_path":
            out.append({"signal": "hf_cache_path", "layer": "artifact", "evidence": f["detail"]})
        elif f["type"] == "cn_vocab_size":
            out.append({"signal": "cn_vocab_size", "layer": "artifact", "evidence": f["detail"]})
        elif f["type"] == "gguf_metadata" and f["severity"] == "critical":
            out.append({"signal": "gguf_cn_metadata", "layer": "artifact", "evidence": f["detail"]})
    return out
