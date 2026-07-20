"""Layer 7: on-prem / self-hosted artifact inspection."""
from __future__ import annotations
import json, os, struct, hashlib, re

CN_ARCH = {
    "qwen2": "Qwen", "qwen3": "Qwen", "qwen2_moe": "Qwen-MoE", "qwen3_moe": "Qwen-MoE",
    "qwen2_vl": "Qwen-VL", "deepseek_v2": "DeepSeek", "deepseek_v3": "DeepSeek",
    "deepseek": "DeepSeek", "chatglm": "GLM/Zhipu", "glm": "GLM/Zhipu",
    "glm4": "GLM/Zhipu", "internlm": "InternLM", "internlm2": "InternLM",
    "baichuan": "Baichuan", "minicpm": "MiniCPM/OpenBMB", "yuan": "Yuan/Inspur",
    "telechat": "TeleChat", "skywork": "Skywork", "hunyuan": "Tencent Hunyuan",
    "minimax": "MiniMax", "ernie": "Baidu Ernie", "step1": "StepFun",
}
CN_VOCAB = {151936: "Qwen2/2.5", 151669: "Qwen3", 152064: "Qwen2-72B",
            129280: "DeepSeek-V3", 102400: "DeepSeek-LLM", 100000: "DeepSeek-Coder",
            151552: "GLM-4", 65024: "ChatGLM2/3", 64000: "Yi", 92544: "InternLM2",
            125696: "Baichuan2", 73448: "MiniCPM"}
NON_CN_VOCAB = {128256: "Llama-3", 32000: "Llama-2/Mistral", 32768: "Mistral-v0.3",
                256000: "Gemma", 262144: "Gemma-3", 100352: "Phi-3", 200019: "GPT-OSS"}


def scan_dir(root: str) -> dict:
    findings, files = [], []
    for dirpath, _, names in os.walk(root):
        for n in names:
            p = os.path.join(dirpath, n)
            if n == "config.json":
                findings += _config(p)
                files.append(p)
            elif n in ("tokenizer_config.json", "tokenizer.json"):
                findings += _tokenizer(p)
                files.append(p)
            elif n.endswith(".gguf"):
                findings += _gguf(p)
                files.append(p)
            elif n.endswith(".safetensors"):
                findings += _safetensors(p)
                files.append(p)
    # HF cache path leakage
    for dirpath, dirs, _ in os.walk(root):
        for d in dirs:
            m = re.match(r"models--([^-]+(?:-[^-]+)*)--(.+)", d)
            if m:
                org = m.group(1).lower()
                if any(k in org for k in ("qwen", "deepseek", "thudm", "01-ai", "internlm",
                                          "openbmb", "baichuan", "zhipu", "moonshot", "minimax")):
                    findings.append({"type": "hf_cache_path", "severity": "critical",
                                     "path": os.path.join(dirpath, d),
                                     "detail": f"HuggingFace cache for PRC-origin org '{m.group(1)}'."})
    return {"root": root, "files_examined": len(files), "findings": findings}


def _config(p):
    out = []
    try:
        c = json.load(open(p))
    except Exception as e:
        return [{"type": "config_unreadable", "severity": "info", "path": p, "detail": str(e)}]
    archs = [a.lower() for a in (c.get("architectures") or [])]
    mt = (c.get("model_type") or "").lower()
    for key, fam in CN_ARCH.items():
        if mt == key or any(key in a for a in archs):
            out.append({"type": "cn_architecture", "severity": "critical", "path": p,
                        "detail": f"model_type/architecture '{mt or archs}' -> {fam} (PRC-origin)."})
            break
    name = c.get("_name_or_path") or ""
    if name:
        out.append({"type": "name_or_path", "severity": "high", "path": p,
                    "detail": f"_name_or_path = {name}"})
    v = c.get("vocab_size")
    if v in CN_VOCAB:
        out.append({"type": "cn_vocab_size", "severity": "high", "path": p,
                    "detail": f"vocab_size {v} matches {CN_VOCAB[v]} (PRC-origin)."})
    elif v in NON_CN_VOCAB:
        out.append({"type": "vocab_size", "severity": "info", "path": p,
                    "detail": f"vocab_size {v} matches {NON_CN_VOCAB[v]}."})
    for k in ("rope_theta", "num_key_value_heads", "hidden_size", "num_hidden_layers",
              "intermediate_size", "num_experts", "n_routed_experts"):
        if k in c:
            out.append({"type": "arch_param", "severity": "info", "path": p,
                        "detail": f"{k}={c[k]}"})
    return out


def _tokenizer(p):
    try:
        h = hashlib.sha256(open(p, "rb").read()).hexdigest()
    except Exception:
        return []
    out = [{"type": "tokenizer_hash", "severity": "info", "path": p,
            "detail": f"sha256={h[:32]} (compare to upstream HF repo file)"}]
    try:
        c = json.load(open(p))
        blob = json.dumps(c)[:200000].lower()
        for k, fam in CN_ARCH.items():
            if k in blob:
                out.append({"type": "cn_tokenizer_ref", "severity": "high", "path": p,
                            "detail": f"tokenizer references '{k}' -> {fam}."})
                break
        if isinstance(c.get("model"), dict) and c["model"].get("vocab"):
            n = len(c["model"]["vocab"])
            out.append({"type": "tokenizer_vocab", "severity": "info", "path": p,
                        "detail": f"vocab entries = {n}"
                                  + (f" -> {CN_VOCAB[n]} (PRC-origin)" if n in CN_VOCAB else "")})
    except Exception:
        pass
    return out


def _gguf(p):
    out = []
    try:
        with open(p, "rb") as f:
            if f.read(4) != b"GGUF":
                return []
            struct.unpack("<I", f.read(4))
            struct.unpack("<Q", f.read(8))
            n_kv = struct.unpack("<Q", f.read(8))[0]
            for _ in range(min(n_kv, 200)):
                klen = struct.unpack("<Q", f.read(8))[0]
                key = f.read(klen).decode("utf-8", "replace")
                vt = struct.unpack("<I", f.read(4))[0]
                if vt == 8:  # string
                    slen = struct.unpack("<Q", f.read(8))[0]
                    val = f.read(slen).decode("utf-8", "replace")
                    if key in ("general.name", "general.architecture", "general.basename",
                               "general.organization", "general.base_model.0.repo_url",
                               "tokenizer.ggml.model"):
                        sev = "critical" if any(k in val.lower() for k in CN_ARCH) else "info"
                        out.append({"type": "gguf_metadata", "severity": sev, "path": p,
                                    "detail": f"{key} = {val}"})
                    continue
                break  # non-string: stop cheap parse
    except Exception:
        pass
    return out


def _safetensors(p):
    try:
        with open(p, "rb") as f:
            n = struct.unpack("<Q", f.read(8))[0]
            hdr = json.loads(f.read(min(n, 2_000_000)).decode("utf-8", "replace"))
    except Exception:
        return []
    names = [k for k in hdr if k != "__metadata__"][:40]
    out = [{"type": "safetensors_tensors", "severity": "info", "path": p,
            "detail": f"{len(hdr)} tensors; sample: {names[:6]}"}]
    meta = hdr.get("__metadata__") or {}
    if meta:
        out.append({"type": "safetensors_metadata", "severity": "high", "path": p,
                    "detail": json.dumps(meta)[:400]})
    return out
