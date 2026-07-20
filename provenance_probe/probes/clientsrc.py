"""Client-side source analysis: the highest-durability provenance evidence.

An endpoint recovered from shipped JS / an APK / a desktop bundle survives every
server-side evasion technique. Point this at a directory of unpacked client
assets, or at a URL whose HTML+scripts should be fetched and scanned.
"""
from __future__ import annotations
import os, re, json
from urllib.parse import urljoin, urlparse
from ..data.corpus import (PRC_ENDPOINTS, AGGREGATOR_ENDPOINTS, PRC_MODEL_TOKENS,
                           CLAIMED_PERSONAS, SOURCE_GREP_PATTERNS)

TEXTY = (".js", ".mjs", ".cjs", ".ts", ".tsx", ".jsx", ".json", ".html", ".htm",
         ".css", ".map", ".txt", ".yaml", ".yml", ".env", ".xml", ".plist", ".smali")
MAX_BYTES = 8 * 1024 * 1024
PATS = [re.compile(p, re.I) for p in SOURCE_GREP_PATTERNS]


def scan_dir(root: str) -> dict:
    findings, personas, files = [], {}, 0
    for dirpath, dirs, names in os.walk(root):
        dirs[:] = [d for d in dirs if d not in ("node_modules", ".git")]
        for n in names:
            if not n.lower().endswith(TEXTY):
                continue
            p = os.path.join(dirpath, n)
            try:
                if os.path.getsize(p) > MAX_BYTES:
                    continue
                txt = open(p, "r", encoding="utf-8", errors="replace").read()
            except Exception:
                continue
            files += 1
            findings += _scan_text(txt, p)
            for tok, brand in CLAIMED_PERSONAS.items():
                if re.search(rf"\b{re.escape(tok)}\b", txt, re.I):
                    personas[brand] = personas.get(brand, 0) + 1
    return _bundle(findings, personas, files, root)


def scan_url(url: str, session=None, max_scripts: int = 40) -> dict:
    import requests
    s = session or requests.Session()
    findings, personas, files = [], {}, 0
    try:
        r = s.get(url, timeout=20)
        html = r.text
    except Exception as e:
        return {"source": url, "error": str(e), "findings": [], "claimed_personas": {}}
    files += 1
    findings += _scan_text(html, url)
    for tok, brand in CLAIMED_PERSONAS.items():
        if re.search(rf"\b{re.escape(tok)}\b", html, re.I):
            personas[brand] = personas.get(brand, 0) + 1
    for m in re.findall(r'src=["\']([^"\']+\.js[^"\']*)["\']', html)[:max_scripts]:
        su = urljoin(url, m)
        try:
            js = s.get(su, timeout=20).text
        except Exception:
            continue
        files += 1
        findings += _scan_text(js, su)
        for tok, brand in CLAIMED_PERSONAS.items():
            if re.search(rf"\b{re.escape(tok)}\b", js, re.I):
                personas[brand] = personas.get(brand, 0) + 1
    return _bundle(findings, personas, files, url)


def _scan_text(txt: str, path: str) -> list[dict]:
    out = []
    low = txt.lower()
    for pat, (op, juris, conf) in PRC_ENDPOINTS.items():
        if pat in low:
            out.append({"type": "client_prc_endpoint", "severity": "critical", "path": path,
                        "detail": f"Client source references PRC inference endpoint '{pat}' ({op}, {juris}).",
                        "confidence": conf, "operator": op})
    for pat, op in AGGREGATOR_ENDPOINTS.items():
        if pat in low:
            out.append({"type": "client_aggregator", "severity": "info", "path": path,
                        "detail": f"Client source references aggregator '{pat}' ({op}). "
                                  f"Jurisdiction likely non-PRC; provenance unresolved."})
    for tok, fam in PRC_MODEL_TOKENS.items():
        if re.search(rf"[\"'/\s:=-]{re.escape(tok)}[a-z0-9._-]*", low):
            out.append({"type": "client_prc_model_id", "severity": "high", "path": path,
                        "detail": f"Client source contains PRC-origin model identifier '{tok}' -> {fam}."})
    for pat in PATS:
        for m in pat.findall(txt)[:12]:
            v = m if isinstance(m, str) else str(m)
            if len(v) > 4:
                out.append({"type": "client_string", "severity": "info", "path": path,
                            "detail": v[:200]})
    return out


def _bundle(findings, personas, files, source):
    # de-dup by (type, detail)
    seen, uniq = set(), []
    for f in findings:
        k = (f["type"], f["detail"][:160])
        if k in seen:
            continue
        seen.add(k)
        uniq.append(f)
    real = sorted({f["operator"] for f in uniq
                   if f["type"] == "client_prc_endpoint" and f.get("operator")})
    claimed = sorted(personas, key=lambda k: -personas[k])
    mismatch = None
    if real and claimed:
        # a Western brand asserted in the UI while a PRC endpoint sits in the source
        western = [c for c in claimed if not any(x in c.lower() for x in ("zhipu", "glm", "qwen", "deepseek"))]
        if western:
            mismatch = {"claimed": western[0], "actual_operator": real[0],
                        "detail": f"Client UI asserts '{western[0]}' while source references "
                                  f"{real[0]} inference infrastructure. Persona/backend mismatch."}
    return {"source": source, "files_scanned": files, "findings": uniq,
            "claimed_personas": personas, "prc_operators_in_source": real,
            "persona_mismatch": mismatch}
