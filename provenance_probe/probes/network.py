"""Layer 2: jurisdictional / egress analysis. Passive DNS + RDAP, no traffic sent to target."""
from __future__ import annotations
import socket, ipaddress, json
from urllib.parse import urlparse
from ..data.corpus import PRC_ENDPOINTS, AGGREGATOR_ENDPOINTS, FIRST_PARTY_ENDPOINTS

PRC_ASN_HINTS = ("alibaba", "aliyun", "tencent", "huawei", "baidu", "chinanet",
                 "china telecom", "china unicom", "china mobile", "cernet",
                 "bytedance", "volcengine", "cnnic")


def _rdap(ip: str, session=None) -> dict:
    try:
        import requests
        s = session or requests
        r = s.get(f"https://rdap.org/ip/{ip}", timeout=10)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return {}


def analyze_host(url: str, do_rdap: bool = True) -> dict:
    host = urlparse(url).hostname or url
    out = {"host": host, "addresses": [], "findings": [], "jurisdiction": "unknown",
           "operator": None, "confidence": 0.0}

    low = host.lower()
    for pat, (op, juris, conf) in PRC_ENDPOINTS.items():
        if pat in low:
            out.update(operator=op, jurisdiction=juris, confidence=conf)
            out["findings"].append(
                {"type": "prc_endpoint", "severity": "critical",
                 "detail": f"Hostname matches known PRC-operated inference endpoint: {op}"})
            break
    else:
        for pat, op in AGGREGATOR_ENDPOINTS.items():
            if pat in low:
                out.update(operator=op, jurisdiction="non-PRC-operator", confidence=0.8)
                out["findings"].append(
                    {"type": "aggregator", "severity": "info",
                     "detail": f"{op} is a multi-model aggregator. Jurisdiction likely non-PRC, "
                               f"but PRC-origin WEIGHTS may still be served. Provenance unresolved."})
                break
        else:
            for pat, (op, origin) in FIRST_PARTY_ENDPOINTS.items():
                if pat in low:
                    out.update(operator=op, jurisdiction="non-PRC-firstparty", confidence=0.85)
                    out["findings"].append(
                        {"type": "first_party", "severity": "info",
                         "detail": f"{op} is a first-party {origin} model developer serving its own "
                                   f"weights; jurisdiction non-PRC. Verify the served model with the "
                                   f"tokenizer/behavioral layers (a first-party can still reroute)."})
                    break

    if low.endswith(".cn") or ".cn." in low:
        out["findings"].append({"type": "cn_tld", "severity": "high",
                                "detail": "Hostname uses .cn TLD."})
        out["jurisdiction"] = "PRC"
        out["confidence"] = max(out["confidence"], 0.85)

    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
    except Exception as e:
        out["findings"].append({"type": "dns_fail", "severity": "info", "detail": str(e)})
        return out

    for ip in ips:
        rec = {"ip": ip, "ptr": None, "asn": None, "asn_name": None, "country": None}
        try:
            rec["ptr"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        if do_rdap:
            d = _rdap(ip)
            rec["country"] = d.get("country")
            rec["asn_name"] = d.get("name")
            for e in d.get("entities", []) or []:
                v = e.get("vcardArray")
                if v and len(v) > 1:
                    for f in v[1]:
                        if f and f[0] == "fn":
                            rec["asn_name"] = rec["asn_name"] or f[3]
        blob = " ".join(str(x) for x in rec.values() if x).lower()
        if rec.get("country") == "CN":
            out["findings"].append({"type": "prc_ip_geo", "severity": "critical",
                                    "detail": f"{ip} registered in CN ({rec.get('asn_name')})."})
            out["jurisdiction"] = "PRC"
            out["confidence"] = max(out["confidence"], 0.95)
        elif any(h in blob for h in PRC_ASN_HINTS):
            out["findings"].append({"type": "prc_asn_hint", "severity": "high",
                                    "detail": f"{ip} network registration references a PRC operator "
                                              f"({rec.get('asn_name') or rec.get('ptr')})."})
            out["confidence"] = max(out["confidence"], 0.75)
        out["addresses"].append(rec)
    return out


def scan_pcap_hosts(hosts: list[str]) -> list[dict]:
    """Feed SNI/DNS names harvested from an egress capture."""
    return [analyze_host(h) for h in hosts]
