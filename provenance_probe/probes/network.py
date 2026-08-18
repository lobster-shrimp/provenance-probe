"""Layer 2: jurisdictional / egress analysis. Passive DNS + RDAP, no traffic sent to target."""
from __future__ import annotations
import ipaddress
import socket
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


def _blocked_ip(ip: str) -> bool:
    """True for private / loopback / link-local / reserved / multicast addresses —
    the SSRF denylist. Non-IP strings return False (they are hostnames)."""
    try:
        a = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return (a.is_private or a.is_loopback or a.is_link_local
            or a.is_reserved or a.is_multicast or a.is_unspecified)


def analyze_host(url: str, do_rdap: bool = True, resolve: bool = True) -> dict:
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

    # SSRF guard: static hostname signals above need no network. DNS + RDAP only
    # run when the caller opts in (resolve=True) — untrusted inputs (e.g. an agent
    # trace) default to resolve=False so a hostile host can't drive lookups.
    if not resolve:
        return out
    if _blocked_ip(host):
        out["findings"].append({"type": "blocked_host", "severity": "info",
                                "detail": f"{host} is a private/reserved address; "
                                          f"resolution skipped (SSRF guard)."})
        return out

    try:
        infos = socket.getaddrinfo(host, 443, proto=socket.IPPROTO_TCP)
        ips = sorted({i[4][0] for i in infos})
    except Exception as e:
        out["findings"].append({"type": "dns_fail", "severity": "info", "detail": str(e)})
        return out

    for ip in ips:
        if _blocked_ip(ip):
            # hostname resolved to an internal address (DNS-rebinding); do not
            # PTR/RDAP it and do not treat it as jurisdiction evidence.
            out["findings"].append({"type": "blocked_host", "severity": "info",
                                    "detail": f"{host} resolved to private/reserved {ip}; skipped."})
            continue
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


def attribute_ip(ip: str, *, session=None, do_rdap: bool = True) -> dict:
    """RDAP/PTR a SINGLE egress IP into a jurisdiction pointer.

    Unlike `analyze_host` (which starts from a URL and does its own DNS), this takes
    an IP already observed on the wire — e.g. a remote address from the no-egress
    connection table — and resolves *who it is registered to*. It is the "authorized
    network path" the fleet connection collector defers IP→operator attribution to.

    SSRF-guarded: a private/loopback/reserved IP is never looked up (returns a record
    with `skipped=True`). Never raises — a failed lookup yields an `unknown` record so
    one bad IP can't sink a batch. The result is a SUB-CONFIRMED pointer, never a
    measured verdict (guardrail 2): registration != which model served.
    """
    rec = {"ip": ip, "ptr": None, "asn_name": None, "country": None,
           "jurisdiction": "unknown", "confidence": 0.0, "prc_hint": False,
           "skipped": False}
    if _blocked_ip(ip):
        rec["skipped"] = True
        return rec
    if do_rdap:
        # Reverse-DNS + RDAP are BOTH network calls, so both live under do_rdap —
        # `do_rdap=False` is then honestly a no-egress mode.
        try:
            rec["ptr"] = socket.gethostbyaddr(ip)[0]
        except Exception:
            pass
        # RDAP is untrusted external data at a system boundary: a well-formed 200 may
        # still carry a wrong-shaped body (a JSON list, non-dict entities, a short
        # vCard). Every access is type-guarded so a hostile response degrades this IP
        # to `unknown` — honouring the never-raises contract (one bad IP can't sink a
        # batch), never an AttributeError/IndexError.
        d = _rdap(ip, session)
        if isinstance(d, dict):
            rec["country"] = d.get("country")
            rec["asn_name"] = d.get("name")
            ents = d.get("entities")
            for e in (ents if isinstance(ents, list) else []):
                if not isinstance(e, dict):
                    continue
                v = e.get("vcardArray")
                if isinstance(v, list) and len(v) > 1 and isinstance(v[1], list):
                    for f in v[1]:
                        if isinstance(f, list) and len(f) >= 4 and f[0] == "fn":
                            rec["asn_name"] = rec["asn_name"] or f[3]
    blob = " ".join(str(x) for x in (rec["ptr"], rec["asn_name"], rec["country"]) if x).lower()
    if rec.get("country") == "CN":
        rec.update(jurisdiction="PRC", confidence=0.95)
    elif any(h in blob for h in PRC_ASN_HINTS):
        rec.update(jurisdiction="PRC-operator", confidence=0.75, prc_hint=True)
    return rec


def scan_pcap_hosts(hosts: list[str]) -> list[dict]:
    """Feed SNI/DNS names harvested from an egress capture."""
    return [analyze_host(h) for h in hosts]
