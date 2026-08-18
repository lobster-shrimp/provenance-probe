"""Tier-2 egress attribution: RDAP/PTR of observed upstream IPs + corpus join.

The orchestration (`attribute_egress`) is tested with an INJECTED resolver so no
real network call happens; `network.attribute_ip` is tested with a fake RDAP
session + monkeypatched PTR so it too stays offline.
"""
from __future__ import annotations

import pytest

from provenance_probe.fleet.connections import Conn
from provenance_probe.fleet.egress_attr import (
    EgressAttribution,
    attribute_egress,
)
from provenance_probe.probes import network

pytestmark = pytest.mark.unit


# --- fakes ------------------------------------------------------------------ #

class _Resp:
    def __init__(self, payload, status=200):
        self.status_code, self._p = status, payload

    def json(self):
        return self._p


class _Session:
    def __init__(self, payload):
        self._p = payload

    def get(self, url, timeout=None):
        return _Resp(self._p)


def _est(cmd, pid, raddr, rport=443):
    return Conn(cmd, pid, "192.168.1.9", 54000, raddr, rport, "ESTABLISHED")


# --- network.attribute_ip --------------------------------------------------- #

def test_attribute_ip_ssrf_skips_private(monkeypatch):
    # A private/reserved IP must never be looked up (SSRF guard) → skipped record.
    called = []
    monkeypatch.setattr(network.socket, "gethostbyaddr", lambda ip: called.append(ip))
    rec = network.attribute_ip("10.0.0.5")
    assert rec["skipped"] is True
    assert rec["jurisdiction"] == "unknown"
    assert called == []  # no PTR, no RDAP


def test_attribute_ip_cn_country_is_prc(monkeypatch):
    monkeypatch.setattr(network.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError))
    rec = network.attribute_ip("1.2.3.4", session=_Session({"country": "CN", "name": "Aliyun"}))
    assert rec["jurisdiction"] == "PRC"
    assert rec["confidence"] == 0.95
    assert rec["prc_hint"] is False


def test_attribute_ip_prc_asn_hint(monkeypatch):
    # US-registered geo but a PRC operator name in the ASN → PRC-operator pointer.
    monkeypatch.setattr(network.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError))
    rec = network.attribute_ip("1.2.3.5", session=_Session({"country": "US", "name": "Tencent Cloud"}))
    assert rec["jurisdiction"] == "PRC-operator"
    assert rec["prc_hint"] is True
    assert rec["confidence"] == 0.75


def test_attribute_ip_unknown_stays_unknown(monkeypatch):
    monkeypatch.setattr(network.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError))
    rec = network.attribute_ip("8.8.8.8", session=_Session({"country": "US", "name": "GOOGLE"}))
    assert rec["jurisdiction"] == "unknown"
    assert rec["country"] == "US"


def test_attribute_ip_never_raises_on_bad_rdap(monkeypatch):
    # 8.8.4.4 is a GLOBAL address (not caught by the SSRF skip), so the RDAP path is
    # actually exercised. gethostbyaddr is faked so no real reverse-DNS happens.
    monkeypatch.setattr(network.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError))
    assert network._blocked_ip("8.8.4.4") is False  # guard: really reaches RDAP

    class _Boom:
        def get(self, *a, **k):
            raise RuntimeError("network down")

    rec = network.attribute_ip("8.8.4.4", session=_Boom())
    assert rec["jurisdiction"] == "unknown"  # transport error → degrade, not throw


@pytest.mark.parametrize("body", [
    ["not", "a", "dict"],                                    # 200 body is a JSON list
    {"country": "US", "entities": "wat"},                    # entities not a list
    {"country": "US", "entities": [{"vcardArray": ["vcard", [["fn", {}, "text"]]]}]},  # short fn
    {"country": "US", "entities": [None, 42, {"vcardArray": None}]},  # junk entities
    "a bare string",                                          # 200 body is a JSON string
])
def test_attribute_ip_survives_malformed_rdap_200(monkeypatch, body):
    # A well-formed HTTP 200 whose JSON body is the WRONG shape must degrade the IP,
    # never raise (the never-raises contract; one bad IP can't sink a --rdap batch).
    monkeypatch.setattr(network.socket, "gethostbyaddr", lambda ip: (_ for _ in ()).throw(OSError))
    rec = network.attribute_ip("8.8.4.4", session=_Session(body))
    assert rec["skipped"] is False
    assert rec["jurisdiction"] in ("unknown", "PRC", "PRC-operator")  # no exception


def test_attribute_egress_survives_resolver_crash():
    # A resolver that throws degrades that IP to a visible 'unknown', batch survives.
    conns = [_est("codex", "1", "1.2.3.4")]

    def boom(ip, *, session=None, do_rdap=True):
        raise RuntimeError("resolver exploded")
    res = attribute_egress(conns, resolver=boom)
    assert len(res.attributions) == 1
    assert res.attributions[0].jurisdiction == "unknown"
    assert res.attributions[0].ip == "1.2.3.4"


# --- attribute_egress orchestration ----------------------------------------- #

def _fake_resolver(recs):
    def resolver(ip, *, session=None, do_rdap=True):
        return recs[ip]
    return resolver


def test_distinct_upstreams_excludes_loopback_and_dedupes():
    conns = [
        _est("codex", "1", "1.2.3.4"),
        _est("codex", "1", "1.2.3.4"),        # dup ip+proc
        _est("node", "2", "1.2.3.4"),         # same ip, other proc
        _est("cli", "3", "127.0.0.1", 20128),  # loopback remote → excluded
        Conn("router", "4", "*", 4000, "", None, "LISTEN"),  # LISTEN → no remote
    ]
    recs = {"1.2.3.4": {"ip": "1.2.3.4", "ptr": None, "country": None, "asn_name": None,
                        "jurisdiction": "unknown", "confidence": 0.0, "prc_hint": False,
                        "skipped": False}}
    res = attribute_egress(conns, resolver=_fake_resolver(recs))
    assert res.ips_total == 1
    assert res.ips_resolved == 1
    assert res.attributions[0].processes == ["codex/1", "node/2"]


def test_corpus_ptr_join_flags_prc_operator():
    conns = [_est("codex", "1", "1.2.3.4")]
    recs = {"1.2.3.4": {"ip": "1.2.3.4", "ptr": "api.deepseek.com", "country": "CN",
                        "asn_name": "Aliyun", "jurisdiction": "PRC", "confidence": 0.95,
                        "prc_hint": False, "skipped": False}}
    res = attribute_egress(conns, resolver=_fake_resolver(recs))
    a = res.attributions[0]
    assert a.operator  # corpus resolved DeepSeek
    assert (a.origin or "").upper().startswith("PRC")
    assert a.corpus_source == "corpus:api.deepseek.com"
    assert a.flagged is True
    assert res.flagged == 1


def test_skipped_private_upstream_is_dropped():
    conns = [_est("app", "1", "10.9.9.9")]  # a LAN upstream that resolves as private
    recs = {"10.9.9.9": {"ip": "10.9.9.9", "ptr": None, "country": None, "asn_name": None,
                         "jurisdiction": "unknown", "confidence": 0.0, "prc_hint": False,
                         "skipped": True}}
    res = attribute_egress(conns, resolver=_fake_resolver(recs))
    assert res.ips_total == 1
    assert res.attributions == []  # skipped → not attributed


def test_cap_surfaces_dropped_count():
    conns = [_est("x", str(i), f"1.2.3.{i}") for i in range(5)]
    recs = {f"1.2.3.{i}": {"ip": f"1.2.3.{i}", "ptr": None, "country": None, "asn_name": None,
                           "jurisdiction": "unknown", "confidence": 0.0, "prc_hint": False,
                           "skipped": False} for i in range(5)}
    res = attribute_egress(conns, resolver=_fake_resolver(recs), max_ips=2)
    assert res.ips_total == 5
    assert res.ips_resolved == 2
    assert res.dropped == 3
    assert "not looked up" in res.headline


def test_attribution_is_never_measured():
    a = EgressAttribution(ip="1.2.3.4", ptr=None, country=None, asn_name=None,
                          jurisdiction="unknown", operator=None, origin=None,
                          confidence=0.0, prc_hint=False, corpus_source=None)
    assert a.measured is False
