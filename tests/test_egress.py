"""SSRF egress guard (#51). The guard is OFF unless PROVENANCE_PROBE_BLOCK_PRIVATE
is truthy; when on it refuses private/reserved/metadata targets, fails closed on
zero/failed DNS or any blocked answer, and pins the connection to the validated
IP (preserving Host + TLS SNI/cert) so a DNS-rebinding / split-horizon resolver
can't swap in a private IP between validate and connect.

The load-bearing property — pinning defeats rebinding — is proven by
``test_rebinding_split_horizon_pin_connects_only_to_validated_ip``.
"""
from __future__ import annotations

import socket

import pytest
import urllib3.util.connection as u3conn

from provenance_probe import egress
from provenance_probe.client import Client
from provenance_probe.config import Target


def _one(ip: str, port: int):
    """A single getaddrinfo answer tuple for an IPv4/IPv6 literal."""
    fam = socket.AF_INET6 if ":" in ip else socket.AF_INET
    return (fam, socket.SOCK_STREAM, 6, "", (ip, port))


# --------------------------------------------------------------------------- #
# Literal targets: private / reserved / metadata / IPv6 ranges blocked
# --------------------------------------------------------------------------- #

@pytest.mark.unit
@pytest.mark.parametrize("ip", ["127.0.0.1", "127.5.5.5"])
def test_literal_loopback_blocked(ip):
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target(ip, 443)
    assert ip in str(e.value) and "loopback" in str(e.value)


@pytest.mark.unit
@pytest.mark.parametrize("ip", ["10.0.0.1", "192.168.1.5", "172.16.9.9"])
def test_literal_rfc1918_blocked(ip):
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target(ip, 80)
    assert ip in str(e.value) and "private" in str(e.value)


@pytest.mark.unit
def test_metadata_ip_blocked():
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("169.254.169.254", 80)
    msg = str(e.value)
    assert "169.254.169.254" in msg and "metadata" in msg


@pytest.mark.unit
def test_ipv6_loopback_blocked():
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("::1", 443)
    assert "loopback" in str(e.value)


@pytest.mark.unit
def test_ipv6_ula_fc00_blocked():
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("fc00::1", 443)
    assert "private" in str(e.value)


@pytest.mark.unit
def test_ipv6_link_local_blocked():
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("fe80::1", 443)
    assert "link-local" in str(e.value)


@pytest.mark.unit
def test_unspecified_blocked():
    with pytest.raises(egress.BlockedAddressError):
        egress.validate_connect_target("0.0.0.0", 80)


@pytest.mark.unit
def test_cgnat_shared_address_blocked():
    # RFC 6598 100.64.0.0/10 — is_private is False in CPython, so this must be
    # caught explicitly (host-internal on real cloud/container platforms).
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("100.64.0.1", 443)
    assert "100.64.0.1" in str(e.value)


@pytest.mark.unit
@pytest.mark.parametrize("ip", ["198.18.0.1", "240.0.0.1", "192.0.0.170"])
def test_non_global_reserved_ranges_blocked(ip):
    with pytest.raises(egress.BlockedAddressError):
        egress.validate_connect_target(ip, 443)


# --------------------------------------------------------------------------- #
# Public targets allowed
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_public_literal_ip_allowed():
    assert egress.validate_connect_target("8.8.8.8", 443) == ["8.8.8.8"]


@pytest.mark.unit
def test_public_hostname_allowed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda h, p, *a, **k: [_one("93.184.216.34", p)])
    assert egress.validate_connect_target("example.com", 443) == ["93.184.216.34"]


# --------------------------------------------------------------------------- #
# Fail closed: any blocked answer, zero answers, DNS failure
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_all_answers_fail_closed_if_any_is_private(monkeypatch):
    # Split-horizon answer set: one public, one private -> the whole host is
    # refused (the private answer wins).
    monkeypatch.setattr(socket, "getaddrinfo",
                        lambda h, p, *a, **k: [_one("93.184.216.34", p),
                                              _one("10.1.2.3", p)])
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("split.example", 443)
    assert "10.1.2.3" in str(e.value)


@pytest.mark.unit
def test_zero_answers_fail_closed(monkeypatch):
    monkeypatch.setattr(socket, "getaddrinfo", lambda h, p, *a, **k: [])
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("empty.example", 443)
    assert "zero addresses" in str(e.value)


@pytest.mark.unit
def test_dns_failure_fails_closed(monkeypatch):
    def boom(h, p, *a, **k):
        raise socket.gaierror("Name or service not known")
    monkeypatch.setattr(socket, "getaddrinfo", boom)
    with pytest.raises(egress.BlockedAddressError) as e:
        egress.validate_connect_target("nxdomain.invalid", 443)
    assert "DNS resolution failed" in str(e.value)


# --------------------------------------------------------------------------- #
# AC-1: byte-identical when unset — the guard is NOT mounted
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_guard_not_mounted_when_env_unset(monkeypatch):
    monkeypatch.delenv("PROVENANCE_PROBE_BLOCK_PRIVATE", raising=False)
    c = Client(Target(name="t", base_url="https://api.example", model="m"))
    adapters = list(c.s.adapters.values())
    assert not any(isinstance(a, egress.GuardedAdapter) for a in adapters)
    # Stock requests mounts exactly the two default HTTPAdapters.
    assert set(c.s.adapters) == {"http://", "https://"}
    assert c.s.trust_env is True


@pytest.mark.unit
@pytest.mark.parametrize("flag", ["1", "true", "YES", "on"])
def test_guard_mounted_when_env_truthy(monkeypatch, flag):
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", flag)
    c = Client(Target(name="t", base_url="https://api.example", model="m"))
    assert all(isinstance(a, egress.GuardedAdapter) for a in c.s.adapters.values())
    assert c.s.trust_env is False


@pytest.mark.unit
@pytest.mark.parametrize("flag", ["0", "false", "off", "no", ""])
def test_guard_not_mounted_when_env_falsey(monkeypatch, flag):
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", flag)
    assert egress.guard_enabled() is False


# --------------------------------------------------------------------------- #
# DNS-rebinding / split-horizon: pinning proven
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_rebinding_split_horizon_pin_connects_only_to_validated_ip(monkeypatch):
    """Resolver returns PUBLIC at validate, PRIVATE on any later lookup. The pin
    must make the socket dial the validated PUBLIC IP and never the private one."""
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    PUBLIC, PRIVATE = "93.184.216.34", "10.0.0.7"
    calls = {"n": 0}
    real_gai = socket.getaddrinfo

    def fake_gai(host, port, *a, **k):
        if host == "rebind.test":
            calls["n"] += 1
            ip = PUBLIC if calls["n"] == 1 else PRIVATE   # rebind after validate
            return [_one(ip, port)]
        return real_gai(host, port, *a, **k)

    dialed = []

    def fake_create_connection(address, *a, **k):
        dialed.append(address)
        raise ConnectionRefusedError("sentinel: no real connect in test")

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    monkeypatch.setattr(u3conn, "create_connection", fake_create_connection)

    c = Client(Target(name="rb", base_url="https://rebind.test", model="m"))
    r = c.chat("ping", max_tokens=1)

    assert r.status == 0                       # sentinel connect error surfaced
    assert dialed, "the pin should have produced a connect attempt"
    assert all(addr[0] == PUBLIC for addr in dialed)   # pinned to validated IP
    assert all(addr[0] != PRIVATE for addr in dialed)  # never dialed the rebind


# --------------------------------------------------------------------------- #
# Proxy: a private proxy is refused (the proxy is the socket target)
# --------------------------------------------------------------------------- #

@pytest.mark.unit
def test_private_proxy_refused(monkeypatch):
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    dialed = []
    monkeypatch.setattr(u3conn, "create_connection",
                        lambda address, *a, **k: dialed.append(address))
    c = Client(Target(name="p", base_url="https://api.example", model="m",
                      proxy="http://127.0.0.1:8080"))
    r = c.chat("ping", max_tokens=1)
    assert r.status == 0
    assert "127.0.0.1" in (r.err or "")
    assert dialed == []                        # no socket opened to the proxy


@pytest.mark.unit
def test_proxy_rebinding_pin_connects_only_to_validated_ip(monkeypatch):
    """The proxy leg is pinned too: a proxy host that resolves public at validate
    then private on a later lookup must still be dialed at the validated IP."""
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    PUBLIC, PRIVATE = "93.184.216.34", "10.0.0.7"
    calls = {"n": 0}
    real_gai = socket.getaddrinfo

    def fake_gai(host, port, *a, **k):
        if host == "proxy.rebind":
            calls["n"] += 1
            return [_one(PUBLIC if calls["n"] == 1 else PRIVATE, port)]
        return real_gai(host, port, *a, **k)

    dialed = []

    def fake_create_connection(address, *a, **k):
        dialed.append(address)
        raise ConnectionRefusedError("sentinel")

    monkeypatch.setattr(socket, "getaddrinfo", fake_gai)
    monkeypatch.setattr(u3conn, "create_connection", fake_create_connection)

    c = Client(Target(name="p", base_url="https://api.example", model="m",
                      proxy="http://proxy.rebind:8080"))
    r = c.chat("ping", max_tokens=1)
    assert r.status == 0
    assert dialed, "expected a connect attempt to the pinned proxy IP"
    assert all(addr[0] == PUBLIC for addr in dialed)
    assert all(addr[0] != PRIVATE for addr in dialed)


# --------------------------------------------------------------------------- #
# Integration: guarded Client refuses a private target across all surfaces,
# and a redirect to an internal host is re-validated.
# --------------------------------------------------------------------------- #

@pytest.mark.integration
def test_guarded_client_refuses_private_target_across_surfaces(monkeypatch):
    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    dialed = []
    monkeypatch.setattr(u3conn, "create_connection",
                        lambda address, *a, **k: dialed.append(address))
    c = Client(Target(name="int", base_url="http://127.0.0.1:9", model="m",
                      chat_path="/v1/chat/completions", models_path="/v1/models"))
    results = [c.chat("x", max_tokens=1),
               c.raw_post("/v1/chat/completions", {"a": 1}),
               c.list_models()]
    for r in results:
        assert r.status == 0
        assert "127.0.0.1" in (r.err or ""), r.err
    assert dialed == []            # no socket ever opened to the private IP


@pytest.mark.integration
def test_redirect_to_internal_host_revalidated(monkeypatch):
    """A 3xx to an internal host must be re-validated on the next hop. Because the
    guarded session is reused, resolve_redirects re-enters the guard's send()."""
    import requests

    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    s = requests.Session()
    egress.install_guard(s)

    first = requests.Request("GET", "https://public.example/redir").prepare()
    resp = requests.models.Response()
    resp.status_code = 302
    resp.headers["Location"] = "http://169.254.169.254/latest/meta-data/"
    resp.request = first
    resp.url = first.url
    resp._content = b""
    resp._content_consumed = True

    class _Raw:
        def release_conn(self): pass
        def read(self, *a, **k): return b""
        def close(self): pass
    resp.raw = _Raw()

    gen = s.resolve_redirects(resp, first)
    with pytest.raises(egress.BlockedAddressError) as e:
        next(gen)
    assert "169.254.169.254" in str(e.value)


@pytest.mark.integration
def test_clientsrc_scan_url_is_guarded(monkeypatch):
    """The client-source scan fetches a user-supplied URL (+ its <script src>
    children). With the flag set it must refuse an internal target and open no
    socket to it (regression for the CRITICAL unguarded-session bypass)."""
    from provenance_probe.probes import clientsrc

    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    dialed = []
    monkeypatch.setattr(u3conn, "create_connection",
                        lambda address, *a, **k: dialed.append(address))
    out = clientsrc.scan_url("http://169.254.169.254/latest/meta-data/")
    assert "169.254.169.254" in (out.get("error") or "")
    assert dialed == []


@pytest.mark.integration
def test_detect_default_probe_is_guarded(monkeypatch):
    """/wizard/detect reaches detect._default_probe with a user URL; it must be
    guarded in public-hosting mode (regression for the wizard-detect SSRF path)."""
    from provenance_probe import detect

    monkeypatch.setenv("PROVENANCE_PROBE_BLOCK_PRIVATE", "1")
    dialed = []
    monkeypatch.setattr(u3conn, "create_connection",
                        lambda address, *a, **k: dialed.append(address))
    pr = detect._default_probe("GET", "http://169.254.169.254/latest/", {}, None)
    assert pr.status == 0 and pr.error       # refused, friendly transport error
    assert dialed == []                      # no socket opened to metadata IP
