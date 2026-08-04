# -*- coding: utf-8 -*-
"""SSRF egress guard for the shared probe HTTP session.

This is OFF by default. It is mounted on ``Client``'s ``requests.Session`` only
when the environment variable ``PROVENANCE_PROBE_BLOCK_PRIVATE`` is truthy — the
public-hosting mode (see ``deploy/hf-space/``). With the guard unmounted the
transport is byte-identical to stock ``requests``.

The whole point of a *public* deploy of a tool whose job is "make an outbound
request to a user-named endpoint" is that it must never be turned into an open
proxy into the host's own network / cloud-metadata service. The guard:

* resolves the host the socket will actually connect to and refuses if ANY
  resolved address is loopback / private (RFC1918 + ULA ``fc00::/7``) /
  link-local / reserved / multicast / unspecified, or the cloud-metadata IP
  ``169.254.169.254``. It fails CLOSED on zero answers or a DNS failure.
* closes the DNS-rebinding / split-horizon TOCTOU window by *pinning* the
  connection to the exact validated IP while preserving the original ``Host``
  header and TLS SNI + certificate hostname — TLS verification is never
  weakened.
* validates the PROXY host instead when the session routes through a proxy
  (that is the address the socket opens), and refuses a private proxy. The proxy
  connection is pinned by rewriting the proxy URL host to the validated IP with
  no SNI override for the proxy leg, so an ``https://`` proxy fails closed with a
  cert-hostname mismatch under this mode — only "run without a proxy" is
  supported in public-hosting mode (see ``deploy/hf-space/``).

Because ``chat`` / its temperature retry / ``raw_post`` / ``list_models`` and
redirect following all reuse the one guarded session, every hop — including a
3xx to an internal host — is re-validated.
"""
from __future__ import annotations

import ipaddress
import os
import socket
from urllib.parse import urlparse

import requests
from requests.adapters import HTTPAdapter
from requests.exceptions import ConnectionError as RequestsConnectionError
from requests.utils import prepend_scheme_if_needed, select_proxy

_ENV_FLAG = "PROVENANCE_PROBE_BLOCK_PRIVATE"
_METADATA_IP = ipaddress.ip_address("169.254.169.254")
_CGNAT = ipaddress.ip_network("100.64.0.0/10")   # RFC 6598 shared address space
# Values that mean "off" even though the variable is set.
_FALSEY = {"", "0", "false", "no", "off"}


class BlockedAddressError(RequestsConnectionError):
    """A connect target was refused by the egress guard.

    Subclasses ``requests.exceptions.ConnectionError`` so it surfaces through the
    client's existing ``except Exception`` path as the normal transport-failure
    shape ``Response(status=0, err=...)`` with ``err`` naming the blocked
    IP / range.
    """


def guard_enabled() -> bool:
    """True when the env flag selects public-hosting mode."""
    val = os.environ.get(_ENV_FLAG)
    if val is None:
        return False
    return val.strip().lower() not in _FALSEY


def _blocked_reason(ip_str: str) -> str | None:
    """Return a human reason if ``ip_str`` is a non-routable / dangerous target,
    else ``None``. Not-an-IP returns a reason (fail closed — we only ever call
    this on things we intend to connect to)."""
    try:
        addr = ipaddress.ip_address(ip_str)
    except ValueError:
        return f"{ip_str!r} is not an IP address"
    # Keep the explicit cloud-metadata check even though is_link_local covers it
    # (clarity + an unambiguous test + defense against future classifier drift).
    if addr == _METADATA_IP:
        return "cloud-metadata address 169.254.169.254"
    if addr.is_loopback:
        return f"loopback address {addr}"
    if addr.is_link_local:
        return f"link-local address {addr}"
    if addr.is_private:                      # RFC1918 + ULA fc00::/7
        return f"private address {addr}"
    if addr.is_reserved:
        return f"reserved address {addr}"
    if addr.is_multicast:
        return f"multicast address {addr}"
    if addr.is_unspecified:
        return f"unspecified address {addr}"
    # RFC 6598 Carrier-Grade-NAT / Shared Address Space (100.64.0.0/10) is NOT
    # covered by is_private in CPython, yet it is host-internal on real cloud /
    # container platforms — name it explicitly.
    if isinstance(addr, ipaddress.IPv4Address) and addr in _CGNAT:
        return f"shared/CGNAT address {addr}"
    # Final catch-all: anything the stdlib does not consider globally routable
    # (benchmarking 198.18/15, IETF protocol 192.0.0/24, future-use 240/4, …).
    # Public addresses are is_global True, so this never blocks a real endpoint.
    if not addr.is_global:
        return f"non-global address {addr}"
    return None


def _strip_zone(ip_str: str) -> str:
    """Drop an IPv6 scope/zone id, e.g. ``fe80::1%eth0`` -> ``fe80::1``."""
    return ip_str.split("%", 1)[0]


def validate_connect_target(host: str, port: int) -> list[str]:
    """Resolve ``host`` and return the list of validated IPs to pin to.

    Raises :class:`BlockedAddressError` (fail closed) if ``host`` is empty, is a
    blocked literal, resolves to zero addresses, resolution fails, or ANY
    resolved answer is blocked (defeats split-horizon answers).
    """
    if not host:
        raise BlockedAddressError("egress guard: empty connect host")

    # Literal IP target -> validate directly, no DNS.
    try:
        ipaddress.ip_address(_strip_zone(host))
    except ValueError:
        is_literal = False
    else:
        is_literal = True
    if is_literal:
        ip = _strip_zone(host)
        reason = _blocked_reason(ip)
        if reason:
            raise BlockedAddressError(f"egress guard: refused connection to {reason}")
        return [ip]

    # Hostname -> enumerate EVERY A/AAAA answer.
    try:
        infos = socket.getaddrinfo(host, port, proto=socket.IPPROTO_TCP)
    except (socket.gaierror, OSError, UnicodeError) as exc:
        # Fail closed on any resolution error (bad IDNA -> UnicodeError,
        # timeouts -> OSError), keeping the clean guard-framed message.
        raise BlockedAddressError(
            f"egress guard: DNS resolution failed for {host!r}: {exc}") from exc

    addrs: list[str] = []
    for info in infos:
        ip = _strip_zone(info[4][0])
        if ip not in addrs:
            addrs.append(ip)
    if not addrs:                            # fail closed on zero answers
        raise BlockedAddressError(
            f"egress guard: {host!r} resolved to zero addresses")

    for ip in addrs:                         # ANY blocked answer blocks the host
        reason = _blocked_reason(ip)
        if reason:
            raise BlockedAddressError(
                f"egress guard: {host!r} resolves to {reason}")
    return addrs


def _authority(host: str, port: int, scheme: str) -> str:
    """Build the ``Host`` header value for the original host, bracketing IPv6."""
    default = 443 if scheme == "https" else 80
    h = f"[{host}]" if ":" in host and not host.startswith("[") else host
    return h if port == default else f"{h}:{port}"


def _replace_host(parsed, ip: str) -> str:
    """Rebuild a URL string from a parsed URL with its host replaced by ``ip``,
    preserving scheme, userinfo, and port (used to pin the proxy connection)."""
    userinfo = ""
    if parsed.username:
        userinfo = parsed.username
        if parsed.password is not None:
            userinfo += f":{parsed.password}"
        userinfo += "@"
    hostpart = f"[{ip}]" if ":" in ip else ip
    if parsed.port:
        hostpart += f":{parsed.port}"
    return parsed._replace(netloc=userinfo + hostpart).geturl()


class GuardedAdapter(HTTPAdapter):
    """A ``requests`` transport adapter that validates + pins the connect target.

    Validation and pinning happen in :meth:`send`, which raises before any socket
    is opened when the target is blocked. Pinning is applied in
    :meth:`get_connection_with_tls_context` (and the legacy
    :meth:`get_connection`) by pointing the urllib3 pool at the validated IP while
    keeping SNI + cert hostname = the original name. The pin is threadlocal, so a
    session shared across Flask worker threads never crosses pins.
    """

    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        import threading
        self._local = threading.local()

    # -- orchestration ------------------------------------------------------ #
    def send(self, request, stream=False, timeout=None, verify=True,
             cert=None, proxies=None):
        proxies = proxies or {}
        proxy = select_proxy(request.url, proxies)
        if proxy:
            # The socket opens to the PROXY; validate that instead. We do not pin
            # the target through a proxy (the proxy performs the egress), but we
            # DO pin the proxy connection itself to its validated IP by rewriting
            # the proxy URL — otherwise urllib3 would re-resolve the proxy host at
            # connect time, reopening the rebinding window on the proxy leg.
            # Hosted mode runs without a proxy — see the deploy runbook.
            pinned_proxy = self._pin_proxy(proxy)      # raises on block
            new_proxies = {k: (pinned_proxy if v == proxy else v)
                           for k, v in proxies.items()}
            self._local.pin = None
            return super().send(request, stream=stream, timeout=timeout,
                                verify=verify, cert=cert, proxies=new_proxies)

        parsed = urlparse(request.url)
        host = parsed.hostname or ""
        scheme = (parsed.scheme or "").lower()
        port = parsed.port or (443 if scheme == "https" else 80)
        ips = validate_connect_target(host, port)      # raises on block
        # Pin to the first validated IP and keep vhost routing + SNI intact.
        self._local.pin = (host, ips[0], scheme)
        request.headers["Host"] = _authority(host, port, scheme)
        try:
            return super().send(request, stream=stream, timeout=timeout,
                                verify=verify, cert=cert, proxies=proxies)
        finally:
            self._local.pin = None

    def _pin_proxy(self, proxy: str) -> str:
        """Validate the proxy host and return the proxy URL with its host rewritten
        to the validated IP, pinning the proxy socket against rebinding."""
        p = urlparse(prepend_scheme_if_needed(proxy, "http"))
        host = p.hostname or ""
        port = p.port or (443 if (p.scheme or "").lower() == "https" else 80)
        ips = validate_connect_target(host, port)      # raises on block
        return _replace_host(p, ips[0])

    # -- pinning ------------------------------------------------------------ #
    def _pin_host_params(self, host_params: dict, pool_kwargs: dict) -> None:
        """Rewrite the pool host to the validated IP and preserve TLS identity."""
        pin = getattr(self._local, "pin", None)
        if not pin:
            return
        orig_host, ip, scheme = pin
        host_params["host"] = ip
        if scheme == "https":
            # Validate the cert against the ORIGINAL hostname; send SNI for it.
            # Never weakens verification — server_hostname/assert_hostname stay
            # the real name while the socket connects to the pinned IP.
            # (These are top-level urllib3 pool kwargs: server_hostname flows
            # through HTTPSConnectionPool's **conn_kw to the connection's SNI.)
            pool_kwargs["assert_hostname"] = orig_host
            pool_kwargs["server_hostname"] = orig_host

    def get_connection_with_tls_context(self, request, verify, proxies=None,
                                        cert=None):
        pin = getattr(self._local, "pin", None)
        if not pin or select_proxy(request.url, proxies):
            return super().get_connection_with_tls_context(
                request, verify, proxies=proxies, cert=cert)
        host_params, pool_kwargs = self.build_connection_pool_key_attributes(
            request, verify, cert)
        self._pin_host_params(host_params, pool_kwargs)
        return self.poolmanager.connection_from_host(
            **host_params, pool_kwargs=pool_kwargs)

    def get_connection(self, url, proxies=None):        # pragma: no cover
        # Legacy path for requests < 2.32.2. Pin by building the pool against the
        # validated IP with SNI + cert hostname preserved.
        pin = getattr(self._local, "pin", None)
        if not pin or select_proxy(url, proxies):
            return super().get_connection(url, proxies=proxies)
        orig_host, ip, scheme = pin
        parsed = urlparse(url)
        port = parsed.port or (443 if scheme == "https" else 80)
        pool_kwargs: dict = {}
        host_params = {"scheme": scheme, "host": ip, "port": port}
        self._pin_host_params(host_params, pool_kwargs)
        return self.poolmanager.connection_from_host(
            **host_params, pool_kwargs=pool_kwargs)


def install_guard(session: requests.Session) -> None:
    """Mount the egress guard on ``session`` for public-hosting mode.

    Also disables ``trust_env`` so an ambient ``HTTP(S)_PROXY`` / ``.netrc`` on
    the host can't silently reroute the probe session; explicit
    ``session.proxies`` (a user-configured inspecting proxy) is still honored and
    its host is validated.
    """
    adapter = GuardedAdapter()
    session.mount("http://", adapter)
    session.mount("https://", adapter)
    session.trust_env = False
