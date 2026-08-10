"""Gateway-config resolution: see THROUGH a localhost gateway to its upstream.

The localhost blind spot (outside-voice T1): a gateway like OmniRoute presents as
`base_url=http://localhost:20128/v1`, so a base_url-only scan would report
"localhost, unattributed" and miss the real (often PRC) upstream. When a base_url
points at a known local gateway, we parse the gateway's OWN config and extract the
upstream URLs it routes to, then attribute THOSE.

Config parsing is a heuristic key-scan (api_base / base_url / url / endpoint /
target) over the already-parsed config object, so it works across OmniRoute,
LiteLLM, and hand-rolled proxies without hard-coding one vendor's schema. If no
config is found or no upstream is extractable, the endpoint is honestly marked
GATEWAY_UPSTREAM_UNRESOLVED — never silently treated as clean.

NO NETWORK: this module reads a config object handed to it by the caller; it never
opens a socket. The caller (scan.py) injects a file reader.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

from ..presets import _hostname
from ..gateways import KNOWN_LOCAL_GATEWAYS

_LOOPBACK_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}  # noqa: S104 (recognition, not a bind)
_UPSTREAM_KEYS = {"api_base", "base_url", "base", "url", "endpoint", "target", "api_url"}


@dataclass(frozen=True)
class GatewayResolution:
    gateway: str                                   # gateway name, or "" if not a local gateway
    is_local_gateway: bool = False
    upstream_hosts: list[str] = field(default_factory=list)
    resolved: bool = False                         # True iff at least one upstream host was extracted


def _port(base_url: str) -> int | None:
    try:
        return urlsplit(base_url if "://" in base_url else "http://" + base_url).port
    except ValueError:
        return None


def local_gateway_name(base_url: str) -> str | None:
    """Return the known-gateway name if base_url points at a local gateway, else None."""
    host = _hostname(base_url)
    if host not in _LOOPBACK_HOSTS:
        return None
    port = _port(base_url)
    for name, (_gw_host, gw_port) in KNOWN_LOCAL_GATEWAYS.items():
        if port == gw_port:
            return name
    # loopback but an unknown port — still a local gateway of unknown type
    return "unknown-local-gateway"


def extract_upstream_hosts(config: object) -> list[str]:
    """Recursively scan a parsed config object for upstream URLs and return their
    hostnames, excluding loopback (the gateway pointing at itself). De-duplicated,
    order-preserving.
    """
    found: list[str] = []
    seen: set[str] = set()

    def walk(node: object) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if isinstance(v, str) and str(k).lower() in _UPSTREAM_KEYS:
                    host = _hostname(v)
                    if host and host not in _LOOPBACK_HOSTS and host not in seen:
                        seen.add(host)
                        found.append(host)
                else:
                    walk(v)
        elif isinstance(node, (list, tuple)):
            for item in node:
                walk(item)

    walk(config)
    return found


def resolve_gateway(base_url: str, config: object | None) -> GatewayResolution:
    """Resolve a base_url through a local gateway's config, if applicable.

    `config` is the gateway's already-parsed config object (dict/list) or None if
    no config was found. Returns a GatewayResolution; `resolved` is False when the
    endpoint is a local gateway but no upstream could be extracted (→ caller marks
    GATEWAY_UPSTREAM_UNRESOLVED).
    """
    name = local_gateway_name(base_url)
    if name is None:
        return GatewayResolution(gateway="", is_local_gateway=False)
    if config is None:
        return GatewayResolution(gateway=name, is_local_gateway=True, resolved=False)
    upstreams = extract_upstream_hosts(config)
    return GatewayResolution(gateway=name, is_local_gateway=True,
                             upstream_hosts=upstreams, resolved=bool(upstreams))
