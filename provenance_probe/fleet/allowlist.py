"""Operator-supplied allowlist: which hosts are sanctioned egress targets.

Matching reuses the same exact-or-subdomain hostname semantics as
`presets.match_host` — a security boundary, NOT substring matching, so
`api.openai.com.evil.test` never matches `api.openai.com` (guardrail 5 zero-FP
case). Localhost is sanctioned only if the operator lists a localhost entry.
"""
from __future__ import annotations

from ..presets import _hostname


def load_allowlist(text: str) -> list[str]:
    """Parse an allowlist file body into a list of lowercased hostnames.

    Format is deliberately simple: one host per line, `#` comments and blank
    lines ignored. A line may be a bare host (`api.openai.com`) or a URL
    (`https://api.openai.com/v1`) — either way we keep the hostname.
    """
    hosts: list[str] = []
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip()
        if not line:
            continue
        # Always parse through _hostname so a bare `host:port` (e.g. a sanctioned
        # localhost gateway) drops its port and still matches (provenance-reviewer LOW).
        host = _hostname(line)
        if host:
            hosts.append(host)
    return hosts


def is_sanctioned(host: str, allowlist: list[str]) -> bool:
    """Exact-or-subdomain match. `host` matches `h` iff host == h or host ends
    with '.' + h. Never substring (the DNS-rebinding / suffix-attack boundary)."""
    h = (host or "").strip().lower().rstrip(".")
    if not h:
        return False
    for entry in allowlist:
        e = entry.strip().lower().rstrip(".")
        if not e:
            continue
        if h == e or h.endswith("." + e):
            return True
    return False
