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


# A STARTER egress allowlist an operator forks into their own policy (T7). This is
# the "prevention posture" input, not a second competing allowlist and not the
# corpus registry: it names the hosts the org SANCTIONS, and fleet-scan reports
# everything else as drift. Emitted by `fleet-scan --print allowlist-template`.
# The first-party hosts are a curated SUBSET of corpus.py's FIRST_PARTY_ENDPOINTS
# (the common ones) — a starting point to trim/extend, not the full set.
TEMPLATE = """\
# provenance-probe fleet-scan — reference egress allowlist (STARTER — fork this).
#
# List the AI inference hosts your org SANCTIONS. fleet-scan reports any agent-CLI
# base_url NOT on this list as drift. Matching is exact-or-subdomain on the
# hostname: a subdomain of a listed host is allowed; a suffix attack like
# api.openai.com.evil.test is NOT. One host per line; '#' starts a comment; a URL
# is accepted (its hostname is used). This is a starting point, not policy —
# delete what you don't sanction and add your own. See docs/fleet-posture.md.

# --- US / EU first-party providers (trim to match your policy) ---
api.openai.com
api.anthropic.com
generativelanguage.googleapis.com
api.mistral.ai
api.cohere.com
api.x.ai

# --- your cloud tenants (uncomment and set your tenant/region) ---
# <tenant>.openai.azure.com
# bedrock-runtime.<region>.amazonaws.com
# <region>-aiplatform.googleapis.com

# --- your ONE sanctioned gateway, if you run one (the prevention posture) ---
# Prefer a LOCALHOST gateway: fleet-scan resolves a loopback gateway's real
# upstream from its config, so a localhost gateway pointed at a PRC backend is
# still caught. A NON-loopback gateway host (below) is matched directly and its
# upstream is NOT resolved — sanctioning it hides whatever it routes to. See
# docs/fleet-posture.md ("gateway blind spot").
# localhost:8080
# ai-gateway.internal.example.com   # non-loopback: upstream NOT resolved — probe it directly
"""
