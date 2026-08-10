"""Fleet detection: find AI router/gateway tools configured on a host.

A no-egress, read-only, host-forensics module. It discovers where local agent
CLIs are pointed (the `base_url` in their config files and env), resolves
localhost gateways to their real upstream by parsing the gateway's OWN config,
classifies each endpoint against an operator-supplied allowlist plus bundled
corpus attribution, and returns a private local report.

INVARIANT: nothing in this package makes a network call. It only reads files and
the process environment. It imports `provenance_probe.gateways` (pure) but never
`provenance_probe.omniroute` (which is network-bearing).
"""
from .scan import run_scan  # noqa: F401
