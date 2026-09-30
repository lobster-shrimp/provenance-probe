"""Per-request request signers for web-app endpoints that gate on a signed,
time-bound query string / header (not a static replayable token).

A signer is a pure function of the request context that returns the extra query
params and headers a signed endpoint requires. It is wired into the transport via
``Target.signer`` (a name) + ``Target.signer_config`` (signer-specific inputs),
and is applied by ``client.Client.chat`` for ``api_style="template"`` targets.

Signers are per-app adapters. They are recovered from the app's PUBLIC client JS
and are inherently fragile: if the app changes its signing scheme, its embedded
key, or its canonical string, the adapter must be re-recovered. See each signer
module for the recovered algorithm and the JS provenance.
"""
from __future__ import annotations
from typing import Callable

# A signer takes (body, config) and returns a dict with:
#   {"params": {str: str}, "headers": {str: str}, ...diagnostics}
Signer = Callable[[dict, dict], dict]


def get_signer(name: str) -> Signer | None:
    """Resolve a signer by name. Returns None for an unknown name so the caller
    can surface a clear config error rather than crash."""
    if not name:
        return None
    if name == "zai":
        from . import zai
        return zai.build_signed_request
    return None
