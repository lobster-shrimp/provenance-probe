"""Client-side capture import (#53).

Turns a client-supplied capture payload into the internal `capture_proxy.Flow`
(and, via `to_captured`, the `wizard.Captured` the existing `synthesize()`
pipeline consumes). This is the SHARED ingest contract used by the hosted
HAR-upload front-end (P1) and the future browser extension (P2).

SECURITY MODEL (issue #53). The capture happens CLIENT-SIDE — in the user's own
browser, already logged into the target app. This module runs on the server but
makes NO outbound request and drives NO browser: it only RESHAPES an
already-captured exchange into the internal form. That is why
`/wizard/capture-import` is safe under the egress guard while the
server-side-browser `/wizard/capture-run` is not (the latter fetches a
caller-named URL from the server → un-pinnable SSRF; this does not).

It deliberately reuses the SAME primitives as the proxy and HAR paths —
`capture_proxy.select_chat_flow` and `flow_to_captured` (which themselves use
`detect_response_mode` / `sse_reassemble`) — so there is exactly ONE definition
of "which request is the chat call" and of how a response is fingerprinted. No
new synthesis/fingerprinting logic lives here.
"""
from __future__ import annotations

import json

from .capture_proxy import Flow, flow_to_captured, select_chat_flow


def _as_text(body: object) -> str:
    """Coerce a client-supplied body to the raw text a `Flow` expects.

    A browser HAR gives request/response bodies as strings, but an extension may
    hand us already-parsed JSON. Accept both: JSON-dump objects/arrays, pass text
    through unchanged, treat null/missing as empty.
    """
    if body is None:
        return ""
    if isinstance(body, str):
        return body
    if isinstance(body, (dict, list)):
        try:
            return json.dumps(body)
        except (TypeError, ValueError):
            return ""
    return str(body)


def _norm_headers(headers: object) -> dict:
    """Normalize headers from either a mapping or a HAR-style list of
    ``{name, value}`` pairs into a plain dict. Non-string names/values are
    dropped (never trust external data)."""
    if isinstance(headers, dict):
        items = list(headers.items())
    elif isinstance(headers, list):
        items = [(h.get("name"), h.get("value")) for h in headers
                 if isinstance(h, dict)]
    else:
        return {}
    return {name: value for name, value in items
            if isinstance(name, str) and name and isinstance(value, str)}


def _content_type(headers: dict) -> str:
    for k, v in headers.items():
        if k.lower() == "content-type":
            return v
    return ""


def _flow_from_entry(entry: object) -> Flow:
    """Build one `Flow` from a ``{request, response}`` entry, validating shape
    at the boundary and failing with a clear, operator-facing message."""
    if not isinstance(entry, dict):
        raise ValueError("capture entry must be a JSON object")
    req = entry.get("request")
    resp = entry.get("response")
    if not isinstance(req, dict):
        raise ValueError("capture is missing the 'request' object")
    if not isinstance(resp, dict):
        raise ValueError("capture is missing the 'response' object")
    url = (req.get("url") or "").strip()
    if not url:
        raise ValueError("capture 'request' has no url")
    resp_headers = _norm_headers(resp.get("headers"))
    return Flow(
        url=url,
        method=(req.get("method") or "POST").upper(),
        req_headers=_norm_headers(req.get("headers")),
        req_body=_as_text(req.get("body")),
        resp_headers=resp_headers,
        resp_body=_as_text(resp.get("body")),
        resp_content_type=_content_type(resp_headers),
    )


def normalize(payload: object, *, allowed_host: str = "") -> Flow:
    """Normalize a client capture payload into the chosen chat `Flow`.

    Accepts either the P1 single-flow contract
    ``{request, response, prompt_hint}`` (the client already chose the one flow)
    OR a ``{flows: [...]}`` list of candidates — in which case
    `select_chat_flow` picks the model call with the SAME scorer the HAR/proxy
    paths use, so `prompt_hint` decides. When `allowed_host` is given, selection
    is bound to that registrable domain, so a stray third-party POST can never be
    chosen (and get its cookie replayed).
    """
    if not isinstance(payload, dict):
        raise ValueError("capture payload must be a JSON object")
    prompt_hint = payload.get("prompt_hint") or ""
    raw_flows = payload.get("flows")
    if isinstance(raw_flows, list) and raw_flows:
        flows = [_flow_from_entry(e) for e in raw_flows]
    else:
        flows = [_flow_from_entry(payload)]
    flow = select_chat_flow(flows, prompt_hint, allowed_host=allowed_host)
    if flow is None:
        raise ValueError(
            "no chat request found in the capture — the chosen flow must be a "
            "POST with a request body to the app's own domain (re-capture the "
            "message you sent).")
    return flow


def to_captured(payload: object, *, allowed_host: str = ""):
    """`normalize()` then `flow_to_captured()` — the `wizard.Captured` that
    `synthesize()` consumes.

    A non-JSON request body flows through as a template adapter (synthesize
    warns); an SSE / JSON-lines response is reassembled and the per-chunk delta
    path pre-filled, exactly as the proxy path does — no second live replay is
    needed. The Cookie header is split out as the credential by
    `flow_to_captured` (never left in the committable headers).
    """
    flow = normalize(payload, allowed_host=allowed_host)
    prompt_hint = payload.get("prompt_hint") or "" if isinstance(payload, dict) else ""
    return flow_to_captured(flow, prompt_hint)
