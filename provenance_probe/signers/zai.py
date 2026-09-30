"""z.ai (chat.z.ai / Zhipu GLM) request signer — the founding-case reactivation.

RECOVERED FROM PUBLIC CLIENT JS (read-only, treated as untrusted data):
  bundle: https://z-cdn.chatglm.cn/z-ai/frontend/prod-fe-<VER>/assets/index-*.js
  (observed VER "1.1.98"), referenced from https://chat.z.ai/ .

The chat gateway moved to a SIGNED per-request API:
  POST {base}/api/v2/chat/completions?<query>
with an ``X-Signature`` header + a time-bound query string. The gateway 404s any
request lacking a valid, fresh signature, so a captured URL cannot be replayed and
a static template cannot precompute it. This signer reproduces the client's
computation so the probe can actively fingerprint z.ai again.

--- The recovered algorithm (from the minified functions ``ane`` + ``sne``) -------
Two client helpers build the request:

  ane():   # gathers request identity + browser telemetry
    timestamp = String(Date.now())          # ms since epoch
    requestId = uuidv4()                     # random per request
    user_id   = session user id or ""        # tied to the logged-in session
    params    = {timestamp, requestId, user_id}
    telemetry = {version:"0.0.1", platform, token, user_agent, ...many fields}
    urlParams = URLSearchParams({...params, ...telemetry}).toString()
    sortedPayload = Object.entries(params).sort(byKey).join(",")
                  # -> "requestId,<id>,timestamp,<ts>,user_id,<uid>"

  sne(sortedPayload, message, timestamp):    # the signature builder
    b64       = base64( utf8( message ) )     # last user message text
    canonical = sortedPayload + "|" + b64 + "|" + timestamp
    window    = floor(timestamp / (5*60*1000))          # 5-minute bucket
    derived   = js_sha256.hmac(SECRET_KEY, String(window))   # HMAC-SHA256 hex
    signature = js_sha256.hmac(derived, canonical)           # HMAC-SHA256 hex

The request is then sent as:
    POST {base}/api/v2/chat/completions?{urlParams}&signature_timestamp={timestamp}
    headers: X-Signature: {signature}, X-FE-Version: "prod-fe-<VER>",
             Authorization: Bearer {session token}

Key facts that make this recoverable (no server-issued secret):
  * The signing key is a CONSTANT embedded in the client JS (function ``sne``) — a
    client-side value anyone can read from the public bundle, NOT a server-issued
    secret. This repo deliberately does NOT vendor that literal value: the operator
    recovers it from the current bundle and supplies it via
    ``signer_config["secret_key"]`` (see docs/zai-reactivation.md). There is no
    embedded default — the signer raises if the key is not configured.
  * The hash is standard HMAC-SHA256 (js-sha256 ``sha256.hmac(key, msg)``); the
    derived key (a 64-char hex string) is used as the *text* key of the 2nd HMAC.
  * The signature covers only requestId/timestamp/user_id + the message text +
    timestamp — NOT the auth token and NOT the browser telemetry.

Python's ``hmac`` + ``hashlib.sha256`` reproduce js-sha256 byte-for-byte
(verified against the real library, including a multibyte-UTF-8 message).

CAVEAT: this is a fragile, per-app adapter. It breaks if z.ai rotates the signing
key, changes the canonical string, the window size, or the hash. Re-recover the key
(and the algorithm, if it changed) from the then-current client bundle if active
probing starts 404ing again.
"""
from __future__ import annotations
import base64
import hashlib
import hmac
import time
import uuid

# The frontend version string sent as X-FE-Version (observed value; override via
# signer_config["fe_version"] when the bundle rev changes).
FE_VERSION = "prod-fe-1.1.98"

# Signature validity window: floor(timestamp_ms / WINDOW_MS) selects the HMAC key.
WINDOW_MS = 5 * 60 * 1000

# Signed API path (v2). Set the target's chat_path to this; kept here for docs.
CHAT_PATH = "/api/v2/chat/completions"


def _hmac_sha256_hex(key: str, message: str) -> str:
    """HMAC-SHA256 over UTF-8 bytes, lowercase hex — matches js-sha256
    ``sha256.hmac(key, message)`` (string args are UTF-8 encoded)."""
    return hmac.new(key.encode("utf-8"), message.encode("utf-8"),
                    hashlib.sha256).hexdigest()


def sorted_payload(*, timestamp_ms: int, request_id: str, user_id: str) -> str:
    """Reproduce the client's ``sortedPayload``: the identity params joined as
    ``k,v`` pairs, keys sorted ascending. For the fixed key set this is
    ``requestId,<id>,timestamp,<ts>,user_id,<uid>`` (r < t < u)."""
    params = {"timestamp": str(timestamp_ms),
              "requestId": request_id,
              "user_id": user_id}
    return ",".join(f"{k},{v}" for k, v in sorted(params.items()))


def compute_signature(*, message: str, timestamp_ms: int, request_id: str,
                      secret_key: str, user_id: str = "") -> str:
    """Pure signature computation. Given the signed inputs, return the hex
    ``X-Signature`` value. Deterministic: same inputs -> same output.

    ``secret_key`` is required and operator-supplied (recovered from the client
    bundle); there is no embedded default."""
    if not secret_key:
        raise ValueError(
            "z.ai signer: secret_key not configured. Recover it from the current "
            "client bundle and pass it via signer_config.secret_key — see "
            "docs/zai-reactivation.md")
    sp = sorted_payload(timestamp_ms=timestamp_ms, request_id=request_id,
                        user_id=user_id)
    b64 = base64.b64encode(message.encode("utf-8")).decode("ascii")
    canonical = f"{sp}|{b64}|{timestamp_ms}"
    window = timestamp_ms // WINDOW_MS
    derived = _hmac_sha256_hex(secret_key, str(window))
    return _hmac_sha256_hex(derived, canonical)


def _last_user_message(body: dict) -> str:
    """Extract the text the client signs: the last ``role == "user"`` message's
    content (falls back to the last message, then to "")."""
    if not isinstance(body, dict):
        return ""
    msgs = body.get("messages")
    if not isinstance(msgs, list) or not msgs:
        return ""
    for m in reversed(msgs):
        if isinstance(m, dict) and m.get("role") == "user":
            c = m.get("content")
            if isinstance(c, str):
                return c
            # OpenAI content-parts array -> concat text parts
            if isinstance(c, list):
                return "".join(p.get("text", "") for p in c
                               if isinstance(p, dict) and isinstance(p.get("text"), str))
    last = msgs[-1]
    if isinstance(last, dict) and isinstance(last.get("content"), str):
        return last["content"]
    return ""


def build_signed_request(body: dict, config: dict | None = None) -> dict:
    """Signer entry point (see ``signers.Signer``). Given the OpenAI-style request
    body and a config, return the extra query params + headers a signed z.ai
    request needs.

    config keys:
      secret_key    str   REQUIRED. The signing key recovered from the current
                          z.ai client bundle. No embedded default — a missing/empty
                          value raises ValueError.
      user_id       str   session user id (must match the session for the server
                          to accept it; part of the signed payload). Default "".
      fe_version    str   X-FE-Version value. Default FE_VERSION.
      timestamp_ms  int   pin the timestamp (tests / determinism). Default now.
      request_id    str   pin the requestId (tests). Default a fresh uuid4.
      telemetry     dict  extra query params (browser fingerprint) the server may
                          require. NOT signed. Merged into the query string.

    Returns: {"params": {...}, "headers": {...}, "signature": ...,
              "timestamp_ms": ..., "request_id": ...}
    """
    cfg = config or {}
    timestamp_ms = int(cfg.get("timestamp_ms") or int(time.time() * 1000))
    request_id = cfg.get("request_id") or str(uuid.uuid4())
    user_id = str(cfg.get("user_id", "") or "")
    secret_key = cfg.get("secret_key") or ""   # required; compute_signature raises if empty
    fe_version = cfg.get("fe_version") or FE_VERSION

    message = _last_user_message(body)
    signature = compute_signature(message=message, timestamp_ms=timestamp_ms,
                                  request_id=request_id, user_id=user_id,
                                  secret_key=secret_key)

    params = {"timestamp": str(timestamp_ms), "requestId": request_id,
              "user_id": user_id, "signature_timestamp": str(timestamp_ms)}
    telemetry = cfg.get("telemetry")
    if isinstance(telemetry, dict):
        params.update({k: str(v) for k, v in telemetry.items()})

    headers = {"X-Signature": signature, "X-FE-Version": fe_version}
    return {"params": params, "headers": headers, "signature": signature,
            "timestamp_ms": timestamp_ms, "request_id": request_id}
