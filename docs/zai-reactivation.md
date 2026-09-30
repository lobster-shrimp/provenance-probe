# Reactivating the z.ai founding case (signed active probing)

z.ai (`chat.z.ai`, Zhipu GLM) is the founding provenance case (advisory
**MPA-2026-001**): a served model that presented a Google-Gemini persona while the
backend served **GLM**. It went **dark** when z.ai moved its chat to a **signed,
per-request API** — `POST /api/v2/chat/completions` guarded by an `X-Signature`
header + a time-bound query string. The gateway **404s** any request without a
valid, fresh signature, so a captured URL can't be replayed and a static template
can't precompute it. Re-enabling active probing therefore needs a z.ai-specific
**request signer**, which this repo now ships: `provenance_probe/signers/zai.py`.

This doc is the operator runbook for turning it back on. It requires **you** to
supply a fresh session credential — the probe ships **no secret**.

---

## The recovered signing scheme (public client JS)

Recovered read-only from the public bundle
`https://z-cdn.chatglm.cn/z-ai/frontend/prod-fe-<VER>/assets/index-*.js`
(observed `VER = 1.1.98`), linked from `https://chat.z.ai/`. Two minified helpers
build every signed request:

- **`ane()`** gathers request identity + browser telemetry:
  - `timestamp = String(Date.now())` (ms)
  - `requestId = uuidv4()` (random per request)
  - `user_id` = the logged-in session's user id (or `""`)
  - builds `sortedPayload = "requestId,<id>,timestamp,<ts>,user_id,<uid>"`
    (the three identity params joined `k,v`, keys sorted ascending)
  - builds `urlParams` = a `URLSearchParams` string of the identity params **plus**
    ~30 browser-fingerprint fields (`platform`, `user_agent`, `screen_*`, …).
- **`sne(sortedPayload, message, timestamp)`** builds the signature:
  1. `b64 = base64(utf8(message))` — `message` is the **last user message text**
  2. `canonical = sortedPayload + "|" + b64 + "|" + timestamp`
  3. `window = floor(timestamp / (5*60*1000))` — a **5-minute** bucket
  4. `derived = HMAC_SHA256(SECRET_KEY, str(window))` (hex)
  5. `signature = HMAC_SHA256(derived, canonical)` (hex) ← the `X-Signature` value

The request is then:

```
POST {base}/api/v2/chat/completions?{urlParams}&signature_timestamp={timestamp}
headers:
  X-Signature: {signature}
  X-FE-Version: prod-fe-1.1.98
  Authorization: Bearer {session token}
```

Why this is recoverable (no server-issued secret):

- The signing key is a **constant embedded in the client JS** (in function `sne`),
  not a server-issued value — anyone can read it from the public bundle. **This repo
  deliberately does not ship that literal key.** You recover it yourself from the
  current bundle (see "Recover the signing key" below) and pass it via
  `signer_config.secret_key`. The signer has **no embedded default** and raises a
  clear error if the key is not configured.
- The hash is standard **HMAC-SHA256** (the client uses `js-sha256`'s
  `sha256.hmac(key, msg)`). The derived key (a 64-char hex string) is used as the
  **text** key of the second HMAC. Python's stdlib `hmac`+`hashlib.sha256`
  reproduce it **byte-for-byte** (cross-verified against the real `js-sha256`,
  including a multibyte-UTF-8 message — see `tests/test_zai_signer.py`, which pins
  the algorithm with a clearly-FAKE key, not z.ai's real one).
- The signature covers **only** `requestId`/`timestamp`/`user_id` + the message
  text + timestamp — **not** the auth token and **not** the telemetry.

### Recover the signing key (operator, read-only)

The key is a short constant string used as the first argument of the HMAC call in
the minified `sne` signer helper. Recover it from the current client bundle:

```bash
# 1. Find the main JS bundle referenced by the app shell.
BUNDLE=$(curl -s https://chat.z.ai/ \
  | grep -oE 'https://[^"]+/prod-fe-[^"]+/assets/index-[^"]+\.js' | head -1)

# 2. Fetch it and locate the HMAC key constant near the signer helpers.
#    It is the FIRST string argument of the inner `.hmac("<KEY>", ""+<window>)`
#    call (the one whose second arg is the floor(timestamp/300000) bucket).
curl -s "$BUNDLE" | grep -oE '\.hmac\("[^"]+",""\+[a-zA-Z0-9_$]+\)' | head
```

The quoted string in that match is the key. Pass it as `signer_config.secret_key`.
If the grep returns nothing, the bundle changed — re-inspect the `sne`/`ane` helpers
(search the bundle for `signature_timestamp` and read outward) and, if the algorithm
itself changed, update `provenance_probe/signers/zai.py` accordingly.

---

## Re-enable checklist (operator)

1. **Get a FRESH session credential.** Sign in to `chat.z.ai` in a browser you
   control, and copy the session `Cookie` (and/or the `Authorization: Bearer`
   token from a chat request). This is **your** credential; the probe never stores
   it — pass it via an environment variable.
   - Note the **`user_id`** for that session (it is part of the signed payload;
     the server rejects a signature whose `user_id` doesn't match the session).
     It appears in the chat request's query string as `user_id=…`.

2. **Point the target at the signed v2 endpoint and enable the signer.** Example
   target JSON (secrets stay in env vars):

   ```json
   {
     "name": "z.ai-glm",
     "base_url": "https://chat.z.ai",
     "api_style": "template",
     "chat_path": "/api/v2/chat/completions",
     "cookie_env": "ZAI_COOKIE",
     "auth_header": "Authorization",
     "auth_prefix": "Bearer ",
     "auth_value_env": "ZAI_TOKEN",
     "request_template": {
       "messages": [{ "role": "user", "content": "__PROMPT__" }],
       "stream": true
     },
     "stream_mode": "sse",
     "stream_delta_path": "choices.0.delta.content",
     "response_text_path": "choices.0.message.content",
     "signer": "zai",
     "signer_config": {
       "user_id": "<your-session-user-id>",
       "secret_key": "<key recovered from the client bundle — see above>"
     },
     "authorized": true,
     "notes": "Founding case (MPA-2026-001). Signed v2 API. Set authorized=true only with authorization."
   }
   ```

   `signer_config.secret_key` is **required** (recovered per "Recover the signing
   key" above); the signer raises if it is missing. Note it is a client-side
   constant, not a personal secret — but it is kept out of this repo and supplied by
   you so the repo never vendors z.ai's literal key. Then set the session
   credential(s) in the environment (never in the file):

   ```bash
   export ZAI_COOKIE='<fresh cookie header from your browser session>'
   export ZAI_TOKEN='<fresh bearer token, if the endpoint needs it>'
   ```

3. **Flip `authorized` to `true`.** Active probing requires the scope attestation.
   Only set it with authorization to probe that session.

4. **Run.** The signer computes a fresh `timestamp`/`requestId`/`signature` on
   every request, appends `…&signature_timestamp=<ts>` to the URL, and sets the
   `X-Signature` / `X-FE-Version` headers. `signer_config` also accepts:
   - `fe_version` — override `X-FE-Version` when the bundle rev changes.
   - `telemetry` — a dict of the browser-fingerprint query fields, if the server
     starts requiring them (they are sent but **not** signed).
   - `secret_key` — **required** (above); re-recover and update it if z.ai rotates
     the key.

---

## Honest caveats — this is fragile

- **Per-app adapter.** It reproduces one app's private signing scheme. It **breaks**
  the moment z.ai rotates the signing key, changes the canonical string, the 5-minute
  window, the hash, or the `X-FE-Version` gate. When active probing starts 404ing,
  **re-recover** the scheme from the then-current client bundle and update
  `signers/zai.py` (the golden vectors in `tests/test_zai_signer.py` will flag a
  drift).
- **Needs a live, authenticated session.** The signature isn't enough on its own —
  the request still carries **your** `Authorization`/`Cookie`, and `user_id` must
  match that session. The probe holds no z.ai secret; you supply a fresh one.
- **Telemetry not signed, but maybe required.** The signature covers only identity
  + message. If the gateway begins enforcing the browser-fingerprint fields, add
  them via `signer_config.telemetry`.
- **Server-side freshness.** `signature_timestamp` is time-bound (5-minute bucket).
  A signed request must be sent promptly; large clock skew will 404.
