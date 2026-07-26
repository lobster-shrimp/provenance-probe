# Adding sources — APIs and web apps

How to point the probe at a new endpoint. Two kinds of source:

- **API source** — an OpenAI- or Anthropic-style REST endpoint.
- **Web-app source** — a browser chat app (chat.z.ai and friends) with a custom
  request/response shape, cookie session, and often SSE streaming, driven by the
  `template` adapter.

> **Authorization first.** Only probe a system you are authorized in writing to
> test. The behavioral and deception layers send politically sensitive prompts
> and may trip a provider's abuse monitoring or breach its ToS. Set
> `authorized: true` (or pass `--i-am-authorized`) only when that is true. See
> [`docs/tos-notes.md`](tos-notes.md).

There are three front doors, same underlying config:

| Front door | Best for |
|---|---|
| **Local web UI** (`provenance-probe serve`, :8770) | one-off, interactive; a form with a web-app/template panel |
| **CLI + config file** (`assess --config targets.json`) | scripted / repeatable, multiple targets |
| **Observatory `targets.yaml`** | continuous nightly monitoring (separate repo) |

The config shape is one `Target` object; the fields are identical across all three.

---

## Adding an API source

### 1. Write a starting config

```bash
provenance-probe init            # writes an example targets.json
$EDITOR targets.json
```

### 2. OpenAI-style endpoint

```json
{
  "name": "vendor-under-test",
  "base_url": "https://api.vendor.example/v1",
  "model": "vendor-flagship-1",
  "api_style": "openai",
  "auth_value_env": "VENDOR_API_KEY",
  "authorized": true
}
```

- `base_url` includes the version prefix (e.g. `/v1`); the default `chat_path`
  is `/chat/completions` and `models_path` is `/models`, so the probe calls
  `https://api.vendor.example/v1/chat/completions`.
- `auth_value_env` names the environment variable holding the key (never put the
  key in the file). Default header is `Authorization: Bearer <key>`. Override
  with `auth_header` / `auth_prefix` for non-standard schemes.

### 3. Anthropic-style endpoint

```json
{
  "name": "anthropic",
  "base_url": "https://api.anthropic.com",
  "model": "claude-opus-4-8",
  "api_style": "anthropic",
  "auth_value_env": "ANTHROPIC_API_KEY",
  "authorized": true
}
```

`api_style: anthropic` **auto-configures** the `/v1/messages` chat path, the
`x-api-key` auth header, and the `anthropic-version` header — set `chat_path` /
`auth_header` only to override. Anthropic returns `usage.input_tokens`, which the
tokenizer battery reads, so provenance is genuinely measured (a Claude endpoint
clears to UNLIKELY today, since no Claude-specific reference vector exists yet —
see [`EXTENDING.md` §4](EXTENDING.md) to add one). Use a model id your account can
call (`claude-opus-4-8`, etc.).

### 4. Run it

```bash
export VENDOR_API_KEY=sk-...
provenance-probe assess --config targets.json --out ./reports --latency
```

### Reasoning models that reject `temperature=0`

Some reasoning models (e.g. Kimi `kimi-k2.6`) reject `temperature=0` with an
HTTP 400. The client detects a temperature-related 400 and retries without the
field automatically — no config needed.

---

## Adding a web-app source (`api_style: template`)

Browser chat apps aren't clean REST APIs: custom bodies, cookie auth, SSE. The
`template` adapter drives any of them from one captured request.

### 1. Capture a real request

Open the app, send a message, and in DevTools → Network grab the chat request
(Copy as cURL, or copy the JSON body + headers). You need: the path, the JSON
body shape, where the reply text lives, and the session cookie.

### 2. Describe it as a template

```json
{
  "name": "chat.z.ai",
  "base_url": "https://chat.z.ai",
  "chat_path": "/api/paas/v4/chat/completions",
  "models_path": "/api/paas/v4/models",
  "api_style": "template",
  "cookie_env": "ZAI_COOKIE",
  "request_template": {
    "model": "glm-4.6",
    "messages": [{"role": "user", "content": "__PROMPT__"}],
    "max_tokens": "__MAX_TOKENS__",
    "temperature": "__TEMPERATURE__"
  },
  "response_text_path": "choices.0.message.content",
  "response_prompt_tokens_path": "usage.prompt_tokens",
  "response_model_path": "model",
  "authorized": true
}
```

### 3. Placeholders (substituted per probe)

| Placeholder | Becomes |
|---|---|
| `__PROMPT__` | the probe's prompt text |
| `__MAX_TOKENS__` | the probe's max-tokens (1 for tokenizer probes) |
| `__TEMPERATURE__` | the probe's temperature |
| `__SYSTEM__` | the system prompt, if the probe sets one |

A placeholder used as a **whole value** keeps its type (`"__MAX_TOKENS__"` → the
number `1`); used **inside a string** it is stringified. Put placeholders
anywhere in `request_template` — nested objects and arrays are walked.

### 4. Read the reply by dotted path

`response_*_path` fields address the response by dotted path with numeric
indices, so any nested shape works:

| Field | Points at | Example |
|---|---|---|
| `response_text_path` | the assistant reply text | `choices.0.message.content` |
| `response_prompt_tokens_path` | prompt-token usage (if any) | `usage.prompt_tokens` |
| `response_model_path` | the echoed model id (if any) | `model` |

### 5. Session auth and streaming

- **Cookie session:** put the browser `Cookie` header value in the env var named
  by `cookie_env` (preferred — keeps the credential out of the file), or inline
  in `cookie`. Add any other required headers to `extra_headers`.
- **SSE streaming:** set `"stream_mode": "sse"` and
  `"stream_delta_path": "choices.0.delta.content"`; per-chunk deltas are
  accumulated into the full reply for the behavioral layers.

### What works on web apps — and what degrades

The **behavioral and deception layers are the primary signal** on web apps
(self-ID, persona vs jurisdiction claims, confrontation, CJK leakage) plus
network and wire. The **tokenizer fingerprint only works if the app exposes
prompt-token usage** — many web apps suppress it. When usage is suppressed the
tokenizer layer is unavailable (logged as a transparency finding), provenance
floors at INDETERMINATE, and drift detection runs on wire + latency only at
**degraded confidence** (see `monitor.diff`'s `confidence` field). This is the
chat.z.ai case: a GLM backend asserting a Google Gemini persona and denying PRC
jurisdiction is caught as a **material misrepresentation** by the deception layer
even with no tokenizer signal.

---

## Full `Target` field reference

Defined in `provenance_probe/config.py`. Unset fields take these defaults.

| Field | Default | Purpose |
|---|---|---|
| `name` | (required) | label for the target |
| `base_url` | (required) | endpoint root incl. version prefix |
| `model` | `""` | model id to request |
| `api_style` | `openai` | `openai` \| `anthropic` \| `raw` \| `template` |
| `chat_path` | `/chat/completions` | chat endpoint path |
| `models_path` | `/models` | catalog endpoint path |
| `auth_header` | `Authorization` | header carrying the token |
| `auth_value_env` | `""` | env var holding the token |
| `auth_prefix` | `Bearer ` | prefix before the token |
| `extra_headers` | `{}` | any additional headers |
| `cookie` / `cookie_env` | `""` | web-app session cookie (inline / via env) |
| `request_template` | `{}` | template-mode request body with placeholders |
| `response_text_path` | `""` | dotted path to reply text (template) |
| `response_prompt_tokens_path` | `""` | dotted path to prompt-token usage (template) |
| `response_model_path` | `""` | dotted path to echoed model id (template) |
| `stream_mode` | `none` | `none` \| `sse` |
| `stream_delta_path` | `""` | per-chunk delta path for SSE accumulation |
| `timeout` | `60` | per-request timeout (s) |
| `verify_tls` | `true` | TLS verification |
| `proxy` | `""` | route through an inspecting proxy |
| `authorized` | `false` | **scope attestation — must be true to run active probes** |
| `notes` | `""` | freeform |

---

## Verify a new source

```bash
provenance-probe assess --config targets.json --out ./reports --latency
```

Check:
- **Tokenizer** — `tokenizer.usable: true` and a top match, OR a logged "no
  usage" transparency finding (expected for many web apps).
- **Wire** — vendor headers / error schema / catalog populated.
- **A `fingerprint_id`** was produced (the stable backend identity used for drift).

Then wire it into drift detection:

```bash
# store an accepted baseline once, e.g. after contract award
cp reports/<target>_<stamp>.json baseline.json
# later runs
provenance-probe monitor --baseline baseline.json --current fresh.json   # exit 2 on drift
```

For continuous nightly monitoring, add the same target to the Observatory's
`targets.yaml` — see that repo's `docs/adding-targets.md`.

---

## Troubleshooting

| Symptom | Likely cause / fix |
|---|---|
| HTTP 401 | wrong/missing key or cookie; check `auth_value_env` / `cookie_env` is exported; some keys are host-specific (e.g. Moonshot `.ai` vs `.cn`) |
| HTTP 400 mentioning temperature | reasoning model rejecting `temperature=0`; handled automatically by retry — if it persists the field name differs, adjust `request_template` |
| `tokenizer.usable: false` | endpoint suppressed `usage.prompt_tokens`; expected for many web apps — provenance floors at INDETERMINATE, drift runs degraded |
| reply text empty | wrong `response_text_path`; re-check the captured response shape |
| template body rejected | your `request_template` doesn't match the real request; re-capture from DevTools, keep every field the app sends |
| SSE reply truncated/empty | set `stream_mode: sse` and the correct `stream_delta_path` |
| wrong `chat_path` (404) | web apps rarely use `/chat/completions`; copy the exact path from the captured request |
