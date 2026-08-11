# Changelog

## [0.25.0] — Fleet trust-store watch: transparent-MITM root-CA detection

### Added
- **`provenance-probe fleet-scan --trust-store`** — watches the host's trusted root
  CAs for transparent interception. A MITM-capable proxy must install a root CA;
  this enumerates admin/user-added roots, fingerprints each (SHA-256 of the DER,
  stdlib — no `cryptography` dep), and flags any not in an operator-supplied
  baseline, escalating known interception tools (mitmproxy/Charles/Burp, matched on
  the DER commonName). Capture a golden baseline with `--print ca-baseline`.
- macOS + Linux; no-egress (reads local trust stores via the `security` CLI / cert
  dirs, no network). Report + `--json` + `--out` (0600 / `O_NOFOLLOW`).

### Security
- **Inert without `--i-am-authorized`** — reading the system trust store is a
  privacy/labor-review surface, so both `--trust-store` and `--print ca-baseline`
  refuse until documented policy is attested.
- **Never a silent false-clean** — an unsupported OS (Windows) or an unreadable
  store (`security` errored) refuses with exit 3 ("host not certified clean")
  rather than reporting a green result; a genuinely empty admin-CA dir is clean.
- **Honest limits** — attribution of the *installing process* is out of scope (the
  macOS keychain records no PID); that needs an EDR/osquery event hook.

## [0.24.1] — Fleet posture: prevention-first framing + starter allowlist (T7)

### Added
- **`provenance-probe fleet-scan --print allowlist-template`** emits a starter
  egress allowlist (sanctioned first-party hosts + commented placeholders for cloud
  tenants and one sanctioned gateway) for an operator to fork into their own policy.
- **`docs/fleet-posture.md`** — the prevention-first posture: the control is an
  egress allowlist + one sanctioned gateway, and `fleet-scan`'s
  `allowlist holding: N sanctioned, M drifted` headline is the posture's health,
  not a rogue-developer list. Documents the gateway blind spot honestly (upstream
  resolution is loopback-only + config-dependent; a non-loopback sanctioned gateway
  hides its backend — probe it directly).

## [0.24.0] — Fleet detection: find AI router/gateway tools on a host

### Added
- **`provenance-probe fleet-scan` — no-egress, read-only host forensics.** Discovers
  where local agent CLIs (Claude Code, Codex, Continue, aider, Cursor) are pointed by
  scanning config files + env for a redirected `base_url`, and classifies each endpoint
  against an operator allowlist plus bundled `corpus.py` attribution into honest buckets
  (`sanctioned` / `off-allowlist-attributed` / `off-allowlist-unattributed` /
  `aggregator-unresolvable` / `gateway-upstream-unresolved`). Report headline is
  allowlist-drift. Flags: `--allowlist`, `--json`, `--out`, `--no-redact`, `--exit-code`.
- **Gateway-config resolution (the localhost blind-spot fix).** When a `base_url` points at
  a local gateway (OmniRoute `localhost:20128`, LiteLLM), fleet-scan parses the gateway's
  own config to resolve the real upstream and attributes THAT — so the founding OmniRoute
  case is caught instead of shrugged off as "localhost".
- **osquery delivery (T6).** `fleet-scan --sqlite <db>` writes a `fleet_findings` SQLite
  table that osquery reads via ATC; `--print {launchd,systemd,cron,osquery-atc}` emits the
  scheduled-scan unit or the ATC config. Recipe in `docs/fleet-osquery.md`.

### Security
- The fleet package makes **no network calls** — a structural boundary: pure gateway
  knowledge lives in `provenance_probe/gateways.py`, which both `fleet/` and the
  network-bearing `omniroute.py` import, so `fleet/` never imports the egress path.
- Attribution is a **sub-CONFIRMED static pointer** (`measured=False`), never collapsed into
  a measured provenance verdict. Exact-or-subdomain host matching rejects suffix attacks
  (`api.deepseek.com.evil.test`).
- Credentials in a `base_url` (`user:pass@`) are stripped at collection; reports and the
  SQLite DB are written `0600` with home paths redacted, and the DB write refuses to follow
  a symlink (`O_NOFOLLOW`).

## [0.23.1] — Copy fixes: extension install honesty + always-on now shipped

### Changed
- **Capture-extension copy no longer oversells "one-click."** The landing card and
  the import page now describe the extension as a load-unpacked developer-mode install
  (a one-time ~2-minute setup, steps in the README) instead of a store one-click, and
  the link reads "Get the extension & install steps." The link target is unchanged.
- **"Always-on watching is coming" copy updated — it shipped (P3).** The landing watch
  card, the `/watch` "keep this tab open" banner, and the shared `explain.py`
  watching primer now point to the real local `watch` daemon (runs on a timer, installs
  under launchd/systemd) instead of promising a future "background watcher."

## [0.23.0] — Local always-on `watch` daemon (P3 / #66)

### Added
- **`provenance-probe watch` — an unattended, always-on model-swap daemon.** The
  local counterpart to the tab-bound hosted watch (P2 #64) and the real-time
  `sentinel` proxy: it re-probes your OWN configured targets on a schedule and
  raises a loud LOCAL alert the moment a served model silently changes — no
  browser, no open terminal, survives logout.
  - **Modes (mutually exclusive):** `--once` (single pass; **exit 2 on ANY
    drift**, 1 on operational error, 0 clean/seeded — the cron/launchd
    primitive), `--loop` (run forever on a timer with jitter; clean
    SIGINT/SIGTERM shutdown that finishes the in-flight target and exits 0;
    one target's exception never kills the loop), `--pin` / `--reset-baseline`
    (re-baseline to the current fingerprint), and `--print-launchd` /
    `--print-systemd` unit-file generators (Windows documented via Task
    Scheduler).
  - **Per-target baseline store** at `~/.provenance-probe/watch/<slug>/`
    (`baseline.json` = the FULL bundle, `state.json`, `switches.jsonl`). First
    run seeds the baseline (no drift), like the observatory's first-run seed;
    later runs `monitor.diff(baseline, current)`.
  - **Loud, secret-free alerts on drift:** a stderr **MODEL SWITCH DETECTED**
    banner with the changes table, an appended `switches.jsonl` record, a
    best-effort desktop notification (`osascript` / `notify-send`,
    feature-detected, never fatal), and an optional `--webhook <url>` POST
    (10 s timeout, failure logged not fatal). Keys/cookies read from local
    config **never** appear in any sink — payloads are built from the diff +
    fingerprints only, and every transport error is routed through
    `client._safe_err`.
  - **Path-traversal defense:** the per-target directory name is slugified to
    `[A-Za-z0-9._-]`, rejects `.`/`..`/empty, and is `realpath`-contained inside
    the watch root (same discipline as the `/media` route).
  - Pure-stdlib scheduling (no APScheduler / heavy deps). `--behavioral` /
    `--deception` are off by default for a fast, cheap re-check (tokenizer, wire
    and determinism — the strongest swap signals — stay on).

### Changed
- **New `provenance_probe/assess.py` — one source of truth for a "bundle".**
  Extracted `assess_target(target, opts) -> bundle` (full multi-layer bundle
  **incl. `score`, `user_warning` AND `fingerprint_id`**) and refactored BOTH
  `cli.cmd_assess` and the `serve.py` assess worker to call it. Previously
  `cmd_assess` omitted `fingerprint_id` and `serve` computed it inline; now the
  CLI, the web service and the daemon are byte-identical, so a `watch` baseline
  is directly comparable to `serve` / the Observatory. Behavior-preserving
  (full existing suite stays green; a fingerprint-parity test pins it).

## [Unreleased] — MV3 browser extension for one-click hosted capture (P2 / #54)

### Changed
- Added a **`/favicon.ico` + `/favicon.svg` route** serving the lie-detector
  SVG, so pages not rendered through `ui.doc()` (the agent flight-recorder
  report) and direct browser favicon requests resolve it instead of 404-ing.
- The web UI's **Observatory** nav link now defaults to the live public
  observatory (`https://lobster-shrimp.github.io/provenance-observatory/`) and
  opens in a new tab; override with `PROVENANCE_OBSERVATORY_URL` to point at a
  local observatory instead.
- Added a **lie-detector favicon** (a coral polygraph waveform on the deep-green
  brand square) inlined as an SVG data-URI in the shared page shell, so it needs
  no route and does not hit the hosted auth gate.

### Added
- **`extension/` — a Manifest V3 Chrome extension**, a one-click alternative to
  the HAR-upload path (#53). It captures the target app's chat request in the
  **user's own browser/session** (via the DevTools network API, scoped to the
  single inspected tab and only while explicitly armed), sanitizes it with the
  **same** header allow-list / registrable-domain binding / chat scorer / cookie
  consent as the built-in uploader, and POSTs the **same** normalized
  `{name, prompt_hint, cookie_consent, request, response}` payload to a
  user-configured instance's `POST /wizard/capture-import`. Purely a **second
  front-end** onto the existing #53 ingest — **no server-side browser** (no SSRF)
  and **no server contract change** (`serve.py` untouched).
  - Minimal MV3 permissions — `storage` + `declarativeNetRequestWithHostAccess`
    only; **no** `<all_urls>`, `webRequest`, `cookies`, `tabs`, `activeTab`,
    `scripting`, or static `host_permissions`. Host access to the single
    configured instance origin is requested at runtime. Every permission is
    documented in `extension/README.md`.
  - Credentials (instance URL + Basic auth) live only in `chrome.storage.local`,
    are read only by the background worker, attached only to the configured
    instance over HTTPS (`credentials: "omit"`), and never logged. No vendor keys.
  - Shared pure logic in `extension/lib/sanitize.js` with standalone
    `node --test` unit tests (payload assembly, header/cookie sanitization, XSS
    escaping); packaged into a Chrome Web Store zip by
    `.github/workflows/extension.yml` (**build only — not published**).
- **The extension versions independently** (`extension/manifest.json` /
  `extension/package.json` at `0.1.0`); this change ships **no Python code
  changes**, so the `provenance_probe` package version is intentionally unchanged.

## [0.22.0] - 2026-08-06 — Client-side "watch a service for a silent swap" (P2 / #64)

The mission's second half — **watching** a service over time — made real and
**self-service on BOTH hosted and local**. A server-side daemon can't run on the
scale-to-zero, single-credential, no-stored-keys hosted demo, so the watch loop
lives in the **user's own browser tab**: the API key never leaves the browser and
there is no server persistence.

### Added
- **A `/watch` page** (rendered via `ui.doc()`): configure a target, pin a baseline
  fingerprint, and re-check it on a timer (5 / 15 / 60 min, with a 5-min floor and a
  little jitter). Each tick reuses the **existing** endpoints with **no new detection
  logic** — `POST /api/assess` → poll `GET /api/run/<rid>` → `POST /api/monitor`
  (the same `monitor.diff` the CLI and observatory use). On drift it raises a **loud,
  unmissable alert**: a red banner, a browser-tab **title** change
  (`⚠ MODEL SWITCH — provenance-probe`), an optional permission-gated desktop
  **Notification**, and a timestamped entry in a live **Switches** log.
  **"Accept new baseline"** re-pins to the current fingerprint and stops re-alerting.
- **Entry points**: the landing "Watch a service for a silent swap" CTA now opens
  `/watch`; a **"Watch this"** button appears on a finished probe result; and each
  **Local-run-history** row gets a **watch** link. Each pre-fills the target
  (`base_url`/`model`/paths) — **never** the API key or session cookie (those would
  leak into browser history / server logs from a URL).
- **`/api/run` now also returns `fingerprint_id`** (the same value `/api/history`
  already exposes) so the client can display the pinned baseline id without a second
  round-trip. Purely additive; no secret is added to the response.

### Security properties (verified by tests + review)
- **The API key is held in the browser only** — in memory for the life of the tab,
  posted **solely** to `/api/assess` for each probe, and **never** written to server
  storage or to `localStorage`/`sessionStorage`, and never placed in a URL. The
  server continues to store only `base_url` in its run record and never echoes the
  key.
- **No DOM-XSS**: every probe-derived value (`monitor.diff` change severity/field/
  detail/implication, fingerprint ids, timestamps) and user string is HTML-escaped
  before it touches `innerHTML`; the Switches log uses `textContent`. (Does not
  reintroduce the #53 echoed-value DOM-XSS.)
- **Fast, cheap re-checks**: the watch spec defaults **behavioral + deception OFF**
  (fingerprint drift is a tokenizer+wire signal), so a re-check is quick and low-cost.
- **Egress guard intact**: each re-probe goes through `/api/assess`, so in
  public-hosting mode (`PROVENANCE_PROBE_BLOCK_PRIVATE`) a private target is still
  refused. **No new server endpoint, no new outbound request path** — nothing depends
  on a server daemon or stored keys, which is exactly why it works on the hosted demo.
- **The async poll can't wedge**: per-probe polling is bounded (attempt ceiling,
  always clears its interval) and a `busy` guard prevents overlapping probes.

### Security
- **Closed a credential-leak path** surfaced while hardening this feature (which
  runs unattended for hours, re-sending the key every tick): a pasted API key or
  session cookie carrying a stray newline / leading-trailing whitespace (a common
  clipboard/`.env` artifact) made `requests` raise `InvalidHeader` with the **raw
  secret in the exception message**, which the client swallowed into `Response.err`
  and then **persisted verbatim** into the on-disk report (served by
  `GET /report/<name>`). Fixed at the root in `Target.headers()` by sanitizing every
  caller-supplied header value (strip surrounding whitespace, drop control
  characters) so the secret can never reach header validation; added defense-in-depth
  redaction of any credential value from `Response.err` in `client.py`; and the watch
  form trims the key client-side. Protects the pre-existing `/api/assess` and CLI
  paths too — not just the new watch loop.

### Changed
- `explain.py` "Watching for model swaps" primer rewritten for the client-side watch
  (key stays in your browser, keep the tab open, always-on options: run locally — a
  background watcher is coming — or use the Observatory). Rendered on `/help`.

### Out of scope (P3)
- The **local always-on background watcher** + registry + webhook. P2 is browser-only.

## [0.21.0] - 2026-08-06 — Make the mission clear + automated capture discoverable (P1 / #62)

Content/UX only — **no engine, scoring, egress, auth, or route behaviour changed.**
The goal: a first-time, non-technical visitor should grasp within seconds that the
tool catches AI services that silently swap the model behind an API, see the two
things they can do, and know real services are being watched live.

### Added
- **Plain-English mission hero on the landing (`/`)** — headline *"Is the AI you're
  paying for still the AI you're getting?"* plus a jargon-free explanation of the
  silent-swap threat. The hero copy is the SINGLE source in `explain.py`
  (`MISSION_HEADLINE` / `MISSION_BODY`), shared with `/help` so the two never drift,
  and injected into the page escaped.
- **The two jobs named as the primary choices** — *"See what's answering right now"*
  (anchors to the existing probe form) and *"Watch a service for a silent swap"* (a
  prominent CTA to the capture/watch path). The watch card is honest that unattended,
  always-on watching is a later phase; for now it routes to capture + the Monitor
  compare panel.
- **Observatory "see it live" card** — a prominent LINKED card (not a heavy iframe)
  to the public observatory
  (`https://lobster-shrimp.github.io/provenance-observatory/`, override with
  `PROVENANCE_OBSERVATORY_URL`), opened in a new tab with `rel="noopener noreferrer"`.
- **Two new `/help` sections sourced from `explain.py`** — *"Why this matters"* (the
  silent-swap threat in non-technical terms, `WHY_THIS_MATTERS`) and *"Watching for
  model swaps"* (`WATCHING_PRIMER`), rendered through the escaping `_prose_section`
  helper.

### Changed
- **Capture-page UX pass** — the `/wizard` chooser and `/wizard/import` page now lead
  with the **one-click browser extension** (`extension/`, #54) as the recommended
  path, with the manual HAR recording kept as the no-install fallback. **Every route,
  form field id, JS behaviour, and the #53 `/wizard/capture-import` contract are
  preserved** (the extension link is a trusted internal literal, injected escaped).
- Landing hero styling: added `.jobs` / `.job` two-choice cards and the `.obs`
  Observatory linked-card styles to the shared design system (`ui.py`).

## [0.20.0] - 2026-08-05 — In-product documentation: plain-language `/help`, layer tooltips, verdict explainers

### Added
- **`provenance_probe/explain.py` — a single source of truth for all explainer
  copy.** `LAYERS` maps each evidence layer (network, wire, tokenizer, logprob,
  behavioral, deception, latency, artifacts) to a plain-language
  `{title, what it measures, what a "hit" means}`; `VERDICTS` explains the two
  independent axes (provenance = whose weights; jurisdiction = who runs it and
  where), each enumerating the **same five tiers** the scorer emits
  (`CONFIRMED / LIKELY / INDETERMINATE / UNLIKELY / NO EVIDENCE`) so a reader
  never meets an undocumented verdict word. `FLOWS`, `FAQ` and a worked
  `EXAMPLE` (a Chinese model on US servers = CONFIRMED provenance + UNLIKELY
  jurisdiction) live here too. Every downstream surface reads from this module —
  no copy is duplicated.
- **A `/help` page (`GET /help`)** rendered via `ui.doc()` from the module above:
  a plain-language tour of each flow (Live probe, Add a target / capture, Agent
  board, Monitor, Observatory), a "What each check does" table from `LAYERS`, a
  "What the verdict means" section from `VERDICTS` with the two-axis example, and
  a short privacy FAQ ("Do you store my key?", "Is my data sent anywhere?",
  "What if it says INDETERMINATE?"). Behind the global auth gate like every route.
- **A shared `ui.nav()` helper** carrying the standard poster nav incl. a **Help**
  link; `ui.header()` falls back to it when a page passes no custom nav, so Help
  is reachable from **every** page. The home nav gains the Help link alongside
  Observatory.
- **In-context explainers on the technical report** (`report.py`): each Signals
  "Layer" cell is now an `<abbr title=…>` sourced from `LAYERS` (hover for a
  one-line description; escaped for the attribute context), plus a "New here? see
  the help page" pointer. The probe form's Advanced options gains a short
  "these are optional — every check is explained on the help page" note.
- **Two demo-GIF slots** reusing the existing `<figure class="demo">` +
  `/media/` + caption-fallback pattern: `/media/probe-demo.gif` on the live
  probe page ("watch a probe run") and `/media/agent-demo.gif` on the agent
  board. The GIF files are dropped in by the maintainer later; until then the
  `<img>` 404s and its `onerror` hides it, leaving the caption.

### Notes
- **Additive/clarifying only.** No route, form field id, JS behavior, scoring or
  verdict path changed; the auth gate, egress guard, `/media` hardening and
  same-origin CSRF checks are untouched. Verified by `provenance-reviewer`
  (APPROVE) and `security-reviewer` (APPROVE — no findings).

## [0.19.0] - 2026-08-04 — Non-technical capture wizard: method chooser, plain-language guides, `/media` demo route

Restyle-and-clarify pass making the "add a target / capture" flow usable by a
**non-technical visitor**. No route, form field id, JS behavior, egress guard,
auth gate, same-origin gate, or the #53 `/wizard/capture-import` contract
changed — this is presentation only, built entirely on the shared `ui.doc()`
design system (no new dependencies, no framework).

### Added
- **A "which method is right for you?" chooser** at the top of `/wizard`: three
  plain-language cards — (A) "I have a plain API address" → the paste/identify
  path, (B) "It's a website I log into" (the **recommended, visually-emphasized**
  path) → the no-install browser capture / HAR import, and (C) "I already have a
  cURL or HAR" → the paste box. Each card says in one sentence when to use it and
  what it needs, and carries its primary action.
- **A read-only `GET /media/<path:name>` route** serving static demo media (GIF/
  PNG) from a new `provenance_probe/media/` package, so the capture guides can
  embed short walkthrough clips. Hardened against path traversal / LFI: it
  rejects any `..`/absolute/drive-letter/NUL path segment up front, resolves
  symlinks with `realpath()` and requires the result stay **inside** the media
  dir, allowlists a small set of media extensions/mimes, opens the final file
  with `O_NOFOLLOW` and requires a regular file (closing the realpath→open TOCTOU
  window), and sends `X-Content-Type-Options: nosniff`. It serves the bytes
  itself (no `send_file`, no directory listing) and stays **behind the global
  Basic-auth gate** like every route. `provenance_probe/media/*` is registered as
  package-data; a 1×1 `placeholder.gif` is committed so the route/tests work, and
  the real demo GIFs are dropped in later by the maintainer.
- **Embeddable demo-GIF slots** on `/wizard/capture` and `/wizard/import`: a
  `<figure>` whose `<img>` points at `/media/capture-guide.gif` /
  `/media/capture-import.gif` and, if the file is absent, hides itself via
  `onerror` and leaves a graceful caption fallback.
- `tests/test_capture_ux.py` — the `/media` route (serves an existing file, 404s
  a missing one, refuses percent-encoded/absolute traversal and non-allowlisted
  types, stays behind the auth gate), the chooser + capture/import step content
  rendering, and that `capture_guide.guide()` still returns coherent numbered
  steps.

### Changed
- **Every capture surface rewritten with big numbered visual steps and
  plain-language explainers.** `/wizard/capture` and `/wizard/import` now each
  open with a "What this does" line, an **"Is my login safe?"** reassurance
  (login never recorded / session cookie only sent to its own host / nothing
  leaves until you approve), a "What happens next" section, and 3–6 numbered
  steps with the exact click path. Jargon reduced (e.g. "the developer Network
  panel" instead of "DevTools → Network").
- Added `.chooser`, `ol.steps` (numbered step chips), and `figure.demo` classes
  to the shared `ui.py` stylesheet so the new surfaces stay on-system.
- Aligned the package version (`provenance_probe.__version__` and the
  `pyproject.toml` version were `0.18.0`/`0.18.2`) to **`0.19.0`**.

## [0.18.0] - 2026-08-04 — "Provenance" design system for the serve web UI

### Added
- **`provenance_probe/ui.py` — one shared "Provenance" stylesheet + page shell.**
  The DESIGN.md tokens (warm cream `--paper`, near-black `--ink`, deep-forest
  `--green` poster band, terminal-green `--green-ink` on the dark `--green-2`
  evidence card, and the verdict accents `--coral`/`--amber`/`--green`) as CSS
  custom properties, plus a Google Fonts `<link>` for **Fraunces** (display),
  **Geist** (UI), and **Geist Mono** (evidence/vectors). Exposes `header()`,
  `doc()`, and `verdict_color()` so both the live service and the standalone HTML
  report render from ONE source and never drift.

### Changed
- **`serve.py` — every server-rendered page now uses the shared shell.** The main
  probe/landing page, the agent board (`_AGENT_FORM`), the add-target wizard
  (`_WIZARD_FORM`), the consent (`_WIZARD_CONSENT`), preview (`_WIZARD_PREVIEW`),
  the `_wiz_page` helper, and the HAR-import page (`/wizard/import`) dropped their
  ad-hoc inline CSS in favour of a green poster header + cream body + one hot
  accent. The landing page leads with a Fraunces hero ("A lie detector for AI
  APIs") over a single clean form card.
- **`report.py` — the results HTML is now a verdict-first lab report.** A large
  Fraunces verdict headline in the verdict colour + a plain-English fact, a
  `VERDICT` stamp, then evidence as an editorial two-column layout: the
  tokenizer-match table as terminal-green mono on the dark card, big serif stat
  numbers, a signals table, a network & jurisdiction row, and a footer strip with
  artifact id, timestamp, engine version, target model, and a report hash.
- **The verdict → accent colour is driven by the real result** (`ui.verdict_color`
  / `report._lead_verdict`): `NO EVIDENCE`/US → green, `LIKELY` → amber,
  `CONFIRMED`/CN → coral. Never hardcoded per page.
- Corrected the stale `provenance_probe.__version__` (`0.3.0` → `0.18.0`) so the
  report's "analysis engine" footer reports the true version.

### Unchanged (restyle only — verified)
- Every route, form-field `name`/`id`, and client-side JS behaviour is preserved
  byte-for-byte: the `authorized` checkbox, the `/api/assess → run_id →
  /api/run/<rid>` polling, the wizard/import HAR JS (including its `esc()`
  DOM-XSS guard), and the `_same_origin_ok` / basic-auth / egress / cookie-origin
  gating. All user/measurement-derived strings remain HTML-escaped.

## [0.17.0] - 2026-08-04 — Hosted no-install capture: client-side HAR import (#53)

### Added
- **`provenance_probe/capture_import.py` — client-side capture normalizer.** Turns
  a client-supplied payload `{request:{method,url,headers,body},
  response:{status,headers,body}, prompt_hint}` (or a `{flows:[…]}` candidate
  list) into the internal `capture_proxy.Flow` / `wizard.Captured`. It REUSES the
  existing capture primitives — `capture_proxy.select_chat_flow` and
  `flow_to_captured` (which themselves use `detect_response_mode` /
  `sse_reassemble`) — so there is exactly ONE definition of "which request is the
  chat call" and how a response is fingerprinted; no new synthesis logic. Pure /
  no-I/O: it only reshapes an already-captured exchange.
- **`GET /wizard/import` page + `POST /wizard/capture-import` endpoint in
  `serve.py` — no-install, hosted-safe capture.** The user's OWN browser records
  the request (already logged into the target app), the HAR is parsed
  **client-side**, filtered to candidate JSON POSTs on the app's own registrable
  domain, auto-picked via `prompt_hint` (or chosen), sanitized (essential headers
  only; Cookie included only on explicit consent), and **only the single chosen
  flow is uploaded** — the full HAR with all its cookies never leaves the machine.
  The endpoint feeds the existing `flow_to_captured → synthesize → dry-run`
  pipeline and returns the synthesized target for review. A guided DevTools →
  Export HAR walkthrough is included; the wizard advertises this path in
  public-hosting mode (where server-side browser capture is refused).

### Security (load-bearing)
- **`/wizard/capture-import` is ALLOWED under the egress guard**
  (`PROVENANCE_PROBE_BLOCK_PRIVATE`), unlike `/wizard/capture-run` which stays
  refused. It is SSRF-safe by construction: it drives **no** browser and makes
  **no** arbitrary fetch at import time. The only outbound request is the optional
  dry-run replay, which goes through the ONE egress-guarded `Client` session — a
  target resolving to a private/metadata IP is refused before a socket opens.
- **Cookie handling:** a captured session cookie is used for an **ephemeral single
  dry-run and is NEVER persisted** on a guarded/public instance (no authed
  web-app target is saved there). Explicit consent must **name the destination
  host**; a cookie can only ever be replayed to the host it was captured from
  (`_cookie_origin_ok`, plus a captured-host cross-check before the cookie-bearing
  egress). The cookie value is never reflected into any response body.
- **CSRF / auth:** the endpoint requires `Content-Type: application/json` (415
  otherwise) and a localhost same-origin (`_same_origin_ok`, 403 otherwise),
  matching the other mutating wizard POSTs, and is covered by the global
  `before_request` basic-auth gate.
- The `/wizard/import` result page **HTML-escapes** every server/derived string
  (note / warnings / error / target JSON) before `innerHTML`, and renders
  HAR-derived values via `textContent`, so a malicious HAR cannot inject script
  (DOM-XSS closed in review).
- **OFF-path unchanged:** with the env flag unset, behavior is byte-identical; the
  only pre-existing-path change is `_capture_ui()` offering the import link
  instead of nothing when the guard is enabled.

### Tests
- **`tests/test_capture_import.py` (+14).** Normalizer (valid→Flow; missing
  request/response→clear error; non-JSON body→template adapter; SSE→reassembled;
  picks chat flow via `prompt_hint`), endpoint guards (auth-gated; JSON required;
  refuses without cookie-consent; cookie origin-bound; egress guard blocks a
  private dry-run host with no socket opened; ALLOWED while `/wizard/capture-run`
  is REFUSED under the same guard; page renders + escapes under the guard), and
  integration (a z.ai-shaped capture → import → synthesize → dry-run yields a
  usable target; a stateful/HTTP-400 capture → the existing "stale, re-capture"
  message with no false save).

## [0.16.0] - 2026-08-04 — Gated public-hosting mode: SSRF egress guard + basic auth (#51)

### Added
- **`provenance_probe/egress.py` — SSRF egress guard (`GuardedAdapter`).** A
  `requests` `HTTPAdapter` mounted on the shared probe session ONLY when
  `PROVENANCE_PROBE_BLOCK_PRIVATE` is truthy. It resolves the host the socket will
  actually connect to and **fails closed** if any answer is
  loopback / private (RFC1918 + ULA `fc00::/7`) / link-local / reserved /
  multicast / unspecified or the cloud-metadata IP `169.254.169.254`, and also on
  zero answers or a DNS failure. Literal-IP targets are validated directly.
  **DNS-rebinding defense:** the connection is *pinned* to the validated IP while
  the original `Host` header and TLS SNI + certificate hostname are preserved
  (`server_hostname`/`assert_hostname` stay the real name) — TLS verification is
  never weakened. Covers `chat` + its temperature retry + `raw_post` +
  `list_models` + redirects (all reuse the one guarded session, so a 3xx to an
  internal host is re-validated). When a proxy is configured the **proxy** host is
  validated (a private proxy is refused); `trust_env` is disabled so an ambient
  `HTTP(S)_PROXY` can't reroute the probe session.
- **Basic-auth gate in `serve.py`.** When `PROVENANCE_PROBE_BASIC_AUTH="user:pass"`
  is set, a `before_request` hook requires HTTP Basic auth on **all** routes
  (constant-time compare via `hmac.compare_digest`,
  `WWW-Authenticate: Basic realm="provenance-probe"` on 401). Parsed once at
  startup; a malformed value (no colon) fails loudly rather than silently
  disabling the gate.
- **`deploy/hf-space/README.md`** — Hugging Face Space file (YAML frontmatter
  `sdk: docker`, `app_port: 8770`) plus a PRIVATE→verify→PUBLIC deploy runbook:
  set both gates as Space secrets, hold ZERO vendor API keys (bring-your-own),
  and the "401 still reads as Running on HF" liveness note.
- Tests: `tests/test_egress.py` (classification incl. CGNAT/non-global,
  fail-closed, guard mount/unmount, the load-bearing rebinding/split-horizon pin
  for both the target and proxy legs, private-proxy refusal, and cross-surface +
  redirect + client-source + wizard-detect re-validation integration) and
  `tests/test_auth_gate.py`.

### Security (security-reviewer pass — all HIGH/CRITICAL driven to zero)
- **Every user-URL fetch on the public surface now routes through the guard, not
  just the probe `Client`.** The client-source scan (`clientsrc.scan_url`, reached
  via `/api/assess` `client_url`) and the wizard endpoint-detection probe
  (`detect._default_probe`, reached via `/wizard/detect`) previously used bare
  `requests` sessions — an unguarded SSRF hole in public-hosting mode. Both now
  mount the egress guard when the flag is set.
- **Proxy leg is pinned, not just validated once.** The proxy connection is now
  pinned to its validated IP (rewriting the proxy URL host), closing the
  DNS-rebinding window on the proxy socket.
- **RFC 6598 CGNAT (`100.64.0.0/10`) and all non-globally-routable addresses are
  blocked** (`is_private` misses CGNAT in CPython); added an explicit check plus an
  `is_global` catch-all.
- **`/api/assess` requires `Content-Type: application/json`** (415 otherwise),
  killing cross-origin form-based JSON-CSRF while the same-origin `fetch()` UI is
  unaffected.
- **Browser "Capture for me" flow refused in public-hosting mode.**
  `/wizard/capture-run` (+ `capture-advance`) navigate a real browser to a
  user-named URL and cannot be IP-pinned like the `requests` transport, so they are
  refused outright when `PROVENANCE_PROBE_BLOCK_PRIVATE` is set (capture is out of
  scope for the public instance); the button is hidden too. `_same_origin_ok` is
  not relied on here (a non-browser client sends no Origin/Referer).
- Fail-closed on all DNS resolution errors (`gaierror`/`OSError`/`UnicodeError`).

### Notes on proxy support
- Under `PROVENANCE_PROBE_BLOCK_PRIVATE=1`, `https://`-scheme proxies are
  unsupported: the proxy leg is pinned to the proxy's raw IP with no SNI override,
  so an `https://` proxy fails closed on a cert-hostname mismatch. Hosted mode
  should run without a proxy.

### Changed
- **`Dockerfile` `CMD` honors `$PORT`** (shell form,
  `--port ${PORT:-8770}`) for Render/HF/Cloud-Run portability.

### Notes
- All three pieces are **env-gated and OFF by default** — with the flags unset the
  transport is byte-identical to before (no adapter mounted, `trust_env`
  unchanged) and local single-user behavior is untouched. The HF Space deploy
  itself is the repo owner's step (needs their HF token) and is **not** performed
  by this change.

## [0.15.3] - 2026-07-30 — Security sign-off hardening for proxy capture (#44)

### Security (final security-reviewer pass)
- **CWE-59 symlink/TOCTOU on the credential write boundary.** `write_target` (and
  `ensure_gitignored`) now open `.env.capture` / `targets.json` / `.gitignore` with
  `O_NOFOLLOW` and fail loudly, so a pre-planted symlink can't redirect a captured
  session cookie to an attacker-chosen file on a shared/predictable directory.
- **`serve` capture leaked the ephemeral CA on process signal/exit.** The
  "Capture for me" flow runs in a daemon thread whose `finally` blocks don't run
  when the process is killed. `capture_proxy.install_process_cleanup()` (called by
  `serve`) now tears down every in-flight capture's browser + proxy + ephemeral-CA
  dir via `atexit` + a main-thread `SIGTERM` handler. Verified live: `SIGTERM` to
  `serve` mid-capture removes the CA dir and leaves no orphaned browser.
- **Domain binding for local/IP endpoints.** `_reg_domain` now exact-matches IP
  literals (previously `192.168.1.5` and `10.0.1.5` both collapsed to `1.5`) and
  uses the public-suffix list for multi-part TLDs — so a background request to an
  unrelated local endpoint can't be selected as the target and have its cookie saved.
- Defense-in-depth: Origin check added to `/wizard/save` + `/wizard/probe-response`;
  capture-worker error strings are redacted; recorded request/response bodies are
  size-capped (symmetry with the client's stream cap).

## [0.15.2] - 2026-07-30 — Clean teardown when a capture is aborted with SIGTERM (#44)

### Fixed
- **Aborting a proxy capture with `SIGTERM` (`kill <pid>`) leaked the ephemeral
  CA directory.** Python's default `SIGTERM` terminates the process without
  running the `finally` blocks that close the browser, stop the proxy, and remove
  the per-session CA dir — so the CA private-key files were left on disk. `capture()`
  now installs a `SIGTERM` handler (main thread only) that unwinds through those
  same teardown blocks, matching the existing clean `SIGINT` (Ctrl-C) behavior.
  Found by real-environment §4 abort testing. The proxy listener and browser
  already died with the process; this closes the on-disk CA leak.

## [0.15.1] - 2026-07-30 — Fix proxy capture on mitmproxy 12 (#44)

### Fixed
- **Proxy capture (`capture_proxy._MitmRecorder`) was broken on mitmproxy ≥12.**
  `DumpMaster.__init__` resolves the event loop via `asyncio.get_running_loop()`,
  so constructing it before the loop ran raised `RuntimeError: no running event
  loop` — i.e. `provenance-probe capture <url>` and the `/wizard` "Capture for
  me" button crashed on the version `mitmproxy>=11` resolves to today. The master
  is now built inside the running loop. Found by real-environment validation
  (the adapter was `# pragma: no cover` and had never run live).
- **Lingering proxy listener after teardown.** mitmproxy's Rust-backed listener
  isn't closed when `master.run()` returns, so the 127.0.0.1 proxy port survived
  `stop()` — a leaked listener per capture on the long-lived `serve` process. The
  servers are now torn down (`setup_servers()` with an empty mode) and the loop
  closed before the thread exits.

### Tests
- Added a `[capture]`-gated integration test that binds and cleanly tears down a
  real embedded proxy (skipped in CI; runs where the `[capture]` extra is
  installed). Registered the `integration` pytest marker.

## [0.15.0] - 2026-07-30 — Wizard "Capture for me" button (#44 child B)

### Added
- **"Capture for me" in the `/wizard` web UI.** The recording-proxy capture
  shipped in 0.14.0 (CLI) is now available from the browser: enter a URL, name,
  and the message you'll send, and the wizard runs the proxy capture and lands
  you on the editable preview → save. New endpoints: `POST /wizard/capture-run`
  (starts the capture in a background thread), `POST /wizard/capture-advance`
  (the two-phase "Continue" button — log in, then send one message),
  `GET /wizard/capture-run/<id>` (status poll), `GET /wizard/capture-preview/<id>`.
  The session cookie is held server-side only and never reflected to the browser;
  runs are one-shot. Shown only when the `[capture]` extra is installed.

### Security (adversarial review — Codex + Claude)
- **CSRF guard** on the capture endpoints: a cross-site POST can't start a
  browser-driving capture (Origin/Referer must be the local origin). URL scheme
  restricted to http(s).
- **No resource leak on abandon:** the worker's wait for each "Continue" is
  bounded (times out to an error) so a closed tab can't strand a thread/browser.
- **Safe eviction:** the run map drops only finished runs, never an in-flight one
  (which would strand its worker and lose its cookie).

## [0.14.0] - 2026-07-29 — Local recording-proxy web-app capture (#44)

### Added
- **Local recording-proxy capture (`provenance_probe/capture_proxy.py`).**
  `provenance-probe capture <url>` now captures the real chat request **and**
  response end-to-end and saves a probeable `template` target — no manual HAR
  paste. It drives an isolated throwaway browser through a localhost
  TLS-intercepting proxy (mitmproxy), two-phase so the login is never recorded,
  and feeds the existing `wizard.synthesize → dry_run → write_target` pipeline.
  The interception CA is ephemeral (per-session 0600 temp dir, removed on exit)
  and trusted by nothing in any OS/browser store — the throwaway context uses
  `ignore_https_errors` so no CA install is needed.
- **Three explicit capture modes:** `capture <url>` (proxy, default),
  `--paste` (manual copy-as-cURL / save-HAR steps), `--auto` (legacy HAR record).
- **Streamed-response support (SSE + JSON-lines), end-to-end.** Response mode is
  detected by sniffing the body, not the `content-type` header, so a stream
  mislabeled `text/plain` (e.g. v0.app) is handled. JSON-lines streams replay
  through the runtime client. `[capture]` extra now also installs `mitmproxy`.

### Changed
- **`wizard.synthesize` locates the reply path with the echo-safe detector**
  (`find_reply_path`) so an app that echoes the user's turn no longer mis-selects
  the prompt as the reply. Shared chat-request scorer (`score_chat_request`)
  lifted out of `parse_har` so HAR and proxy capture pick "the chat call" the
  same way. `Captured` gained `stream_delta_path`.
- Stateful request fields are blanked more precisely for replay-safety
  (`chatId`/`messageId` blanked; a `*model*` selector field is never blanked).

### Security (pre-landing review — Codex + security/python specialists + Claude)
- Flow selection is bound to the target's registrable domain, so a third-party
  background POST can't be saved with the wrong site's session cookie.
- Browser/contexts are torn down on the error/abort path (an abort no longer
  leaves a headed Chromium profile holding the live session cookie).
- A stream with no matching delta path fails the dry-run instead of saving a
  broken target that returns raw protocol text as the "reply."
- The recording proxy binds `127.0.0.1` only; the proxy thread is joined before
  the ephemeral-CA dir is removed; streamed bodies are byte-capped; capture error
  output redacts URL query strings.
- **Note:** the mitmproxy/Playwright adapter (`_MitmRecorder`, `_default_driver`)
  is exercised only with the `[capture]` extra installed and a real browser; it
  still needs a real-environment validation pass (TLS interception, keychain
  absence, abort cleanup) before it should be relied on in production.

## [0.13.0] - 2026-07-28 — Guided web-app capture (P3 / E8)

### Added
- **Guided capture (`provenance_probe/capture_guide.py` + `/wizard/capture` +
  `provenance-probe capture`).** Annotated, browser-specific (Chrome/Firefox/
  Safari) step-by-step instructions for capturing the one chat request the
  `template` adapter needs — for operators who have never opened DevTools.
  Names known apps (ChatGPT/Claude/Gemini/Lindy/Z.ai/…), tailors the "Copy as
  cURL" label per browser, offers the HAR alternative, and always carries the
  credential-safety note. No new dependency.
- **Optional Playwright capture assist (`capture --auto`, `[capture]` extra).**
  Drives a headed browser to your target and records the chat request to a HAR
  the wizard ingests. **Two-phase so your login is never recorded:** you log in
  in an *unrecorded* context; only the authenticated session's chat traffic is
  captured. The tool never types or sees a password. The HAR is written 0600 to
  a private `~/.provenance-probe/captures/` dir (gitignored if it lands in a
  repo) and clearly flagged as credential-bearing. Absent Playwright, `--auto`
  degrades to the manual guided steps.

### Security (adversarial review — Codex + Claude)
- Two-phase capture keeps the login POST / OAuth / password out of every HAR
  (was: recording started before login). Credential-bearing HAR defaults to a
  private 0600 path, never cwd, and is gitignored inside a repo.

## [0.12.0] - 2026-07-28 — OmniRoute cross-check + calibration gate (P2a)

### Added
- **`provenance_probe/omniroute.py` + `provenance-probe omniroute` CLI.** Uses a
  local OmniRoute router (localhost:20128) as an OPTIONAL accelerator and a second
  evidence source: fingerprint a model *through* OmniRoute and cross-check the
  router's claimed model against the tokenizer fingerprint.
- **Calibration gate (the honest core).** Measuring through OmniRoute only works
  if its injected ~2000-token system prompt is a *constant* offset that cancels.
  We test exactly that: subtract the modal overhead, then require ≥90% of probes
  to match a known family's first-party reference **exactly**. Until a given
  OmniRoute version calibrates, a via-OmniRoute verdict is **confidence-capped
  (never CONFIRMED, max SUGGESTIVE)**.
- **Three-state cross-check.** Router claim → family (maintained label→family map)
  vs fingerprint → `CORROBORATED` / `INCONCLUSIVE` / `CONTRADICTED`. INCONCLUSIVE
  is the default for any uncertainty (unknown label, uncalibrated, unclear family
  relation); version drift (V4 reuses V3's tokenizer) is CORROBORATED. **A
  CONTRADICTED result is an analyst-review signal, never an auto-published
  verdict** (quarantined).
- Captures `x-omniroute-*` router metadata as evidence; records a first-class
  `measurement_path: via_omniroute`.

### Finding
- **OmniRoute v3.8.48 does NOT calibrate.** Empirically it injects ~2004 tokens
  and lands 15/20 probes exact after offset (0.75, below the 0.90 bar); the 5
  misses are CJK/whitespace probes — the ones that matter most for CN origin.
  So measuring DeepSeek through this OmniRoute is reported as **SUGGESTIVE, not
  CONFIRMED** — the calibration gate correctly refuses to over-claim what an
  earlier n=1 observation had read as a clean match.

### Hardening (adversarial review — Codex + Claude)
- Calibration metric changed from Pearson correlation (scale-blind; false-passed
  156 cross-family pairs, e.g. OpenAI-o200k vs DeepSeek at r≈0.99) to
  exact-fraction-after-offset (cross-family false-passes → 4, all genuine
  tokenizer-twins). CONFIRMED now also requires the cross-check not be
  CONTRADICTED and a decisive fingerprint score. Router claim reads the
  `x-omniroute-model` header, never the user's typed route. Family rooting
  handles vendor-suffixed reference names (`GLM/Zhipu`); related roots
  (`gpt` ⊂ `gptneox`) never produce a false CONTRADICTED.

## [0.11.0] - 2026-07-28 — One-door add-target: auto-detect API style

### Added
- **One-door "Add a target" wizard (`/wizard`).** A single box takes whatever you
  have — a plain API address, a `curl` command, or a saved HAR — and figures out
  the rest. The operator never picks an "API style" (CEO plan E1/E2). A pasted
  URL is identified by *observing* the endpoint, not guessing from the name.
- **`provenance_probe/detect.py` — endpoint auto-detection.** A local input
  classifier (`classify_input`) plus an API-probe state machine (`detect`) that
  infers `api_style` (openai | anthropic) from responses. LLM-POSITIVE requires
  the full combination — assistant content **and** integer usage **and** a model
  id — else INDETERMINATE (no false-positive JSON detection). Ambiguous or
  partial matches ALWAYS ask for confirmation (E6); errors are plain sentences,
  never stack traces.
- **Consent gate before any network egress.** A pasted endpoint runs no probe
  until the operator approves, enforced by a one-shot **server-side consent
  token** (a direct/CSRF POST to `/wizard/detect` sends nothing). The consent
  copy states the real request volume (~28 for a full check), not "one test".
- **`provenance_probe/presets.py` — known-vendor presets (E4) + env-key lookup
  (E3).** Recognizes OpenAI/Anthropic/DeepSeek/Moonshot/OpenRouter/Gemini by
  **hostname** (exact-or-subdomain, not substring — a look-alike host like
  `api.openai.com.evil.test` is rejected) and offers a `{VENDOR}_API_KEY` already
  in your environment. The key **value never touches the committed config**; only
  the env-var NAME rides `auth_value_env`.
- **`EgressBudget`** caps the identify phase so it can't runaway.
- Plain-English detection card + one-click **"Probe it now"** hand-off to the
  probe tool with the target prefilled (E5). +48 tests.

### Security (hardening from adversarial review — Codex + Claude)
- Vendor matching is hostname-aware (was substring) — closes a credential-exfil
  path to look-alike hosts. The write-boundary secret-header filter now strips
  smuggled key headers (`X-Api-Key-Alt`, `x-session-token`) while keeping CSRF
  headers needed for replay. Every detection carries a self-reported-usage caveat.

## [0.10.0] - 2026-07-26 — Add-target wizard (paste-first)

### Added
- **Add-a-target wizard in the local `serve` UI (`/wizard`, 127.0.0.1 only).**
  Paste a captured web-app chat request (DevTools → Copy-as-cURL, or a saved HAR)
  and it synthesizes a `template` target: `base_url`/`chat_path`, a
  `request_template` (your prompt → `__PROMPT__`; stateful conversation/message
  ids blanked for replay-safety), response dotted-paths (text/usage/model, from a
  HAR response), SSE detection, and CSRF/origin headers (dynamic ones flagged).
  A 2-probe **dry-run** checks HTTP health, usage exposure, and replay-safety
  before saving. **Security:** the session cookie is written only to a gitignored
  `.env.capture` (auto-added to `.gitignore`) and referenced by `cookie_env` — it
  never enters the committed config; saved targets default `authorized: false`.
  Paste-first v1 (no browser dependency); `provenance_probe/wizard.py` +28 tests.
  Playwright auto-capture is a planned optional `[capture]` extra.

### Changed
- **Publication policy is now full transparency.** The observatory publishes the
  complete work behind every finding — measurements **and** the interpreted
  provenance/jurisdiction verdict — as collected, in an append-only signed log,
  so consumers can see exactly how each verdict was reached. The prior two-tier
  withholding + 30-day disclosure-window gate is removed. Accuracy safeguards are
  retained and emphasized: known-answer + negative controls, a published
  false-positive rate, per-verdict confidence labels, and prominent
  corrections/retractions. `DISCLOSURE.md` rewritten as the operative policy;
  `docs/tos-notes.md` / `counsel-brief.md` / `openrouter-approval-request.md`
  retained as risk context (no longer gates); README/WHITEPAPER/EXTENDING updated.

## [0.9.1] - 2026-07-26

### Fixed
- **Anthropic endpoints now measure provenance instead of flooring at
  INDETERMINATE.** `api_style: "anthropic"` auto-configures the `/v1/messages`
  path and `x-api-key` auth (they were defaulting to the OpenAI
  `/chat/completions` + `Authorization: Bearer`, so probes 404'd and no usage came
  back). Anthropic returns `usage.input_tokens`, which the tokenizer battery reads.
- **`serve` web UI now honours the target's auth scheme.** It injected the entered
  key as a hardcoded `Authorization: Bearer`, bypassing the anthropic `x-api-key`;
  it now uses the target's configured `auth_header`/`auth_prefix`.

### Added
- **Claude and Gemini reference vectors.** Both families now clear to a firm non-CN
  **NO EVIDENCE** (were UNLIKELY / INDETERMINATE). Their tokenizers aren't published,
  so the vectors are measured from the genuine first-party API — a genuine endpoint
  matches its own family ≈1.0 with CN families near zero.
- **`build-reference-endpoint`** — measure a reference vector from a live authorized
  first-party endpoint (requires `--i-am-authorized`; entries tagged
  `source: "live-first-party-api"`). This is the supported path for families with no
  published tokenizer.
- **[`docs/EXTENDING.md`](docs/EXTENDING.md)** — the coverage playbook: adding API
  / web-app / **agent** sources, adding a **model family to the reference corpus**
  (including the live-endpoint path for Claude/Gemini), and continuous monitoring.

## [0.9.0] - 2026-07-25 — Adversarial red-team corpus (E8)

### Fixed (pre-merge adversarial review — Codex)
- **`redteam` requires `--i-am-authorized`** (an explicit per-run attestation, not
  just config) — the prompts are deliberately adversarial.
- **Adapter-aware identity:** reads `Response.echoed_model()` / `.text()`, so
  template / Anthropic / raw endpoints are covered, not just OpenAI-shaped JSON.
- **`model_id` is the hard switch signal** (drives exit 2); a changing `self_id`
  is an advisory `self_id_flags` entry — the corpus asks about "underlying"
  identity, so a refusal/negation can trip the self-ID regex and must not fire a
  false alert. Baseline signals backfill (a never-seen signal is seeded, not a
  switch). A non-2xx transport response is recorded as an error, not a clean
  no-identity scenario.

### Added
- **`redteam` command.** Drives an authorized endpoint through a corpus of
  stress / adversarial prompts (`provenance_probe/redteam.py`) and detects whether
  the served model's identity **changes under pressure** — a router that swaps to a
  cheaper or fallback model when pushed, or reveals a different origin. Reuses the
  same passive identity (echoed model id + self-ID) as the sentinel, so a
  switch-under-stress is reported like a mid-session switch. `--cap N` bounds the
  quota/abuse budget; one scenario erroring never aborts the run; **exit 2** on a
  switch. Authorized-use only (the prompts are deliberately provocative).

## [0.8.0] - 2026-07-25 — Live agent board (E4)

### Fixed (pre-merge adversarial review — Codex)
- **Reflected XSS on `/agent/live` closed.** An attacker-controlled `?session=`
  went into an inline `<script>`; `json.dumps` escaped JS quotes but not
  `</script>`, so `?session=</script><img src=x onerror=…>` broke out. Now `<`/`>`
  are escaped to `<`/`>` too (regression test added). The rendered report
  fragment was already fully `html.escape`d.
- **Read-side DoS bounded:** `/agent/report.html` caches the rendered fragment per
  `(session, step-count)`, so a 2s poll with no new calls is O(1) (no re-render).
- Live/read endpoints are a local surface (like `/sentinel/events`) — serve
  loopback-only; front with auth if you change `--host`.

### Added
- **Live streaming board in the `sentinel` proxy.** `GET /agent/live?session=<id>`
  serves a self-contained page that shows the per-step board **updating in real
  time** as the agent makes calls through the proxy — session picker, animated
  live indicator, pause/resume. It polls a server-rendered report fragment
  (`GET /agent/report.html`), so it reuses the same tooltip-rich `agent_report`
  render (DRY) — hover any term for what it means. `GET /sentinel/sessions` lists
  active sessions. Browser-verified live against a real endpoint (board went
  2 → 3 steps as calls arrived, no reload).

## [0.7.0] - 2026-07-25 — Sub-agent call graph (E6)

### Fixed (pre-merge adversarial review — Codex)
- **No recursion on deep graphs.** `agent_graph.flatten` and the sentinel
  `/agent/graph` builder are now iterative (a 1500-deep acyclic chain — reachable
  under `MAX_STEPS=5000` — no longer `RecursionError`s the report/endpoint);
  `/agent/graph` caps nested-JSON depth.
- **Parent reachable even with no own call:** a child declaring `X-Provenance-Parent`
  creates a placeholder parent session, so `/agent/graph?session=<parent>` works
  even when the parent made no proxied call itself.
- **No silent reparenting** (first-writer wins) and **first-span-wins** on duplicate
  span ids (adversarial traces can't misattach nodes).

### Added
- **Sub-agent call graph.** When a trace carries span parentage (OpenTelemetry
  `spanId`/`parentSpanId`) or the proxy carries `X-Provenance-Parent`, the flat
  per-step board nests into the tree that actually ran — you see *which* step
  spawned the sub-call that switched models or leaked data. `AgentStep` gains
  `span_id`/`parent_id`; `agent_graph.build_tree` is cycle-safe (ancestor-walk
  guard) and drops nothing (a missing/cyclic parent attaches at the root).
- The HTML report renders a **"Sub-agent call graph"** section (indented tree)
  when parentage exists, and documents the blind spot: a sub-agent calling an
  un-proxied backend, or whose spans aren't exported, can't appear.
- **`sentinel` `GET /agent/graph?session=<root>`** returns the tree of sessions
  linked by `X-Provenance-Parent`, each node carrying that agent's verdict.

## [0.6.0] - 2026-07-25 — Agent Flight Recorder Phase 2 (A + E5)

### Fixed (pre-merge adversarial review — Codex)
- **Baseline no longer poisoned by a model-less first response.** A first response
  with no `model_id` (e.g. a 400) set the session baseline to `None` and silently
  swallowed all later switches; the baseline now backfills a never-seen signal
  without alerting, so a real later switch is still caught (regression test added).
- **SSE memory limits are now reliable under concurrency:** the runaway-line guard
  caps `buf` at `MAX_LINE`, and the per-call + global accumulation ceiling is
  checked-and-reserved atomically under one lock (was a TOCTOU race that let
  concurrent streams blow past `MAX_GLOBAL_ACCUM`).
- **Upstream sockets are closed** (`r.close()`) in the tee, JSON, and passthrough
  paths — no socket leak on client disconnect.
- **TTL eviction skips in-flight sessions** (`last` refreshed on entry) so a long
  stream isn't evicted mid-call; distinct sessions capped (evict oldest idle) and
  the event log bounded.
- **Passthrough is fully transparent:** adds `HEAD`/`OPTIONS`, forwards raw bytes,
  and preserves `content-encoding`.

### Added — live proxy interposition (A)
- **`sentinel` is now a live agent flight recorder.** The proxy **tees SSE**
  streams — forwards each chunk to the agent unchanged as it arrives (preserves
  token-streaming), accumulates the delta in parallel (capped per-call + a global
  in-flight ceiling), fingerprints on completion. **Fail-open:** a fingerprinting
  error can never alter or truncate the proxied bytes (tested: raise at mid-stream,
  all chunks still arrive).
- **Generic passthrough** — every path/method reaches upstream unchanged (not just
  `/v1/chat/completions`), so the proxy is a real `base_url` interposition point;
  provenance is collected only on chat completions.
- **Response headers preserved** end-to-end (hop-by-hop denylist) — vendor/rate-limit
  headers are both agent-visible behavior and wire evidence.
- Per-session `AgentStep` accumulation + `GET /agent/report?session=…` runs
  `agent.analyze` over the collected steps. Session key = `X-Provenance-Session`;
  concurrent calls without it are flagged `unordered`, which **withholds** the
  switch verdict. Per-session step cap + byte accounting + TTL eviction.
- Passive by design: the proxy emits a response-IDENTITY (model id / self-ID /
  header shape) for switch detection — NOT a tokenizer fingerprint (that needs the
  active probe). Shared `client.parse_sse_delta` (one SSE parser for client + proxy).

### Added — export pack (E5)
- **`--export` on `agent`/`agent-trace`** writes a deterministic, signed-ready
  evidence record (`agent_export.py`): verdict + per-step board + engine version +
  SHA256 of the input, canonical JSON (`captured_at` isolated so the core is
  reproducible). The record drops under the observatory `data/agents/<target>/<date>/`
  tree and is signed by the existing daily cosign+Rekor manifest — the observatory's
  `build_manifest` now includes agent records. No signing in the engine, no
  duplicated crypto.

### Added — `AgentStep` quality fields
- `degraded` / `unordered` / `truncated` / `session_id`, carried through `analyze`,
  the report (badges + tooltips), and the export. An `unordered` step withholds
  order-dependent switch claims instead of asserting a meaningless one.

## [0.5.2] - 2026-07-25

### Added — the agent report illustrates what happened, and it's in the local UI
- **Bolstered HTML report.** Beyond the per-step board, it now leads with a
  plain-language **"What happened"** narrative (steps, distinct models, each model
  switch, which steps flagged and why, overall verdict), a **"What this tool did"**
  panel naming the observation surfaces that ran (trace ingest / egress mapping /
  active probe — or why the probe didn't run), and an **"Evidence — why each verdict
  fired"** table listing the actual signals per step. So a non-technical reviewer
  sees the reasoning, not just a tier.
- **Agent board in the local `serve` UI.** New `/agent` route + an "Agent board →"
  nav link: paste an agent trace (OTel spans or minimal JSON), get the full
  tooltip-rich report in the browser. Reuses `agent_report.render_html` (DRY);
  untrusted-trace hosts are not DNS-resolved unless you tick the box.
- `render_html(..., fragment=True)` for embedding; +4 tests (112 total).

## [0.5.1] - 2026-07-25

### Added — agent board: operator/soil basis + educational HTML report
- **Jurisdiction basis on the board.** Each step now carries `jurisdiction_basis`
  (the network layer's operator-vs-soil distinction), so the board shows *why* a
  step is flagged: `CONFIRMED (PRC-soil)` vs `CONFIRMED (PRC-operator)` vs
  `UNLIKELY (non-PRC-1p)`. Surfaces that a CDN-fronted PRC vendor (e.g.
  `api.moonshot.ai` → Cloudflare) is caught on operator grounds even when geo-IP
  reads "US".
- **`--html` report** (`provenance_probe/agent_report.py`) — a self-contained HTML
  page for `agent-trace` / `agent` with **hover tooltips on every column, verdict
  tier, and concept** (provenance vs jurisdiction, each tier's meaning, model
  switch, egress, active probe, operator vs soil, …) plus a full glossary. Teaches
  a non-technical reviewer what the tool measured and what each verdict means.
- +3 tests (108 total).

## [0.5.0] - 2026-07-25

### Added — Agent Provenance Flight Recorder (Phase 1)
- The unit of assessment can now be an **agent** (a multi-step, multi-model
  workflow), not just one endpoint. `provenance_probe/agent.py` ingests a captured
  agent run and reports a per-step board: which model each step ran on, model
  switches across steps, and tool-call egress jurisdiction.
- `agent-trace <file>` CLI — ingest **OpenTelemetry GenAI spans** (primary) or a
  minimal JSON fallback; prints the board; **exit 2** on a model switch.
- `agent --config a.json` CLI — config-driven assessment: trace ingest + optional
  **active backend probe** (the only route to a CONFIRMED provenance verdict).
- `AgentTarget` / `AgentBackend` config types with **per-backend authorization** —
  active probing aborts on the first unauthorized backend (the consent surface
  widens to the agent operator AND each backend).
- `scoring.combine_agent()` — agent verdict = the worst step, labelled MIXED when
  steps differ; the full per-step board is always shown.
- Honest by design: trace-only provenance floors at INDETERMINATE (no tokenizer
  signal in a post-hoc trace). Egress jurisdiction and model switch are the
  reliable trace signals. `docs/CONOPS.md` = executive/federal concept of ops.
- 26 tests (`tests/test_agent.py`), fixtures for OTel + JSON traces.

### Security / hardening (agent trace ingest)
- **SSRF guard:** an ingested agent trace is untrusted, so `agent-trace` does NOT
  DNS-resolve trace-supplied hosts by default — static hostname jurisdiction
  signals (`.cn`, known PRC endpoints) still fire with zero network I/O. Pass
  `--resolve-hosts` to opt into DNS + RDAP. `network.analyze_host` gained a
  `resolve` flag and a private/reserved/loopback/link-local/metadata IP denylist
  (`_blocked_ip`) applied to both IP-literal hosts and resolved addresses
  (DNS-rebinding defense), plus a distinct-host cap.
- **Self-ID now scores:** a step whose text concedes a CN family feeds `selfid_cn`
  into scoring (previously written to a dead `_self_id` key scoring never read).
- **Switch detection namespaced:** echoed-model-id changes and self-ID brand flips
  are tracked separately (no more spurious `gpt-4o -> OpenAI` cross-namespace hits).
- **Exit-on-worst-verdict:** `agent`/`agent-trace` exit 2 on a LIKELY/CONFIRMED
  worst step even without a switch (CI no longer reads a PRC finding as clean).
- **Malformed-trace hardening:** non-object rows/spans, non-list containers, and
  over-size/over-step traces raise `TraceError`; unknown config keys raise a clear
  `ValueError` instead of a raw `TypeError`.

## [0.4.1] - 2026-07-20

### Fixed
- **`fingerprint_id` no longer flips on a benign chat-template / token-accounting
  change.** `_fp()` hashed the raw tokenizer vector (raw `prompt_tokens`), so a
  constant per-probe overhead shift from an endpoint changing its chat template
  or token accounting produced a new fingerprint — a false "backend changed"
  drift. The fingerprint now hashes the overhead-invariant *shape* of the vector
  (each probe minus the vector's own minimum), which cancels a constant offset
  while preserving the relative structure that distinguishes tokenizer families.
- **`monitor` no longer reports a critical `tokenizer_vector` drift on the same
  benign overhead shift.** Its direct probe-count diff now compares the
  overhead-corrected shape instead of raw counts, matching the fingerprint fix.
  A genuine change in relative token structure still drifts.

### Added
- `tokenizer.shape_vector()` — reference-free overhead-invariant form of a probe
  vector, used by both `_fp()` and `monitor`.
- First automated test suite (`tests/`, `pip install -e '.[test]'`): 12
  characterization tests pinning the three contracts downstream tooling depends
  on — fingerprint overhead-invariance, `monitor` exit-2 drift semantics
  (including no-false-drift on benign overhead), and tokenizer family match
  against the shipped Qwen2 reference.
