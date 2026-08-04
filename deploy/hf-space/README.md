---
title: Provenance Probe
emoji: 🔎
colorFrom: indigo
colorTo: gray
sdk: docker
app_port: 8770
pinned: false
---

# provenance-probe — Hugging Face Space deploy runbook

This directory documents how to run a **public demo** of `provenance-probe serve`
on a [Hugging Face Space](https://huggingface.co/docs/hub/spaces) using the
Docker SDK. The frontmatter above is what a Space needs: `sdk: docker` (build the
repo `Dockerfile`) and `app_port: 8770` (the port HF routes to; the container's
`CMD` already honors `$PORT` and falls back to `8770`).

> **Why this is gated.** The whole job of this UI is to make an outbound request
> to an endpoint *you* name. An unauthenticated public instance is therefore an
> open SSRF/egress proxy. Two env-gated protections MUST be on for any public
> exposure:
>
> | Env var | Value | Effect |
> |---|---|---|
> | `PROVENANCE_PROBE_BLOCK_PRIVATE` | `1` | Mounts the SSRF egress guard: refuses targets/proxies that resolve to loopback / private / link-local / reserved / ULA / multicast / unspecified, or the cloud-metadata IP `169.254.169.254`; pins the connection to the validated IP to defeat DNS rebinding. |
> | `PROVENANCE_PROBE_BASIC_AUTH` | `user:pass` | Requires HTTP Basic auth on **all** routes. |
>
> Both are OFF by default so local single-user use is unaffected.

## Hold ZERO vendor API keys

**Do not put any vendor API keys (OpenAI, Anthropic, DeepSeek, Moonshot, …) in
the Space — not as secrets, not in config, not baked into the image.** A public
instance holding a key is a key-burning proxy. The hosted instance is
**bring-your-own-key** (see below). The only secrets the Space needs are the two
gate variables above.

## 1. Create the Space (PRIVATE first)

1. Create a new Space: **New → Space**. Set **SDK = Docker**, **Visibility =
   Private**. (Keep it private until you have verified both gates are live.)
2. Point the Space at this repository's build. Either:
   - push this repo to the Space git remote (the root `Dockerfile` is the build), or
   - use a one-line `Dockerfile` in the Space that `FROM`s a published image / does
     `pip install` of this package, then runs the same `CMD`.
   The container listens on `8770`, matching `app_port`.

## 2. Set the gate variables as Space **secrets**

In the Space: **Settings → Variables and secrets → New secret**. Add BOTH as
**secrets** (not public variables — the basic-auth pair is a credential):

```
PROVENANCE_PROBE_BLOCK_PRIVATE = 1
PROVENANCE_PROBE_BASIC_AUTH     = <choose-a-user>:<choose-a-strong-pass>
```

A malformed `PROVENANCE_PROBE_BASIC_AUTH` with no colon makes the app **fail to
start** (by design — it refuses to run with auth silently disabled). If the Space
crashes on boot, check that value first.

## 3. Verify on HF infra (still PRIVATE)

Open the Space (as the owner, private) and confirm:

- [ ] The browser is challenged for HTTP Basic auth, and wrong credentials get a
      401 with a `WWW-Authenticate: Basic realm="provenance-probe"` header.
- [ ] Correct credentials load the UI.
- [ ] With `PROVENANCE_PROBE_BLOCK_PRIVATE=1`, an assessment of an internal
      target (e.g. `http://127.0.0.1:8770`, `http://169.254.169.254/…`, or a host
      that resolves privately) fails with a transport error that names the blocked
      address — and no internal request is made.
- [ ] Assessing a real *public* endpoint still works (HTTPS cert validation
      unchanged).

> **Liveness note.** HF reads the Space as **"Running"** when the port answers —
> and a 401 is a valid HTTP response. So the Space will show "Running" while the
> browser still gets 401 until you authenticate. That is expected, not a failure.

## 4. Flip to PUBLIC

Only after every checkbox above passes: **Settings → Change visibility →
Public**. Rollback at any time by flipping back to Private (or deleting the
Space) — instant.

## Bring-your-own-key (how users run keyed endpoints)

Because the server holds **no** vendor keys:

- **Keyless / already-authenticated endpoints** (e.g. a local-network model, or a
  web-app template capture) work as-is, subject to the egress guard.
- **Keyed vendor endpoints** require the *user* to supply their own API key in
  the assessment form / target config for that run. The key is used only for that
  request and is not persisted server-side.
- The **browser "Capture for me" flow is disabled in public-hosting mode.** When
  `PROVENANCE_PROBE_BLOCK_PRIVATE` is set, `/wizard/capture-run` is refused
  outright: it drives a real headless browser to a user-named URL, which cannot be
  IP-pinned like the `requests` transport, so it would be an SSRF hole. Do **not**
  rely on the localhost same-origin check (`_same_origin_ok`) for this — a
  non-browser client sends no `Origin`/`Referer` and would pass it; the hard
  control is the `BLOCK_PRIVATE` refusal. (Also: do not install the `[capture]`
  extra in a public image.) The core fingerprint flow (enter a target, run the
  assessment) still works. Users who want capture should run the tool locally
  (`pip install` + `provenance-probe serve`).
- The **wizard "save target" flow** (`/wizard/save`) is same-origin-restricted to a
  localhost Origin/Referer, so a cross-origin browser POST is refused; it also only
  writes target config to the container's own disk (no egress). Run it locally for
  the full wizard-save experience.

## Proxy note

**Run the hosted instance without a proxy.** Hosted mode disables `trust_env`, so
an ambient `HTTP_PROXY` / `HTTPS_PROXY` on the Space host is **not** honored for
the probe session. If a user configures an inspecting proxy in a target, the guard
validates the **proxy** host (a private proxy is refused) and pins the proxy
connection to the validated IP. Two caveats in this mode:

- **`https://`-scheme proxies are unsupported.** The proxy connection is pinned to
  the proxy's raw IP with no SNI override for the proxy leg, so an `https://` proxy
  fails closed with a TLS cert-hostname mismatch. Only plain-`http://` proxies (or,
  preferably, no proxy) work.
- With a proxy set, the destination host is reached by the proxy, not the container,
  so the destination is not IP-pinned locally. This does not grant SSRF into the
  container's own network (the proxy performs the connect), but it is another reason
  hosted mode should run without a proxy.
