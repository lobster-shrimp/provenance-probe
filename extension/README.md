# provenance-probe capture (Chrome extension)

A Manifest V3 browser extension that gives non-technical users a **one-click**
alternative to the HAR-upload path: it captures the target AI app's chat request
**in your own browser and session** and uploads it to **your** hosted
`provenance-probe` instance's `POST /wizard/capture-import` endpoint.

It is purely a **second front-end onto the same server ingest** shipped in #53.
There is **no server-side browser** — the capture happens client-side in the tab
you are already logged into, exactly like the built-in HAR uploader — so it adds
**no SSRF surface** and **no new server contract**.

Chrome-first (Firefox/Edge packaging is a later follow-up).

---

## What it does

1. In the **popup** you set your hosted instance URL + Basic-auth username /
   password **once**. These are stored only in `chrome.storage.local` on your
   machine and are sent only to that instance, over HTTPS.
2. Open your AI chat app, log in, open **DevTools → "Provenance Capture"**, and
   click **Arm capture**.
3. Send **one** short message. The panel records requests **only while armed**
   and **only for the inspected tab**, picks the chat/model POST (using the same
   scorer as the HAR uploader), and shows it for confirmation.
4. If the request carries a session cookie, an explicit **cookie-consent** prompt
   that **names the destination host** must be ticked before anything is sent.
5. On upload the panel assembles the **same normalized payload** the endpoint
   expects — `{ name, prompt_hint, cookie_consent, request:{method,url,headers,body}, response:{status,headers,body} }` —
   and the background worker POSTs it with your Basic-auth header. The server runs
   the existing `flow_to_captured → synthesize → dry-run` pipeline and returns the
   synthesized target for review.

Header sanitization, registrable-domain binding, the chat-request scorer, the
cookie-consent contract, and the `{request,response}` shape are all mirrored
field-for-field from the server's built-in uploader (`_WIZARD_IMPORT_JS` in
`serve.py`) via the shared, unit-tested [`lib/sanitize.js`](lib/sanitize.js).

---

## Install

**Easiest — download a build (see [INSTALL.md](INSTALL.md)):** grab the latest
`provenance-probe-extension-X.Y.Z.zip` from the repo's Releases page, unzip, and
**Load unpacked**. Each `ext-v*` tag publishes one automatically (unit tests + a
tag-vs-manifest version guard run first).

**From source (for development):**

1. `chrome://extensions` → enable **Developer mode**.
2. **Load unpacked** → select this `extension/` directory.
3. Click the toolbar icon, enter your instance URL + credentials, click **Test
   connection** to confirm they work, then **Save** (Chrome will prompt to grant
   access to that one host).

CI packages the zip two ways: `extension.yml` on every change (a build artifact),
and `extension-release.yml` attaches it to a **GitHub Release** on an `ext-v*` tag.
**NOT on the Chrome Web Store** — submitting there is the owner's manual step; the full
listing package (copy, permission justifications, data-safety answers, privacy policy,
promo tile, and a submission checklist) is prepared in [`store/`](store/).

---

## Permissions requested — and why

The extension requests the **minimum** needed. It does **not** request
`<all_urls>`, `webRequest`, `cookies`, `tabs`, `activeTab`, or `scripting`, and
declares **no** static `host_permissions` (nothing is granted at install time).

| Permission | Type | Why | Scope |
|---|---|---|---|
| `storage` | required | Store the instance URL + Basic-auth creds and nothing else. | Local to this browser. |
| `declarativeNetRequestWithHostAccess` | required | Remove the `Origin` header from the extension's **own upload** to the configured instance (see below). Header rules only apply to hosts you have been granted. | One dynamic rule, matched to the exact instance origin + `/wizard/capture-import`, POST only, scoped to the extension's own initiator (`initiatorDomains: [chrome.runtime.id]`). |
| `optional_host_permissions`: `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*` | optional, requested at runtime | Reach **your** instance to upload. Nothing is granted at install; when you Save the config the extension calls `chrome.permissions.request` for **only the exact origin you typed**. HTTPS is required (loopback `http` allowed for local dev). | The single instance origin you configure. |

**Capture needs no host permission at all.** It uses the DevTools network API
(`chrome.devtools.network.onRequestFinished`), which is scoped to the single
inspected tab and available only while DevTools is open. There is no passive or
cross-tab observation: the network listener is attached only when you click **Arm
capture** and detached on **Stop**.

### Why the `Origin` header is removed on upload

The server's `/wizard/capture-import` has a CSRF guard (`_same_origin_ok`) that
accepts requests with **no** `Origin`/`Referer` (or a localhost one) and rejects
cross-site ones. A `fetch` from an extension carries `Origin: chrome-extension://<id>`,
which that guard would reject. The extension therefore strips **only its own**
`Origin` header, **only** for the configured instance's `/wizard/capture-import`
endpoint, via one narrowly-scoped `declarativeNetRequest` rule.

This does **not** reintroduce a CSRF risk:

- The endpoint's real CSRF defense is that it requires `Content-Type:
  application/json`, which forces a CORS preflight this app never answers — so a
  malicious web page still cannot invoke it cross-site.
- The upload is authenticated with an **explicit** `Authorization: Basic` header
  the extension sets, not with ambient cookies (`credentials: "omit"`), so there
  is no ambient-credential vector for an attacker to ride.
- The rule is bound to the exact instance origin + path + POST method **and to
  the extension's own initiator** (`initiatorDomains: [chrome.runtime.id]`), so it
  strips `Origin` only from the extension's own upload — never from any web page's
  request to the same endpoint. It never touches any other host, path, or request.

> Server-side alternative (not done here): #53 owns the endpoint contract, so this
> extension does **not** modify `serve.py`. A cleaner long-term fix would be for
> #53 to add `chrome-extension://` to the `_same_origin_ok` allow-list, after
> which this dNR rule (and the `declarativeNetRequestWithHostAccess` permission)
> could be dropped entirely.

---

## Security properties

- **No vendor API keys** anywhere in the code or config. The header allow-list is
  paired with a deny-list (`DENY_HEADER_RE`) so a captured `Authorization` /
  `x-api-key` / `api-key`-style vendor credential is stripped before upload, even
  though a benign `x-api-version` routing header is kept.
- **No credential leakage**: creds live only in `chrome.storage.local`, are read
  only by the background worker, are attached only to the configured instance
  over HTTPS, and are never written to logs or the console.
- **Explicit capture only**: nothing is recorded until you Arm capture; the
  listener is per-inspected-tab and removed on Stop.
- **Cookie consent names the host**: a session cookie is uploaded only if you
  tick a consent box that names the destination host; the server independently
  re-checks that the consent matches the captured host before any replay.
- **No XSS from captured data**: every captured or server-returned string is
  HTML-escaped (`escapeHtml`) or set via `textContent` before display.

---

## Files

| File | Purpose |
|---|---|
| `manifest.json` | MV3 manifest (permissions, popup, devtools page, background). |
| `background.js` | Reads creds, manages the Origin-strip rule, performs the upload. |
| `popup.{html,js,css}` | Configure instance URL + Basic-auth creds (once) + **Test connection**. |
| `devtools.{html,js}` | Registers the "Provenance Capture" DevTools panel. |
| `panel.{html,js}` | Arm/capture, pick the request, cookie consent, upload. |
| `icons/` | Toolbar + store icons (16/32/48/128) rendered from `icon.svg`. |
| `lib/sanitize.js` | Pure, DOM-free payload-assembly + sanitization (unit-tested). |
| `lib/config.js` | Pure URL validation + connection-test result mapping + picker label (unit-tested). |
| `test/sanitize.test.mjs` | `node --test` unit tests for the logic above. |

## Versioning

The extension versions **independently** of the Python package (its own
`manifest.json` / `package.json` `version`, starting at `0.1.0`). It ships no
Python changes.
