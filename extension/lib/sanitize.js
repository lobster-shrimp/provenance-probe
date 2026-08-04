// Pure, DOM-free capture logic for the provenance-probe browser extension (#54).
//
// This module is the SINGLE source of truth for how the extension chooses the
// chat request, strips headers, handles the session cookie, and assembles the
// normalized payload. It is deliberately free of any `chrome.*` / DOM / network
// reference so it can be unit-tested under plain Node (see ../test/) and reused
// verbatim by the devtools panel and popup.
//
// It mirrors, field-for-field, the CLIENT-SIDE logic the built-in HAR uploader
// already ships in serve.py (`_WIZARD_IMPORT_JS`): the same KEEP header allow
// list, the same registrable-domain binding, the same chat-request scorer, and
// the same `{name, prompt_hint, cookie_consent, request, response}` contract that
// `POST /wizard/capture-import` (#53) consumes. The extension is purely a second
// front-end onto that ingest — it adds no new server contract.

// Header allow list. Mirrors serve.py `_WIZARD_IMPORT_JS`'s `KEEP` regex, which
// itself mirrors the server-side `_KEEP_HEADER_RE`: content-type plus a small set
// of routing/CSRF headers the template adapter can safely replay. Authorization
// (and everything else) is dropped so it never leaves the machine. The Cookie
// header is handled SEPARATELY and only with explicit, host-named consent.
export const KEEP_HEADER_RE =
  /^(content-type|x-csrf|x-xsrf|csrf|x-request|x-tenant|x-org|x-client|anthropic-version|openai-|x-api|x-requested-with)/i;

// Credential-bearing headers that must NEVER be forwarded, even when the positive
// allow list above would otherwise match them. `x-api` in KEEP_HEADER_RE matches
// `x-api-version` (wanted) but also `x-api-key` (a raw vendor key many browser-side
// chat demos send) — this deny list, checked first, keeps such keys off the wire.
// The extension is deliberately stricter here than the built-in HAR uploader,
// honouring the "no vendor API keys anywhere" rule.
export const DENY_HEADER_RE =
  /^(authorization|proxy-authorization|x-api-key|api-key|x-goog-api-key|x-amz-security-token)$/i;

// A request whose URL looks like a chat/completions call.
const CHAT_URL_RE = /chat|complet|message|conversation|generate|ask/i;

/** Registrable domain, mirroring the HAR uploader's `regdom`: IP literals and
 * host:port forms are returned whole (a last-two-labels split is meaningless and
 * unsafe for IPs); domain names collapse to their last two labels. */
export function regDomain(host) {
  host = String(host || "").toLowerCase().replace(/\.$/, "");
  if (/^[0-9.]+$/.test(host) || host.indexOf(":") >= 0) return host; // IP / has port
  const parts = host.split(".");
  return parts.length >= 2 ? parts.slice(-2).join(".") : host;
}

/** Hostname of a URL, or "" if it cannot be parsed. */
export function hostOf(url) {
  try {
    return new URL(url).hostname.toLowerCase();
  } catch (e) {
    return "";
  }
}

function looksChat(url) {
  return CHAT_URL_RE.test(url || "");
}

/** Normalize headers to a HAR-style `[{name, value}]` list. Accepts either that
 * shape or a plain object. Non-string / empty names are dropped (never trust
 * captured data). */
export function toHeaderList(headers) {
  if (Array.isArray(headers)) {
    return headers
      .filter((h) => h && typeof h.name === "string" && h.name)
      .map((h) => ({ name: h.name, value: String(h.value == null ? "" : h.value) }));
  }
  if (headers && typeof headers === "object") {
    return Object.keys(headers)
      .filter((k) => typeof k === "string" && k)
      .map((k) => ({ name: k, value: String(headers[k] == null ? "" : headers[k]) }));
  }
  return [];
}

/** True if the request carries a non-empty Cookie header. */
export function hasCookie(headers) {
  return toHeaderList(headers).some(
    (h) => h.name.toLowerCase() === "cookie" && h.value,
  );
}

/** Sanitize a header list into the plain object the payload sends.
 * Keeps only the allow-listed headers; includes Cookie ONLY when `sendCookie`
 * is true (i.e. the user gave explicit, host-named consent). */
export function sanitizeHeaders(headers, { sendCookie = false } = {}) {
  const out = {};
  for (const h of toHeaderList(headers)) {
    const lower = h.name.toLowerCase();
    if (lower === "cookie") {
      if (sendCookie) out[h.name] = h.value;
      continue;
    }
    // Deny credential-bearing headers first — this wins over the positive allow
    // list so an `x-api-key`-style vendor key can never ride along.
    if (DENY_HEADER_RE.test(h.name)) continue;
    if (KEEP_HEADER_RE.test(h.name)) out[h.name] = h.value;
  }
  return out;
}

/** Score a captured entry `{request:{method,url,body|postData}}` for how likely
 * it is the chat/model call. Mirrors the HAR uploader's `score()`. */
export function scoreEntry(entry, hint) {
  const req = (entry && entry.request) || {};
  const body = entryBody(entry);
  const hasHint = hint && body.indexOf(hint) >= 0;
  const isPost = String(req.method || "").toUpperCase() === "POST" && !!body;
  return (
    (hasHint ? 1 : 0) * 1e9 +
    (isPost ? 1 : 0) * 1e8 +
    (looksChat(req.url) ? 1 : 0) * 1e7 +
    body.length
  );
}

/** Extract a request body string from an entry, tolerating both the HAR
 * `request.postData.text` shape and a flat `request.body` string. */
export function entryBody(entry) {
  const req = (entry && entry.request) || {};
  if (typeof req.body === "string") return req.body;
  if (req.postData && typeof req.postData.text === "string") return req.postData.text;
  return "";
}

/** Choose the chat flow from a list of captured entries and return the on-domain
 * candidate list plus the index of the best one.
 *
 * Mirrors the uploader's `rebuild()`: sort by score, take the registrable domain
 * of the best candidate, and restrict selection to that domain so a stray
 * third-party POST can never be chosen (its cookie would be wrong). Returns
 * `{ candidates: [], bestIndex: -1 }` when nothing qualifies. */
export function pickChatFlows(entries, hint) {
  const posts = (entries || []).filter((e) => {
    const req = (e && e.request) || {};
    return String(req.method || "").toUpperCase() === "POST" && !!entryBody(e);
  });
  if (!posts.length) return { candidates: [], bestIndex: -1 };
  const sorted = posts
    .slice()
    .sort((a, b) => scoreEntry(b, hint) - scoreEntry(a, hint));
  const appDom = regDomain(hostOf(((sorted[0] || {}).request || {}).url));
  const candidates = sorted.filter(
    (e) => regDomain(hostOf((e.request || {}).url)) === appDom,
  );
  return { candidates, bestIndex: candidates.length ? 0 : -1 };
}

/** Assemble the exact `/wizard/capture-import` payload (#53 contract).
 *
 * `sendCookie` gates inclusion of the Cookie header; `cookieConsentHost` is the
 * host the user consented to (echoed as `cookie_consent`). The server re-checks
 * that `cookie_consent` matches the captured host before any cookie-bearing
 * replay, so this must be the real destination host. */
export function assemblePayload({
  name,
  promptHint,
  request,
  response,
  sendCookie = false,
  cookieConsentHost = "",
}) {
  const req = request || {};
  const resp = response || {};
  const host = hostOf(req.url);
  return {
    name: (name || "").trim() || host || "target",
    prompt_hint: (promptHint || "").trim(),
    cookie_consent: sendCookie ? String(cookieConsentHost || host).toLowerCase() : "",
    request: {
      method: String(req.method || "POST").toUpperCase(),
      url: String(req.url || ""),
      headers: sanitizeHeaders(req.headers, { sendCookie }),
      body: typeof req.body === "string" ? req.body : entryBody({ request: req }),
    },
    response: {
      status: Number(resp.status || 0) || 0,
      headers: sanitizeHeaders(resp.headers, { sendCookie: false }),
      body: typeof resp.body === "string" ? resp.body : "",
    },
  };
}

/** HTML-escape an untrusted string before it touches innerHTML. Mirrors the
 * uploader's `esc()`. EVERY captured/derived string shown in the panel or popup
 * MUST pass through this (prevents DOM-based XSS via a captured header/body). */
export function escapeHtml(s) {
  return String(s == null ? "" : s)
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}
