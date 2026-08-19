// Pure, DOM-free config + preflight + picker helpers, shared by popup.js,
// background.js, and panel.js and unit-tested with `node --test`. Keeping these
// here (beside lib/sanitize.js) means the HTTPS-only rule, the connection-test
// result mapping, and the capture-picker label are defined ONCE and tested once —
// no drift between the popup and the background worker (the CQ1 finding).

/**
 * Validate + canonicalize a user-entered instance URL. HTTPS only, except loopback
 * (http://localhost / http://127.0.0.1) for local development. This is the single
 * source of truth for the rule (popup + background + preflight all call it).
 * @param {string} raw
 * @returns {{origin: string, base: string}} origin (scheme+host[:port]) and base
 *   (origin + path, trailing slashes trimmed). Throws Error with a user-facing message.
 */
export function validateInstanceUrl(raw) {
  let u;
  try {
    u = new URL(String(raw || "").trim());
  } catch (e) {
    throw new Error("Enter a full URL, e.g. https://your-instance.example.com");
  }
  const isLoopback = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLoopback)) {
    throw new Error("Use https:// (http:// is only allowed for localhost).");
  }
  return { origin: u.origin, base: u.origin + u.pathname.replace(/\/+$/, "") };
}

/**
 * Map a two-probe connection test into a user-facing result. The background worker
 * sends a HEAD to `/` WITHOUT auth then (if challenged) WITH auth, so we can tell
 * "wrong password" apart from "this instance doesn't enforce auth at all" — a HEAD
 * that returns 200 with no challenge never actually validated the credentials
 * (auth is env-gated off by default on the server), so we must not report a false
 * "connected ✓".
 * @param {{noAuthStatus?: number, authStatus?: number, err?: string}} r
 * @returns {{kind: "connected"|"badcreds"|"auth-not-enforced"|"unreachable"|"unexpected", ok: boolean, message: string}}
 */
export function testConnResult({ noAuthStatus = 0, authStatus = 0, err = "" } = {}, host = "the instance") {
  if (err || noAuthStatus === 0) {
    return { kind: "unreachable", ok: false, message: `Can't reach ${host} — check the URL and that it's running.` };
  }
  if (noAuthStatus === 200) {
    // Reachable, but the server answered without a password challenge, so the creds
    // were never checked. Honest, not a false ✓.
    return { kind: "auth-not-enforced", ok: true, message: `${host} is reachable but didn't ask for a password — it may not be enforcing auth, so your credentials weren't verified.` };
  }
  if (authStatus === 200) {
    return { kind: "connected", ok: true, message: `Connected to ${host} ✓` };
  }
  if (authStatus === 401 || authStatus === 403) {
    return { kind: "badcreds", ok: false, message: "Check your username / password." };
  }
  return { kind: "unexpected", ok: false, message: `${host} returned an unexpected status (${authStatus || noAuthStatus}).` };
}

/**
 * A friendly one-line label for a captured request in the picker, instead of the
 * raw `METHOD URL`. Shows host + the tail of the path (what a human recognizes),
 * null-safe on a missing/garbage URL. Deliberately does NOT try to extract a model
 * name — the response body isn't available at pick time, so that would be brittle.
 * @param {{request?: {method?: string, url?: string}}} entry
 * @returns {string}
 */
export function pickerLabel(entry) {
  const req = (entry && entry.request) || {};
  const url = String(req.url || "");
  let host = "";
  let path = "";
  try {
    const u = new URL(url);
    host = u.host;
    path = u.pathname || "";
  } catch (e) {
    // not a parseable URL — fall back to the raw string, trimmed
    return (String(req.method || "POST") + " " + url).slice(0, 90) || "(request)";
  }
  const seg = path.replace(/\/+$/, "").split("/").filter(Boolean);
  const tail = seg.length ? "/" + seg.slice(-2).join("/") : "/";
  return host ? `${host} · ${tail}` : (path || "/");
}
