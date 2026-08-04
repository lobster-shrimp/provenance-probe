// Background service worker (MV3) for the provenance-probe capture extension.
//
// It is the ONLY place that reads the stored Basic-auth credentials and performs
// the upload, so credentials never travel through the capture UI. It also owns a
// single, tightly-scoped declarativeNetRequest rule (see ensureOriginRule) that
// strips the `Origin` header from the extension's own upload to the configured
// instance. Nothing here is ever logged.

const ORIGIN_RULE_ID = 1;
const CAPTURE_PATH = "/wizard/capture-import";

/** Parse + validate a user-entered instance URL. Only HTTPS is allowed, except
 * loopback (http://localhost / http://127.0.0.1) for local development. Returns
 * `{ origin, base }` or throws. */
function parseInstance(instanceUrl) {
  const u = new URL(String(instanceUrl || "").trim());
  const isLoopback = u.hostname === "localhost" || u.hostname === "127.0.0.1";
  if (u.protocol !== "https:" && !(u.protocol === "http:" && isLoopback)) {
    throw new Error("Instance URL must use https:// (http:// is only allowed for localhost).");
  }
  return { origin: u.origin, base: u.origin + u.pathname.replace(/\/+$/, "") };
}

/** Build a Basic-auth header value, UTF-8 safe. */
function basicAuth(username, password) {
  const raw = `${username || ""}:${password || ""}`;
  const bytes = new TextEncoder().encode(raw);
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return "Basic " + btoa(bin);
}

async function getConfig() {
  const { config } = await chrome.storage.local.get("config");
  return config || null;
}

/** Install/replace the Origin-strip rule for exactly one instance host + the
 * capture endpoint. See README "Why the Origin header is removed". */
async function ensureOriginRule(instanceUrl) {
  const { origin } = parseInstance(instanceUrl);
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ORIGIN_RULE_ID],
    addRules: [
      {
        id: ORIGIN_RULE_ID,
        priority: 1,
        condition: {
          // Match ONLY the extension's OWN request to the exact instance origin +
          // endpoint. `initiatorDomains: [chrome.runtime.id]` scopes the rule to
          // requests this extension issues, so it can never strip Origin from a
          // web page's POST to the same endpoint (which would silently disable the
          // server's `_same_origin_ok` CSRF guard for any tab). Both ends of the
          // URL are anchored so a longer path (e.g. /wizard/capture-import-batch)
          // is never matched.
          urlFilter: "|" + origin + CAPTURE_PATH + "|",
          initiatorDomains: [chrome.runtime.id],
          requestMethods: ["post"],
          resourceTypes: ["xmlhttprequest", "other"],
        },
        action: {
          type: "modifyHeaders",
          requestHeaders: [{ header: "origin", operation: "remove" }],
        },
      },
    ],
  });
}

async function clearOriginRule() {
  await chrome.declarativeNetRequest.updateDynamicRules({
    removeRuleIds: [ORIGIN_RULE_ID],
  });
}

/** POST an already-assembled payload to the configured instance. Reads creds
 * here (never in the UI), attaches Basic auth, and returns the server's JSON.
 * Credentials and payload are never logged. */
async function upload(payload) {
  const config = await getConfig();
  if (!config || !config.instanceUrl) {
    return { ok: false, error: "No instance configured. Open the popup and set the URL + credentials first." };
  }
  let base;
  try {
    ({ base } = parseInstance(config.instanceUrl));
  } catch (e) {
    return { ok: false, error: String(e.message || e) };
  }
  const origin = new URL(config.instanceUrl).origin;
  const granted = await chrome.permissions.contains({ origins: [origin + "/*"] });
  if (!granted) {
    return { ok: false, error: "Permission to reach the instance was not granted. Re-save the configuration in the popup." };
  }
  await ensureOriginRule(config.instanceUrl);
  let res;
  try {
    res = await fetch(base + CAPTURE_PATH, {
      method: "POST",
      credentials: "omit", // never attach ambient cookies to the instance
      headers: {
        "Content-Type": "application/json",
        Authorization: basicAuth(config.username, config.password),
      },
      body: JSON.stringify(payload),
    });
  } catch (e) {
    return { ok: false, error: "Could not reach the instance. Check the URL and that it is running." };
  }
  let body = null;
  try {
    body = await res.json();
  } catch (e) {
    body = null;
  }
  if (res.status === 401 || res.status === 403) {
    return {
      ok: false,
      status: res.status,
      error: (body && body.error) || "The instance rejected the request (check your username/password).",
      server: body || null,
    };
  }
  return { ok: !!(body && body.ok), status: res.status, server: body };
}

chrome.runtime.onMessage.addListener((msg, _sender, sendResponse) => {
  (async () => {
    try {
      if (!msg || typeof msg.type !== "string") {
        sendResponse({ ok: false, error: "bad message" });
        return;
      }
      switch (msg.type) {
        case "installRule":
          await ensureOriginRule(msg.instanceUrl);
          sendResponse({ ok: true });
          break;
        case "clearRule":
          await clearOriginRule();
          sendResponse({ ok: true });
          break;
        case "upload":
          sendResponse(await upload(msg.payload));
          break;
        default:
          sendResponse({ ok: false, error: "unknown message type" });
      }
    } catch (e) {
      sendResponse({ ok: false, error: String((e && e.message) || e) });
    }
  })();
  return true; // async response
});
