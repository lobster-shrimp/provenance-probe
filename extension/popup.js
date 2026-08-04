// Popup: set the hosted instance URL + Basic-auth credentials ONCE. Credentials
// live only in chrome.storage.local on this machine and are sent (by the
// background worker) only to the configured instance. This script never logs
// them and never sends them anywhere itself.

const $ = (id) => document.getElementById(id);

function setStatus(msg, kind) {
  const el = $("status");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

/** Validate the instance URL the same way the background worker does: HTTPS
 * only, except loopback for local development. */
function validateInstance(raw) {
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
  return u;
}

async function load() {
  const { config } = await chrome.storage.local.get("config");
  if (config) {
    $("instanceUrl").value = config.instanceUrl || "";
    $("username").value = config.username || "";
    $("password").value = config.password || "";
    setStatus("Configured for " + new URL(config.instanceUrl).host + ".", "ok");
  }
}

async function save(ev) {
  ev.preventDefault();
  let u;
  try {
    u = validateInstance($("instanceUrl").value);
  } catch (e) {
    setStatus(e.message, "err");
    return;
  }
  const username = $("username").value.trim();
  const password = $("password").value;
  if (!username || !password) {
    setStatus("Enter the Basic-auth username and password.", "err");
    return;
  }

  // Ask for host access to exactly this instance origin (user gesture required).
  // We never request <all_urls>; only the origin the user typed.
  let granted;
  try {
    granted = await chrome.permissions.request({ origins: [u.origin + "/*"] });
  } catch (e) {
    setStatus("Could not request permission: " + (e.message || e), "err");
    return;
  }
  if (!granted) {
    setStatus("Permission for " + u.host + " was declined — cannot upload without it.", "err");
    return;
  }

  await chrome.storage.local.set({
    config: { instanceUrl: u.origin, username, password },
  });
  const res = await chrome.runtime.sendMessage({ type: "installRule", instanceUrl: u.origin });
  if (res && res.ok) {
    setStatus("Saved. Capture from the DevTools “Provenance Capture” panel.", "ok");
  } else {
    setStatus("Saved, but could not install the upload rule: " + ((res && res.error) || "unknown"), "err");
  }
}

async function forget() {
  const { config } = await chrome.storage.local.get("config");
  await chrome.storage.local.remove("config");
  await chrome.runtime.sendMessage({ type: "clearRule" });
  if (config && config.instanceUrl) {
    try {
      await chrome.permissions.remove({ origins: [new URL(config.instanceUrl).origin + "/*"] });
    } catch (e) {
      /* best effort */
    }
  }
  $("instanceUrl").value = "";
  $("username").value = "";
  $("password").value = "";
  setStatus("Configuration cleared.", "ok");
}

$("cfg").addEventListener("submit", save);
$("forget").addEventListener("click", forget);
load();
