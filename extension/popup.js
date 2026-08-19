// Popup: set the hosted instance URL + Basic-auth credentials ONCE, and optionally
// TEST the connection before saving. Credentials live only in chrome.storage.local
// on this machine and are sent (by the background worker) only to the configured
// instance. This script never logs them and never sends them anywhere itself.

import { validateInstanceUrl } from "./lib/config.js";

const $ = (id) => document.getElementById(id);

function setStatus(msg, kind) {
  const el = $("status");
  el.textContent = msg;
  el.className = "status" + (kind ? " " + kind : "");
}

/** Read + validate the form's instance URL, or set an error status and return null. */
function readInstance() {
  try {
    return validateInstanceUrl($("instanceUrl").value);
  } catch (e) {
    setStatus(e.message, "err");
    return null;
  }
}

/** Request host access to exactly this instance origin (user gesture required).
 * Never requests <all_urls>; only the origin the user typed. Returns true if granted. */
async function ensurePermission(origin) {
  try {
    return await chrome.permissions.request({ origins: [origin + "/*"] });
  } catch (e) {
    setStatus("Could not request permission: " + (e.message || e), "err");
    return false;
  }
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
  const parsed = readInstance();
  if (!parsed) return;
  const username = $("username").value.trim();
  const password = $("password").value;
  if (!username || !password) {
    setStatus("Enter the Basic-auth username and password.", "err");
    return;
  }
  if (!(await ensurePermission(parsed.origin))) {
    setStatus("Permission for " + new URL(parsed.origin).host + " was declined — cannot upload without it.", "err");
    return;
  }
  await chrome.storage.local.set({
    config: { instanceUrl: parsed.origin, username, password },
  });
  const res = await chrome.runtime.sendMessage({ type: "installRule", instanceUrl: parsed.origin });
  if (res && res.ok) {
    setStatus("Saved. Capture from the DevTools “Provenance Capture” panel.", "ok");
  } else {
    setStatus("Saved, but could not install the upload rule: " + ((res && res.error) || "unknown"), "err");
  }
}

/** Test the CURRENTLY-TYPED URL + creds against the instance before saving, so a
 * typo or wrong password fails here — not silently at the first capture upload. */
async function test() {
  const parsed = readInstance();
  if (!parsed) return;
  const username = $("username").value.trim();
  const password = $("password").value;
  if (!username || !password) {
    setStatus("Enter the username and password to test.", "err");
    return;
  }
  if (!(await ensurePermission(parsed.origin))) {
    setStatus("Permission for " + new URL(parsed.origin).host + " was declined — can't test without it.", "err");
    return;
  }
  setStatus("Testing…", null);
  $("test").disabled = true;
  let res;
  try {
    res = await chrome.runtime.sendMessage({
      type: "testConnection", instanceUrl: parsed.origin, username, password,
    });
  } catch (e) {
    res = { ok: false, message: "Could not reach the extension background worker." };
  }
  $("test").disabled = false;
  setStatus((res && res.message) || "Test failed.", res && res.ok ? "ok" : "err");
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
$("test").addEventListener("click", test);
$("forget").addEventListener("click", forget);
load();
