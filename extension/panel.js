// DevTools panel: capture one chat request from the inspected tab and upload it.
//
// Capture is EXPLICIT (nothing is recorded until "Arm capture") and scoped to
// the single inspected tab (DevTools cannot see other tabs). The network
// listener is attached only while armed and detached on stop. All captured and
// server-returned strings are HTML-escaped before display (no DOM XSS via a
// captured header/body/host).

import {
  pickChatFlows,
  hasCookie,
  assemblePayload,
  hostOf,
  escapeHtml,
  entryBody,
} from "./lib/sanitize.js";

const $ = (id) => document.getElementById(id);
const MAX_ENTRIES = 60;

let armed = false;
let entries = []; // {request:{method,url,headers,body}, response:{status,headers}, _har}
let current = []; // on-domain candidate list from the last pick

function onRequestFinished(harEntry) {
  if (!armed) return;
  const req = harEntry.request || {};
  const method = String(req.method || "").toUpperCase();
  const body = (req.postData && req.postData.text) || "";
  if (method !== "POST" || !body) return; // only chat-shaped POSTs are candidates
  const entry = {
    request: {
      method,
      url: req.url || "",
      headers: req.headers || [],
      body,
    },
    response: {
      status: (harEntry.response && harEntry.response.status) || 0,
      headers: (harEntry.response && harEntry.response.headers) || [],
    },
    _har: harEntry,
  };
  entries.push(entry);
  if (entries.length > MAX_ENTRIES) entries = entries.slice(-MAX_ENTRIES);
  renderPicker();
}

function renderPicker() {
  const hint = $("hint").value.trim();
  const { candidates } = pickChatFlows(entries, hint);
  current = candidates;
  const sel = $("flow");
  sel.textContent = "";
  if (!candidates.length) {
    $("pick").style.display = "none";
    return;
  }
  candidates.forEach((e, i) => {
    const o = document.createElement("option");
    o.value = String(i);
    // textContent — never innerHTML — so a crafted URL cannot inject markup.
    o.textContent = (e.request.method || "POST") + " " + (e.request.url || "").slice(0, 90);
    sel.appendChild(o);
  });
  $("pick").style.display = "block";
  onSelect();
}

function onSelect() {
  const e = current[parseInt($("flow").value || "0", 10)];
  if (!e) return;
  const host = hostOf(e.request.url);
  const consentBox = $("cookieConsent");
  // Reset consent on EVERY selection change so it can never carry over to a host
  // the user did not explicitly consent to in this click (two candidates can share
  // a registrable domain but have different exact hosts).
  $("consent").checked = false;
  if (hasCookie(e.request.headers)) {
    $("cookieLine").textContent = "This request carries a session cookie for " + host + ".";
    $("consentLabel").textContent =
      "I consent to sending this session cookie to " + host +
      " for a one-time dry-run (it is not saved on the hosted instance).";
    consentBox.style.display = "block";
  } else {
    $("cookieLine").textContent = "No session cookie on this request.";
    consentBox.style.display = "none";
  }
}

/** Resolve the response body for a captured entry via the DevTools content API. */
function getResponseBody(harEntry) {
  return new Promise((resolve) => {
    if (!harEntry || typeof harEntry.getContent !== "function") {
      resolve("");
      return;
    }
    harEntry.getContent((content, encoding) => {
      if (content == null) {
        resolve("");
      } else if (encoding === "base64") {
        try {
          resolve(atob(content));
        } catch (e) {
          resolve("");
        }
      } else {
        resolve(String(content));
      }
    });
  });
}

async function checkConfig() {
  const { config } = await chrome.storage.local.get("config");
  const configured = !!(config && config.instanceUrl);
  $("needcfg").style.display = configured ? "none" : "block";
  return configured;
}

async function arm() {
  if (!(await checkConfig())) return;
  entries = [];
  armed = true;
  chrome.devtools.network.onRequestFinished.addListener(onRequestFinished);
  $("arm").disabled = true;
  $("stop").disabled = false;
  $("armnote").textContent = "Armed — now send ONE short message in the app. Captured requests appear below.";
  $("out").textContent = "";
}

function stop() {
  armed = false;
  try {
    chrome.devtools.network.onRequestFinished.removeListener(onRequestFinished);
  } catch (e) {
    /* no-op */
  }
  $("arm").disabled = false;
  $("stop").disabled = true;
  $("armnote").textContent = entries.length
    ? "Stopped. Pick the request and upload."
    : "Stopped. No POST request was captured — try again and send a message.";
}

function renderResult(res) {
  const out = $("out");
  const server = res.server || {};
  const warnings = (server.warnings || [])
    .map((w) => '<div class="warn">&#9888; ' + escapeHtml(w) + "</div>")
    .join("");
  const targetPre = server.target
    ? "<h3>Synthesized target</h3><pre>" + escapeHtml(JSON.stringify(server.target, null, 2)) + "</pre>"
    : "";
  if (res.ok && server.ok) {
    out.innerHTML =
      '<div class="ok-box">' + escapeHtml(server.note || "Dry-run succeeded.") + "</div>" +
      warnings + targetPre;
  } else {
    const err = res.error || (server && server.error) || "Upload failed.";
    out.innerHTML = '<div class="err-box">' + escapeHtml(err) + "</div>" + warnings + targetPre;
  }
}

async function send() {
  const e = current[parseInt($("flow").value || "0", 10)];
  if (!e) return;
  if (!(await checkConfig())) return;

  const host = hostOf(e.request.url);
  const cookiePresent = hasCookie(e.request.headers);
  const consented = $("consent").checked;
  const sendCookie = cookiePresent && consented;

  const out = $("out");
  if (cookiePresent && !consented) {
    out.innerHTML =
      '<div class="warn">This request needs its session cookie to replay. Tick the ' +
      "consent box, or the dry-run will likely fail with a 401. Uploading without the cookie…</div>";
  } else {
    out.textContent = "Uploading the one chosen request…";
  }

  const responseBody = await getResponseBody(e._har);
  const payload = assemblePayload({
    name: $("name").value,
    promptHint: $("hint").value,
    request: e.request,
    response: {
      status: e.response.status,
      headers: e.response.headers,
      body: responseBody,
    },
    sendCookie,
    cookieConsentHost: host,
  });

  $("send").disabled = true;
  let res;
  try {
    res = await chrome.runtime.sendMessage({ type: "upload", payload });
  } catch (err) {
    res = { ok: false, error: "Could not reach the extension background worker." };
  }
  $("send").disabled = false;
  renderResult(res || { ok: false, error: "No response from the uploader." });
}

$("arm").addEventListener("click", arm);
$("stop").addEventListener("click", stop);
$("send").addEventListener("click", send);
$("flow").addEventListener("change", onSelect);
$("hint").addEventListener("input", () => {
  if (entries.length) renderPicker();
});
checkConfig();
