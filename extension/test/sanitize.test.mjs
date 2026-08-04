// Standalone unit tests for the extension's payload-assembly + sanitization
// logic. No dependencies — run with `node --test test/`. These guard the exact
// `/wizard/capture-import` contract (#53) and the security-critical header /
// cookie / XSS handling.

import { test } from "node:test";
import assert from "node:assert/strict";

import {
  KEEP_HEADER_RE,
  regDomain,
  hostOf,
  toHeaderList,
  hasCookie,
  sanitizeHeaders,
  scoreEntry,
  entryBody,
  pickChatFlows,
  assemblePayload,
  escapeHtml,
} from "../lib/sanitize.js";

test("sanitizeHeaders keeps only the allow-listed headers", () => {
  const headers = [
    { name: "Content-Type", value: "application/json" },
    { name: "X-Request-Id", value: "r-1" },
    { name: "anthropic-version", value: "2023-06-01" },
    { name: "Accept-Encoding", value: "gzip" },
    { name: "User-Agent", value: "evil" },
  ];
  const out = sanitizeHeaders(headers);
  assert.deepEqual(out, {
    "Content-Type": "application/json",
    "X-Request-Id": "r-1",
    "anthropic-version": "2023-06-01",
  });
});

test("sanitizeHeaders never forwards Authorization even if allow-list-adjacent", () => {
  const out = sanitizeHeaders([
    { name: "Authorization", value: "Bearer sk-secret" },
    { name: "Proxy-Authorization", value: "Basic zzz" },
    { name: "Content-Type", value: "application/json" },
  ]);
  assert.deepEqual(out, { "Content-Type": "application/json" });
});

test("sanitizeHeaders drops vendor API-key headers the allow-list would otherwise match", () => {
  const out = sanitizeHeaders([
    { name: "x-api-key", value: "sk-vendor-secret" },
    { name: "api-key", value: "another-secret" },
    { name: "x-goog-api-key", value: "goog-secret" },
    { name: "x-api-version", value: "2024-01" },
    { name: "Content-Type", value: "application/json" },
  ]);
  assert.equal(out["x-api-key"], undefined);
  assert.equal(out["api-key"], undefined);
  assert.equal(out["x-goog-api-key"], undefined);
  // A benign x-api-* routing header still passes.
  assert.equal(out["x-api-version"], "2024-01");
  assert.equal(out["Content-Type"], "application/json");
});

test("sanitizeHeaders includes Cookie only with explicit consent", () => {
  const headers = [
    { name: "Content-Type", value: "application/json" },
    { name: "Cookie", value: "session=secret" },
  ];
  assert.equal(sanitizeHeaders(headers, { sendCookie: false }).Cookie, undefined);
  assert.equal(sanitizeHeaders(headers, { sendCookie: true }).Cookie, "session=secret");
});

test("toHeaderList drops non-string/empty names and accepts object form", () => {
  assert.deepEqual(
    toHeaderList({ "X-Api-Key": "k", "": "x" }),
    [{ name: "X-Api-Key", value: "k" }],
  );
  assert.deepEqual(
    toHeaderList([{ name: "X-Org", value: "o" }, { value: "no-name" }, { name: 3 }]),
    [{ name: "X-Org", value: "o" }],
  );
});

test("hasCookie detects a non-empty Cookie header only", () => {
  assert.equal(hasCookie([{ name: "Cookie", value: "a=b" }]), true);
  assert.equal(hasCookie([{ name: "Cookie", value: "" }]), false);
  assert.equal(hasCookie([{ name: "Content-Type", value: "x" }]), false);
});

test("regDomain collapses domains but keeps IP literals whole", () => {
  assert.equal(regDomain("api.chat.z.ai"), "z.ai");
  assert.equal(regDomain("chat.z.ai"), "z.ai");
  assert.equal(regDomain("192.168.1.5"), "192.168.1.5");
  assert.equal(regDomain("localhost"), "localhost");
});

test("hostOf returns lowercase hostname or empty string", () => {
  assert.equal(hostOf("https://Chat.Z.ai/api"), "chat.z.ai");
  assert.equal(hostOf("not a url"), "");
});

test("scoreEntry ranks the prompt-hint POST highest", () => {
  const chat = { request: { method: "POST", url: "https://z.ai/chat", body: "hello fingerprint me" } };
  const other = { request: { method: "POST", url: "https://z.ai/track", body: "telemetry" } };
  assert.ok(scoreEntry(chat, "fingerprint me") > scoreEntry(other, "fingerprint me"));
});

test("entryBody reads both flat body and HAR postData.text", () => {
  assert.equal(entryBody({ request: { body: "flat" } }), "flat");
  assert.equal(entryBody({ request: { postData: { text: "har" } } }), "har");
  assert.equal(entryBody({ request: {} }), "");
});

test("pickChatFlows binds selection to the best candidate's registrable domain", () => {
  const entries = [
    { request: { method: "POST", url: "https://chat.z.ai/api/chat", body: "hi fingerprint me" } },
    { request: { method: "POST", url: "https://telemetry.other.com/collect", body: "x".repeat(9999) } },
    { request: { method: "GET", url: "https://chat.z.ai/ping", body: "" } },
    { request: { method: "POST", url: "https://cdn.z.ai/log", body: "noise" } },
  ];
  const { candidates } = pickChatFlows(entries, "fingerprint me");
  // Only z.ai POSTs survive; the higher-scoring third-party POST is excluded.
  assert.equal(candidates.length, 2);
  for (const c of candidates) {
    assert.equal(regDomain(hostOf(c.request.url)), "z.ai");
  }
  assert.match(candidates[0].request.url, /chat\.z\.ai\/api\/chat/);
});

test("pickChatFlows returns nothing when there is no POST with a body", () => {
  const { candidates, bestIndex } = pickChatFlows(
    [{ request: { method: "GET", url: "https://z.ai/x", body: "" } }],
    "",
  );
  assert.equal(candidates.length, 0);
  assert.equal(bestIndex, -1);
});

test("assemblePayload produces the exact /wizard/capture-import contract", () => {
  const payload = assemblePayload({
    name: " zai ",
    promptHint: " fingerprint me ",
    request: {
      method: "post",
      url: "https://chat.z.ai/api/paas/v4/chat/completions",
      headers: [
        { name: "Content-Type", value: "application/json" },
        { name: "Cookie", value: "z_session=secret" },
        { name: "Authorization", value: "Bearer nope" },
      ],
      body: '{"model":"glm-4.6"}',
    },
    response: {
      status: 200,
      headers: [{ name: "Content-Type", value: "application/json" }],
      body: '{"choices":[]}',
    },
    sendCookie: true,
    cookieConsentHost: "chat.z.ai",
  });
  assert.deepEqual(Object.keys(payload).sort(), ["cookie_consent", "name", "prompt_hint", "request", "response"]);
  assert.equal(payload.name, "zai");
  assert.equal(payload.prompt_hint, "fingerprint me");
  assert.equal(payload.cookie_consent, "chat.z.ai");
  assert.equal(payload.request.method, "POST");
  assert.equal(payload.request.headers.Cookie, "z_session=secret");
  assert.equal(payload.request.headers.Authorization, undefined);
  assert.equal(payload.response.status, 200);
  assert.equal(payload.response.body, '{"choices":[]}');
  // Response headers never carry a cookie.
  assert.equal(payload.response.headers.Cookie, undefined);
});

test("assemblePayload omits cookie_consent + Cookie when consent not given", () => {
  const payload = assemblePayload({
    name: "",
    promptHint: "",
    request: {
      method: "POST",
      url: "https://chat.z.ai/api/chat",
      headers: [{ name: "Cookie", value: "z=secret" }],
      body: "{}",
    },
    response: { status: 0, headers: [], body: "" },
    sendCookie: false,
  });
  assert.equal(payload.cookie_consent, "");
  assert.equal(payload.request.headers.Cookie, undefined);
  assert.equal(payload.name, "chat.z.ai"); // falls back to host
});

test("escapeHtml neutralizes markup from captured strings", () => {
  assert.equal(
    escapeHtml('<img src=x onerror="alert(1)">'),
    "&lt;img src=x onerror=&quot;alert(1)&quot;&gt;",
  );
  assert.equal(escapeHtml("a & b 'c'"), "a &amp; b &#39;c&#39;");
  assert.equal(escapeHtml(null), "");
});

test("KEEP_HEADER_RE matches routing headers, rejects credentials", () => {
  assert.ok(KEEP_HEADER_RE.test("content-type"));
  assert.ok(KEEP_HEADER_RE.test("x-csrf-token"));
  assert.ok(KEEP_HEADER_RE.test("openai-organization"));
  assert.ok(!KEEP_HEADER_RE.test("authorization"));
  assert.ok(!KEEP_HEADER_RE.test("cookie"));
});
