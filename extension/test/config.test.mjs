// Unit tests (node --test) for the shared config/preflight/picker logic.
import { test } from "node:test";
import assert from "node:assert/strict";
import { validateInstanceUrl, testConnResult, pickerLabel } from "../lib/config.js";

test("validateInstanceUrl: https ok, canonicalizes origin + trims trailing slash", () => {
  assert.deepEqual(validateInstanceUrl("https://x.example.com/"), {
    origin: "https://x.example.com", base: "https://x.example.com",
  });
  assert.deepEqual(validateInstanceUrl("https://x.example.com/sub/"), {
    origin: "https://x.example.com", base: "https://x.example.com/sub",
  });
});

test("validateInstanceUrl: http allowed ONLY for loopback", () => {
  assert.equal(validateInstanceUrl("http://localhost:8770").origin, "http://localhost:8770");
  assert.equal(validateInstanceUrl("http://127.0.0.1:8770").origin, "http://127.0.0.1:8770");
  assert.throws(() => validateInstanceUrl("http://public.example.com"), /https/);
});

test("validateInstanceUrl: garbage / empty throws a friendly message", () => {
  assert.throws(() => validateInstanceUrl("not a url"), /full URL/);
  assert.throws(() => validateInstanceUrl(""), /full URL/);
  assert.throws(() => validateInstanceUrl(null), /full URL/);
});

test("testConnResult: unreachable on transport error or status 0", () => {
  assert.equal(testConnResult({ err: "network down" }).kind, "unreachable");
  assert.equal(testConnResult({ noAuthStatus: 0 }).kind, "unreachable");
});

test("testConnResult: no-auth 200 => auth-not-enforced (honest, not a false connected)", () => {
  const r = testConnResult({ noAuthStatus: 200, authStatus: 200 }, "demo.host");
  assert.equal(r.kind, "auth-not-enforced");
  assert.equal(r.ok, true);
  assert.match(r.message, /didn't ask for a password/);
});

test("testConnResult: challenged then 200 => connected", () => {
  const r = testConnResult({ noAuthStatus: 401, authStatus: 200 }, "demo.host");
  assert.equal(r.kind, "connected");
  assert.equal(r.ok, true);
});

test("testConnResult: challenged then 401/403 => badcreds", () => {
  assert.equal(testConnResult({ noAuthStatus: 401, authStatus: 401 }).kind, "badcreds");
  assert.equal(testConnResult({ noAuthStatus: 401, authStatus: 403 }).kind, "badcreds");
});

test("pickerLabel: host + path tail", () => {
  assert.equal(
    pickerLabel({ request: { method: "POST", url: "https://api.z.ai/api/paas/v4/chat/completions" } }),
    "api.z.ai · /chat/completions",
  );
  assert.equal(pickerLabel({ request: { url: "https://chat.example.com/" } }), "chat.example.com · /");
});

test("pickerLabel: null-safe on missing/garbage url", () => {
  assert.equal(pickerLabel({}), "POST ");
  assert.equal(pickerLabel({ request: { method: "POST", url: "::::" } }), "POST ::::");
  assert.doesNotThrow(() => pickerLabel(null));
});
