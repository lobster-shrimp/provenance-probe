"""Local recording-proxy capture (#44).

Captures the ONE real chat request+response from a logged-in web app by driving
an isolated throwaway browser through a localhost TLS-intercepting proxy, then
hands the result to the existing `wizard.synthesize()` pipeline — no manual paste.

Design (see issue #44):
- The proxy (mitmproxy, embedded) uses an EPHEMERAL CA in a per-session temp
  confdir; the throwaway browser context sets `ignore_https_errors=True`, so the
  CA is trusted by NOTHING in any OS/browser trust store and dies with the run.
- Two-phase, mirroring capture_playwright: phase 1 (login) is NOT proxied/recorded;
  phase 2 (one message) is recorded. The login exchange never enters a capture.
- The recorded exchange is normalized to a proxy-agnostic `Flow`, the chat flow is
  chosen by wizard.score_chat_request (the SAME scorer parse_har uses), and
  converted to a `wizard.Captured` — the exact hand-off `synthesize()` consumes.

This module's PURE core (Flow / sse_reassemble / select_chat_flow /
flow_to_captured) imports nothing heavy and is fully unit-testable. mitmproxy and
playwright are imported lazily inside `capture()` only (the `[capture]` extra),
so importing this module never requires them.
"""
from __future__ import annotations

import json
import re
import sys
from dataclasses import dataclass, field


@dataclass
class Flow:
    """One recorded HTTP exchange, proxy-agnostic (so the core is testable)."""
    url: str
    method: str = "POST"
    req_headers: dict = field(default_factory=dict)
    req_body: str = ""
    resp_headers: dict = field(default_factory=dict)
    resp_body: str = ""                 # for SSE, the raw concatenated event stream
    resp_content_type: str = ""


@dataclass
class SSEResult:
    text: str                           # deltas concatenated (the assistant reply)
    usage_prompt_tokens: int | None     # read off the final chunk, if present
    delta_path: str                     # per-chunk incremental path (or "")


# Per-chunk delta locations, tried in order (OpenAI, then Anthropic-ish shapes).
_SSE_DELTA_CANDIDATES = (
    "choices.0.delta.content", "choices.0.text", "delta.text",
    "content_block.delta.text", "delta",
)


def sse_reassemble(body: str) -> SSEResult:
    """Rebuild the reply text + usage + per-chunk delta path from a raw SSE body.

    Parses `data:` lines (ignoring `[DONE]` and non-JSON), detects the delta path
    from the first chunk carrying an incremental string, concatenates that path
    across chunks, and reads prompt-token usage from whichever chunk reports it.
    """
    from .client import dig

    chunks = []
    for line in (body or "").splitlines():
        line = line.strip()
        if not line:
            continue
        # Accept both SSE (`data: {...}`) and bare JSON-lines (`{...}`) frames, so
        # one reassembler serves event-stream AND newline-delimited-JSON streams.
        payload = line[5:].strip() if line.startswith("data:") else line
        if not payload or payload == "[DONE]":
            continue
        try:
            chunks.append(json.loads(payload))
        except json.JSONDecodeError:
            continue

    delta_path = ""
    for path in _SSE_DELTA_CANDIDATES:
        if any(isinstance(dig(ch, path), str) and dig(ch, path) for ch in chunks):
            delta_path = path
            break

    text = ""
    if delta_path:
        for ch in chunks:
            v = dig(ch, delta_path)
            if isinstance(v, str):
                text += v

    usage = None
    for ch in chunks:
        u = ch.get("usage") if isinstance(ch, dict) else None
        if isinstance(u, dict):
            for k in ("prompt_tokens", "input_tokens", "promptTokens"):
                if isinstance(u.get(k), int):
                    usage = u[k]
                    break
        if usage is not None:
            break

    return SSEResult(text=text, usage_prompt_tokens=usage, delta_path=delta_path)


_SSE_FRAME_RE = re.compile(r"(^|\n)\s*data:", re.MULTILINE)


def detect_response_mode(body: str, content_type: str = "") -> str:
    """Classify a response body by SNIFFING it, not by trusting content-type.

    Real apps mislabel streams (v0.app streams newline-delimited JSON as
    `text/plain`), so header-only detection silently fails. Returns one of:
    'json' (a single JSON value) | 'sse' (event-stream frames) |
    'jsonlines' (>=2 newline-delimited JSON objects) | 'none'."""
    b = (body or "").strip()
    if not b:
        return "none"
    if "text/event-stream" in (content_type or "").lower() or _SSE_FRAME_RE.search(body or ""):
        return "sse"
    try:
        json.loads(b)
        return "json"
    except json.JSONDecodeError:
        pass
    # Ignore blank lines AND SSE/NDJSON comment-heartbeat lines (`: keep-alive`)
    # so a real JSON-lines stream sprinkled with heartbeats isn't misjudged 'none'.
    lines = [ln for ln in b.splitlines() if ln.strip() and not ln.strip().startswith(":")]
    parsed = 0
    for ln in lines:
        try:
            json.loads(ln)
            parsed += 1
        except json.JSONDecodeError:
            pass
    if parsed >= 2 and parsed >= len(lines) * 0.6:      # mostly-JSON lines -> a JSON-lines stream
        return "jsonlines"
    return "none"


def _reg_domain(host: str) -> str:
    """Naive registrable domain (last two labels). No PSL, so multi-part TLDs
    (co.uk) collapse to the TLD+1 approximation — sufficient to keep a capture
    bound to the target site and reject an unrelated third-party origin."""
    parts = (host or "").lower().strip(".").split(".")
    return ".".join(parts[-2:]) if len(parts) >= 2 else (host or "").lower()


def _flow_host(url: str) -> str:
    from urllib.parse import urlsplit
    u = url if "://" in (url or "") else "https://" + (url or "")
    return (urlsplit(u).hostname or "").lower()


def select_chat_flow(flows: list[Flow], prompt_hint: str = "",
                     allowed_host: str = "") -> Flow | None:
    """Pick the flow most likely to be the model call, using the SAME scorer as
    wizard.parse_har (one definition of "which request is the chat call").

    When `allowed_host` is given, candidates are restricted to the target's
    registrable domain FIRST — the proxy records every origin the browser hits,
    so without this a third-party background POST could outscore the real chat
    call and get its cookie saved as the target (review #44, HIGH). If nothing
    on the target domain qualifies, return None rather than a cross-domain flow."""
    from . import wizard

    posts = [f for f in flows if (f.method or "").upper() == "POST" and f.req_body]
    if allowed_host:
        want = _reg_domain(allowed_host)
        posts = [f for f in posts if _reg_domain(_flow_host(f.url)) == want]
    if not posts:
        return None
    return max(posts, key=lambda f: wizard.score_chat_request(
        f.method, f.req_body, f.url, prompt_hint))


def flow_to_captured(flow: Flow, prompt_hint: str = ""):
    """Convert a recorded Flow into the `wizard.Captured` synthesize() consumes.

    Splits the Cookie header out as the credential (never left in headers), parses
    a JSON response, or for SSE reassembles the stream and pre-fills the per-chunk
    delta path so no second live replay is needed.
    """
    from . import wizard

    headers, cookie = {}, ""
    for k, v in (flow.req_headers or {}).items():
        if k.lower() == "cookie":
            cookie = v
        elif not k.startswith(":"):     # skip HTTP/2 pseudo-headers
            headers[k] = v

    body = flow.resp_body or ""
    mode = detect_response_mode(body, flow.resp_content_type or "")
    response, stream_delta_path = None, ""
    # Normalize content_type to a mode synthesize/runtime understand, so a stream
    # mislabeled as text/plain (v0.app) is still handled by shape, not header.
    if mode == "sse":
        stream_delta_path = sse_reassemble(body).delta_path
        content_type = "text/event-stream"
    elif mode == "jsonlines":
        stream_delta_path = sse_reassemble(body).delta_path   # "" for custom (non-delta) shapes
        content_type = "application/x-ndjson"
    elif mode == "json":
        try:
            response = json.loads(body)
        except json.JSONDecodeError:
            response = None
        content_type = flow.resp_content_type or ""
    else:
        content_type = flow.resp_content_type or ""           # 'none' — synthesize warns

    return wizard.Captured(
        url=flow.url, method="POST", headers=headers, body=flow.req_body or "",
        cookie=cookie, response=response, content_type=content_type,
        stream_delta_path=stream_delta_path,
    )


# --------------------------------------------------------------------------- #
# Orchestration (two-phase). The session logic below is fully unit-testable via
# an injected launcher + proxy; only the real mitmproxy adapter needs the extra.
# --------------------------------------------------------------------------- #

import contextlib
import os
import shutil
import tempfile


@dataclass
class ProxyCaptureResult:
    ok: bool
    captured: object = None             # wizard.Captured (selected chat flow) or None
    error: str = ""
    available: bool = True              # mitmproxy + playwright present


def proxy_available() -> bool:
    """True only if BOTH the proxy engine and the browser launcher are installed
    (the `[capture]` extra). Kept import-light so this module always imports."""
    try:
        import mitmproxy            # noqa: F401
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


@contextlib.contextmanager
def proxy_confdir():
    """A per-session, owner-only temp dir for mitmproxy's EPHEMERAL CA.

    Created under umask 0077 so it is 0700 from birth (no world-readable window),
    and removed on exit — including on exception / KeyboardInterrupt — so the
    interception CA never outlives the capture (design #44, AC3/AC4)."""
    old = os.umask(0o077)
    d = tempfile.mkdtemp(prefix="provenance-proxy-")
    try:
        os.chmod(d, 0o700)
        yield d
    finally:
        os.umask(old)
        shutil.rmtree(d, ignore_errors=True)


def _free_port() -> int:
    import socket
    s = socket.socket()
    s.bind(("127.0.0.1", 0))
    port = s.getsockname()[1]
    s.close()
    return port


def _prompt(msg: str) -> None:                          # pragma: no cover - interactive
    try:
        input(f"\n  -> {msg}")
    except EOFError:
        pass


def _run_capture_session(url, *, launcher, proxy, login_wait, send_wait, confdir):
    """Two-phase capture. Phase 1 (login) uses a context with NO proxy, so its
    traffic never reaches the recorder — the login exchange is structurally
    un-recordable (AC5). Phase 2 reuses the authenticated storage_state in a
    throwaway context pointed at the proxy with `ignore_https_errors=True`, so the
    ephemeral CA is trusted by NOTHING in any store. The proxy is always stopped
    (finally); the confdir is removed by the `proxy_confdir` wrapper (AC4)."""
    port = proxy.start(confdir)
    try:
        with launcher() as pw:
            browser = pw.chromium.launch(headless=False)
            login_ctx = rec_ctx = None
            try:
                # Phase 1 — login, NOT proxied, NOT recorded.
                login_ctx = browser.new_context()
                login_ctx.new_page().goto(url)
                login_wait()
                state = login_ctx.storage_state()
                login_ctx.close()
                login_ctx = None
                # Phase 2 — authenticated, proxied, recorded.
                proxy.begin_recording()
                rec_ctx = browser.new_context(
                    storage_state=state,
                    proxy={"server": f"http://127.0.0.1:{port}"},
                    ignore_https_errors=True)
                rec_ctx.new_page().goto(url)
                send_wait()
                return list(proxy.flows())
            finally:
                # Always tear the browser down — an abort (Ctrl-C at the prompt,
                # nav timeout) must NOT leave a headed Chromium whose profile holds
                # the operator's live session cookie (review #44, HIGH).
                for ctx in (rec_ctx, login_ctx):
                    if ctx is not None:
                        try:
                            ctx.close()
                        except Exception:
                            pass
                try:
                    browser.close()
                except Exception:
                    pass
    finally:
        proxy.stop()


class _MitmRecorder:
    """Embeds mitmproxy to record phase-2 flows into `Flow` objects.

    Requires the `[capture]` extra. The RECORDING ORCHESTRATION (two-phase,
    teardown, login-not-recorded) is unit-tested via a fake proxy in
    `_run_capture_session`; this adapter's mitmproxy internals (TLS interception)
    can't run in unit CI, so they are validated by the `[capture]`-gated E2E test
    and the security-review pass (issue #44). Version-sensitive: targets
    mitmproxy>=11's async DumpMaster embedding.
    """

    def __init__(self, port=None):
        self._port = port or _free_port()
        self._flows: list = []
        self._recording = False
        self._master = None
        self._loop = None
        self._thread = None

    def start(self, confdir):                           # pragma: no cover - needs extra
        import asyncio
        import threading
        import time
        from mitmproxy import options
        from mitmproxy.tools.dump import DumpMaster

        rec = self

        class _Addon:
            def response(self, flow):
                if not rec._recording:
                    return
                try:
                    req, resp = flow.request, flow.response
                    rec._flows.append(Flow(
                        url=req.pretty_url, method=req.method,
                        req_headers={k: v for k, v in req.headers.items()},
                        req_body=req.get_text(strict=False) or "",
                        resp_headers={k: v for k, v in resp.headers.items()},
                        resp_body=resp.get_text(strict=False) or "",
                        resp_content_type=resp.headers.get("content-type", "")))
                except Exception as e:                  # never let a capture crash the proxy
                    print(f"[capture] warning: dropped a recorded flow: {e}", file=sys.stderr)

        def _run():
            loop = asyncio.new_event_loop()
            asyncio.set_event_loop(loop)
            self._loop = loop

            async def _serve():
                # Construct DumpMaster INSIDE the running loop: mitmproxy>=11's
                # Master.__init__ falls back to asyncio.get_running_loop() when no
                # loop is passed, so building it before the loop runs raises
                # "no running event loop" on 12.x (real-env validation, #44).
                opts = options.Options(listen_host="127.0.0.1",
                                       listen_port=self._port, confdir=confdir)
                self._master = DumpMaster(opts, with_termlog=False, with_dumper=False)
                self._master.addons.add(_Addon())
                await self._master.run()

            try:
                loop.run_until_complete(_serve())
            finally:
                # master.run() returning does NOT close mitmproxy's (Rust-backed)
                # proxy listeners — they're torn down by setup_servers() once the
                # mode is cleared. Do that explicitly so the 127.0.0.1 port is
                # released; otherwise a long-lived `serve` leaks an open proxy per
                # capture (real-env validation, #44).
                async def _teardown():
                    ps = self._master.addons.get("proxyserver") if self._master else None
                    if ps is not None:
                        self._master.options.update(mode=[])   # inside the loop: configure()'s
                        await ps.setup_servers()               # create_task has a running loop
                try:
                    loop.run_until_complete(_teardown())
                except Exception:
                    pass
                try:
                    loop.close()
                except Exception:
                    pass

        self._thread = threading.Thread(target=_run, daemon=True)
        self._thread.start()
        # Poll until the listener actually accepts, instead of a blind sleep — a
        # fixed delay races a slow first-run CA generation and hides a bind failure.
        import socket as _socket
        for _ in range(50):
            try:
                with _socket.create_connection(("127.0.0.1", self._port), timeout=0.1):
                    return self._port
            except OSError:
                time.sleep(0.1)
        raise RuntimeError(f"capture proxy failed to bind 127.0.0.1:{self._port}")

    def begin_recording(self):
        self._recording = True

    def flows(self):
        return list(self._flows)

    def stop(self):                                     # pragma: no cover - needs extra
        # Signal shutdown AND wait for the proxy thread to actually exit before
        # returning, so the caller's `proxy_confdir` rmtree can't race the still-
        # running mitmproxy holding the ephemeral CA (review #44, HIGH).
        try:
            if self._master is not None and self._loop is not None:
                self._loop.call_soon_threadsafe(self._master.shutdown)
            if self._thread is not None:
                self._thread.join(timeout=5)
                if self._thread.is_alive():
                    print("[capture] warning: proxy thread did not stop within 5s; "
                          "the ephemeral CA dir may linger.", file=sys.stderr)
        except Exception:
            pass


def _default_driver(url, *, login_wait, send_wait, proxy_port=None):   # pragma: no cover - needs extra
    from playwright.sync_api import sync_playwright
    proxy = _MitmRecorder(port=proxy_port)
    with proxy_confdir() as confdir:
        return _run_capture_session(url, launcher=sync_playwright, proxy=proxy,
                                    login_wait=login_wait, send_wait=send_wait,
                                    confdir=confdir)


def capture(url, *, prompt_hint: str = "", login_wait=None, send_wait=None,
            driver=None, proxy_port=None) -> ProxyCaptureResult:
    """Capture one chat request+response from a logged-in web app via the proxy,
    returning a `wizard.Captured` ready for synthesize(). `driver` is injectable
    for tests; the default drives real mitmproxy + Playwright (needs `[capture]`)."""
    if driver is None:
        if not proxy_available():
            return ProxyCaptureResult(
                ok=False, available=False,
                error="proxy capture needs the [capture] extra "
                      "(pip install -e '.[capture]' && playwright install chromium), "
                      "or run with --paste for the manual steps.")
        driver = _default_driver
    login_wait = login_wait or (lambda: _prompt(
        "Log in in the browser, then press Enter here (do NOT send a message yet)..."))
    send_wait = send_wait or (lambda: _prompt(
        "Now send ONE short message in the chat, then press Enter here..."))
    try:
        flows = driver(url, login_wait=login_wait, send_wait=send_wait, proxy_port=proxy_port)
    except Exception as e:                              # noqa: BLE001 - transport/user-abort
        return ProxyCaptureResult(ok=False, error=f"capture failed: {_redact(str(e))}")
    # Bind selection to the target's domain so a third-party POST can't be saved
    # with the wrong cookie (review #44).
    flow = select_chat_flow(flows or [], prompt_hint, allowed_host=_flow_host(url))
    if flow is None:
        return ProxyCaptureResult(
            ok=False,
            error="no chat request was captured from this site — send exactly one "
                  "message after logging in, then press Enter; re-run and try again.")
    return ProxyCaptureResult(ok=True, captured=flow_to_captured(flow, prompt_hint))


def _redact(msg: str) -> str:
    """Strip URL query strings from an error message before it reaches the CLI/logs
    — some apps put auth tokens in the query, and transport errors echo the URL
    (review #44, LOW)."""
    return re.sub(r"(https?://[^\s?]+)\?[^\s]*", r"\1?<redacted>", msg or "")
