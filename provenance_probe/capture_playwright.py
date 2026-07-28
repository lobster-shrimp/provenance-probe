"""Optional Playwright capture assist (E8, P3 optional extra).

Automates the guided capture: open a real browser at the operator's target,
let THEM log in and send one message (we never handle passwords), record the
traffic to a HAR, and hand it to the existing wizard.parse_har/synthesize path.

Playwright is an OPTIONAL dependency (`pip install -e '.[capture]'` +
`playwright install chromium`). If it isn't installed, `capture()` returns a
clear, non-crashing status and the CLI prints the manual guided steps instead.

SECURITY:
- The operator logs in themselves in the headed browser; this module never sees
  or types a password (prohibited action).
- TWO-PHASE so the login exchange is NEVER recorded: the operator logs in in an
  UNRECORDED context; we snapshot the authenticated `storage_state` (cookies /
  localStorage) and open a SECOND, recorded context from that state. The HAR
  therefore captures only the post-login chat traffic — no login POST, no
  password, no OAuth code lands in the file (Codex adversarial, HIGH).
- The recorded HAR contains the authenticated session's traffic — the session
  cookie, and any token the app sends on load (e.g. a silent refresh) — but
  never the password (it is submitted only in the unrecorded login phase). It is
  written 0600 to a private captures dir (the CLI adds a .gitignore entry if it
  lands in a repo) and the operator is warned it is a credential; the wizard's
  write-boundary sanitize additionally keeps it out of any committed config.
- Only drive a browser to a service the operator is authorized to test
  (--i-am-authorized), same scope rule as the rest of the tool.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass
class CaptureResult:
    ok: bool
    har_path: str = ""
    error: str = ""
    playwright_available: bool = True


def playwright_available() -> bool:
    try:
        import playwright.sync_api  # noqa: F401
        return True
    except Exception:
        return False


def capture(url: str, har_path: str, *, login_wait=None, send_wait=None,
            launcher=None, timeout_ms: int = 300000) -> CaptureResult:
    """Open `url` in a headed browser and record ONLY the post-login chat traffic.

    Phase 1 (unrecorded): navigate, `login_wait()` blocks while the operator
    logs in. Phase 2 (recorded): a fresh context reuses the authenticated
    storage_state and records to `har_path` while `send_wait()` blocks for the
    operator to send one message. The login exchange is never recorded.

    `login_wait`/`send_wait` are injectable for tests; `launcher` defaults to
    playwright sync_api. Never raises for the common failure (playwright absent).
    """
    if launcher is None:
        if not playwright_available():
            return CaptureResult(ok=False, playwright_available=False,
                                 error="Playwright is not installed. Install the capture extra "
                                       "(pip install -e '.[capture]' && playwright install chromium), "
                                       "or follow the manual steps.")
        from playwright.sync_api import sync_playwright
        launcher = sync_playwright

    login_wait = login_wait or (lambda: _prompt(
        "Log in in the browser window, then press Enter here (do NOT send a message yet)… "))
    send_wait = send_wait or (lambda: _prompt(
        "Now send ONE short message in the chat, then press Enter here… "))
    nav_timeout = min(timeout_ms, 60000)
    import os
    # Restrict the umask for the whole capture so the HAR Playwright creates is
    # 0600 AT CREATION — no world-readable window between flush and chmod, and no
    # exposure if the post-hoc chmod fails (Claude adversarial, MEDIUM).
    old_umask = os.umask(0o077)
    try:
        with launcher() as pw:
            browser = pw.chromium.launch(headless=False)
            # Phase 1 — login, NOT recorded.
            login_ctx = browser.new_context()
            page = login_ctx.new_page()
            page.goto(url, wait_until="domcontentloaded", timeout=nav_timeout)
            login_wait()
            state = login_ctx.storage_state()          # cookies/localStorage AFTER login
            login_ctx.close()
            # Phase 2 — authenticated session only, recorded to the HAR.
            rec_ctx = browser.new_context(storage_state=state, record_har_path=har_path)
            page2 = rec_ctx.new_page()
            page2.goto(url, wait_until="domcontentloaded", timeout=nav_timeout)
            send_wait()
            rec_ctx.close()                            # flushes the HAR
            browser.close()
        _chmod_600(har_path)                           # belt-and-suspenders
        return CaptureResult(ok=True, har_path=har_path)
    except Exception as e:                             # transport / navigation / user-abort
        return CaptureResult(ok=False, error=f"capture failed: {e}")
    finally:
        os.umask(old_umask)


def _chmod_600(path: str) -> None:
    import os
    try:
        os.chmod(path, 0o600)                          # credential-bearing; owner-only
    except OSError:
        pass


def _prompt(msg: str) -> None:                         # pragma: no cover - interactive
    try:
        input(f"\n  → {msg}")
    except EOFError:
        pass
