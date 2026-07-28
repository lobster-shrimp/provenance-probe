"""Guided web-app capture (E8): annotated, browser-specific steps that walk a
non-technical operator through capturing the ONE chat request the template
adapter needs — no DevTools experience assumed.

This is the no-dependency core of P3. The optional Playwright assist
(`capture_playwright.py`, behind the `[capture]` extra) automates the very same
capture when installed, and falls back to these steps when it isn't.

Everything here is pure (URL/host in → structured steps out), so the wizard can
render it and tests can assert on it. It NEVER performs a capture or touches the
network itself.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import urlsplit

# Per-browser DevTools specifics: how to open it, and the exact "copy as cURL"
# menu label (they differ, and the label is the step people get stuck on).
_BROWSERS = {
    "chrome": {"label": "Chrome / Edge / Brave (Chromium)",
               "open": "Press F12 (or ⌘⌥I on macOS) and click the Network tab.",
               "curl": 'Right-click the request → Copy → "Copy as cURL" '
                       '(pick "bash" if asked, not "cmd").'},
    "firefox": {"label": "Firefox",
                "open": "Press F12 (or ⌘⌥I on macOS) and click the Network tab.",
                "curl": 'Right-click the request → Copy Value → "Copy as cURL".'},
    "safari": {"label": "Safari",
               "open": "First enable Settings → Advanced → “Show features for web "
                       "developers”, then Develop → Show Web Inspector → Network tab.",
               "curl": 'Right-click the request → "Copy as cURL".'},
}

# Hosts we can name in the guidance (informational only — not a verdict).
_KNOWN_APPS = {
    "chat.openai.com": "ChatGPT", "chatgpt.com": "ChatGPT",
    "claude.ai": "Claude", "gemini.google.com": "Gemini",
    "chat.lindy.ai": "Lindy", "chat.z.ai": "Z.ai / GLM",
    "replit.com": "Replit", "base44.com": "Base44",
}


@dataclass
class Step:
    n: int
    title: str
    detail: str
    why: str = ""


@dataclass
class CaptureGuide:
    url: str
    host: str
    app: str
    browser: str
    steps: list = field(default_factory=list)
    har_alternative: list = field(default_factory=list)
    security_note: str = ""
    playwright_hint: str = ""


def _host(url: str) -> str:
    s = (url or "").strip()
    if s and "://" not in s:
        s = "https://" + s
    return (urlsplit(s).hostname or "").lower()


def guide(url: str, *, browser: str = "chrome", playwright_available: bool = False) -> CaptureGuide:
    """Return annotated capture steps for `url`, tailored to `browser`.

    `browser` is one of chrome|firefox|safari (unknown → chrome, the common case).
    `playwright_available` toggles a one-line hint about the automated path.
    """
    host = _host(url)
    app = _KNOWN_APPS.get(host, "the web app")
    b = _BROWSERS.get((browser or "").lower(), _BROWSERS["chrome"])

    steps = [
        Step(1, f"Sign in to {app}",
             f"Open {host or 'the app'} in your browser and log in as you normally would.",
             "The request we capture must be authenticated, exactly as your real session sends it."),
        Step(2, "Open the Network tab",
             b["open"],
             "This records the requests the page makes so we can find the model call."),
        Step(3, "Send one short message",
             'Type a short, distinctive message (e.g. "fingerprint me") and hit send. '
             "In the Network list, find the request that fires the moment you send — it is "
             "usually a POST whose name looks like chat, completion, message, conversation, or generate.",
             "That POST is the call to the model. Its response carries the reply (and sometimes token usage)."),
        Step(4, "Copy it as cURL",
             b["curl"],
             "cURL captures the URL, headers, cookies, and JSON body together — everything the probe needs."),
        Step(5, "Paste it back into the wizard",
             'Paste the copied cURL into the "Add a target" box, and put the exact message you sent '
             '("fingerprint me") in the message field so we can locate it in the request.',
             "The wizard turns it into a probe target and dry-runs it before saving."),
    ]
    har_alternative = [
        "Prefer a file? In the Network tab, right-click any request → "
        '"Save all as HAR" (Chrome/Firefox) and paste the file’s contents into the wizard.',
        "A HAR also captures the RESPONSE body, which lets the wizard auto-fill the "
        "reply / token-usage paths — slightly better than cURL when it works.",
    ]
    security_note = (
        "The captured request contains your session cookie. The wizard writes it only to a "
        "gitignored .env.capture file and references it by name — it never enters the committed "
        "config. Only capture services you are authorized to test.")
    playwright_hint = ""
    if playwright_available:
        playwright_hint = (
            f"Automated option: run `provenance-probe capture {url or '<url>'}` — it opens a "
            "browser, waits while you log in and send one message, and captures the request for you.")
    else:
        playwright_hint = (
            "Want this automated? Install the optional capture extra "
            "(`pip install -e '.[capture]'`) and run `provenance-probe capture <url>`.")

    return CaptureGuide(url=url, host=host, app=app, browser=b["label"], steps=steps,
                        har_alternative=har_alternative, security_note=security_note,
                        playwright_hint=playwright_hint)


def as_text(g: CaptureGuide) -> str:
    """Plain-text rendering (for the CLI fallback)."""
    lines = [f"Capturing a request from {g.app} ({g.host or 'web app'}) — {g.browser}", ""]
    for s in g.steps:
        lines.append(f"  {s.n}. {s.title}")
        lines.append(f"     {s.detail}")
        if s.why:
            lines.append(f"     why: {s.why}")
        lines.append("")
    lines.append("HAR alternative:")
    lines += [f"  - {h}" for h in g.har_alternative]
    lines.append("")
    lines.append(f"Security: {g.security_note}")
    if g.playwright_hint:
        lines += ["", g.playwright_hint]
    return "\n".join(lines)
