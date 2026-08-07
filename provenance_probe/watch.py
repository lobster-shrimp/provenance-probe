"""Local always-on watch daemon: unattended silent-model-swap detection.

The polling counterpart to the real-time ``sentinel`` proxy and the tab-bound
hosted watch (P2 #64). It assesses configured targets on a schedule, diffs each
against a pinned baseline with the SAME engine the CLI / web service / observatory
use (``assess.assess_target`` -> ``monitor.fingerprint`` -> ``monitor.diff``), and
raises a loud LOCAL alert the moment a target's fingerprint moves.

No new detection logic. The daemon only adds scheduling, a per-target baseline
store, and alert transports (stderr banner, ``switches.jsonl``, best-effort
desktop notification, optional webhook).

Trust model: on a single-user machine the target config may legitimately carry
keys/cookies, so the daemon can re-probe on its own. But a secret that is READ
from config must NEVER appear in any alert sink — the banner, ``switches.jsonl``,
the webhook payload, the desktop notification, or any logged error. Every switch
payload is built from the diff + fingerprints ONLY, and every transport error is
routed through ``client._safe_err`` before it is logged.
"""
from __future__ import annotations

import datetime
import json
import os
import random
import re
import shutil
import subprocess
import sys
import threading
from dataclasses import dataclass
from typing import Callable, Optional

from .config import Target
from .client import Client
from . import assess, monitor, egress


# --------------------------------------------------------------- storage paths ---
_SLUG_OK = re.compile(r"[^A-Za-z0-9._-]")


def _home() -> str:
    """The private data root (read at call time so tests can redirect it)."""
    return os.path.expanduser(os.environ.get("PROVENANCE_PROBE_HOME", "~/.provenance-probe"))


def watch_root() -> str:
    return os.path.join(_home(), "watch")


def slugify(name: str) -> str:
    """Turn a config-supplied target name into a safe single path segment.

    Allows ``[A-Za-z0-9._-]``; every other character becomes ``-``. Rejects the
    empty string and the traversal tokens ``.`` / ``..``. This is the first line
    of the path-traversal defense; ``target_dir`` adds a realpath containment
    check as the platform-independent backstop.
    """
    slug = _SLUG_OK.sub("-", name or "")[:100]     # cap length (avoid ENAMETOOLONG)
    if slug in ("", ".", ".."):
        raise ValueError(f"unsafe target name {name!r}: refusing to derive a watch directory")
    return slug


def target_dir(name: str, *, create: bool = False) -> str:
    """Resolve ``<watch_root>/<slug(name)>`` and PROVE it stays inside watch_root.

    A malicious or typo'd target name must never let the per-target directory
    escape the watch root. Mirrors the ``/media`` route discipline: slugify, then
    ``os.path.realpath`` containment.
    """
    root = os.path.realpath(watch_root())
    full = os.path.realpath(os.path.join(root, slugify(name)))
    if full != root and not full.startswith(root + os.sep):
        raise ValueError(f"unsafe target name {name!r}: resolved path escapes the watch dir")
    if full == root:
        raise ValueError(f"unsafe target name {name!r}: resolved to the watch root itself")
    if create:
        # 0700: baseline.json holds the full assessment bundle (response headers,
        # catalog, error excerpts) — keep it off other local accounts.
        os.makedirs(full, exist_ok=True)
        try:
            os.chmod(full, 0o700)
        except OSError:
            pass
    return full


def assert_unique_slugs(targets: list[Target]) -> None:
    """Reject a config where two DISTINCT target names collide onto the same
    watch directory (slugify is not injective: ``a/b`` and ``a:b`` -> ``a-b``).
    A collision would make two targets share one baseline/state/switches file and
    silently corrupt each other's drift detection."""
    seen: dict[str, str] = {}
    for t in targets:
        slug = slugify(t.name)
        if slug in seen and seen[slug] != t.name:
            raise ValueError(
                f"target names {seen[slug]!r} and {t.name!r} both map to the watch "
                f"directory {slug!r}; rename one so their baselines don't collide")
        seen[slug] = t.name


def _baseline_path(name: str) -> str:
    return os.path.join(target_dir(name), "baseline.json")


def _state_path(name: str) -> str:
    return os.path.join(target_dir(name), "state.json")


def _switches_path(name: str) -> str:
    return os.path.join(target_dir(name), "switches.jsonl")


def load_baseline(name: str) -> Optional[dict]:
    p = _baseline_path(name)
    if not os.path.exists(p):
        return None
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_baseline(name: str, bundle: dict) -> None:
    target_dir(name, create=True)
    with open(_baseline_path(name), "w", encoding="utf-8") as f:
        json.dump(bundle, f, indent=2)


def load_state(name: str) -> dict:
    p = _state_path(name)
    if not os.path.exists(p):
        return {}
    with open(p, encoding="utf-8") as f:
        return json.load(f)


def save_state(name: str, state: dict) -> None:
    target_dir(name, create=True)
    with open(_state_path(name), "w", encoding="utf-8") as f:
        json.dump(state, f, indent=2)


def append_switch(name: str, record: dict) -> None:
    target_dir(name, create=True)
    with open(_switches_path(name), "a", encoding="utf-8") as f:
        f.write(json.dumps(record) + "\n")


# ------------------------------------------------------------------ scheduling ---
def parse_interval(s: str) -> int:
    """Parse ``30s`` / ``15m`` / ``1h`` (or a bare integer = seconds) to seconds."""
    s = (s or "").strip().lower()
    if not s:
        raise ValueError("empty interval")
    unit = {"s": 1, "m": 60, "h": 3600}
    if s[-1] in unit:
        num, mult = s[:-1], unit[s[-1]]
    else:
        num, mult = s, 1
    try:
        val = int(num)
    except ValueError:
        raise ValueError(f"bad interval {s!r}: use forms like 30s, 15m, 1h")
    if val <= 0:
        raise ValueError(f"interval must be positive, got {s!r}")
    return val * mult


def jitter_seconds(interval: int, frac: float) -> float:
    """A random 0..(frac*interval) delay, capped at 30s. ``frac<=0`` disables it."""
    if not frac or frac <= 0:
        return 0.0
    cap = min(interval * frac, 30.0)
    return random.uniform(0.0, cap)


# ------------------------------------------------------------- secret-safe alert ---
def _redact(target: Target, msg: str) -> str:
    """Route any transport/error string through the target's credential redactor.

    Fails CLOSED: if the redactor itself raises we return a fixed generic string
    rather than the raw (possibly secret-bearing) message.
    """
    try:
        return Client(target)._safe_err(msg or "")
    except Exception:
        return "[error redacted]"


def switch_record(name: str, baseline_fp: Optional[str], current_fp: Optional[str],
                  diff_result: dict) -> dict:
    """The machine-readable switch record — built from the diff + fingerprints ONLY.

    Contains NO header/key/cookie material by construction; this exact shape is
    what lands in ``switches.jsonl`` and is POSTed to ``--webhook``.
    """
    rec = {
        "ts": datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds"),
        "target": name,
        "baseline_fp": baseline_fp,
        "current_fp": current_fp,
        "changes": diff_result.get("changes", []),
        "confidence": diff_result.get("confidence"),
    }
    if diff_result.get("confidence_note"):
        rec["confidence_note"] = diff_result["confidence_note"]
    return rec


def render_banner(name: str, baseline_fp: Optional[str], current_fp: Optional[str],
                  diff_result: dict) -> str:
    """The loud multi-line stderr banner. Fingerprints + diff table only."""
    bar = "=" * 68
    lines = [
        bar,
        "  !!  MODEL SWITCH DETECTED  !!",
        bar,
        f"  target      : {name}",
        f"  fingerprint : {baseline_fp} -> {current_fp}",
        f"  confidence  : {diff_result.get('confidence')}",
        "  changes     :",
    ]
    for c in diff_result.get("changes", []):
        lines.append(f"    [{c.get('severity','?'):<8}] {c.get('field','?')}: {c.get('detail','')}")
    if diff_result.get("confidence_note"):
        lines.append(f"  note        : {diff_result['confidence_note']}")
    lines.append(bar)
    return "\n".join(lines)


def desktop_notify(title: str, message: str) -> bool:
    """Best-effort desktop notification. Feature-detected; NEVER raises/fails a run."""
    try:
        if sys.platform == "darwin" and shutil.which("osascript"):
            body = f'display notification {json.dumps(message)} with title {json.dumps(title)}'
            subprocess.run(["osascript", "-e", body], timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
        if shutil.which("notify-send"):
            subprocess.run(["notify-send", title, message], timeout=5,
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            return True
    except Exception:
        pass
    return False


def _webhook_host(url: str) -> str:
    """scheme://host[:port] of a URL — never its PATH (which may be a secret token)."""
    from urllib.parse import urlsplit
    try:
        u = urlsplit(url)
        host = f"{u.scheme}://{u.hostname}" if u.scheme and u.hostname else "(webhook)"
        return host + (f":{u.port}" if u.port else "")
    except Exception:
        return "(webhook)"


def post_webhook(url: str, record: dict, target: Optional[Target] = None,
                 *, log: Callable[[str], None] = None) -> bool:
    """Best-effort POST of the (secret-free) switch record. Failure logs, not fatal.

    The POST goes through an SSRF-egress-guarded session (mirroring the rest of
    the codebase's user-supplied-URL fetches). On failure we log the exception
    CLASS + ``scheme://host`` only — NEVER the raw exception, which ``requests``
    populates with the full URL whose PATH may itself be a webhook secret token
    (Slack/Discord/PagerDuty), and which would then land in the launchd/systemd
    log files.
    """
    log = log or (lambda m: print(m, file=sys.stderr))
    host = _webhook_host(url)
    try:
        import requests
        s = requests.Session()
        if egress.guard_enabled():
            egress.install_guard(s)
        r = s.post(url, json=record, timeout=10)
        if r.status_code >= 400:
            log(f"[watch] webhook {host} returned HTTP {r.status_code}")
            return False
        return True
    except Exception as e:
        log(f"[watch] webhook POST to {host} failed (non-fatal): {type(e).__name__}")
        return False


# ------------------------------------------------------------------- per-target ---
def check_target(target: Target, opts: assess.AssessOpts, *, pin: bool = False,
                 webhook: Optional[str] = None, quiet: bool = False,
                 log: Callable[[str], None] = None) -> dict:
    """Assess one target, seed-or-diff against its baseline, alert on drift.

    Returns a status dict; NEVER raises (operational errors are captured with a
    redacted message). Alert side-effects are individually best-effort so they
    can never downgrade a decided-drift result.
    """
    out = print if log is None else log
    name = target.name
    try:
        target_dir(name, create=True)                      # validates the name/path first
        cur = assess.assess_target(target, opts)
        cur_fp = cur.get("fingerprint_id")
        baseline = load_baseline(name)
        now = datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="seconds")
        if pin or baseline is None:
            save_baseline(name, cur)
            save_state(name, {"last_check": now, "last_fingerprint": cur_fp,
                              "baseline_fingerprint": cur_fp, "baseline_pinned_at": now})
            if not quiet:
                out(f"[watch] {name}: baseline pinned ({cur_fp})")
            return {"target": name, "status": "seeded", "drift": False,
                    "baseline_fp": cur_fp, "current_fp": cur_fp}
        base_fp = baseline.get("fingerprint_id")
        result = monitor.diff(baseline, cur)
        st = load_state(name)
        st.update({"last_check": now, "last_fingerprint": cur_fp,
                   "baseline_fingerprint": base_fp})
        save_state(name, st)
        decided = {"target": name, "current_fp": cur_fp, "baseline_fp": base_fp,
                   "changes": result["changes"], "confidence": result["confidence"]}
    except Exception as e:                                  # operational error, no drift
        return {"target": name, "status": "error", "drift": False,
                "error": _redact(target, str(e))}

    if not result["drift_detected"]:
        if not quiet:
            out(f"[watch] {name}: no drift ({cur_fp})")
        return {**decided, "status": "clean", "drift": False}

    # --- drift: raise the loud, secret-free alert (every sink best-effort) ---
    rec = switch_record(name, base_fp, cur_fp, result)
    try:
        append_switch(name, rec)
    except Exception as e:
        out(f"[watch] {name}: could not append switches.jsonl (non-fatal): {_redact(target, str(e))}")
    print(render_banner(name, base_fp, cur_fp, result), file=sys.stderr)
    desktop_notify(f"provenance-probe: {name}",
                   f"MODEL SWITCH {(base_fp or '')[:12]} -> {(cur_fp or '')[:12]}")
    if webhook:
        post_webhook(webhook, rec, target, log=out)
    return {**decided, "status": "drift", "drift": True}


# ------------------------------------------------------------------ run modes ---
def _select(targets: list[Target], only: Optional[str]) -> list[Target]:
    if not only:
        return targets
    picked = [t for t in targets if t.name == only]
    if not picked:
        raise ValueError(f"no target named {only!r} in the config")
    return picked


def run_once(targets: list[Target], opts: assess.AssessOpts, *, pin: bool = False,
             webhook: Optional[str] = None, only: Optional[str] = None,
             log: Callable[[str], None] = None) -> int:
    """One pass over all (or ``only``) targets. Exit 2 on ANY drift (drift wins),
    else 1 on any operational error, else 0."""
    out = print if log is None else log
    assert_unique_slugs(targets)
    results = [check_target(t, opts, pin=pin, webhook=webhook, log=out)
               for t in _select(targets, only)]
    drifted = [r["target"] for r in results if r["status"] == "drift"]
    errored = [r["target"] for r in results if r["status"] == "error"]
    seeded = [r["target"] for r in results if r["status"] == "seeded"]
    clean = [r["target"] for r in results if r["status"] == "clean"]
    out(f"[watch] summary: {len(drifted)} drifted, {len(errored)} errored, "
        f"{len(seeded)} seeded, {len(clean)} clean")
    if drifted:
        out(f"[watch]   drifted: {', '.join(drifted)}")
    if errored:
        out(f"[watch]   errored: {', '.join(errored)}")
    if drifted:
        return 2
    if errored:
        return 1
    return 0


def pin_targets(targets: list[Target], opts: assess.AssessOpts, *,
                only: Optional[str] = None, log: Callable[[str], None] = None) -> int:
    """Re-pin baselines to the current fingerprint for all (or ``only``) targets."""
    out = print if log is None else log
    assert_unique_slugs(targets)
    rc = 0
    for t in _select(targets, only):
        r = check_target(t, opts, pin=True, log=out)
        if r["status"] == "error":
            out(f"[watch] {t.name}: pin failed: {r.get('error')}")
            rc = 1
    return rc


def run_loop(targets: list[Target], opts: assess.AssessOpts, *, interval: int,
             jitter_frac: float = 0.10, webhook: Optional[str] = None,
             only: Optional[str] = None, stop_event: Optional[threading.Event] = None,
             max_passes: Optional[int] = None,
             on_cycle: Optional[Callable[[int], None]] = None,
             log: Callable[[str], None] = None) -> int:
    """Run forever (until ``stop_event`` is set): each pass assesses every target,
    diffs, and alerts on drift — then sleeps ``interval`` + jitter. One target's
    exception is caught and logged; it never kills the loop. Returns 0 on a clean
    shutdown.

    ``stop_event`` / ``max_passes`` / ``on_cycle`` make the loop drivable by tests
    and by the signal handlers in ``cmd_watch`` without real signals leaking here.
    """
    out = print if log is None else log
    assert_unique_slugs(targets)
    stop = stop_event or threading.Event()
    selected = _select(targets, only)
    passes = 0
    while not stop.is_set():
        for t in selected:
            if stop.is_set():                              # finish nothing new after a stop
                break
            try:
                check_target(t, opts, webhook=webhook, log=out)
            except Exception as e:                         # belt-and-suspenders: never die
                out(f"[watch] {t.name}: unexpected error (loop continues): {_redact(t, str(e))}")
        passes += 1
        if on_cycle:
            on_cycle(passes)
        if stop.is_set() or (max_passes is not None and passes >= max_passes):
            break
        delay = interval + jitter_seconds(interval, jitter_frac)
        stop.wait(delay)                                   # interruptible sleep
    out("[watch] shutting down cleanly")
    return 0


# ------------------------------------------------------------ unit generators ---
def _watch_argv(config_path: str) -> list[str]:
    """The argv a scheduler should run: this interpreter, this package, watch --once."""
    return [sys.executable, "-m", "provenance_probe.cli", "watch", "--once",
            "--config", os.path.abspath(config_path)]


def _plist_str(v: str) -> str:
    import html as _html
    return f"<string>{_html.escape(v)}</string>"


def launchd_plist(config_path: str, *, interval: int = 3600,
                  label: str = "com.provenance-probe.watch") -> str:
    """A ready-to-load launchd ``.plist`` running ``watch --once`` on a StartInterval.

    Parses under ``plutil -lint``. Install hint is an XML comment.
    """
    args = "\n".join("    " + _plist_str(a) for a in _watch_argv(config_path))
    logdir = os.path.join(watch_root(), "launchd")
    # NB: an XML comment may not contain the "--" sequence, so the install hint
    # is phrased without CLI flags (the flags live safely in ProgramArguments).
    plist_path = f"~/Library/LaunchAgents/{label}.plist"
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<!-- provenance-probe always-on watch. To install, save this file to
     {plist_path} then run: launchctl load {plist_path}
     To uninstall, run: launchctl unload {plist_path} -->
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>{label}</string>
  <key>ProgramArguments</key>
  <array>
{args}
  </array>
  <key>StartInterval</key>
  <integer>{int(interval)}</integer>
  <key>RunAtLoad</key>
  <true/>
  <key>StandardOutPath</key>
  <string>{os.path.join(logdir, 'stdout.log')}</string>
  <key>StandardErrorPath</key>
  <string>{os.path.join(logdir, 'stderr.log')}</string>
</dict>
</plist>
"""


def systemd_units(config_path: str, *, interval: int = 3600) -> str:
    """A systemd ``.service`` + ``.timer`` pair running ``watch --once``.

    Structurally valid (passes ``systemd-analyze verify`` where available). The
    two units are emitted together with ``# ---`` file markers + an install hint.
    """
    exec_line = " ".join(_watch_argv(config_path))
    service = f"""[Unit]
Description=provenance-probe watch (unattended silent-model-swap detection)
After=network-online.target
Wants=network-online.target

[Service]
Type=oneshot
ExecStart={exec_line}
"""
    timer = f"""[Unit]
Description=Run provenance-probe watch on a timer

[Timer]
OnBootSec={int(interval)}
OnUnitActiveSec={int(interval)}
AccuracySec=30
Persistent=true

[Install]
WantedBy=timers.target
"""
    return (
        "# provenance-probe watch (always-on) — systemd units.\n"
        "# Install (user scope):\n"
        "#   provenance-probe watch --print-systemd --config "
        f"{os.path.abspath(config_path)} > /tmp/pp-watch.units\n"
        "#   csplit the two sections below into ~/.config/systemd/user/provenance-probe-watch.service\n"
        "#   and provenance-probe-watch.timer, then:\n"
        "#   systemctl --user daemon-reload && systemctl --user enable --now provenance-probe-watch.timer\n"
        "# ===== FILE: provenance-probe-watch.service =====\n"
        f"{service}"
        "# ===== FILE: provenance-probe-watch.timer =====\n"
        f"{timer}"
    )
