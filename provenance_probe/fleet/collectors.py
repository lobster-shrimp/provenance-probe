"""Collectors: discover where local agent CLIs are pointed (their base_url).

Two collectors behind a thin seam (plan-eng-review Step 0 — no formal interface
until a 3rd collector type lands): config files and process env. Both produce
CONFIGURED-tier evidence — the weakest tier, because a config value may be stale
and is not proof of effective traffic (Codex #4).

Config parsing is a dependency-free, format-agnostic regex over base-url-ish keys,
so it works on TOML (`base = "..."`), JSON (`"base_url": "..."`), and YAML
(`base_url: ...`) alike without pulling in per-format parsers. Filesystem access
is injected so the collectors are pure and unit-testable.

Env caveat (Codex #3): a scheduled scanner sees its OWN environment, not every
developer shell / IDE / direnv / npm session. Env findings carry that caveat.
"""
from __future__ import annotations

import re
from collections.abc import Callable

from .evidence import CONFIGURED, Finding
from ..presets import _hostname

# Per-tool config files to scan (path is relative to home; "~" expanded by caller).
# Ships macOS + Linux first (plan defers Windows).
DEFAULT_CONFIG_TARGETS: list[str] = [
    ".codex/config.toml",
    ".continue/config.json",
    ".aider.conf.yml",
    ".claude/settings.json",
    ".cursor/mcp.json",
]

# Env vars that redirect an agent CLI's base URL.
DEFAULT_ENV_VARS: list[str] = [
    "ANTHROPIC_BASE_URL",
    "OPENAI_BASE_URL",
    "OPENAI_API_BASE",
]

# Match a base-url-ish key followed by an http(s) URL, across TOML/JSON/YAML/env.
_BASE_URL_RE = re.compile(
    r"(?i)(?:api_base|base_url|openai_api_base|anthropic_base_url|openai_base_url"
    r"|api_url|base|endpoint)"
    r"""["']?\s*[:=]\s*["']?(https?://[^\s"',]+)""",
)


def extract_base_urls_from_text(text: str) -> list[str]:
    """Return base_url values found in a config file body (format-agnostic).
    De-duplicated, order-preserving."""
    out: list[str] = []
    seen: set[str] = set()
    for m in _BASE_URL_RE.finditer(text or ""):
        url = m.group(1).rstrip("/")
        if url and url not in seen:
            seen.add(url)
            out.append(url)
    return out


def collect_config_files(
    read_text: Callable[[str], str | None],
    home: str = "~",
    targets: list[str] | None = None,
) -> list[Finding]:
    """Scan per-tool config files for base_url redirects.

    `read_text(path)` returns the file body or None if absent/unreadable — the
    injection point that keeps this pure. A permission error surfaces as None
    (the collector degrades, never raises)."""
    findings: list[Finding] = []
    base = home.rstrip("/")
    for rel in (targets or DEFAULT_CONFIG_TARGETS):
        path = f"{base}/{rel}"
        try:
            text = read_text(path)
        except Exception:
            text = None
        if not text:
            continue
        for url in extract_base_urls_from_text(text):
            findings.append(Finding(
                source=path, base_url=url, host=_hostname(url),
                evidence_tier=CONFIGURED, classification="",
            ))
    return findings


def collect_env(
    environ: dict[str, str],
    var_names: list[str] | None = None,
) -> list[Finding]:
    """Scan the process environment for base_url redirects. Findings note the
    scanner-env coverage limit (Codex #3)."""
    findings: list[Finding] = []
    for name in (var_names or DEFAULT_ENV_VARS):
        val = (environ or {}).get(name)
        if not val:
            continue
        url = val.strip().rstrip("/")
        findings.append(Finding(
            source=f"env:{name}", base_url=url, host=_hostname(url),
            evidence_tier=CONFIGURED, classification="",
            notes=["scanner-process env only; not every developer shell/IDE session"],
        ))
    return findings
