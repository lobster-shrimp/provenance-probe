"""Known-vendor presets (E4) and env-key lookup (E3).

Presets map a recognizable host (or a short vendor slug) to a base_url and an
api-shape hint, so the common case is two clicks instead of "which API style?".
The env-key lookup finds a `{VENDOR}_API_KEY` already in the environment and
offers it — the VALUE is never written to the committed config (only the
env-var NAME rides `auth_value_env`, the same invariant the wizard enforces).

`jurisdiction_hint` is INFORMATIONAL prefill only — it is never a verdict. The
tokenizer fingerprint, not this table, decides provenance/jurisdiction.
"""
from __future__ import annotations

from dataclasses import dataclass


@dataclass(frozen=True)
class Preset:
    slug: str
    label: str
    base_url: str
    api_style: str            # openai | anthropic
    host_match: tuple         # host substrings that identify this vendor
    key_env: str              # env var conventionally holding the key
    jurisdiction_hint: str = ""   # "CN" etc. — prefill hint, NOT a verdict


# Ordered most-specific first; match_host stops at the first hit.
PRESETS: tuple[Preset, ...] = (
    Preset("openai", "OpenAI", "https://api.openai.com/v1", "openai",
           ("api.openai.com",), "OPENAI_API_KEY"),
    Preset("anthropic", "Anthropic", "https://api.anthropic.com", "anthropic",
           ("api.anthropic.com",), "ANTHROPIC_API_KEY"),
    Preset("deepseek", "DeepSeek", "https://api.deepseek.com", "openai",
           ("api.deepseek.com",), "DEEPSEEK_API_KEY", "CN"),
    Preset("moonshot", "Moonshot (Kimi)", "https://api.moonshot.ai/v1", "openai",
           ("api.moonshot.ai", "api.moonshot.cn"), "MOONSHOT_API_KEY", "CN"),
    Preset("openrouter", "OpenRouter", "https://openrouter.ai/api/v1", "openai",
           ("openrouter.ai",), "OPENROUTER_API_KEY"),
    Preset("gemini", "Google Gemini (OpenAI-compat)",
           "https://generativelanguage.googleapis.com/v1beta/openai", "openai",
           ("generativelanguage.googleapis.com",), "GEMINI_API_KEY"),
)


def _hostname(url_or_host: str) -> str:
    """Extract the hostname from a URL or bare host, lowercased, no port."""
    from urllib.parse import urlsplit
    s = (url_or_host or "").strip().lower()
    if not s:
        return ""
    if "://" not in s:
        s = "https://" + s
    return (urlsplit(s).hostname or "").rstrip(".")


def match_host(url_or_host: str) -> Preset | None:
    """Return the preset for this URL/host, or None.

    Matches on the parsed HOSTNAME with exact-or-subdomain semantics — NOT a raw
    substring. This is a security boundary: substring matching would let
    `https://api.openai.com.evil.test` select `OPENAI_API_KEY` and send the real
    key to an attacker host (Codex adversarial review, CRITICAL). A host matches
    a preset host `h` only if it equals `h` or ends with `"." + h`.
    """
    host = _hostname(url_or_host)
    if not host:
        return None
    for p in PRESETS:
        for h in p.host_match:
            if host == h or host.endswith("." + h):
                return p
    return None


def match_slug(slug: str) -> Preset | None:
    """Return the preset for an exact vendor slug (e.g. 'openai'), or None."""
    s = (slug or "").strip().lower()
    for p in PRESETS:
        if p.slug == s:
            return p
    return None


def env_key_for(preset: Preset | None, environ: dict | None = None) -> str | None:
    """Return the env-var NAME (never the value) if it is set and non-empty.

    The caller resolves the value in-memory for the probe; the config only ever
    stores this NAME via `auth_value_env`. Returns None if unset.
    """
    import os
    environ = environ if environ is not None else os.environ
    if preset and preset.key_env and (environ.get(preset.key_env) or "").strip():
        return preset.key_env
    return None
