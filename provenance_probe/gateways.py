"""Pure, network-free gateway knowledge.

Shared by the OmniRoute cross-check (``omniroute.py``) and the fleet scanner
(``fleet/``). This module NEVER imports ``requests`` or performs any I/O — it
holds only the static label->family map and local-gateway recognition
constants.

Why a separate module: the fleet scanner is a no-egress host-forensics tool. By
keeping the knowledge it needs in a pure module it can import, the fleet package
never imports the network-bearing ``omniroute.py`` at all. The no-egress
boundary is enforced by module structure, not by convention (plan-eng-review
Arch 1).
"""
from __future__ import annotations

import re

# Default OpenAI-compatible base for a local OmniRoute router.
OMNIROUTE_DEFAULT_BASE = "http://localhost:20128/v1"

# Known local AI gateways: name -> (loopback host, default port). Used by the
# fleet scanner to recognize that a base_url pointing at localhost is a router
# whose OWN config must be parsed to resolve the real upstream (the localhost
# blind-spot fix). Ports are recognition hints, not proof; the config parser
# does the authoritative resolution.
KNOWN_LOCAL_GATEWAYS: dict[str, tuple[str, int]] = {
    "omniroute": ("localhost", 20128),
    "litellm": ("localhost", 4000),
}

# Maintained LABEL -> tokenizer-family map. Maps a router/model label
# (optionally provider-prefixed, e.g. "oc/deepseek-v4-flash-free") to the family
# we expect. An UNMAPPED label yields None (INCONCLUSIVE downstream), never a
# guess. Keys match at LETTER boundaries only. Ordered MOST-SPECIFIC-FIRST: the
# first hit wins, so multi-word keys (gpt-neox) must precede their prefixes (gpt).
LABEL_FAMILY: dict[str, str] = {
    "gpt-neox": "GPT-NeoX",
    "neox": "GPT-NeoX",
    "deepseek": "DeepSeek",
    "qwen": "Qwen",
    "qwq": "Qwen",
    "chatglm": "GLM",
    "glm": "GLM",
    "zhipu": "GLM",
    "minimax": "MiniMax",
    "ling": "Ling",
    "yi": "Yi",
    "kimi": "Moonshot",
    "moonshot": "Moonshot",
    "internlm": "InternLM",
    "baichuan": "Baichuan",
    "chatgpt": "OpenAI",
    "gpt": "OpenAI",
    "o1": "OpenAI",
    "o3": "OpenAI",
    "o4": "OpenAI",
    "claude": "Claude",
    "anthropic": "Claude",
    "gemini": "Gemini",
    "gemma": "Gemma",
    "llama": "Llama-3",
    "mistral": "Mistral",
    "mixtral": "Mistral",
    "command": "Cohere",
    "cohere": "Cohere",
    "phi": "Phi",
}


def _normalize_label(label: str) -> str:
    """Lowercase; drop a leading provider prefix like 'oc/' or 'openrouter/'."""
    s = (label or "").strip().lower()
    if "/" in s:
        s = s.split("/", 1)[1]
    return s


def label_to_family(label: str) -> str | None:
    """Map a router label to a tokenizer family, or None if unmapped.

    Keys match only at LETTER boundaries (a digit or separator adjacent is fine),
    so a short key can't match mid-word: ``o1`` matches ``o1-preview`` and
    ``gpt-4o`` but NOT ``proto1-vision``; ``yi`` matches a ``yi`` segment but not
    ``yixin``. Bare substring matching produced false accusations from incidental
    substrings in router-supplied headers (Claude adversarial review, HIGH).
    Unmapped is deliberate: it yields INCONCLUSIVE downstream, never a guess.
    """
    s = _normalize_label(label)
    if not s:
        return None
    for key, fam in LABEL_FAMILY.items():
        if re.search(r"(?<![a-z])" + re.escape(key) + r"(?![a-z])", s):
            return fam
    return None
