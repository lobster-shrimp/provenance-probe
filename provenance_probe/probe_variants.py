# -*- coding: utf-8 -*-
"""Probe randomization (evasion hardening).

The 20-probe corpus is public, so a vendor being monitored could special-case
the exact probe strings and return doctored `usage.prompt_tokens` for them,
silently defeating the tokenizer layer. Countermeasure: rotate the exact bytes
sent on the wire per run, while keeping each probe's dominant script/structure
so family discrimination still works.

`variant_probes(seed)` returns a deterministic variant of the corpus for a given
seed:

  - seed 0  -> the canonical corpus, byte-for-byte (the shipped reference is
    built at seed 0, so nothing changes for existing users).
  - seed !=0 -> each probe gets a short deterministic salt of its OWN dominant
    script inserted at a seed-chosen position. The string differs (exact-match
    special-casing fails), the script mix is preserved (a CJK probe stays CJK),
    and it is reproducible so the reference can be rebuilt for the same seed.

Workflow: the operator periodically picks a fresh random seed, rebuilds the
reference for it (`build-reference --variant-seed N`, needs the tokenizers), and
probes with the same seed (`assess --variant-seed N`). The seed is not published,
so an adversary never sees the exact strings currently on the wire.

Limits (documented, not hidden): a determined adversary who detects "a salted
variant of a known probe" could still try to normalize — this raises the cost of
evasion, it does not make it impossible. See README "Known limits".
"""
from __future__ import annotations
import hashlib

from .data.corpus import TOKENIZER_PROBES

# Per-script salt alphabets. A salt is drawn from the probe's dominant script so
# the tokenizer-stressing property is preserved.
_SALT_ALPHABETS = {
    "han":   "的一是不了人我在有他这为之大来以个中上们时到国和地",
    "latin": "abcdefghijklmnopqrstuvwxyz",
    "cyrillic": "абвгдеёжзийклмнопрстуфхцчшщ",
    "digit": "0123456789",
    "space": " \t\n",
    "punct": "!.-=*",
    "other": "abcdefghijklmnopqrstuvwxyz",
}


def _dominant_script(text: str) -> str:
    counts = {k: 0 for k in _SALT_ALPHABETS}
    for ch in text:
        o = ord(ch)
        if 0x4e00 <= o <= 0x9fff or 0x3040 <= o <= 0x30ff or 0xac00 <= o <= 0xd7af:
            counts["han"] += 1
        elif 0x0400 <= o <= 0x04ff:
            counts["cyrillic"] += 1
        elif ch.isascii() and ch.isalpha():
            counts["latin"] += 1
        elif ch.isdigit():
            counts["digit"] += 1
        elif ch.isspace():
            counts["space"] += 1
        elif ch in "!.-=*":
            counts["punct"] += 1
        else:
            counts["other"] += 1
    return max(counts, key=counts.get)


def _salt(script: str, digest: bytes, length: int) -> str:
    alpha = _SALT_ALPHABETS.get(script, _SALT_ALPHABETS["other"])
    return "".join(alpha[digest[i % len(digest)] % len(alpha)] for i in range(length))


def _mutate(pid: str, text: str, seed: int) -> str:
    digest = hashlib.sha256(f"{seed}:{pid}".encode()).digest()
    length = 4 + digest[0] % 8                      # 4..11 salt chars
    script = _dominant_script(text)
    salt = _salt(script, digest, length)
    pos = int.from_bytes(digest[1:5], "big") % (len(text) + 1)
    return text[:pos] + salt + text[pos:]


def variant_probes(seed: int = 0, base=None) -> list[tuple[str, str]]:
    """Deterministic per-seed variant of the probe corpus. Same IDs, same
    dominant script per probe; seed 0 is the canonical corpus unchanged."""
    base = base if base is not None else TOKENIZER_PROBES
    if not seed:
        return list(base)
    return [(pid, _mutate(pid, text, seed)) for pid, text in base]
