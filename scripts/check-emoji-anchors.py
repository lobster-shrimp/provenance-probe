#!/usr/bin/env python3
"""Guard: no doc may link to an EMOJI heading's auto-generated anchor.

GitHub and the CI link-checker (lychee) generate DIFFERENT anchors for headings
containing emoji — GitHub keeps the U+FE0F variation selector
(e.g. `#️-companion--the-observatory`), lychee drops it
(`#-companion--the-observatory`). So a link to an emoji-heading auto-anchor either
breaks on GitHub or false-passes lychee. lychee cannot enforce this (it false-passes
the naive form), so this guard does.

Safe pattern — an explicit anchor, which GitHub AND lychee resolve identically:

    <a id="kebab-name"></a>
    ## 🛰️ Heading

  then link to `...#kebab-name`.

Stdlib only. Run from a repo root; exits non-zero on any violation.
"""
from __future__ import annotations
import os, re, subprocess, sys, unicodedata

LINK = re.compile(r"(?<!\\)\]\(\s*([^)]+?)\s*\)")
HEADING = re.compile(r"^#{1,6}\s+(.*?)\s*$")
EXPLICIT_ID = re.compile(r'<a\s+[^>]*id="([^"]+)"', re.I)


def has_emoji(s: str) -> bool:
    for ch in s:
        o = ord(ch)
        if (o >= 0x1F000 or ch == "️" or 0x2600 <= o <= 0x27BF
                or 0x2B00 <= o <= 0x2BFF or unicodedata.category(ch) == "So"):
            return True
    return False


def naive_slug(h: str) -> str:
    # Matches lychee/GitHub for NON-emoji chars: lowercase, drop punctuation/emoji,
    # spaces->hyphens, no trim/collapse (a leading emoji leaves a leading hyphen).
    h = h.strip().lower()
    h = "".join(c for c in h if c.isalnum() or c in " -_")
    return h.replace(" ", "-")


def parse(path: str):
    headings, explicit = [], set()
    with open(path, encoding="utf-8", errors="replace") as fh:
        for line in fh:
            for eid in EXPLICIT_ID.findall(line):
                explicit.add(eid)
            m = HEADING.match(line)
            if m:
                headings.append((naive_slug(m.group(1)), has_emoji(m.group(1)), m.group(1)))
    return headings, explicit


def md_files():
    out = subprocess.run(["git", "ls-files", "*.md"], capture_output=True, text=True).stdout
    return [f for f in out.split("\n") if f]


def main() -> int:
    cache, fails = {}, []

    def info(p):
        if p not in cache:
            cache[p] = parse(p) if os.path.isfile(p) else ([], set())
        return cache[p]

    for md in md_files():
        text = open(md, encoding="utf-8", errors="replace").read()
        for raw in LINK.findall(text):
            url = raw.split()[0]
            if url.startswith(("http://", "https://", "mailto:", "tel:")):
                continue
            path, _, frag = url.partition("#")
            if not frag:
                continue
            tgt = os.path.normpath(os.path.join(os.path.dirname(md), path)) if path else md
            headings, explicit = info(tgt)
            if frag in explicit:
                continue                               # explicit <a id> — safe
            fl = frag.lower().replace("️", "")    # normalize both anchor forms
            for slug, emoji, txt in headings:
                if slug == fl or slug.strip("-") == fl.strip("-"):
                    if emoji:
                        fails.append((md, url, txt, tgt))
                    break

    if fails:
        print("BROKEN-PRONE: links into emoji-heading auto-anchors "
              "(GitHub and lychee generate different anchors for these):\n")
        for md, url, txt, tgt in fails:
            print(f"  {md}: {url}\n      -> emoji heading '{txt}' in {tgt}")
        print('\nFix: give the heading an explicit anchor and link to that:\n'
              '    <a id="kebab-name"></a>\n    ## <emoji> Heading\n'
              '  then link `...#kebab-name` (resolves identically on GitHub and in lychee).')
        return 1
    print("OK: no links into emoji-heading auto-anchors.")
    return 0


if __name__ == "__main__":
    sys.exit(main())
