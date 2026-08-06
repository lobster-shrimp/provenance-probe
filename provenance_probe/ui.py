# -*- coding: utf-8 -*-
"""Shared "Provenance" design system for every server-rendered surface.

ONE stylesheet (the DESIGN.md tokens) + a poster header + a page shell, imported
by both the live web service (`serve.py`) and the standalone HTML report
(`report.py`) so the two never drift. Direction: warm cream document under a
deep-green poster band, one hot accent per view that IS the verdict
(green = clean, amber = likely, coral = confirmed / CN / flagged).

Kept as plain strings (NOT `.format()` templates) so the CSS braces need no
escaping; callers concatenate via `doc()` / `header()` and escape their own
user/measurement-derived data.
"""
from __future__ import annotations

from urllib.parse import quote

# Verdict / severity -> accent token. Drives the ONE hot accent per view so the
# color is a function of the real result, never hardcoded per page.
VERDICT_COLOR = {
    "CONFIRMED": "var(--coral)", "CN": "var(--coral)",
    "LIKELY": "var(--amber)",
    "INDETERMINATE": "var(--muted)",
    "UNLIKELY": "var(--green)", "NO EVIDENCE": "var(--green)",
}

# userwarn level -> accent token (red/orange = flagged, yellow = caution, green = clean).
LEVEL_COLOR = {
    "red": "var(--coral)", "orange": "var(--amber)",
    "yellow": "var(--amber)", "green": "var(--green)",
}


def verdict_color(verdict: str) -> str:
    """Map a scoring verdict string to a CSS accent variable."""
    return VERDICT_COLOR.get((verdict or "").strip().upper(), "var(--muted)")


FONTS = (
    '<link rel="preconnect" href="https://fonts.googleapis.com">'
    '<link rel="preconnect" href="https://fonts.gstatic.com" crossorigin>'
    '<link rel="stylesheet" href="https://fonts.googleapis.com/css2?'
    "family=Fraunces:opsz,wght@9..144,400;9..144,500;9..144,600&"
    "family=Geist:wght@400;500;600;700&"
    'family=Geist+Mono:wght@400;500&display=swap">'
)

# Lie-detector favicon: a coral polygraph waveform on the deep-green brand square,
# inlined as an SVG data-URI so it needs no route (won't hit the hosted auth gate).
FAVICON_SVG = (
    "<svg xmlns='http://www.w3.org/2000/svg' viewBox='0 0 32 32'>"
    "<rect width='32' height='32' rx='7' fill='#0E3B2E'/>"
    "<path d='M2 17h6l2-9 3 16 3-12 2 7h12' fill='none' stroke='#D2483F'"
    " stroke-width='2.4' stroke-linecap='round' stroke-linejoin='round'/></svg>"
)
FAVICON = ('<link rel="icon" type="image/svg+xml" href="data:image/svg+xml,'
           + quote(FAVICON_SVG) + '">')

STYLE = """<style>
:root{
 --paper:#F5F3EC;--surface:#FBFAF6;--ink:#14171A;--muted:#6B7280;--line:#E3E0D6;
 --green:#0E3B2E;--green-2:#0B2B22;--green-ink:#7DD3A8;--coral:#D2483F;--amber:#C9821F;
 --ui:"Geist",ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;
 --serif:"Fraunces",Georgia,"Times New Roman",serif;
 --mono:"Geist Mono","JetBrains Mono",ui-monospace,SFMono-Regular,Menlo,monospace;
}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{font:16px/1.6 var(--ui);color:var(--ink);background:var(--paper);margin:0}
a{color:var(--green);text-underline-offset:2px}
a:hover{color:var(--coral)}
.poster{background:var(--green);color:var(--paper);display:flex;align-items:center;
 justify-content:space-between;gap:16px;padding:18px 28px;flex-wrap:wrap}
.wordmark{font-family:var(--ui);font-weight:600;font-size:15px;letter-spacing:.22em;
 text-transform:uppercase;color:var(--paper)}
.poster nav{display:flex;gap:22px;flex-wrap:wrap}
.poster a{color:var(--paper);opacity:.82;text-decoration:none;font-size:11px;
 letter-spacing:.14em;text-transform:uppercase}
.poster a:hover{opacity:1;color:var(--paper)}
.poster-right{font-family:var(--mono);font-size:12px;color:var(--green-ink);
 word-break:break-all;max-width:60%}
.wrap{max-width:1040px;margin:0 auto;padding:34px 28px 64px}
h1{font-size:26px;margin:0 0 6px;letter-spacing:-.01em;font-weight:600}
h2{font-size:18px;margin:0 0 6px;font-weight:600}
.display{font-family:var(--serif);font-weight:500;line-height:1.02;letter-spacing:-.02em}
.sub{color:var(--muted);font-size:14px;margin:0 0 22px}
.lead{font-family:var(--serif);font-size:20px;line-height:1.35;margin:0 0 24px;max-width:62ch}
h3,.seclabel{font-size:11px;letter-spacing:.14em;text-transform:uppercase;
 color:var(--muted);font-weight:600;margin:26px 0 12px}
.card{background:var(--surface);border:1px solid var(--line);border-radius:14px;
 padding:22px 24px;margin-bottom:18px}
label{display:block;font-size:11px;letter-spacing:.1em;text-transform:uppercase;
 color:var(--muted);font-weight:600;margin:0 0 6px}
input[type=text],input[type=password],input[type=file],input[type=url],input[type=search],
input:not([type]),select,textarea{
 width:100%;padding:11px 13px;border:1px solid var(--line);border-radius:9px;
 font:14px var(--mono);background:#fff;color:var(--ink)}
input::placeholder,textarea::placeholder{color:#9aa0a8}
input[type=text]:focus,input[type=password]:focus,input:not([type]):focus,
select:focus,textarea:focus{outline:none;border-color:var(--green);
 box-shadow:0 0 0 3px rgba(14,59,46,.12)}
textarea{line-height:1.5}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:16px}
.grid3{display:grid;grid-template-columns:2fr 1fr 1fr;gap:16px}
.row{margin-bottom:16px}
@media(max-width:640px){.grid,.grid3{grid-template-columns:1fr}.poster-right{max-width:100%}
 .wrap{padding:26px 18px 48px}}
button{background:var(--green);color:var(--paper);border:0;border-radius:9px;
 padding:12px 22px;font:600 14px var(--ui);cursor:pointer;transition:background .15s}
button:hover{background:var(--coral)}
button:disabled{opacity:.5;cursor:default;background:var(--green)}
.chk{display:flex;gap:10px;align-items:flex-start;font-size:14px;color:var(--ink);
 background:var(--surface);border:1px solid var(--line);border-radius:10px;padding:14px 16px}
.chk input{margin-top:3px}
.mono{font-family:var(--mono);font-size:12px}
.stat{font-size:13px;color:var(--muted);font-family:var(--mono)}
.hint,.eg{color:var(--muted);font-size:13px;margin:.3rem 0 0}
.hide{display:none}
code{font-family:var(--mono);font-size:.9em;background:#ece9df;padding:1px 5px;border-radius:4px}
pre{background:var(--green-2);color:var(--green-ink);border:0;padding:14px 16px;
 border-radius:10px;overflow:auto;font:12px/1.5 var(--mono)}
.warn{background:#fbf1dd;border:1px solid #e7cf9b;color:#7a5a12;padding:12px 14px;
 border-radius:9px;margin:.4rem 0}
.err{background:#fbe6e4;border:1px solid #e6b3ae;color:#8f2b23;padding:12px 14px;
 border-radius:9px;margin:.4rem 0}
.ok{background:#e7f2ea;border:1px solid #bcd8c4;color:var(--green);padding:12px 14px;
 border-radius:9px;margin:.4rem 0}
.box{background:var(--surface);border:1px solid var(--line);padding:16px 18px;border-radius:12px}
.ban{border-radius:14px;padding:20px 22px;border-left:6px solid;margin-bottom:16px}
.ban h2{font-size:22px;margin:6px 0 8px;letter-spacing:-.01em;font-family:var(--serif);font-weight:500}
.lvl{font-size:10px;letter-spacing:.16em;text-transform:uppercase;font-weight:700}
.ban.red{background:#fbe9e7;border-color:var(--coral);color:#8f2b23}
.ban.orange{background:#fbeede;border-color:var(--amber);color:#8a5510}
.ban.yellow{background:#fbf3dd;border-color:var(--amber);color:#7a5a12}
.ban.green{background:#e7f2ea;border-color:var(--green);color:var(--green)}
.ban ul{margin:8px 0 0;padding-left:20px}.ban li{margin-bottom:7px;font-size:15px}
table{width:100%;border-collapse:collapse;font-size:13px}
th{text-align:left;font-size:10px;text-transform:uppercase;letter-spacing:.1em;
 color:var(--muted);padding:9px 11px;border-bottom:1px solid var(--line);font-weight:600}
td{padding:9px 11px;border-top:1px solid var(--line);vertical-align:top}
ul{margin:8px 0 0;padding-left:20px}li{margin-bottom:7px;font-size:14px}
ol.guide li{margin:.4rem 0}
/* method chooser (wizard front door): three plain-language cards, one recommended */
.chooser{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin:0 0 24px}
.chooser .card{margin:0;display:flex;flex-direction:column}
.chooser .card h2{font-size:16px}
.chooser .tag{display:inline-block;font-size:10px;letter-spacing:.12em;text-transform:uppercase;
 font-weight:700;color:var(--green);margin:0 0 6px}
.chooser .needs{font-size:12px;color:var(--muted);margin:8px 0 14px}
.chooser .pick{margin-top:auto}
.chooser .rec{border-color:var(--green);box-shadow:0 0 0 3px rgba(14,59,46,.10)}
@media(max-width:820px){.chooser{grid-template-columns:1fr}}
/* landing: the two jobs as side-by-side choice cards (one recommended) */
.jobs{display:grid;grid-template-columns:1fr 1fr;gap:16px;margin:0 0 22px}
.jobs .job{margin:0;display:flex;flex-direction:column}
.jobs .job h2{font-size:19px;font-family:var(--serif);font-weight:500;margin:0 0 8px}
.jobs .job p{margin:0 0 12px;font-size:14px}
.jobs .job .tag{display:inline-block;font-size:10px;letter-spacing:.12em;
 text-transform:uppercase;font-weight:700;color:var(--green);margin:0 0 8px}
.jobs .job.rec{border-color:var(--green);box-shadow:0 0 0 3px rgba(14,59,46,.10)}
.jobs .job .pick{margin-top:auto}
.jobs .job .needs{font-size:12px;color:var(--muted);margin:10px 0 0}
@media(max-width:820px){.jobs{grid-template-columns:1fr}}
/* landing: observatory "see it live" — a prominent LINKED card, not an iframe */
a.obs{display:block;text-decoration:none;background:var(--green);border-radius:14px;
 padding:20px 22px;margin:0 0 26px;transition:transform .15s,box-shadow .15s}
a.obs:hover{transform:translateY(-1px);box-shadow:0 6px 22px rgba(14,59,46,.18);color:inherit}
a.obs .tag{display:inline-block;font-size:10px;letter-spacing:.14em;text-transform:uppercase;
 font-weight:700;color:var(--green-ink);margin:0 0 6px}
a.obs b{display:block;color:var(--paper);font-family:var(--serif);font-weight:500;
 font-size:19px;line-height:1.25;margin:0 0 6px}
a.obs p{margin:0;color:var(--green-ink);font-size:14px}
/* big numbered visual steps: green counter chips, plain-language body */
ol.steps{counter-reset:step;list-style:none;padding:0;margin:14px 0}
ol.steps>li{counter-increment:step;position:relative;padding:2px 0 16px 48px;margin:0;font-size:15px}
ol.steps>li::before{content:counter(step);position:absolute;left:0;top:0;width:30px;height:30px;
 border-radius:99px;background:var(--green);color:var(--paper);font:600 15px var(--ui);
 display:flex;align-items:center;justify-content:center}
ol.steps>li b{display:block;margin-bottom:2px}
ol.steps>li .sub{margin:3px 0 0;font-size:13px}
/* embeddable demo-GIF slot with graceful caption fallback when the file is absent */
figure.demo{margin:0 0 20px;border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--surface)}
figure.demo img{display:block;width:100%;height:auto}
figure.demo figcaption{padding:10px 14px;font-size:13px;color:var(--muted)}
figure.demo.noimg figcaption::before{content:"\1F3AC  "}
.topnav{display:flex;gap:16px;font-size:11px;letter-spacing:.1em;text-transform:uppercase;margin:0 0 18px}
.topnav .active{color:var(--ink);font-weight:700}
.topnav a{color:var(--green);text-decoration:none}
.adv{font-size:13px;color:var(--green);cursor:pointer;user-select:none;margin-bottom:12px;display:inline-block}
.bar{height:6px;background:#e6e2d6;border-radius:99px;overflow:hidden;margin:14px 0 8px}
.bar>i{display:block;height:100%;background:var(--green);width:0;transition:width .4s}
.hist{font-size:13px}.hist td{padding:7px 9px}
.dot{display:inline-block;width:8px;height:8px;border-radius:99px;margin-right:8px}
.sev{font-size:10px;letter-spacing:.08em;text-transform:uppercase;font-weight:700;padding:2px 7px;border-radius:5px}
.sev.critical{background:#fbe9e7;color:var(--coral)}
.sev.high{background:#fbeede;color:var(--amber)}
.sev.medium{background:#fbf3dd;color:#7a5a12}
/* lab-report specifics (report.py) */
.stamp{border:2px solid;border-radius:12px;padding:12px 18px;text-align:left;min-width:180px}
.stamp .lvl{display:block;margin-bottom:4px}
.stamp .stampverdict{font-family:var(--ui);font-weight:700;font-size:15px;line-height:1.2;letter-spacing:.02em}
.lab{display:grid;grid-template-columns:1.15fr .85fr;gap:22px;align-items:start}
@media(max-width:820px){.lab{grid-template-columns:1fr}}
.evidence{background:var(--green-2);color:var(--green-ink);border-radius:14px;
 padding:20px 22px;font-family:var(--mono);font-size:13px;line-height:1.6}
.evidence table{color:var(--green-ink)}
.evidence th{color:#5fae86;border-bottom-color:#1c4436}
.evidence td{border-top-color:#1c4436}
.evidence .hi{color:#fff;font-weight:500}
.statgrid{display:grid;grid-template-columns:1fr 1fr;gap:20px 26px}
.statnum{font-family:var(--serif);font-size:42px;font-weight:400;line-height:1;
 letter-spacing:-.02em;color:var(--ink)}
.statlbl{font-size:12px;color:var(--muted);margin-top:4px}
.hero-row{display:flex;justify-content:space-between;align-items:flex-start;gap:24px;flex-wrap:wrap}
.footer{display:flex;flex-wrap:wrap;gap:26px;border-top:1px solid var(--line);
 margin-top:32px;padding-top:20px}
.footer div{min-width:120px}
.footer .k{font-size:10px;letter-spacing:.12em;text-transform:uppercase;color:var(--muted)}
.footer .v{font-family:var(--mono);font-size:12px;margin-top:3px;word-break:break-all}
</style>"""


# Standard internal nav. One place so every page links the same set — and so the
# Help link reaches pages that don't build their own nav (see `header`).
_NAV_ITEMS = (("/", "Live probe"), ("/agent", "Agent board"),
              ("/wizard", "Add target"), ("/help", "Help"))


def nav(active: str = "") -> str:
    """The shared poster nav (Live probe · Agent board · Add target · Help). Pass
    the href of the current page as `active` to emphasise it. All hrefs are static
    internal routes, so nothing here needs escaping."""
    links = "".join(
        f'<a href="{href}"' + (' class="active" style="opacity:1;font-weight:700"'
                               if href == active else "") + f">{label}</a>"
        for href, label in _NAV_ITEMS)
    return f"<nav>{links}</nav>"


def header(right: str = "") -> str:
    """Green poster band with the small-caps wordmark. `right` is caller-built
    HTML placed at the band's right edge (a <nav>, or an already-escaped endpoint
    wrapped in .poster-right) — callers escape any user data. When a caller passes
    no `right`, fall back to the shared `nav()` so the Help link is on every page."""
    return ('<header class="poster"><div class="wordmark">PROVENANCE-PROBE</div>'
            + (right or nav()) + "</header>")


def doc(title: str, inner: str, right: str = "") -> str:
    """Full HTML shell: fonts + shared stylesheet + poster header + a centered
    <main>. `title`/`right` are trusted internal callers (or pre-escaped); page
    bodies escape their own user/measurement data."""
    return ('<!doctype html><html lang="en"><meta charset="utf-8">'
            '<meta name="viewport" content="width=device-width,initial-scale=1">'
            f"<title>{title}</title>" + FAVICON + FONTS + STYLE
            + header(right) + f'<main class="wrap">{inner}</main>')
