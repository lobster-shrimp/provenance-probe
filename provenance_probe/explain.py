# -*- coding: utf-8 -*-
"""Plain-language, non-technical-first explainers — the SINGLE source of truth.

Every in-product surface that describes what a probe does or what a verdict means
reads from the data here (never a copy-paste):

  * the ``/help`` page (rendered by :func:`help_html`),
  * the report's Signals-table layer tooltips (via :func:`tooltip_for`),
  * the probe form's "what these checks do" note.

Content is deliberately jargon-light: written for a visitor who has never heard of
a tokenizer. Structural HTML in :func:`help_html` is authored here; every *content*
string is passed through ``html.escape`` when rendered, so no field can inject
markup even though all of it is author-controlled (defense-in-depth).
"""
from __future__ import annotations

import html
from typing import NamedTuple


class Layer(NamedTuple):
    """One evidence layer, in plain language."""
    title: str        # short, non-technical name
    measures: str     # 1-2 plain sentences: what it looks at
    hit_means: str    # what it means when this check "fires"


# The engine's evidence layers, in the order `assess` runs them. This mapping is
# the ONE place layer copy lives; /help and the report tooltips both read it.
LAYERS: "dict[str, Layer]" = {
    "network": Layer(
        "Network & location",
        "Looks up where the endpoint's address actually lives on the internet, "
        "and which company runs that server.",
        "The service is hosted by a Chinese company or on servers inside China."),
    "wire": Layer(
        "Wire fingerprint",
        "Reads the technical 'envelope' around each reply — the response headers, "
        "error messages and streaming style — the way you'd recognise a company "
        "by its letterhead.",
        "The envelope matches a known Chinese provider, or the service names a "
        "Chinese model."),
    "tokenizer": Layer(
        "Tokenizer fingerprint",
        "Watches how the model chops text into pieces before it reads it. Every "
        "model family does this in a slightly different, hard-to-fake way — like "
        "handwriting.",
        "The 'handwriting' matches a Chinese-origin model family."),
    "logprob": Layer(
        "Determinism check",
        "Sends the same prompt more than once and measures how repeatable and "
        "confident the answers are — a fingerprint of the engine doing the work.",
        "Adds supporting detail about which kind of engine is answering; on its "
        "own it doesn't decide the model's origin."),
    "behavioral": Layer(
        "Behaviour tests",
        "Asks the model who it is, compares how it answers matched pairs of "
        "sensitive questions, and watches for Chinese characters slipping into "
        "English answers.",
        "The model identifies as — or behaves like — a Chinese-trained model."),
    "deception": Layer(
        "Honesty check",
        "Asks the model directly about who made it and where it runs, then checks "
        "those claims against the hard evidence — including a deliberately false "
        "control question to catch a model that just agrees with anything.",
        "The model's own claims contradict the evidence — it is misrepresenting "
        "its origin or who runs it."),
    "latency": Layer(
        "Timing profile",
        "Times how quickly replies come back and the rhythm of the stream, which "
        "can hint at where the servers are and what is running.",
        "The timing fits the suspected backend or region — a supporting clue, "
        "not proof on its own."),
    "artifacts": Layer(
        "Files & app source",
        "When you point it at model files on disk, or at the app's own shipped "
        "code, it reads them for names, file paths and settings that reveal the "
        "model's family or the company operating it.",
        "The files name a Chinese model family, or a Chinese operator baked into "
        "the app."),
}

# Layer names as they appear on real signals (report + scoring) can differ from
# the canonical keys above; normalise so every tooltip resolves.
_LAYER_ALIASES = {
    "artifact": "artifacts",
    "client-source": "artifacts",
    "client source": "artifacts",
    "logprobs": "logprob",
}


def layer_info(name: str) -> "Layer | None":
    """Resolve a layer name (canonical or an on-signal alias) to its explainer."""
    key = (name or "").strip().lower()
    key = _LAYER_ALIASES.get(key, key)
    return LAYERS.get(key)


def tooltip_for(name: str) -> str:
    """Plain-text tooltip ('Title — what it measures') for a signal's layer cell,
    or "" when the layer is unknown. The caller escapes it for its context."""
    info = layer_info(name)
    return f"{info.title} — {info.measures}" if info else ""


class Tier(NamedTuple):
    name: str        # the verdict word the engine emits
    meaning: str     # plain-language meaning


class Axis(NamedTuple):
    title: str
    question: str
    tiers: "tuple[Tier, ...]"


# The two INDEPENDENT verdict axes. Provenance = whose model it is; jurisdiction =
# who runs it and where. A model can score high on one and low on the other. Both
# axes run through the SAME five-tier scale (scoring._verdict), so both tables list
# all five — a reader never meets a verdict word that isn't explained here.
VERDICTS: "dict[str, Axis]" = {
    "provenance": Axis(
        "Provenance — whose model is it?",
        "Whose model weights are actually answering, no matter where the servers are?",
        (
            Tier("CONFIRMED",
                 "Strong, direct evidence the weights are Chinese-origin — for "
                 "example a matching tokenizer fingerprint."),
            Tier("LIKELY",
                 "Several clues point to Chinese-origin weights, but no single "
                 "piece is decisive on its own."),
            Tier("INDETERMINATE",
                 "Not enough could be measured to say either way. Treat this as "
                 "'unknown', not as a clean bill of health."),
            Tier("UNLIKELY",
                 "The checks that ran point away from Chinese-origin weights, "
                 "though nothing is ever ruled out with total certainty."),
            Tier("NO EVIDENCE",
                 "A provenance check actually ran and found nothing at all "
                 "suggesting Chinese-origin weights."),
        )),
    "jurisdiction": Axis(
        "Jurisdiction — who runs it, and where?",
        "Is the service operated by a Chinese company, or running on servers inside China?",
        (
            Tier("CONFIRMED",
                 "Direct evidence the operator is Chinese, or the servers sit on "
                 "Chinese soil."),
            Tier("LIKELY",
                 "Signals point to a Chinese operator or location, short of proof."),
            Tier("INDETERMINATE",
                 "Not enough could be measured to place who runs it or where. "
                 "Treat this as 'unknown', not as safe."),
            Tier("UNLIKELY",
                 "The operator and the server location both look non-Chinese."),
            Tier("NO EVIDENCE",
                 "Nothing found points to a Chinese operator or a China-based "
                 "server."),
        )),
}

# The worked example that makes the two axes click for a newcomer.
EXAMPLE = (
    "The two answers are independent. A Chinese-origin model running on US servers "
    "reads as CONFIRMED provenance (the weights are Chinese) but UNLIKELY "
    "jurisdiction (a US operator on US soil). Neither answer overrides the other — "
    "read them together.")

# The mission, in plain language — the SINGLE source for the landing hero AND the
# /help "Why this matters" section, so the two never drift. Honest by design: the
# tool reports with *confidence*, not certainty — the copy says "catch a silent
# switch", never "guarantee".
MISSION_HEADLINE = "Is the AI you're paying for still the AI you're getting?"
MISSION_BODY = (
    "Services can quietly swap the model behind an API — for a cheaper, weaker, "
    "or foreign-built one — without telling you. provenance-probe fingerprints "
    "the model that's actually answering, then re-checks over time so you catch "
    "a silent switch.")

# "Why this matters" — the silent-swap threat spelled out for a non-technical
# reader. Rendered on /help; the landing hero shows the short MISSION_BODY above.
WHY_THIS_MATTERS: "tuple[str, ...]" = (
    "When you pay for an AI API, you are trusting that one particular model is on "
    "the other end. But nothing stops the service from changing the model behind "
    "that same address — swapping in one that is cheaper to run, less capable, or "
    "built in another country — while your app keeps calling the very same URL, "
    "none the wiser. That is a silent model swap.",
    "It matters because the swap is invisible from the outside. A weaker model can "
    "quietly degrade the answers you depend on. A model run by a different operator, "
    "or built in another country, can change who is able to see your prompts and "
    "which country's laws apply to them. You approved one thing and are being served "
    "another, without ever being told.",
    "provenance-probe fingerprints the model that is actually answering — from the "
    "way it chops up text, the shape of its replies, where its servers sit, and how "
    "it answers a fixed set of questions. Re-run that fingerprint over time and a "
    "swap can no longer hide: if the fingerprint moves, the model behind the API "
    "moved with it.")

# "Watching for model swaps" — a short primer on catching a swap over time. Honest
# about what ships today (a browser-tab watch you keep open) versus what is coming
# (a later-phase always-on background watcher).
WATCHING_PRIMER: "tuple[str, ...]" = (
    "Catching a swap is a matter of comparison. Fingerprint the service once to set "
    "a baseline, then fingerprint it again later. If the two fingerprints disagree, "
    "the model behind the API changed between the runs.",
    "The Watch page does that comparison for you on a timer. You pin a baseline, "
    "pick how often to re-check (every 5, 15 or 60 minutes), and the page re-probes "
    "the same target and diffs each result against the baseline. The moment the "
    "fingerprint moves it raises a loud alert — a red banner, a change to the browser "
    "tab title, and an optional desktop notification — and lists exactly what shifted. "
    "'Accept new baseline' re-pins to the current fingerprint and stops re-alerting.",
    "Your API key never leaves your browser. It is held in this tab only (in memory), "
    "sent solely to the probe for each re-check, and is never written to server "
    "storage or to your browser's saved data — which is what lets the watch run the "
    "same way on the hosted demo as it does locally.",
    "One honest limit: a browser-tab watch only runs while the tab stays open. For "
    "always-on, unattended monitoring, run provenance-probe locally (a background "
    "watcher is coming) or track the service on the public Observatory, which watches "
    "well-known endpoints continuously.")

# Plain-language tour of each flow in the web UI, in nav order.
FLOWS: "tuple[tuple[str, str], ...]" = (
    ("Live probe",
     "The home page. Paste an AI endpoint's address (and a model or key if it "
     "needs one), confirm you're allowed to test it, and press Run. The probe "
     "runs its checks and shows a plain-language verdict plus a detailed report."),
    ("Add a target / capture",
     "Not sure how to point the probe at your service? The 'Add target' wizard "
     "walks you through it. If your service is a website you log into, it can "
     "read the one message you send — your password and login are never recorded, "
     "and nothing is saved until you review it."),
    ("Agent board",
     "Paste a recording of an AI agent's steps and see, step by step, which model "
     "answered, whether the model changed mid-run, and whether any step sent data "
     "to a Chinese host."),
    ("Monitor (compare runs)",
     "Run the probe twice — for example before and after a contract — and compare "
     "the two runs. If the backend model was quietly swapped, the comparison "
     "flags exactly what changed."),
    ("Observatory",
     "A public gallery of provenance findings for well-known services, so you can "
     "see how the checks read on endpoints you already recognise."),
)

# Short FAQ. Answers reflect the tool's real privacy posture (loopback-bound,
# keys held in memory, nothing sent except to the endpoint you name).
FAQ: "tuple[tuple[str, str], ...]" = (
    ("Do you store my key?",
     "No. Any API key or session cookie you enter is held in memory for that one "
     "run and is never written into the saved report files."),
    ("Is my data sent anywhere?",
     "The tool runs on your own machine and only ever contacts the one endpoint "
     "you ask it to test. Results are stored on your local disk — nothing is "
     "uploaded to us."),
    ("What if it says INDETERMINATE?",
     "It means there wasn't enough evidence to decide — treat it as 'unknown', "
     "not 'safe'. Often the endpoint hid the information a check needs. Try again "
     "with more of the optional fields filled in, or re-run later."),
)


# --------------------------------------------------------------- /help render ---
def _layers_table() -> str:
    e = html.escape
    rows = "".join(
        f'<tr><td><b>{e(info.title)}</b></td><td>{e(info.measures)}</td>'
        f'<td>{e(info.hit_means)}</td></tr>'
        for info in LAYERS.values())
    return ('<div class="card"><table>'
            '<tr><th>Check</th><th>What it measures</th>'
            '<th>What a "hit" means</th></tr>'
            f'{rows}</table></div>')


def _prose_section(heading: str, paras: "tuple[str, ...]", *, top: int = 30) -> str:
    """A plain-prose /help section (heading + escaped paragraphs), used for the
    non-technical 'Why this matters' and 'Watching for model swaps' copy. Every
    paragraph is passed through html.escape — the copy is author-controlled, but
    escaping keeps it inert (defense-in-depth, like the rest of this module)."""
    e = html.escape
    body = "".join(
        f'<p style="max-width:64ch;margin:0 0 12px;font-size:15px">{e(p)}</p>'
        for p in paras)
    return f'<h2 style="margin-top:{top}px">{e(heading)}</h2>{body}'


def _verdict_block(axis: Axis) -> str:
    e = html.escape
    rows = "".join(
        f'<tr><td class="mono">{e(t.name)}</td><td>{e(t.meaning)}</td></tr>'
        for t in axis.tiers)
    return (f'<h3>{e(axis.title)}</h3>'
            f'<p class="sub">{e(axis.question)}</p>'
            '<div class="card"><table><tr><th>Verdict</th><th>What it means</th></tr>'
            f'{rows}</table></div>')


def help_html() -> str:
    """The full ``/help`` page body, rendered from LAYERS / VERDICTS / FLOWS / FAQ.

    Returns only the inner body; the caller wraps it with :func:`ui.doc` so it
    gets the shared poster header and design-system stylesheet.
    """
    e = html.escape
    flows = "".join(
        f'<h3>{e(title)}</h3><p class="sub">{e(body)}</p>'
        for title, body in FLOWS)
    faq = "".join(
        f'<div class="box" style="margin-bottom:12px"><b>{e(q)}</b>'
        f'<p class="sub" style="margin:.4rem 0 0">{e(a)}</p></div>'
        for q, a in FAQ)
    return (
        '<h1 class="display" style="font-size:clamp(30px,5vw,46px);margin:2px 0 14px">'
        'How provenance-probe works</h1>'
        '<p class="lead">This tool points a battery of controlled checks at an AI '
        'endpoint and tells you two things in plain language: whose model is really '
        'answering, and who is running it. Here is what every part does — no jargon.</p>'

        # The plain-language mission first: the silent-swap threat and how to watch
        # for it. Both sections are sourced from the single-source constants above.
        + _prose_section("Why this matters", WHY_THIS_MATTERS, top=26)
        + _prose_section("Watching for model swaps", WATCHING_PRIMER) +

        '<h2 style="margin-top:30px">The tools, one by one</h2>'
        + flows +

        '<h2 style="margin-top:30px">What each check does</h2>'
        '<p class="sub">A full run tries up to eight checks. Each one adds evidence; '
        'a check that can\'t run just lowers confidence — it never invents a result.</p>'
        + _layers_table() +

        '<h2 style="margin-top:30px">What the verdict means</h2>'
        '<p class="sub">You get two <b>independent</b> answers. Read them together.</p>'
        + _verdict_block(VERDICTS["provenance"])
        + _verdict_block(VERDICTS["jurisdiction"])
        + f'<div class="ok"><b>Worked example.</b> {e(EXAMPLE)}</div>'

        '<h2 style="margin-top:30px">Questions</h2>'
        + faq +

        '<p class="sub" style="margin-top:24px">'
        '<a href="/">&larr; back to the live probe</a></p>')
