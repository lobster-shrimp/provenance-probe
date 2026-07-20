"""Reporting: console, JSON, standalone HTML."""
from __future__ import annotations
import json, html, datetime

SEV_COLOR = {"CONFIRMED": "#8b1a1a", "LIKELY": "#b4531a", "INDETERMINATE": "#8a7413",
             "UNLIKELY": "#2f6b3a", "NO EVIDENCE": "#3a5570"}


def console(bundle: dict) -> str:
    s = bundle["score"]
    L = []
    L.append("=" * 72)
    L.append(f"  MODEL PROVENANCE ASSESSMENT — {bundle['target']['name']}")
    L.append(f"  {bundle['target']['base_url']}   model='{bundle['target']['model']}'")
    L.append(f"  {bundle['timestamp']}")
    L.append("=" * 72)
    for k, label in (("jurisdictional_risk", "JURISDICTIONAL (PRC operator/soil)"),
                     ("provenance_risk", "PROVENANCE (Chinese-origin weights)")):
        r = s[k]
        L.append(f"\n  {label}")
        L.append(f"    verdict    : {r['verdict']}  (p={r['likelihood']})")
        L.append(f"    meaning    : {r['meaning']}")
    L.append(f"\n  Evidence confidence: {s['confidence']}")
    cov = ", ".join(k for k, v in s["evidence_coverage"].items() if v) or "none"
    L.append(f"  Layers with data   : {cov}")
    L.append("\n  SIGNALS")
    if not s["signals"]:
        L.append("    (none fired)")
    for sig in s["signals"]:
        L.append(f"    [{sig['layer']:<11}] {sig['signal']:<22} {sig['evidence'][:120]}")
    tm = bundle.get("tokenizer_match") or []
    if tm:
        L.append("\n  TOKENIZER FINGERPRINT (top 5)")
        L.append(f"    {'model':<48}{'origin':<10}{'score':<8}{'exact'}")
        for r in tm[:5]:
            L.append(f"    {r['model'][:47]:<48}{str(r['origin']):<10}"
                     f"{r['score']:<8}{r['exact_matches']}/{r['shared_probes']}")
    al = bundle.get("alignment") or {}
    if al:
        L.append(f"\n  ALIGNMENT ASYMMETRY: mean={al.get('mean_asymmetry')}")
        for p in al.get("pairs", []):
            L.append(f"    {p['pair']:<20} delta={p['asymmetry']:<6} "
                     f"treat_refusal={p['treatment']['refusal']} ctrl_refusal={p['control']['refusal']}")
    L.append("\n" + "=" * 72)
    return "\n".join(L)


def to_json(bundle: dict, path: str) -> None:
    with open(path, "w") as f:
        json.dump(bundle, f, indent=2, default=str)


def to_html(bundle: dict, path: str) -> None:
    s = bundle["score"]
    def card(k, label):
        r = s[k]
        c = SEV_COLOR.get(r["verdict"], "#444")
        return f"""<div class=card><div class=lbl>{html.escape(label)}</div>
<div class=verdict style="color:{c}">{r['verdict']}</div>
<div class=p>likelihood {r['likelihood']} &nbsp;·&nbsp; log-odds {r['logodds']}</div>
<div class=mean>{html.escape(r['meaning'])}</div></div>"""

    rows = "".join(
        f"<tr><td class=lay>{html.escape(x['layer'])}</td><td class=sig>{html.escape(x['signal'])}</td>"
        f"<td>{html.escape(x['evidence'])}</td></tr>" for x in s["signals"]) or \
        "<tr><td colspan=3 class=none>No signals fired.</td></tr>"

    tm = bundle.get("tokenizer_match") or []
    tok = "".join(
        f"<tr><td>{html.escape(r['model'])}</td><td>{html.escape(str(r['family']))}</td>"
        f"<td>{html.escape(str(r['origin']))}</td><td>{r['score']}</td>"
        f"<td>{r['exact_matches']}/{r['shared_probes']}</td><td>{r['norm_l1']}</td></tr>"
        for r in tm[:12])

    al = bundle.get("alignment") or {}
    alr = "".join(
        f"<tr><td>{html.escape(p['pair'])}</td><td>{p['asymmetry']}</td>"
        f"<td>{p['treatment']['refusal']}/{p['treatment']['state_framing']}</td>"
        f"<td>{p['control']['refusal']}/{p['control']['state_framing']}</td>"
        f"<td class=ex>{html.escape(p['treatment_excerpt'][:200])}</td></tr>"
        for p in al.get("pairs", []))

    doc = f"""<!doctype html><meta charset=utf-8>
<title>Provenance Assessment — {html.escape(bundle['target']['name'])}</title>
<style>
:root{{--ink:#16181d;--mut:#6b7280;--line:#e3e5e9;--bg:#fbfbfc}}
*{{box-sizing:border-box}}
body{{font:15px/1.55 ui-sans-serif,-apple-system,"Segoe UI",Roboto,sans-serif;
color:var(--ink);background:var(--bg);margin:0;padding:32px}}
.wrap{{max-width:1080px;margin:0 auto}}
h1{{font-size:22px;margin:0 0 4px;letter-spacing:-.01em}}
.sub{{color:var(--mut);font-size:13px;margin-bottom:24px;font-family:ui-monospace,monospace}}
.cards{{display:grid;grid-template-columns:1fr 1fr;gap:14px;margin-bottom:28px}}
.card{{background:#fff;border:1px solid var(--line);border-radius:10px;padding:18px}}
.lbl{{font-size:11px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut)}}
.verdict{{font-size:26px;font-weight:650;margin:6px 0;letter-spacing:-.02em}}
.p{{font-size:12px;color:var(--mut);font-family:ui-monospace,monospace}}
.mean{{font-size:13px;margin-top:10px;color:#3d424b}}
h2{{font-size:13px;letter-spacing:.08em;text-transform:uppercase;color:var(--mut);
margin:28px 0 10px;font-weight:600}}
table{{width:100%;border-collapse:collapse;background:#fff;border:1px solid var(--line);
border-radius:10px;overflow:hidden;font-size:13px}}
th{{text-align:left;background:#f4f5f7;padding:9px 12px;font-weight:600;font-size:11px;
text-transform:uppercase;letter-spacing:.05em;color:var(--mut)}}
td{{padding:9px 12px;border-top:1px solid var(--line);vertical-align:top}}
.lay,.sig{{font-family:ui-monospace,monospace;font-size:12px;white-space:nowrap}}
.sig{{font-weight:600}}
.none{{color:var(--mut);text-align:center;padding:20px}}
.ex{{font-size:11px;color:var(--mut);max-width:340px}}
.note{{background:#fff8e6;border:1px solid #f0dfae;border-radius:8px;padding:14px;
font-size:13px;margin-top:26px}}
</style><div class=wrap>
<h1>Model Provenance Assessment</h1>
<div class=sub>{html.escape(bundle['target']['name'])} &nbsp;·&nbsp;
{html.escape(bundle['target']['base_url'])} &nbsp;·&nbsp;
model={html.escape(bundle['target']['model'])} &nbsp;·&nbsp; {bundle['timestamp']}</div>
<div class=cards>{card('jurisdictional_risk','Jurisdictional risk')}
{card('provenance_risk','Provenance risk')}</div>
<div class=p style="margin:-14px 0 8px">Evidence confidence: <b>{html.escape(s['confidence'])}</b></div>
<h2>Signals</h2>
<table><tr><th>Layer</th><th>Signal</th><th>Evidence</th></tr>{rows}</table>
{"<h2>Tokenizer fingerprint</h2><table><tr><th>Reference model</th><th>Family</th><th>Origin</th><th>Score</th><th>Exact</th><th>Norm L1</th></tr>" + tok + "</table>" if tok else ""}
{"<h2>Alignment asymmetry (matched pairs)</h2><table><tr><th>Pair</th><th>Delta</th><th>Treat refuse/frame</th><th>Ctrl refuse/frame</th><th>Treatment excerpt</th></tr>" + alr + "</table>" if alr else ""}
<div class=note><b>Interpretation limits.</b> Black-box probes degrade against a vendor actively
defeating them (normalized usage counts, suppressed logprobs, output post-filtering). Absence of
alignment asymmetry does not clear provenance — offshore-served Chinese open weights are frequently
de-censored by fine-tuning. Chinese weights served entirely inside your accreditation boundary carry
bias/integrity/policy risk but <i>no</i> PRC data-jurisdiction exposure; do not conflate the two.
Re-run continuously: silent backend swaps after contract award are the real threat model.</div>
</div>"""
    with open(path, "w") as f:
        f.write(doc)
