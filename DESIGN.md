# DESIGN.md — provenance-probe

The design source of truth for the `serve` web UI (and any future surface).
Direction: **"Provenance"** — a forensic instrument that tells you the truth about
your AI: calm, rigorous, impossible to argue with. A lab report you'd trust, not a
hacker tool. Grounded in the graphify aesthetic (deep-green poster + warm cream +
one hot accent), remapped so the accent color *is* the verdict.

Reference mockups: `~/.gstack/projects/provenance-probe/designs/` (`mock-entry.png`,
`mock-verdict.png`, `board.html`).

## The one thing to remember
"This tool shows its work." Verdict first, evidence laid out like a lab report
underneath — every claim traces to a measurement you can read.

## Color

The accent carries meaning. Green = verified/clean, coral = flagged, amber =
caution. Use exactly one hot accent per view (the view's verdict).

| Token | Hex | Use |
|---|---|---|
| `--paper` | `#F5F3EC` | body background — warm cream, never stark white |
| `--surface` | `#FBFAF6` | cards on paper |
| `--ink` | `#14171A` | primary text |
| `--muted` | `#6B7280` | secondary text, labels |
| `--line` | `#E3E0D6` | hairlines, table rules |
| `--green` | `#0E3B2E` | poster header/nav band, CLEAN verdict, primary button |
| `--green-2` | `#0B2B22` | dark evidence cards (mono readouts) |
| `--green-ink` | `#7DD3A8` | terminal-green mono text on dark cards |
| `--coral` | `#D2483F` | FLAGGED / CONFIRMED-CN verdict, warnings, button hover — the one hot accent |
| `--amber` | `#C9821F` | LIKELY / caution verdicts |

Verdict → color: `NO EVIDENCE`/US = `--green`; `LIKELY` = `--amber`;
`CONFIRMED`/CN = `--coral`. Confidence and jurisdiction badges follow the same scale.

## Typography

Never Inter/Roboto/Arial/system as the display face.

| Role | Face | Notes |
|---|---|---|
| Display / verdict headline | **Fraunces** (or Instrument Serif) | the big serif verdict line — document authority |
| UI / body | **Geist** (humanist grotesque) | forms, labels, nav, prose |
| Mono / evidence | **Geist Mono** (or JetBrains Mono) | tokenizer vectors, score tables, code, IDs — instrument readout |

Section labels are small-caps, letter-spaced, `--muted` (e.g. `1. TOKENIZER MATCH`).
Big stat numbers use the display serif at large size (`98.7%`, `4.6σ`, `0.997`).

## Layout

- **Poster header band** in `--green` across the top: small-caps wordmark
  `PROVENANCE-PROBE` left, minimal nav / the endpoint being probed right. This is
  the graphify move — a green poster over a cream document.
- **Verdict is the hero.** On the results page: a large calm verdict card
  (serif headline in the verdict color + a one-line plain-English fact), with a
  small `VERDICT` stamp badge. Everything else is subordinate.
- **Evidence as a lab report** below the verdict, in editorial columns:
  tokenizer-match table (mono, terminal-green on a `--green-2` card), high-level
  stat numbers, wire signals list (server header / echoed model id / catalog —
  each with a MATCH/FLAGGED tag), network & jurisdiction row. A footer strip with
  artifact id, timestamp, engine version, and the signed report hash.
- **Entry screen:** green poster hero with the serif headline "A lie detector for
  AI APIs" + plain subhead; below, one clean card form — endpoint URL (mono hint),
  model, "your API key — used once, never stored", "I am authorized to test this
  endpoint" checkbox, one primary `Run the probe` button (`--green`, coral hover).
- Generous whitespace. Composition-first, not component-grid.

## Voice / microcopy

Plain language, verdict-first, non-technical readable (it's a public gated demo).
Lead with the fact ("This app uses an AI model built in China."), then the evidence.
Never hedge the measurement; do state confidence honestly.

## Anti-slop (hard rules)

No purple, no gradients, no 3-column icon grids, no centered-everything, no
decorative blobs, no drop-shadow soup. One hot accent per view. If a thing doesn't
carry meaning, it's not on the page.

## Scope note

The `serve` UI today is several pages with ad-hoc inline CSS (main probe, agent
board, wizard, consent, preview, and the new HAR-import page from #53). This system
unifies them: extract these tokens into one shared `<style>` (CSS variables) and
apply the poster-header + cream-body + verdict-accent structure across every page.
