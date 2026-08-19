# Store screenshots

**Ready to upload:** `screenshot-1-configured.png`, `screenshot-2-armed.png`,
`screenshot-3-result.png` (this folder) are **1280×800** and rendered from the real popup /
panel HTML + the bundled Geist/Fraunces fonts, in each target state, with demo data
(`probe.acme-internal.com` / `acme-chat`). Upload them as-is in the Store listing tab, or
re-capture from a live instance if you'd rather show real endpoints (shot list below).

Chrome requires at least one screenshot (1280×800 or 640×400, PNG/JPEG). These three tell
the story: configure → capture → result.

## 1. Configured popup — "Connected ✓"
- Open the popup, enter a real (or demo) instance URL + credentials, click **Test connection**.
- Capture with the green **"Connected to <host> ✓"** status showing.
- Shows: trust (it verifies before you commit) + the clean cream/green DESIGN.md look.

## 2. DevTools panel — armed / capturing
- Open DevTools → Provenance Capture, click **Arm capture**.
- Capture with the armed state visible (the "Recording — send one short message" line).
- Shows: the capture happens in your own tab/session, explicitly armed.

## 3. Dry-run result
- Complete a capture and upload; capture the **green success card + the target JSON**.
- Shows: the payoff — the instance confirmed it can reach the model, target ready to add.

## Tips
- Use a clean browser profile so no unrelated extensions/toolbars show.
- 1280×800 is the crisper option; keep the popup/panel centered with some cream margin.
- A demo instance (localhost) is fine — no real credentials need to appear.

## Promo tile
`promo/promo-tile.png` (this folder) is a generated marquee-style tile using the poster-band
identity (green band + wordmark), optional for the "Small promo tile" (440×280) slot.
