# Changelog — provenance-probe capture (browser extension)

The extension versions **independently** of the Python package (`llm-provenance-probe`);
these are its `manifest.json` / `package.json` versions, released via `ext-v*` git tags
(each tag builds a zip + a GitHub Release; see `extension-release.yml`). The root
`../CHANGELOG.md` tracks the Python package.

## [0.3.2] — manifest description within the store limit (2026-08-19)

### Fixed
- Shortened the manifest `description` to 125 chars — the Chrome Web Store rejects a
  description over 132 (the previous one was 136). Also dropped the walked-back
  "one-click" wording for an accurate line.

## [0.3.1] — distinct DevTools panel states (2026-08-19)

### Added
- **Panel states** are now visually distinct instead of one note whose text changes:
  - ARMED: a coral **● recording** pill (pulsing dot = active, the one accent; respects
    `prefers-reduced-motion`) carrying the "send one short message" prompt.
  - EMPTY: clearer recovery copy ("No request captured — click Arm capture…").
  - CAPTURED: the cookie-consent block (shown only when a session cookie is present) gets
    a coral left border marking it as the caution step.
  - RESULT: a **Fraunces** headline over the card (green "Dry-run succeeded" / coral
    "Couldn't complete the dry-run") + a real **Copy target JSON** clipboard button.

## [0.3.0] — bundled fonts (2026-08-19)

### Added
- **Bundle Geist 400/600, Geist Mono 400, and Fraunces (variable 400–700) as local
  woff2** (latin subsets, OFL-1.1; `fonts/OFL.txt`), so the DESIGN.md typography renders
  without a CDN (MV3/CSP forbids one): headline **Fraunces**, UI **Geist**, evidence
  `<pre>` **Geist Mono** on the dark-green evidence-card colors. `@font-face` loads from
  the extension's own origin (default MV3 CSP `font-src 'self'`); `fonts/` added to the
  zip.

## [0.2.0] — easier capture: icons, preflight, downloadable release, honest panel (2026-08-19)

### Added
- **Icons** — real 16/32/48/128 set rendered from a hand-authored `icons/icon.svg`
  (speech bubble + magnifier + one coral accent); `manifest.icons` + `action.default_icon`
  wired. Fixes the generic puzzle-piece and satisfies the store's icon requirement.
- **"Test connection" preflight** — the popup verifies the currently-typed URL + creds
  (two `HEAD /` probes via the background worker) before saving; honest states
  (connected / bad creds / instance-not-enforcing-auth / unreachable). New shared, pure,
  unit-tested `lib/config.js` (`validateInstanceUrl` — one source of truth for the
  HTTPS-only-except-loopback rule, replacing the popup/background duplication;
  `testConnResult`; `pickerLabel`).
- **Friendlier capture picker** — `host · path-tail (recommended)` labels instead of raw
  `METHOD URL`; **honest dry-run result copy** with no false "save" link (the endpoint is
  dry-run only, never persists a target).
- **DESIGN.md reskin** of the popup — exact tokens (cream `#F5F3EC`, green `#0E3B2E`,
  coral `#D2483F` hover), poster-band headline.
- **Downloadable release** — `extension-release.yml`: an `ext-v*` tag runs the unit tests,
  guards that the tag version == `manifest.json` == `package.json`, packages the zip, and
  creates a **GitHub Release** with it attached; `INSTALL.md` walks download → unzip →
  Load unpacked.
- **Chrome Web Store submission package** under `store/` — `LISTING.md`, `PERMISSIONS.md`,
  `DATA-SAFETY.md` (data-use disclosures + Limited Use), `PRIVACY.md`, `SUBMIT.md`, a
  generated `promo/promo-tile.png`, and the three 1280×800 `promo/screenshot-*.png`. The
  privacy policy is published at the observatory `/extension-privacy.html`. Submitting is
  the owner's manual step; the README points at the store listing once it's live.

### Fixed
- `package.json` test script → bare `node --test` (the quoted glob didn't expand on
  Node 20); the release/CI zip now includes `icons/`.

## [0.1.0] — initial MV3 capture extension (#54)

### Added
- Manifest V3 Chrome extension: a client-side alternative to the HAR-upload path. Captures
  one AI chat request in the user's own logged-in tab (DevTools network API — no
  server-side browser, no new server contract, no broad host permissions) and uploads it to
  the user's hosted instance's `/wizard/capture-import` with explicit cookie consent.
- Shared pure logic in `lib/sanitize.js` (payload assembly + header sanitization) with
  `node --test` unit tests; `extension.yml` builds + packages the zip on CI.
