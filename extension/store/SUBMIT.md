# Chrome Web Store submission checklist (owner-only)

Everything in this folder prepares the listing; the steps below are the manual submission
only you can do (developer account + upload + review). Order matters — do the two
prerequisites first.

## Prerequisites (do these first)
- [ ] **Publish the privacy page.** Merge the observatory PR that adds `/extension-privacy`
      (`site/build.py`) so `https://lobster-shrimp.github.io/provenance-observatory/extension-privacy`
      resolves. The store requires a live privacy-policy URL for an item that handles auth data.
- [ ] **Have a packaged zip.** Use the `provenance-probe-extension-X.Y.Z.zip` from a GitHub
      Release (tag `ext-vX.Y.Z`), or build locally. This is what you upload.
- [ ] **Capture 3 screenshots** from the loaded extension (see `promo/SCREENSHOTS.md`):
      1) popup configured + "Connected ✓", 2) the DevTools panel armed, 3) a dry-run result.
      1280×800 or 640×400 PNG/JPEG. (Optional: the promo tile in `promo/`.)

## In the Chrome Web Store developer dashboard
- [ ] Create a developer account (one-time $5 fee) at https://chrome.google.com/webstore/devconsole
- [ ] **Upload** the zip → new item.
- [ ] **Store listing tab** — fill from `LISTING.md`: name, summary, detailed description,
      category (Developer Tools), language, screenshots, the 128px icon (already in the zip),
      homepage/support URL.
- [ ] **Privacy practices tab:**
  - [ ] Single-purpose description (from `LISTING.md`).
  - [ ] Permission justifications — one per permission (from `PERMISSIONS.md`).
  - [ ] Data usage disclosures + the three certifications (from `DATA-SAFETY.md`).
  - [ ] Privacy policy URL (the observatory page above).
  - [ ] Limited Use acknowledgement (from `DATA-SAFETY.md`).
- [ ] **Distribution** — public or unlisted, as you prefer.
- [ ] **Submit for review.** Reviews commonly take a few days; a broad host-permission
      pattern (`https://*/*`, even though runtime-narrowed) may draw a reviewer question —
      `PERMISSIONS.md` answers it.

## After it's live
- [ ] Update `extension/README.md` and `extension/INSTALL.md` to point at the store listing
      as the primary install (keep the Load-unpacked path for developers).
- [ ] Note the store item ID somewhere durable for future updates.
