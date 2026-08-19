# Privacy policy — provenance-probe capture

_Canonical source. This exact text is published at the store's required privacy-policy URL:
https://lobster-shrimp.github.io/provenance-observatory/extension-privacy (observatory
`site/build.py`). Keep the two in sync._

_Last updated: 2026-08-19_

The **provenance-probe capture** browser extension helps you send one AI chat request from
your own browser to your own self-hosted **provenance-probe** instance for analysis. It is
built to collect as little as possible and to keep what it touches on your machine or on a
server you control.

## What the extension stores
- **Your instance URL and Basic-auth username/password**, which you enter in the popup.
  These are stored only in your browser's local extension storage (`chrome.storage.local`)
  on your device. They are never sent anywhere except to the instance you configure, over
  HTTPS, and are never written to logs or the console.

## What the extension transmits, and to whom
- **Only** to the hosted provenance-probe instance **you configure**, and **only** the one
  AI chat request you explicitly choose to capture and upload. Transmission happens over
  HTTPS with the Basic-auth header you provided.
- If the captured request carries a **session cookie**, it is included only when you tick a
  consent checkbox that names the destination host, and it is used for a single ephemeral
  analysis run — it is not stored on the instance.
- Vendor API keys or similar credentials in a captured request (for example an
  `Authorization` or `x-api-key` header) are **stripped before upload**.

## What the extension does NOT do
- It does **not** collect data passively, in the background, or across tabs. Capture happens
  only when you click "Arm capture" and only for the tab you are inspecting in DevTools.
- It does **not** record your login. You log in yourself, in your own browser session.
- It does **not** read your browsing history, your other tabs, or your cookie jar.
- It has **no** analytics, **no** telemetry, and sends **no** data to the extension's authors
  or to any third party.

## Data sharing and sale
We do not sell or share your data. The only network destination is the instance you
configure. Use of any data received adheres to the Chrome Web Store User Data Policy,
including its Limited Use requirements.

## Your control
- Click **Forget** in the popup to erase your stored instance URL and credentials and revoke
  the host permission.
- Remove the extension from `chrome://extensions` to delete everything it stored.

## Source and contact
The extension is open source. Review the code and file issues at
https://github.com/lobster-shrimp/provenance-probe.
