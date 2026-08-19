# Chrome Web Store listing copy

Paste these into the Web Store developer dashboard (Store listing tab). Kept within
Chrome's field limits.

## Item name (≤ 45 chars)
`provenance-probe capture`

## Summary / short description (≤ 132 chars)
Capture one AI chat request from your own browser and send it to your self-hosted
provenance-probe instance for model analysis.

## Category
Developer Tools

## Language
English (United States)

## Detailed description
provenance-probe capture is a companion to a self-hosted **provenance-probe** instance —
a tool that measures which AI model actually serves a chat app, and whether it is
Chinese-origin or PRC-jurisdiction.

Some AI chat apps present one brand while a different model answers behind the scenes.
provenance-probe analyzes that. This extension is the easy way to feed it one real
request: instead of exporting a HAR file by hand, you capture the request **in your own
browser, in your own logged-in session**, and upload it to **your own** hosted instance.

How it works:
1. In the popup, set your instance URL + credentials once, and click Test connection.
2. Open your AI chat app, log in, open DevTools → the "Provenance Capture" panel.
3. Click Arm capture, send one short message, pick the request, and upload.
4. Your instance runs its analysis and shows the result.

What it does NOT do:
- No server-side browser and no new server surface — capture happens locally, in the tab
  you already have open.
- It never records your login (you log in yourself).
- It captures nothing until you explicitly Arm it, and only for the tab you're inspecting.
- It requests no broad permissions: no access to all sites, no reading your cookies or
  tabs. It asks for access to exactly the one instance host you type, only when you save.

Your credentials are stored only in your browser (chrome.storage.local) and are sent only
to the instance you configure, over HTTPS. Vendor API keys in a captured request are
stripped before upload. Open source; see the repository for the full security write-up.

## Single-purpose description (Privacy tab)
This extension has a single purpose: to capture one AI chat request from the user's
current browser session and upload it to the user's own self-hosted provenance-probe
instance for model-provenance analysis. All other functionality (the popup config, the
connection test, the cookie-consent prompt) exists solely to support that one purpose.

## Homepage / support URL
`https://github.com/lobster-shrimp/provenance-probe`

## Privacy policy URL
`https://lobster-shrimp.github.io/provenance-observatory/extension-privacy` (see the
observatory PR that publishes this page before submitting).
