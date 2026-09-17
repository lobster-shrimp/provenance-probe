# Install the provenance-probe capture extension

The easiest install is one click from the **[Chrome Web Store](https://chromewebstore.google.com/detail/bapnflcbpphjcooabomhlodifapiopen)** (auto-updates).
This page is the alternative: a **developer-mode build** for inspecting the source or running
an unreleased change — download one zip and load it. Takes about a minute.

## 1. Download the build

Go to the repo's [**Releases**](https://github.com/lobster-shrimp/provenance-probe/releases)
page and download the latest `provenance-probe-extension-X.Y.Z.zip`.

Every `ext-v*` tag builds one automatically (tests + a version guard run first), so the
Release always matches the code.

## 2. Unzip it

Unzip the file. You get a folder named `provenance-probe-extension-X.Y.Z` containing
`manifest.json`, `icons/`, and the rest. Keep this folder somewhere stable — Chrome loads
the extension **from this folder on disk**, so if you delete or move it the extension breaks.

## 3. Load it into Chrome

1. Open `chrome://extensions`.
2. Turn on **Developer mode** (top-right toggle).
3. Click **Load unpacked**.
4. Select the unzipped `provenance-probe-extension-X.Y.Z` folder.

The provenance-probe icon appears in your toolbar. (Pin it via the puzzle-piece menu if
you don't see it.)

## 4. Point it at your instance

1. Click the toolbar icon.
2. Enter your hosted instance URL + Basic-auth username / password.
3. Click **Test connection** — it confirms the URL and credentials work before you save.
4. Click **Save configuration** (Chrome prompts to grant access to that one host).

## 5. Capture a request

1. Open your AI chat app in a tab and **log in**.
2. Open **DevTools** (F12) and select the **Provenance Capture** panel.
3. Click **Arm capture**, send **one** short message, pick the request (the top one is
   the recommended pick), tick the cookie consent if shown, and **Upload**.

The panel shows the dry-run result. Nothing is captured until you arm it, and your login is
never recorded (you log in yourself, in your own tab).

## Updating

Download the newer zip from Releases, unzip over (or beside) the old folder, then click the
**reload** icon on the extension's card in `chrome://extensions`.

## Uninstalling

Remove it from `chrome://extensions`, or click **Forget** in the popup first to clear your
saved instance URL + credentials and revoke the host permission.
