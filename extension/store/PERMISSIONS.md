# Permission justifications

Chrome's review asks for a justification per permission (Privacy practices tab). These
map each requested permission to why it is needed. The extension deliberately requests the
**minimum** — no `<all_urls>`, `webRequest`, `cookies`, `tabs`, `activeTab`, or `scripting`,
and **no** static `host_permissions` (nothing is granted at install time).

## `storage` (required)
Stores only the user's own instance URL and Basic-auth credentials, locally in
`chrome.storage.local`. Nothing else is stored, and nothing leaves the browser except the
upload the user explicitly triggers to their configured instance.

## `declarativeNetRequestWithHostAccess` (required)
Removes the `Origin` header from the extension's **own** upload request to the user's
configured instance, so the instance's same-origin CSRF guard accepts the authenticated
POST. One dynamic rule, scoped to the exact instance origin + the `/wizard/capture-import`
path, POST only, and bound to the extension's own initiator — it never affects any other
site, host, path, or any web page's requests.

## `optional_host_permissions`: `https://*/*`, `http://localhost/*`, `http://127.0.0.1/*` (requested at runtime)
Lets the extension reach the user's own hosted instance to upload the captured request.
**Nothing is granted at install.** When the user saves (or tests) their configuration, the
extension calls `chrome.permissions.request` for **only the exact origin the user typed**.
HTTPS is required; loopback `http` is allowed only for local development. The broad pattern
exists because the instance host is not known until the user enters it — but the grant is
always narrowed to that single origin.

## Capture needs NO host permission
The request capture uses the DevTools network API (`chrome.devtools.network`), scoped to
the single inspected tab and available only while DevTools is open. There is no passive or
cross-tab observation; the listener attaches only on "Arm capture" and detaches on "Stop".

## Why no `activeTab` / `tabs` / `cookies` / `scripting` / `webRequest`
The extension never reads other tabs, never enumerates tabs, never reads the cookie jar
(a captured request's own `Cookie` header rides along only with explicit per-host consent),
and never injects scripts or observes network traffic broadly. Capture is DevTools-scoped
and upload is a single authenticated fetch the user initiates.
