# Data-use disclosures + Limited Use (Privacy practices tab)

Chrome treats authentication info, cookies, and web request/response content as **user
data even when processed locally**, so the Data usage section must be filled in — a static
privacy page alone is not enough. Answers below.

## Data this extension handles
| Data | Collected? | Where it goes | Notes |
|---|---|---|---|
| **Authentication information** (the instance Basic-auth username/password) | Handled | Stored locally in `chrome.storage.local`; transmitted only to the user's own configured instance over HTTPS | User-entered config. Never sent anywhere else; never logged. |
| **Website content** (the one captured AI chat request + response the user selects) | Handled + transmitted | To the user's own configured instance only, on explicit upload | Vendor API keys (`Authorization`/`x-api-key`) are stripped before upload. |
| **Web request session cookie** (only if present on the captured request) | Handled + transmitted | To the user's own instance, ONLY after an explicit per-host consent checkbox | Used for one ephemeral dry-run; never stored on the instance. |

Nothing is collected passively, in the background, or across tabs. Everything is
user-initiated (Save, Test connection, Arm capture, Upload).

## The three required certifications
- ✅ **We do NOT sell or transfer user data to third parties**, outside the approved use cases.
- ✅ **We do NOT use or transfer user data for purposes unrelated to the item's single purpose.**
- ✅ **We do NOT use or transfer user data to determine creditworthiness or for lending.**

## "Is data transferred off the user's device?"
Yes — but only to the destination the user themselves configures (their own hosted
provenance-probe instance), only over HTTPS, and only the one request they explicitly
choose to upload. There is no first-party analytics, no telemetry, and no third-party
transmission of any kind.

## Limited Use compliance statement
Use of information received from this extension adheres to the Chrome Web Store User Data
Policy, including the **Limited Use** requirements. Specifically: the data the user
provides or captures is used **solely** to perform the extension's single purpose —
capturing one AI chat request and delivering it to the user's own provenance-probe
instance for model-provenance analysis. It is not transferred to third parties; it is not
used for advertising, credit, or any purpose unrelated to that single purpose; and no
human reads the data except the user, on their own instance.
