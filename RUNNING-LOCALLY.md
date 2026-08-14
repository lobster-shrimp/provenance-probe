# Running Locally (Windows / macOS / Linux)

A from-scratch guide to running the whole stack on your own machine — the
**engine** (`provenance-probe`: CLI + local web UI) and, optionally, the
**observatory** (`provenance-observatory`: JSON API + static site). Nothing here
touches a network endpoint you don't point it at, and no credentials are needed
for the local walkthrough.

> **New to the project?** Read the [README](README.md) for what this is and the
> [WHITEPAPER](WHITEPAPER.md) for why. This file is purely *how to run it*.

**What you'll have running when you're done:**

| Service | Repo | Default URL | Purpose |
|---|---|---|---|
| Probe web UI | provenance-probe | http://127.0.0.1:8770 | Point-and-click assessment + Monitor tab |
| Observatory API | provenance-observatory | http://127.0.0.1:8000 (docs at `/api/docs`) | JSON API over the evidence log |
| Observatory site | provenance-observatory | http://127.0.0.1:8080 | The public Variant-C site, served statically |

You do **not** need all three. If you only want to fingerprint an endpoint, the
engine alone (Parts 1–2) is enough.

---

## 0. Prerequisites (all platforms)

- **Python 3.10 or newer.** Check with `python --version` (or `python3 --version`).
  - Windows: install from [python.org](https://www.python.org/downloads/) and
    tick **"Add python.exe to PATH"** in the installer. The launcher `py` also works.
  - macOS: `brew install python` (or python.org). Use `python3`.
  - Linux: `sudo apt install python3 python3-venv python3-pip` (Debian/Ubuntu).
- **git** — [git-scm.com](https://git-scm.com/downloads).
- That's it. No Docker, no database, no cloud account for local use.

**A note on the commands below.** Each step gives two forms:

- 🟦 **macOS / Linux / WSL / Git-Bash** (bash/zsh)
- 🟪 **Windows PowerShell**

Pick the row for your shell. Windows users: PowerShell is recommended over
`cmd.exe`; if you use WSL, follow the macOS/Linux rows instead.

---

## 1. Get the code

Clone both repos side by side into one parent folder. The observatory expects to
find the engine as a sibling directory.

🟦 macOS / Linux / WSL
```bash
mkdir -p ~/CODE && cd ~/CODE
git clone https://github.com/lobster-shrimp/provenance-probe.git
git clone https://github.com/lobster-shrimp/provenance-observatory.git
```

🟪 Windows PowerShell
```powershell
mkdir $HOME\CODE -Force; cd $HOME\CODE
git clone https://github.com/lobster-shrimp/provenance-probe.git
git clone https://github.com/lobster-shrimp/provenance-observatory.git
```

You now have `~/CODE/provenance-probe` and `~/CODE/provenance-observatory`
(`$HOME\CODE\...` on Windows).

---

## 2. The engine (`provenance-probe`)

### 2a. Create and activate a virtual environment

Do everything inside a venv so it never touches your system Python.

🟦 macOS / Linux / WSL
```bash
cd ~/CODE/provenance-probe
python3 -m venv .venv
source .venv/bin/activate
```

🟪 Windows PowerShell
```powershell
cd $HOME\CODE\provenance-probe
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

> **PowerShell blocks the activate script?** Run once, then retry:
> `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`

Your prompt now shows `(.venv)`. Everything below assumes it's active. (Re-run
the `activate` line in any new terminal.)

### 2b. Install

The base install is dependency-light. Extras are opt-in:

- `eval` — run the hermetic accuracy/consistency gate (GGUF vocabs).
- `reference` — rebuild tokenizer reference vectors (pulls in `transformers`/`tiktoken`; large).
- `test` — the pytest suite.

Install the base plus the two you'll usually want locally:

🟦 macOS / Linux / WSL
```bash
pip install -e ".[eval,test]"
```

🟪 Windows PowerShell
```powershell
pip install -e ".[eval,test]"
```

Just the engine, nothing extra: `pip install -e .`

### 2c. Verify

```bash
provenance-probe --help          # CLI is on PATH inside the venv
python -m pytest tests/ -q       # should be all green
python -m eval.run_eval          # hermetic zero-false-positive gate
```

(On Windows PowerShell the same three commands work verbatim once the venv is active.)

### 2d. Run the local web UI

```bash
provenance-probe serve            # binds 127.0.0.1:8770
```

Open **http://127.0.0.1:8770**. Use `--port 9000` to change the port, `--host`
to change the bind address (default is loopback-only, which is what you want
locally). Stop it with `Ctrl+C`.

### 2e. Try it from the CLI (no server, no credentials)

Analyze the bundled z.ai case — the canonical model-switch demo (GLM answering
under a "Gemini" persona, conceding GLM at turn 7):

🟦 macOS / Linux / WSL
```bash
provenance-probe transcript tests/fixtures/zai_gemini_glm.json
```

🟪 Windows PowerShell
```powershell
provenance-probe transcript tests\fixtures\zai_gemini_glm.json
```

Other subcommands: `assess` (full multi-layer assessment of a configured
target), `monitor` (diff two assessment JSONs; exits 2 on drift), `session`
(intra-session boundary check), `sentinel` (real-time reverse-proxy alerting).
Run `provenance-probe <cmd> --help` for each. See the [README](README.md) for
adding real API and web-app targets.

---

## 3. The observatory (`provenance-observatory`) — optional

The observatory reuses the **same virtualenv** as the engine, so the engine is
importable as a black-box CLI dependency. Keep the venv from Part 2 active.

### 3a. Install its dependencies

🟦 macOS / Linux / WSL
```bash
cd ~/CODE/provenance-observatory
pip install fastapi "uvicorn>=0.29" "httpx>=0.27" "pyyaml>=6.0"
```

🟪 Windows PowerShell
```powershell
cd $HOME\CODE\provenance-observatory
pip install fastapi "uvicorn>=0.29" "httpx>=0.27" "pyyaml>=6.0"
```

> `requirements.txt` pins `llm-provenance-probe==0.28.0` from PyPI (the PyPI
> distribution name; the CLI command is still `provenance-probe`) — for local dev you
> want the **editable engine you just installed** instead, so install the four
> packages above directly rather than `pip install -r requirements.txt`. The
> editable `provenance-probe` from Part 2 stays on the path.

Run its tests to confirm the wiring:
```bash
python -m pytest tests/ -q
```

### 3b. Run the JSON API

From the `provenance-observatory` directory, with the venv active:

```bash
uvicorn api.app:app --reload        # http://127.0.0.1:8000
```

- Interactive OpenAPI docs: **http://127.0.0.1:8000/api/docs**
- Key endpoints: `/api/verdicts`, `/api/targets/{name}`, `/api/advisories`,
  `/api/manifests`, `/api/model-changes`, `/api/status`, `/api/search`,
  `/api/feed.xml`, `/api/stream` (SSE).

Change the port with `--port 9001`. Stop with `Ctrl+C`.

### 3c. Build and serve the static site

The site is generated from the git-committed `data/` tree, then served as plain
static files. **Two terminals** (both with the venv active, both in
`provenance-observatory`): one already running the API from 3b, one for the site.

Build it (point the footer's API links at your local API):

🟦 macOS / Linux / WSL
```bash
OBSERVATORY_API_URL=http://127.0.0.1:8000 python site/build.py
python -m http.server 8080 --directory site/dist
```

🟪 Windows PowerShell
```powershell
$env:OBSERVATORY_API_URL = "http://127.0.0.1:8000"; python site\build.py
python -m http.server 8080 --directory site\dist
```

Open **http://127.0.0.1:8080**. Rebuild (re-run `build.py`) after changing
anything under `data/`. If you don't set `OBSERVATORY_API_URL` it defaults to
`http://127.0.0.1:8000`, which is what you're running anyway.

---

## 4. Running everything at once

You'll want up to three terminals, each with the venv active:

| Terminal | Directory | Command |
|---|---|---|
| 1 — Probe UI | `provenance-probe` | `provenance-probe serve` |
| 2 — API | `provenance-observatory` | `uvicorn api.app:app --reload` |
| 3 — Site | `provenance-observatory` | `python -m http.server 8080 --directory site/dist` (after `python site/build.py`) |

Activate the venv in each new terminal first:
- 🟦 `source ~/CODE/provenance-probe/.venv/bin/activate`
- 🟪 `& $HOME\CODE\provenance-probe\.venv\Scripts\Activate.ps1`

---

## 5. Docker (API only, optional)

If you'd rather containerize the API, the observatory ships a Dockerfile:

```bash
cd ~/CODE/provenance-observatory
docker build -t provenance-observatory-api .
docker run --rm -p 8000:8000 provenance-observatory-api
```

The site is static — for a container you can serve `site/dist` with any static
file server (nginx, `python -m http.server`, Caddy). For real hosting (Fly.io /
Render) see [`api/DEPLOY.md`](https://github.com/lobster-shrimp/provenance-observatory/blob/main/api/DEPLOY.md).

---

## 6. Stopping and cleaning up

- Stop any running service with **`Ctrl+C`** in its terminal.
- Free a stuck port:
  - 🟦 macOS/Linux: `lsof -ti tcp:8080 | xargs kill` (repeat per port: 8000, 8770)
  - 🟪 Windows PowerShell: `Get-NetTCPConnection -LocalPort 8080 | Select-Object -Expand OwningProcess | ForEach-Object { Stop-Process -Id $_ }`
- Leave the venv: `deactivate`.
- Remove everything: delete the `.venv` folder and the two cloned repos.

---

## 7. Troubleshooting

| Symptom | Fix |
|---|---|
| `provenance-probe: command not found` | The venv isn't active. Re-run the `activate` line for your shell (§2a). |
| `python` opens the Microsoft Store (Windows) | Use `py` instead, or untick the App-execution-alias for Python in Windows Settings. |
| PowerShell: "running scripts is disabled" | `Set-ExecutionPolicy -Scope CurrentUser -ExecutionPolicy RemoteSigned`, then re-activate. |
| `ModuleNotFoundError: provenance_probe` when running the observatory | Install the engine editable **into the same venv** (§2b) before installing observatory deps. |
| Port already in use | Pass `--port <n>` (probe/uvicorn) or a different number to `http.server`, or free the port (§6). |
| `python -m eval.run_eval` fails on import | Install the `eval` extra: `pip install -e ".[eval]"` in the engine. |
| Site shows no data / empty table | It renders the committed `data/` tree; a fresh clone has only sample/control records. Re-run `python site/build.py` after any `data/` change. |

---

## Where to go next

- Add a real API or web-app target → [README](README.md) and
  `provenance-observatory/docs/adding-targets.md`.
- Understand the layers and scoring → [README](README.md) + [WHITEPAPER](WHITEPAPER.md).
- Deploy the observatory for real →
  [`api/DEPLOY.md`](https://github.com/lobster-shrimp/provenance-observatory/blob/main/api/DEPLOY.md).
