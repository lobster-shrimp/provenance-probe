# Installing provenance-probe on Windows

A step-by-step guide for Windows 10/11. Three ways to run it — pick one:

- **[Option A — Native Windows (PowerShell)](#option-a--native-windows-powershell)** — no extra runtime; best if you just want the CLI + local web UI.
- **[Option B — WSL2 (recommended)](#option-b--wsl2-recommended)** — a real Linux shell, so the one-command `./install.sh`, the demo, and Docker all "just work."
- **[Option C — Docker Desktop](#option-c--docker-desktop)** — nothing installed but Docker; fully isolated.

> **Good news on build tools:** the base install (`requests` + `flask`) is pure Python — **no C/C++ compiler needed**. The optional `[reference]` extras (`tiktoken`, `sentencepiece`, `protobuf`, `transformers`) ship **prebuilt wheels** for Python 3.10–3.12 on Windows, so they install without a compiler too. You only need Build Tools in the rare case a wheel isn't published for your exact Python (see [Troubleshooting](#troubleshooting)).

---

## Prerequisites

| Need | Why | Install |
|---|---|---|
| **Python 3.10–3.12** (3.12 recommended) | Runs the tool | `winget install Python.Python.3.12` — or [python.org](https://www.python.org/downloads/windows/) and **check "Add python.exe to PATH"** during setup |
| **Git** | Clone the repo | `winget install Git.Git` — or [git-scm.com](https://git-scm.com/download/win) |
| Docker Desktop *(Option C only)* | Isolated container | `winget install Docker.DockerDesktop` |
| WSL2 *(Option B only)* | Linux shell on Windows | `wsl --install` (in an **admin** PowerShell), then reboot |

> **Pick Python 3.12, not the newest (e.g. 3.13/3.14).** Brand-new Python releases sometimes don't have wheels for `sentencepiece`/`tiktoken` yet, which forces a source build. 3.12 has full wheel coverage today.

Verify the prerequisites in a fresh PowerShell window:

```powershell
py --version      # should print Python 3.12.x  (the "py" launcher ships with python.org installs)
git --version
```

---

## Option A — Native Windows (PowerShell)

`install.sh` is a bash script, so on native Windows you install manually (it's four commands).

```powershell
# 1. Clone
git clone https://github.com/lobster-shrimp/provenance-probe
cd provenance-probe

# 2. Create + activate a virtual environment
py -3.12 -m venv .venv
.\.venv\Scripts\Activate.ps1          # prompt should now start with (.venv)

# 3. Install (with the tokenizer reference extras)
pip install --upgrade pip
pip install -e ".[reference]"

# 4. Run the local web UI
provenance-probe serve                # open http://127.0.0.1:8770
```

If `Activate.ps1` is blocked with a red *"running scripts is disabled on this system"* error, allow local scripts once (safe, current-user only), then re-activate:

```powershell
Set-ExecutionPolicy -Scope CurrentUser RemoteSigned
.\.venv\Scripts\Activate.ps1
```

Prefer classic `cmd.exe`? Use `.\.venv\Scripts\activate.bat` instead of the `.ps1`.

The **11 GGUF-derived reference families ship pre-built**, so you can probe immediately. To *extend* the corpus (GLM, Yi, InternLM, Gemma, Mistral) you need a free HuggingFace account:

```powershell
provenance-probe build-reference       # optional; needs HuggingFace network access
provenance-probe verify-reference       # self-check the corpus (keyless, offline)
```

---

## Option B — WSL2 (recommended)

WSL2 gives you a real Ubuntu shell, so the one-command install, the demo GIF flow, and Docker all work exactly as on Linux.

```powershell
wsl --install          # admin PowerShell; installs Ubuntu; reboot when asked
```

Then open **Ubuntu** from the Start menu and run the Linux path:

```bash
sudo apt update && sudo apt install -y python3 python3-venv git
git clone https://github.com/lobster-shrimp/provenance-probe && cd provenance-probe
./install.sh                           # venv + install + reference vectors, one command
source .venv/bin/activate
provenance-probe serve                 # http://127.0.0.1:8770 (open it in your Windows browser)
```

The full keyless demo (unmask a Chinese model behind a US name) also works here:

```bash
pip install -e ".[eval]"               # adds gguf + tokenizers for the mock
bash provenance_probe/tools/fetch_gguf_vocabs.sh    # pulls the vocab the mock serves
python mock_real_qwen.py &
provenance-probe assess --config docs/media/demo-target.json --i-am-authorized --no-behavioral
```

---

## Option C — Docker Desktop

Nothing to install but Docker. From PowerShell in the cloned repo:

```powershell
docker compose up --build              # binds 127.0.0.1:8770 only
docker compose exec provenance-probe provenance-probe build-reference   # optional
```

Open http://127.0.0.1:8770. Reports persist to the container's `/data`.

---

## Verify it's working

```powershell
provenance-probe --help                 # lists commands
provenance-probe verify-reference        # prints the reference corpus (keyless, offline)
provenance-probe serve                   # web UI at http://127.0.0.1:8770
```

Reports are written to `%USERPROFILE%\.provenance-probe\reports` (override with the `PROVENANCE_PROBE_HOME` environment variable).

---

## Troubleshooting

| Symptom | Fix |
|---|---|
| `Activate.ps1 ... running scripts is disabled` | `Set-ExecutionPolicy -Scope CurrentUser RemoteSigned`, then re-activate. Or use `activate.bat` in cmd. |
| `provenance-probe: command not found` / not recognized | The venv isn't active. Re-run `.\.venv\Scripts\Activate.ps1`; the prompt must show `(.venv)`. |
| `python` opens the Microsoft Store | Use the `py` launcher (`py -3.12 ...`), or turn off the Store alias in *Settings → Apps → App execution aliases*. |
| pip tries to **build** `sentencepiece`/`tiktoken` from source and fails | You're on a too-new Python. Recreate the venv with **3.12** (`py -3.12 -m venv .venv`). If you must stay on the newer one, install [Microsoft C++ Build Tools](https://visualstudio.microsoft.com/visual-cpp-build-tools/) (workload: *Desktop development with C++*), then `pip install` again. |
| `filename too long` during clone/install | Enable long paths: in admin PowerShell `git config --system core.longpaths true`, and set the `LongPathsEnabled` registry key (or clone into a short path like `C:\pp`). |
| `build-reference` fails / hangs | It needs HuggingFace network access and is **optional** — the 11 pre-built families work without it. Skip it, or run on an unrestricted network. |
| The full mock demo won't run natively | It uses bash + a fetched GGUF vocab; easiest under **WSL2** or **Docker**. On native Windows, use `verify-reference` + `serve` to confirm the install. |

Still stuck? Open an issue with your `py --version`, the exact command, and the error text.
