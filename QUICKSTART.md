# QUICKSTART — getting to a working install

Five steps, roughly 20 minutes. Each has a **checkpoint** — if it doesn't match, stop there rather than continuing; a later failure will be much harder to diagnose.

---

## Step 0 — Where everything lives

Download **`provenance-probe.tar.gz`** (or `.zip`) and unpack it anywhere you have write access:

```bash
tar -xzf provenance-probe.tar.gz         # or: unzip provenance-probe.zip
cd provenance-probe                      # <- run EVERY command from here
```

You should land in a folder containing `pyproject.toml`:

```
provenance-probe/                 <- project root. cd here. all commands run from here.
├── pyproject.toml                <- if you cannot see this file, you are in the wrong folder
├── install.sh
├── QUICKSTART.md  README.md
├── mock_real_qwen.py             <- smoke-test fixture (Step 3)
├── mock_zai.py  mock_vendor.py   <- deception-replay fixtures
└── provenance_probe/             <- the package. do NOT cd into this.
    ├── cli.py  serve.py  scoring.py  reference.py  report.py  userwarn.py
    ├── data/
    │   ├── corpus.py
    │   └── tokenizer_ref.json    <- reference vectors. Step 4 writes here.
    ├── probes/                   <- tokenizer, network, wire, deception, clientsrc, artifact…
    └── tools/                    <- GGUF reference builder
```

**The one rule: always run from the project root — the folder containing `pyproject.toml`.**
`cd`-ing into `provenance_probe/` breaks `pip install -e .` and every import after it.

Things written *outside* the project folder:

| What | Where | Note |
|---|---|---|
| Reports from `serve` | `~/.provenance-probe/reports/` | override with `PROVENANCE_PROBE_HOME` |
| Reports from `assess` | wherever you point `--out` | e.g. `./reports` |
| Virtualenv | `.venv/` in the project root | created by `install.sh` |
| HF tokenizer cache | `~/.cache/huggingface/` | Step 4 fills this, several GB |

---

## Step 1 — Install

```bash
./install.sh
source .venv/bin/activate
```

If `install.sh` won't run (Windows, restricted shell, or you want control):

```bash
python3 -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[reference]"
```

**Checkpoint**

```bash
provenance-probe --help
```

Should list: `init, build-reference, verify-reference, assess, monitor, artifacts, serve, clientsrc, network`.

*If `provenance-probe: command not found`* — your venv isn't active, or the install fell back to `--user`. Verify with `which provenance-probe`; it should be inside `.venv/bin`.

---

## Step 2 — Confirm what already works

Eleven real tokenizers ship pre-built. Check them before adding anything:

```bash
provenance-probe verify-reference
```

**Checkpoint** — you should see 11 models, `CN families covered : 3`, and warnings that GLM, Yi and InternLM are missing. Those warnings are expected; Step 4 fixes them.

*If it says `Reference is marked SYNTHETIC`* — you have an older build. Rebuild the real ones:

```bash
bash provenance_probe/tools/fetch_gguf_vocabs.sh
python -m provenance_probe.tools.build_reference_from_gguf
```

---

## Step 3 — Smoke test end to end

Prove the plumbing works before pointing it at anything real. Two terminals:

```bash
# terminal 1 — a fake vendor serving genuine Qwen2 token counts
python mock_real_qwen.py          # wait for "Running on http://127.0.0.1:8902"

# terminal 2
cat > smoke.json <<'EOF'
[{"name":"smoke","base_url":"http://127.0.0.1:8902/v1",
  "model":"northstar-secure-1","authorized":true}]
EOF
provenance-probe assess --config smoke.json --out ./smoke --offline \
  --no-behavioral --no-deception
```

**Checkpoint**

```
Best tokenizer match Qwen2/Qwen2.5 (Qwen, origin=CN) score=1.0, 20/20 exact
```

That mock loads a 151k-token vocabulary — give it ~15 seconds before running the assess, or every probe returns connection-refused and the tokenizer layer silently reports `usable: false`.

---

## Step 4 — Close the reference gap

This is the step that matters for z.ai-style cases. GLM is not in the shipped set, so the tool cannot currently confirm a GLM backend behind a false persona.

**4a. Get a HuggingFace token** (only needed for the gated Western models — every Chinese model below is ungated).

`huggingface.co` → Settings → Access Tokens → New token, `read` scope.

```bash
export HF_TOKEN=hf_xxxxxxxx
```

For Llama, Gemma and Mistral you must *also* click "Agree and access repository" on each model page. The token alone is not enough.

**4b. Build the Chinese families first** — highest value, no gating, no token required:

```bash
provenance-probe build-reference \
  --only zai-org/GLM-4.5 \
  --only 01-ai/Yi-1.5-9B-Chat \
  --only internlm/internlm2_5-7b-chat
```

**4c. Then everything else:**

```bash
provenance-probe build-reference
```

This **merges** — it will not overwrite the eleven real vectors you already have.

**Checkpoint**

```bash
provenance-probe verify-reference
```

Want: `CN families covered : 6` or better, no `PROBLEMS`, and the GLM/Yi/InternLM warnings gone. Han tok/char for the new CN entries should land near **0.5–0.7**. If GLM comes back above 1.0, the tokenizer loaded wrong — check the `source` field in `data/tokenizer_ref.json`.

---

## Step 5 — Run it for real

```bash
provenance-probe serve        # http://127.0.0.1:8770
```

Or headless:

```bash
provenance-probe init                     # writes targets.json
$EDITOR targets.json                      # set base_url, model, authorized=true
export VENDOR_API_KEY=sk-...
provenance-probe assess --config targets.json --out ./reports --latency
```

Then store that first run as your baseline and diff against it on a schedule:

```bash
cp reports/vendor_*.json baseline.json
# nightly
provenance-probe assess --config targets.json --out ./nightly
provenance-probe monitor --baseline baseline.json \
  --current nightly/vendor_*.json --json-out drift.json || echo "BACKEND CHANGED"
```

`monitor` exits 2 on drift, so `|| alert` works directly in cron or CI.

---

## Troubleshooting

| Symptom | Cause | Fix |
|---|---|---|
| `requires trust_remote_code` | Repo ships a custom tokenizer class | Use the `-hf` variant (e.g. `THUDM/glm-4-9b-chat-hf`). Only use `--allow-remote-code` in a throwaway container — it executes repo code on your machine |
| `is gated` | Licence not accepted, or no token | Accept on the model page **and** set `HF_TOKEN` |
| `tokenizer usable: false` | Endpoint strips `usage.prompt_tokens` | Not fixable from your side. It is itself a transparency finding — record it and lean on the network and client-source layers |
| `Corpus version mismatch` | You edited `data/corpus.py` | Rebuild references; the old vectors are invalid |
| `identical vectors` warning | Two models share a tokenizer | Expected for some pairs (MPT/GPT-NeoX). They cannot be told apart by this layer |
| Assessment hangs | No timeout on a slow endpoint | Lower `timeout` in the target config |

## Two things to get right before you report findings

**Authorization.** The deception and alignment probes send politically sensitive prompts to third-party infrastructure. Get that into your written test authorization explicitly, not implied.

**The web UI has no authentication.** It binds to loopback. If you change `--host`, put a real auth proxy in front — it makes outbound requests carrying your API keys.
