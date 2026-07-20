# provenance-probe

Black-box assurance harness for determining **which model is actually serving your requests**, and whether it is Chinese-origin or PRC-jurisdiction — including when a vendor is silently routing, swapping, or rebranding.

> **Scope control.** Only run against systems you are authorized in writing to test. Targets carry an `authorized` flag; active probing aborts without it. The behavioral probes send politically sensitive prompts — get that into your test authorization explicitly.

## The two risks it separates

The tool never collapses these into one verdict, because controls differ:

| Risk | Question | Exposure |
|---|---|---|
| **Jurisdictional** | Is inference executed by a PRC-domiciled operator or on PRC soil? | PIPL, DSL, CSL, National Intelligence Law Art. 7 — data egress |
| **Provenance** | Are the weights Chinese-origin, wherever served? | Embedded alignment/censorship, poisoning, procurement policy |

A vendor can be clean on one and dirty on the other. Chinese open weights running inside your own accreditation boundary carry **zero** PRC data-jurisdiction exposure — treating that as an egress problem misdirects your controls.

## Deploy locally

```bash
./install.sh            # venv + install + build tokenizer references
source .venv/bin/activate
provenance-probe serve  # http://127.0.0.1:8770
```

`install.sh` creates `.venv`, installs the package with its `provenance-probe` entrypoint, pulls the optional tokenizer extras, and attempts `build-reference`. Each step degrades gracefully — if HuggingFace is unreachable the install still succeeds and the tokenizer layer stays inert until you run `build-reference` later.

Manual equivalent:

```bash
python3 -m venv .venv && source .venv/bin/activate
pip install -e '.[reference]'
provenance-probe build-reference
provenance-probe serve
```

Docker:

```bash
docker compose up --build          # published to 127.0.0.1:8770 only
docker compose exec provenance-probe provenance-probe build-reference
```

Reports persist to `~/.provenance-probe/reports` (or `/data` under Docker); override with `PROVENANCE_PROBE_HOME`.

### The local web UI

`provenance-probe serve` gives you the whole harness in a browser: endpoint + model, optional client-source URL or directory, confrontation backend and its false control, proxy, and the advanced toggles. It streams progress, then renders the plain-language warning first and the technical detail below it, with a local run history linking to both report formats.

**Deployment notes.** It binds to loopback and has **no authentication** — if you change `--host`, put it behind something that does. The authorization checkbox is enforced server-side, not just in the UI. API keys you enter are held in memory for the run and never written to the report files. Nothing is transmitted anywhere except to the endpoint you name.

## Install (library / CLI only)

```bash
pip install -e .
provenance-probe init
```

## Quick start

```bash
# 1. Reference vectors: 11 REAL tokenizers ship pre-built (no HF account needed).
#    To rebuild or extend them from llama.cpp's bundled GGUF vocabs:
bash provenance_probe/tools/fetch_gguf_vocabs.sh
python -m provenance_probe.tools.build_reference_from_gguf
#    To add families GGUF does not cover (GLM, Yi, InternLM, Gemma, Mistral),
#    run this on a network with HuggingFace access - it merges, not overwrites:
provenance-probe build-reference

# 2. Configure targets
$EDITOR targets.json          # set base_url, model, auth env var, authorized=true

# 3. Full assessment
export VENDOR_API_KEY=sk-...
python -m provenance_probe.cli assess --config targets.json --out ./reports --latency
```

Produces console output plus JSON and standalone HTML per target.

## Commands

| Command | Purpose |
|---|---|
| `init` | Write an example target config |
| `build-reference` | Compute local tokenizer reference vectors (the strongest signal) |
| `assess` | Full multi-layer assessment |
| `monitor --baseline A.json --current B.json` | Diff two runs; **exit 2 on drift** — wire this into CI |
| `artifacts <dir>` | Inspect on-prem model files; exit 2 on critical findings |
| `network --host X --hosts-file f` | Jurisdiction-analyze SNI/DNS names harvested from an egress capture |

## What each layer does

**Layer 2 — Network / jurisdiction** (`probes/network.py`)
Resolves the endpoint, matches against ~25 known PRC-operated inference hosts, checks `.cn` TLDs, and does RDAP lookups for CN registration and PRC ASN operators. Also classifies neutral aggregators (OpenRouter, Together, Fireworks, DeepInfra, Bedrock, Vertex…) — these resolve *jurisdiction* but leave *provenance* open.

Point `proxy` at your inspecting proxy in the target config to route probe traffic through your capture. For hosts you harvested from a firewall capture rather than tested directly, use `network --hosts-file`.

**Layer 3 — Wire fingerprint** (`probes/wire.py`)
Vendor-specific response headers (`x-tt-logid` → ByteDance, `x-ca-request-id` → Alibaba Gateway, `x-bce-request-id` → Baidu, `x-tc-requestid` → Tencent), the echoed `model` field, a hashed error-schema signature from six deliberate malformed requests, SSE chunk structure, and the `/models` catalog scanned for PRC-origin model IDs.

### Reference vector coverage

`data/tokenizer_ref.json` ships **real** production tokenizers — vocabularies and merge tables extracted from llama.cpp's bundled GGUF files, not surrogates. Every vocab size was checked against its published value.

| Shipped (real) | Origin | Han tokens/char |
|---|---|---|
| Qwen2 / Qwen2.5 | CN | 0.53 |
| DeepSeek-LLM | CN | 0.55 |
| DeepSeek-Coder | CN | 0.68 |
| Command-R | CA | 0.61 |
| Llama-3 | US | 0.73 |
| StarCoder · Refact | EU | 0.83 |
| Falcon | AE | 1.20 |
| MPT · GPT-NeoX | US | 1.40 |
| GPT-2 | US | 2.32 |

**Still missing — you must add these yourself via `build-reference`:** GLM/Zhipu, Yi, InternLM, MiniCPM, Baichuan, Gemma, Mistral, Phi, and the OpenAI `cl100k`/`o200k` encodings. GLM matters most if you are chasing z.ai-style cases; it is not in llama.cpp's vocab set.

Verified blind: a mock endpoint serving genuine Qwen2 token counts under the brand name `northstar-secure-1` was identified as **Qwen2, 20/20 probes exact, score 1.0**, with next-best Llama-3 at 0.175.

### A correction worth knowing about

An earlier version of this tool used `cjk_dense / cyrillic` as the Han-compression discriminator. Measuring it against real tokenizers showed that was wrong — it conflated Han compression with Cyrillic compression and ranked **Falcon** as more CJK-optimized than Qwen. It is now tokens-per-Han-character, normalized against the probe's actual Han count.

The corrected measurement also demoted the signal. Cohere's **Command-R reaches 0.61**, sitting between the Chinese families and Llama-3 — so low Han cost alone does not establish Chinese origin. Modern multilingual Western models overlap the range. Its scoring weight was cut from 1.8 to 0.9, and it is now explicitly a corroborating signal. The full 20-probe vector match is what identifies a family.

**Layer 4 — Tokenizer fingerprint** (`probes/tokenizer.py`) — *highest signal-to-effort*
Sends 20 probes engineered to tokenize differently across vocab families, reads `usage.prompt_tokens`, and compares against locally computed reference vectors. Chat-template overhead is auto-corrected via the modal delta. The Han-compression ratio (`cjk_dense / cyrillic`) alone separates CN from non-CN families.

If the endpoint strips `usage`, that's logged as a transparency finding in its own right.

**Layer 5 — Logprob / determinism** (`probes/logprob.py`)
Captures top-k distributions at temperature 0 for comparison against locally served references, plus a greedy-continuation signature hash that feeds drift detection.

**Layer 6 — Behavioral** (`probes/behavioral.py`)
- *Self-ID*: nine direct and indirect probes (cutoff, context window, tokenizer, system-prompt elicitation).
- *Alignment asymmetry*: **matched pairs** — each PRC-sensitive prompt paired with a structurally equivalent Western-sensitive control. Scores the delta, not the refusal. A model that refuses both is merely conservative; one that refuses only the treatment is the finding.
- *CJK leakage*: long-reasoning prompts at elevated temperature, inspecting output and any exposed `reasoning_content` for Han characters.

**Layer 6b — Latency** (`probes/latency.py`)
TTFT / inter-token distributions with z-score drift detection. This is how you catch a post-award backend swap.

**Layer 7 — Artifacts** (`probes/artifact.py`)
For self-hosted deployments: `config.json` architecture and `_name_or_path`, vocab-size lookup against known CN families, GGUF metadata (`general.name`, `general.architecture`, `general.basename`), safetensors headers, tokenizer file hashes, and HuggingFace cache path leakage.

## Scoring

Signals accumulate as log-odds into two independent likelihoods, mapped to `CONFIRMED / LIKELY / INDETERMINATE / UNLIKELY / NO EVIDENCE`. A separate `confidence` field reports how many evidence layers actually returned data — a verdict from two layers is explicitly labeled unreliable. Weights live in `scoring.py:WEIGHTS`; tune them to your risk appetite.

## Continuous monitoring

The real threat model isn't the point-in-time check at ATO — it's the silent swap three months later.

```bash
# after award, store the accepted baseline
python -m provenance_probe.cli assess --config targets.json --out ./baseline

# scheduled job
python -m provenance_probe.cli assess --config targets.json --out ./nightly
python -m provenance_probe.cli monitor \
  --baseline baseline/vendor_*.json --current nightly/vendor_*.json \
  --json-out drift.json || alert
```

`fingerprint_id` is a composite of the tokenizer vector, error signature, header shape, greedy signature, and streaming fields. Any change means the backend moved.

## Extending

- **New probes**: add to `data/corpus.py`, bump `CORPUS_VERSION`, rebuild references (version mismatch invalidates old vectors).
- **New endpoints**: extend `PRC_ENDPOINTS` / `AGGREGATOR_ENDPOINTS` / `PRC_MODEL_TOKENS`.
- **New architectures**: extend `CN_ARCH` / `CN_VOCAB` in `probes/artifact.py`.
- **Non-OpenAI wire formats**: subclass `Client._payload` or set `api_style="raw"`.

## Known limits — read before reporting a verdict

- **Distills confound provenance.** `DeepSeek-R1-Distill-Llama-70B` is Llama architecture with DeepSeek-generated training data; `-Distill-Qwen-32B` is Qwen architecture. Tokenizer analysis identifies the *base*, behavioral analysis identifies the *training influence*. Decide in advance which your policy actually cares about — most policies are ambiguous here and vendors exploit that.
- **Absence of censorship does not clear provenance.** Chinese open weights served offshore are frequently de-censored by fine-tuning. Presence is strong positive evidence; absence is not negative evidence.
- **Every black-box technique degrades against active evasion**: normalized usage counts, suppressed logprobs, output post-filtering, wrapper-level refusals. Layer network and contractual evidence underneath.
- **TLS pinning / in-app proxying** defeats passive capture. Escalate to contractual attestation.
- **Wrapper vs model.** Refusals and self-ID answers may originate in the vendor's system prompt or filter, not the weights. The tokenizer and wire layers are much harder to fake than the behavioral layer — weight them accordingly.

## Contract language this supports

Assurance is only durable if you can re-test. Require:
1. Notification **before** any change to model weights, inference provider, or serving region.
2. Right to run this battery against production, not a staging mirror.
3. A named subprocessor list covering fallback and overflow routing, with update notification.
4. Disclosure of base model for any fine-tuned or distilled offering.
