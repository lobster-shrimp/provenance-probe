"""Labeled eval corpus: known input -> expected verdict.

Two case families:

  VOCAB_CASES   — a real open-weights GGUF vocab served blind (eval/mock.py),
                  run through the full assess pipeline. Label = the vocab's
                  known origin. Consistency tier.
  BUNDLE_CASES  — a labeled `score()` input bundle (eval/bundles/*.json) fed
                  straight to scoring. Accuracy tier for the scoring logic.

"Flagged Chinese-origin" (the adverse detector output) is defined in one place,
`is_flagged_cn()`, so the corpus and the runner agree on what a positive is.

COVERAGE (honest accounting — see eval/README.md):
  The shipped reference scores against 25 model families. Only the 11 with a
  fetchable llama.cpp GGUF vocab AND a transcribed pre-tokenizer regex can be
  exercised end-to-end here. The other 14 (GLM, Yi, MiniCPM3, Qwen3,
  DeepSeek-V3, Moonshot, InternLM2.5, Baichuan2, Phi-3.5, Mistral-v0.3,
  Gemma-2, OpenAI cl100k/o200k) are reference-only and UNVALIDATED by this
  harness — most were built via the HF/tiktoken path, not GGUF. Do not read a
  green eval as coverage of those families.
"""
from __future__ import annotations

# CN family origins per the shipped reference. A positive is any of these.
CN = "CN"

# key = eval/vocabs/<key>.gguf ; regex_key defaults to key (see eval/mock.py REGEX)
# origin is the ground truth from the reference vector for that family.
VOCAB_CASES = [
    # --- CN positives: must be flagged Chinese-origin ---------------------
    {"key": "qwen2",          "family": "Qwen",         "origin": "CN", "expect_flagged": True},
    {"key": "deepseek-llm",   "family": "DeepSeek",     "origin": "CN", "expect_flagged": True},
    {"key": "deepseek-coder", "family": "DeepSeek",     "origin": "CN", "expect_flagged": True},
    # --- non-CN negatives: must NOT be flagged (false-positive gate) -------
    {"key": "llama-bpe",      "family": "Llama-3",      "origin": "US", "expect_flagged": False},
    {"key": "gpt-2",          "family": "GPT-2/OpenAI", "origin": "US", "expect_flagged": False},
    {"key": "command-r",      "family": "Cohere",       "origin": "CA", "expect_flagged": False},
    {"key": "falcon",         "family": "Falcon/TII",   "origin": "AE", "expect_flagged": False},
    {"key": "starcoder",      "family": "StarCoder",    "origin": "EU", "expect_flagged": False},
    {"key": "mpt",            "family": "MPT",          "origin": "US", "expect_flagged": False},
    {"key": "gpt-neox",       "family": "GPT-NeoX",     "origin": "US", "expect_flagged": False},
    {"key": "refact",         "family": "Refact",       "origin": "EU", "expect_flagged": False},
]

# Scoring golden bundles. `file` lives in eval/bundles/. Expectations are the
# verdict tier the bundle must produce and whether it counts as flagged-CN.
# NOTE (Gate-1): the only real recording here is the non-adverse US anchor.
# CN cases are SYNTHETIC (no real commercial operator is named) so this public
# repo never ships an interpreted named-vendor CN verdict.
BUNDLE_CASES = [
    {"file": "openai_clean_us.json",             "expect_flagged": False,
     "expect_provenance": {"NO EVIDENCE", "UNLIKELY"}},
    {"file": "synth_cn_tokenizer.json",          "expect_flagged": True,
     "expect_provenance": {"CONFIRMED", "LIKELY"}},
    {"file": "synth_behavioral_cn.json",         "expect_flagged": True,
     "expect_provenance": {"CONFIRMED", "LIKELY"}},
    {"file": "synth_noncn_tokenizer.json",       "expect_flagged": False,
     "expect_provenance": {"NO EVIDENCE", "UNLIKELY"}},
    {"file": "suppressed_usage_indeterminate.json", "expect_flagged": False,
     "expect_provenance": {"INDETERMINATE"}},
]

# --- fleet control tier: host attribution zero-FP gate (ET6) -----------------
# fleet-scan attributes a discovered host via the bundled corpus.py endpoint
# intelligence. This tier gates that attribution the same way the tokenizer tier
# gates the fingerprint: a benign host attributed to a PRC operator is a FALSE
# POSITIVE and turns the build red. Cases are the guardrail-5 adversarial inputs
# (suffix attacks, punycode, cloud tenant endpoints, aggregators, loopback) plus
# real PRC positives. Fully offline: attribution is a static dict lookup.
FLEET_CASES = [
    # --- PRC positives: must be attributed Chinese-origin -----------------
    {"host": "api.deepseek.com",                 "expect_flagged": True,  "note": "DeepSeek direct"},
    {"host": "api.moonshot.cn",                  "expect_flagged": True,  "note": "Moonshot direct"},
    {"host": "open.bigmodel.cn",                 "expect_flagged": True,  "note": "Zhipu GLM mainland"},
    {"host": "hunyuan.tencentcloudapi.com",      "expect_flagged": True,  "note": "Tencent Hunyuan (subdomain wins longest-match)"},
    {"host": "API.DeepSeek.COM.",                "expect_flagged": True,  "note": "PRC positive, uppercase + trailing dot (canonicalization)"},
    # --- must NOT be attributed CN (the false-positive gate) --------------
    {"host": "api.deepseek.com.evil.test",       "expect_flagged": False, "note": "suffix attack"},
    {"host": "deepseek.com.attacker.example",    "expect_flagged": False, "note": "suffix attack"},
    {"host": "api-deepseek-com.evil.test",       "expect_flagged": False, "note": "dash-not-dot lookalike"},
    {"host": "xn--80ak6aa92e.com",               "expect_flagged": False, "note": "punycode/IDNA homograph"},
    {"host": "notmoonshot.cn",                   "expect_flagged": False, "note": "lookalike, not a moonshot corpus host"},
    {"host": "myorg.openai.azure.com",           "expect_flagged": False, "note": "Azure cloud tenant (unattributed, not CN)"},
    {"host": "bedrock-runtime.us-east-1.amazonaws.com", "expect_flagged": False, "note": "AWS Bedrock cloud tenant (unattributed, not CN)"},
    {"host": "proj.us-central1-aiplatform.googleapis.com", "expect_flagged": False, "note": "GCP Vertex cloud tenant (unattributed, not CN)"},
    {"host": "api.openai.com",                   "expect_flagged": False, "note": "US first-party"},
    {"host": "api.anthropic.com",                "expect_flagged": False, "note": "US first-party"},
    {"host": "openrouter.ai",                    "expect_flagged": False, "note": "aggregator (unresolvable, not CN)"},
    {"host": "localhost",                        "expect_flagged": False, "note": "loopback gateway"},
    {"host": "example.com",                      "expect_flagged": False, "note": "unknown host"},
]


def fleet_flagged_cn(attribution) -> bool:
    """Fleet's adverse output: a host attributed to a PRC operator. A static
    corpus lookup returning a PRC/PRC-operator origin is the 'points at China'
    flag; anything else (US/EU, aggregator, unknown, None) is not."""
    return attribution is not None and str(attribution.origin).startswith("PRC")


# The eval pins the canonical probe corpus. A reference built with a different
# --variant-seed cannot be matched (compare() trusts only same-seed vectors),
# so a mismatch is a hard error, never a silent false negative.
EXPECTED_VARIANT_SEED = 0

# False-negative budget: CN families the harness is allowed to miss before the
# build goes red. Starts at 0 (all 3 CN vocab cases must be caught) and is
# ratcheted DOWN only — never up to paper over a regression.
MAX_FALSE_NEGATIVES = 0


def is_flagged_cn(score_output: dict, top_match: dict | None) -> bool:
    """The one definition of the adverse output: 'flagged Chinese-origin'.

    Requires BOTH an adverse provenance tier AND that the driving evidence is a
    CN-origin match. This is deliberately conservative — a high logodds from a
    non-CN source must never read as a Chinese-origin flag (guards the FP gate).
    """
    verdict = (score_output.get("provenance_risk") or {}).get("verdict")
    if verdict not in ("CONFIRMED", "LIKELY"):
        return False
    # If a tokenizer match drove the call, its origin must be CN.
    if top_match is not None:
        return top_match.get("origin") == CN
    # No tokenizer match (behavioral-only): trust the adverse provenance tier,
    # which here can only come from CN-tagged behavioral/deception signals.
    return True
