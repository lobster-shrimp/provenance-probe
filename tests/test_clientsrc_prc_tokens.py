"""Regression tests for the client-source PRC model-id matcher (#123).

The `client_prc_model_id` scan false-positived "uses a CN model" on legitimate
Western services because `PRC_MODEL_TOKENS` mapped bare `step-` -> StepFun and
`seed-` -> ByteDance Seed. `step-1`/`step-2` (UI wizards/CSS) and
`seed-123`/`seed=42` (random seeds) are ubiquitous in ordinary web/JS and were
being read as Chinese-origin model identifiers.

These tests pin the fix: the FP strings must NOT yield a `client_prc_model_id`,
real StepFun/Seed model ids MUST, and every pre-existing CN token still flags.
"""
from __future__ import annotations

from provenance_probe.probes.clientsrc import _scan_text


def _cn_model_families(text: str) -> list[str]:
    """Return the family labels of any client_prc_model_id findings for `text`.

    Each finding is embedded in a delimiter-bearing context so the matcher's
    leading `["'/\\s:=-]` boundary fires the way it would in real client source.
    """
    out = _scan_text(f'"{text}"', "test.js")
    return [f["detail"] for f in out if f["type"] == "client_prc_model_id"]


def _flags_cn(text: str) -> bool:
    return len(_cn_model_families(text)) > 0


# --- AC1: over-broad FP strings must NOT flag --------------------------------
FALSE_POSITIVES = [
    "step-1",
    "step-2",
    "step-3-of-5",
    'class=step-1',
    "step-by-step",
    "stepper",
    "seed-123",
    "seed=42",
    "seed-value",
    "seed-data",
    "seed-42-abc",
]


def test_ac1_wizard_and_seed_strings_do_not_flag():
    offenders = {s: _cn_model_families(s) for s in FALSE_POSITIVES if _flags_cn(s)}
    assert not offenders, f"false client_prc_model_id findings: {offenders}"


# --- AC2: real StepFun / ByteDance-Seed model ids MUST flag ------------------
REAL_IDS = [
    "step-1v-8k",
    "step-2-16k",
    "step-1x-medium",
    "step-r1-v-mini",
    "seed-oss",
    "seed-1.6",
    "seed-thinking",
    "seed-coder",
]


def test_ac2_real_stepfun_and_seed_ids_flag():
    missed = [s for s in REAL_IDS if not _flags_cn(s)]
    assert not missed, f"real CN model ids not detected: {missed}"


# --- AC3: every pre-existing CN token still flags ---------------------------
EXISTING_CN_IDS = [
    "qwen-max",
    "deepseek-v3",
    "glm-4.6",
    "kimi-k2",
    "moonshot-v1",
    "minimax-abab",
    "qwq-32b",
    "qvq-72b",
    "internlm2",
    "baichuan2",
    "ernie-4",
    "hunyuan",
    "doubao-pro",
    "minicpm",
    "yi-34b",
]


def test_ac3_existing_cn_tokens_still_flag():
    missed = [s for s in EXISTING_CN_IDS if not _flags_cn(s)]
    assert not missed, f"existing CN tokens regressed to no-detection: {missed}"


# --- AC1 regression: a stepper-heavy HTML blob yields zero CN findings -------
STEPPER_HTML = """
<div class="wizard">
  <ol class="stepper">
    <li class="step-1 active" data-step="step-1">Step 1 of 5</li>
    <li class="step-2" data-step="step-2">Step 2</li>
    <li class="step-3" data-step="step-3-of-5">Step 3</li>
    <li class="step-4 step-by-step">Step 4</li>
  </ol>
</div>
<script>
  const seed = 42;               // seed=42
  const rng = mulberry32("seed-123");
  const cfg = { "seed-value": 7, "seed-data": [1,2,3], id: "seed-42-abc" };
  function nextStep(step) { return "step-" + (step + 1); }
</script>
"""


def test_stepper_heavy_html_yields_zero_cn_findings():
    out = _scan_text(STEPPER_HTML, "wizard.html")
    cn = [f for f in out if f["type"] == "client_prc_model_id"]
    assert cn == [], f"stepper/seed HTML produced CN model findings: {cn}"


# --- self-verify: a gemini-like step-1 UI string does not attribute StepFun --
def test_gemini_like_step1_ui_string_no_stepfun():
    # Mirrors the live gemini.google.com FP: client JS contains a `step-1` UI
    # step counter, which must not be read as a StepFun (CN) model id.
    gemini_like = 'a.setAttribute("data-step","step-1");b.className="step-2";'
    out = _scan_text(gemini_like, "gemini_main.js")
    stepfun = [f for f in out
               if f["type"] == "client_prc_model_id" and "StepFun" in f["detail"]]
    assert stepfun == [], f"gemini-like step-1 string attributed StepFun: {stepfun}"
