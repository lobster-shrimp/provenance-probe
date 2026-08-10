"""ET6: the fleet host-attribution tier is wired into the zero-FP eval gate."""
import pytest

from eval import run_eval
from eval.corpus import FLEET_CASES, fleet_flagged_cn
from eval.run_eval import Result, confusion, gate, run_fleet_cases
from provenance_probe.fleet.evidence import Attribution


@pytest.mark.unit
def test_fleet_tier_has_zero_false_positives():
    results = run_fleet_cases()
    m = confusion(results)
    assert m["FP"] == 0 and m["ERR"] == 0
    # every labeled case resolved to its expected cell
    assert all(r.cell in ("TP", "TN") for r in results)
    # both real PRC positives and benign negatives are represented
    assert m["TP"] >= 4 and m["TN"] >= 12
    assert gate(results, m, max_fn=0) == []          # tier passes the gate


@pytest.mark.unit
def test_fleet_gate_has_teeth():
    # A benign host attributed CN is a FALSE POSITIVE and MUST fail the gate.
    poison = [Result("benign.example (poison)", "fleet",
                     expect_flagged=False, got_flagged=True, verdict="PRC")]
    reasons = gate(poison, confusion(poison), max_fn=0)
    assert any("FALSE POSITIVE" in r for r in reasons)


@pytest.mark.unit
def test_fleet_flagged_cn_definition():
    assert fleet_flagged_cn(Attribution("DeepSeek", "PRC", 0.99)) is True
    assert fleet_flagged_cn(Attribution("Zhipu", "PRC-operator", 0.95)) is True
    assert fleet_flagged_cn(Attribution("OpenAI", "US", 0.9)) is False
    assert fleet_flagged_cn(None) is False


@pytest.mark.unit
def test_suffix_and_punycode_cases_are_present():
    # guard against silently dropping the adversarial inputs this tier exists for
    hosts = {c["host"] for c in FLEET_CASES}
    assert "api.deepseek.com.evil.test" in hosts          # suffix attack
    assert any(h.startswith("xn--") for h in hosts)       # punycode/IDNA
    assert "bedrock-runtime.us-east-1.amazonaws.com" in hosts  # cloud tenant


@pytest.mark.integration
def test_run_eval_fleet_only_exits_zero(capsys):
    rc = run_eval.main(["--fleet-only"])
    capsys.readouterr()
    assert rc == 0
