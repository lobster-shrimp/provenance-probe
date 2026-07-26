"""Re-capture one platform's agent record for the observatory (all callable models).

Usage: python scripts/recapture_agent.py <platform> <date>
Probes each model's tokenizer battery, aggregates worst-step, writes a signed-ready
verdict.json under the observatory data/agents/ tree. Authorized self-probes only.
"""
import json
import os
import sys

from provenance_probe.config import Target
from provenance_probe.client import Client
from provenance_probe.probes import tokenizer
from provenance_probe import agent

OBS = os.environ.get("OBSERVATORY_DIR", os.path.expanduser("~/CODE/provenance-observatory"))

PLATFORMS = {
    "anthropic": dict(
        base_url="https://api.anthropic.com", host="api.anthropic.com",
        api_style="anthropic", env="ANTHROPIC_API_KEY",
        models=["claude-opus-4-8", "claude-sonnet-5", "claude-opus-4-7"],
    ),
    "gemini": dict(
        base_url="https://generativelanguage.googleapis.com/v1beta/openai",
        host="generativelanguage.googleapis.com", api_style="openai",
        env="GEMINI_API_KEY",
        models=["gemini-flash-latest", "gemini-flash-lite-latest"],
    ),
}


def main(name: str, date: str) -> None:
    cfg = PLATFORMS[name]
    ref = tokenizer.load_reference()
    steps, overrides = [], {}
    for i, model in enumerate(cfg["models"]):
        target = Target(
            name=f"{name}-{model}", base_url=cfg["base_url"], model=model,
            api_style=cfg["api_style"], auth_value_env=cfg["env"], authorized=True,
        )
        try:
            vec = tokenizer.measure(Client(target))
            if vec.get("usable"):
                overrides[i] = {"tokenizer": vec, "tokenizer_match": tokenizer.compare(vec, ref)}
                print(f"  {model}: usable ({len(vec.get('vector', []))} vectors)")
            else:
                print(f"  {model}: tokenizer not usable")
        except Exception as exc:  # noqa: BLE001 - surface probe failures, keep going
            print(f"  {model}: ERROR {str(exc)[:80]}")
        steps.append({"name": model, "model": model, "backend_url": cfg["base_url"]})

    out = agent.analyze(agent.parse_trace({"steps": steps}), step_overrides=overrides)
    verdict = out["verdict"]
    record = {
        "schema_version": "0.1.0", "kind": "agent", "captured_at": f"{date}T00:00:00Z",
        "public": True, "target": f"platform-{name}", "endpoint": cfg["host"],
        "observation": ["active-probe"], "engine": "provenance-probe==0.9.1", "authorized": True,
        "note": f"All {len(cfg['models'])} callable chat models probed; tokenizer MEASURED.",
        "verdict": verdict,
        "steps": [{k: v for k, v in s.items() if k != "score"} for s in out["steps"]],
    }
    out_dir = f"{OBS}/data/agents/platform-{name}/{date}"
    os.makedirs(out_dir, exist_ok=True)
    with open(f"{out_dir}/verdict.json", "w") as fh:
        json.dump(record, fh, indent=2, sort_keys=True)
    print(f"=> platform-{name}: {verdict['label']} "
          f"(prov {verdict['provenance_verdict']} / juris {verdict['jurisdiction_verdict']})")


if __name__ == "__main__":
    main(sys.argv[1], sys.argv[2])
