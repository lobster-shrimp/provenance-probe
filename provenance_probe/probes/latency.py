"""Layer 6b: latency/throughput profiling for silent-swap detection."""
from __future__ import annotations
import statistics, time


def profile(client, n=12, prompt="Write exactly one short sentence about rain.",
            max_tokens=64) -> dict:
    ttfts, totals, toks = [], [], []
    for _ in range(n):
        r = client.chat(prompt, max_tokens=max_tokens, temperature=0.0, stream=True)
        if r.ttft:
            ttfts.append(r.ttft)
        totals.append(r.total)
        toks.append(max(1, (r.raw or "").count("data:")))
        time.sleep(0.2)
    def st(v):
        if not v:
            return None
        return {"n": len(v), "mean": round(statistics.fmean(v), 4),
                "median": round(statistics.median(v), 4),
                "p10": round(sorted(v)[max(0, int(len(v) * .1) - 1)], 4),
                "p90": round(sorted(v)[min(len(v) - 1, int(len(v) * .9))], 4),
                "stdev": round(statistics.pstdev(v), 4)}
    itl = [t / k for t, k in zip(totals, toks) if k]
    return {"ttft": st(ttfts), "total": st(totals), "inter_token": st(itl)}


def drift(baseline: dict, current: dict, z: float = 3.0) -> dict:
    """Flag step-changes indicating a backend/model swap after award."""
    out = []
    for key in ("ttft", "total", "inter_token"):
        b, c = baseline.get(key), current.get(key)
        if not b or not c or not b.get("stdev"):
            continue
        delta = abs(c["median"] - b["median"])
        thresh = z * max(b["stdev"], 1e-6)
        if delta > thresh:
            out.append({"metric": key, "baseline_median": b["median"],
                        "current_median": c["median"],
                        "delta": round(delta, 4), "threshold": round(thresh, 4),
                        "severity": "high"})
    return {"drifted": bool(out), "signals": out}
