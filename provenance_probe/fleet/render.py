"""Render a fleet ScanResult as a private report (console + JSON).

Redaction (guardrail 4): a fleet report is "private" only in that it is never
published to the public observatory. Once it rolls up via osquery/Tanium/Intune it
enters the org's SIEM, so by default we redact operator PII — absolute home paths
collapse to `~/…` so a username never leaks. The DRIFT host (e.g. api.deepseek.com)
is the finding and is kept. `--no-redact` keeps full local detail for on-box use.
"""
from __future__ import annotations

import re

from .evidence import (
    OFF_ALLOWLIST_ATTRIBUTED,
    SANCTIONED,
    Finding,
    ScanResult,
)

# Collapse an absolute home path to ~/ so a username never leaks into a SIEM.
_HOME_PATH_RE = re.compile(r"^(/Users/[^/]+|/home/[^/]+|/root)(?=/|$)")


def _redact_source(source: str) -> str:
    return _HOME_PATH_RE.sub("~", source or "")


def _finding_json(f: Finding, redact: bool) -> dict:
    d = {
        "source": _redact_source(f.source) if redact else f.source,
        "base_url": f.base_url,
        "host": f.host,
        "evidence_tier": f.evidence_tier,
        "classification": f.classification,
        "via_gateway": f.via_gateway,
        "notes": f.notes,
    }
    if f.attribution is not None:
        d["attribution"] = {
            "operator": f.attribution.operator,
            "origin": f.attribution.origin,
            "confidence": f.attribution.confidence,
            "source": f.attribution.source,
            "measured": f.attribution.measured,   # always False — sub-CONFIRMED pointer
        }
    return d


def to_json(result: ScanResult, redact: bool = True) -> dict:
    return {
        "headline": result.headline,
        "sanctioned": result.sanctioned,
        "drifted": result.drifted,
        "unresolved": result.unresolved,
        "redacted": redact,
        "findings": [_finding_json(f, redact) for f in result.findings],
    }


def _attr_line(f: Finding) -> str:
    if f.attribution is None:
        return ""
    a = f.attribution
    return (f"      → {a.operator} ({a.origin}), confidence {a.confidence:.2f} "
            f"[static pointer, NOT a measured provenance verdict]")


def render_console(result: ScanResult, redact: bool = True) -> str:
    lines: list[str] = [result.headline, ""]
    if not result.findings:
        lines.append("  no agent-CLI base_url configuration found.")
        return "\n".join(lines)
    for f in result.findings:
        marker = "OK  " if f.classification == SANCTIONED else "FLAG"
        via = f" via {f.via_gateway}" if f.via_gateway else ""
        src = _redact_source(f.source) if redact else f.source
        lines.append(f"  [{marker}] {f.host or '(unparsed)'}{via}  "
                     f"({f.classification}, evidence: {f.evidence_tier})")
        lines.append(f"      source: {src}  base_url: {f.base_url}")
        if f.classification == OFF_ALLOWLIST_ATTRIBUTED:
            lines.append(_attr_line(f))
        for n in f.notes:
            lines.append(f"      note: {n}")
    return "\n".join(lines)
