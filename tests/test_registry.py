"""Provider-attribution registry generator (from corpus.py) + drift verification."""
import json

import pytest

from provenance_probe import registry
from provenance_probe.cli import main
from provenance_probe.data import corpus


def _hostname_count(d) -> int:
    return sum(1 for k in d if "." in k)


@pytest.mark.unit
def test_build_registry_is_deterministic():
    assert registry.build_registry() == registry.build_registry()   # byte-stable
    entries = registry.build_registry()["entries"]
    assert entries == sorted(entries, key=lambda e: (e["domain"], e["kind"]))


@pytest.mark.unit
def test_registry_covers_hostname_entries_and_excludes_bare_tokens():
    doc = registry.build_registry()
    expected = (_hostname_count(corpus.PRC_ENDPOINTS)
                + _hostname_count(corpus.AGGREGATOR_ENDPOINTS)
                + _hostname_count(corpus.FIRST_PARTY_ENDPOINTS))
    assert doc["entry_count"] == expected == len(doc["entries"])
    # the substring-only bare tokens are excluded, not emitted as hostnames
    assert doc["excluded_nonhostname"] == ["bedrock-runtime", "openai-proxy"]
    domains = {e["domain"] for e in doc["entries"]}
    assert "openai-proxy" not in domains and "bedrock-runtime" not in domains
    assert doc["corpus_version"] == corpus.CORPUS_VERSION


@pytest.mark.unit
def test_entry_shapes_per_kind():
    by = {e["domain"]: e for e in registry.build_registry()["entries"]}
    prc = by["api.deepseek.com"]
    assert prc["kind"] == "prc" and prc["jurisdiction"] == "PRC" and prc["confidence"] == 0.99
    agg = by["openrouter.ai"]
    assert agg["kind"] == "aggregator" and agg["jurisdiction"] == "unresolved" and agg["confidence"] is None
    fp = by["api.openai.com"]
    assert fp["kind"] == "first-party" and fp["jurisdiction"] == "US" and fp["confidence"] == 0.9


@pytest.mark.unit
def test_verify_registry_passes_fresh_and_catches_drift():
    doc = registry.build_registry()
    assert registry.verify_registry(doc) == []                 # fresh matches corpus
    stale = json.loads(json.dumps(doc))
    stale["entries"][0]["operating_entity"] = "Tampered"
    assert registry.verify_registry(stale)                     # mutation detected
    wrongver = json.loads(json.dumps(doc))
    wrongver["corpus_version"] = "1999.01.1"
    assert any("corpus_version" in p for p in registry.verify_registry(wrongver))


@pytest.mark.unit
def test_verify_registry_catches_tampered_honesty_and_match_fields():
    # until the observatory signs it, verify_registry IS the integrity gate — a
    # tampered honesty note or a match field flipped to the suffix-attack-enabling
    # "substring" must be caught, not just entry drift.
    doc = registry.build_registry()
    for field, value in (("note", "MEASURED VERDICT: this domain IS a Chinese model"),
                         ("match", "substring"),
                         ("entry_count", 9999),
                         ("registry_version", "999"),
                         ("excluded_nonhostname", [])):
        tampered = json.loads(json.dumps(doc))
        tampered[field] = value
        assert registry.verify_registry(tampered), f"tampered {field} not caught"
    # an injected extra field is caught too
    extra = json.loads(json.dumps(doc))
    extra["backdoor"] = True
    assert any("backdoor" in p for p in registry.verify_registry(extra))


# --- CLI --------------------------------------------------------------------- #

@pytest.mark.integration
def test_cli_build_then_verify_roundtrip(tmp_path, capsys):
    out = tmp_path / "registry.json"
    assert main(["build-registry", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert doc["entry_count"] > 0 and doc["registry_version"] == registry.REGISTRY_VERSION
    capsys.readouterr()
    assert main(["verify-registry", str(out)]) == 0            # matches corpus

@pytest.mark.integration
def test_cli_verify_registry_flags_drift(tmp_path, capsys):
    out = tmp_path / "registry.json"
    main(["build-registry", "--out", str(out)])
    doc = json.loads(out.read_text())
    doc["entries"].pop()                                       # drop an entry -> drift
    out.write_text(json.dumps(doc))
    assert main(["verify-registry", str(out)]) == 1
    assert "FAILED" in capsys.readouterr().err
