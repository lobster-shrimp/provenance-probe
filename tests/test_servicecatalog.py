"""Service catalog: the SERVICE/provider map (AI apps/websites/services), sibling
to the model catalog. It composes LOCAL data only (corpus PRC/AGGREGATOR endpoints
+ known clientsrc findings + a curated consumer-app list) into the LOCKED SCHEMA
(#131). Asserted here against the bundled corpus so a corpus change that would drop
an attribution is caught, and against the invariants: measured=false on every row,
deterministic/byte-identical output, and no egress in the generator.
"""
import json

import pytest

from provenance_probe import servicecatalog as sc
from provenance_probe.data import corpus

pytestmark = pytest.mark.unit

_REQUIRED = {"name", "url", "host", "kind", "operator", "jurisdiction",
             "fronts", "evidence", "source", "confidence", "measured"}
_JUR_ENUM = {"PRC", "PRC-operator", "first-party", "aggregator", "unresolved"}
_KIND_ENUM = {"web-app", "api-service", "aggregator"}
_SRC_ENUM = {"corpus", "clientsrc", "curated"}


def _doc():
    return sc.build_service_catalog()


def _by_host(doc):
    return {s["host"]: s for s in doc["services"]}


# --- schema validity + measured invariant + count consistency ---------------- #

def test_schema_valid_and_measured_false_everywhere():
    doc = _doc()
    assert set(doc) >= {"catalog_version", "generated_from", "corpus_version",
                        "service_count", "services"}
    assert doc["service_count"] == len(doc["services"])
    assert doc["corpus_version"] == corpus.CORPUS_VERSION
    for s in doc["services"]:
        assert _REQUIRED <= set(s), f"missing fields on {s.get('host')}"
        assert s["measured"] is False                    # INVARIANT: static pointer, never measured
        assert s["jurisdiction"] in _JUR_ENUM
        assert s["kind"] in _KIND_ENUM
        assert s["source"] in _SRC_ENUM
        assert isinstance(s["fronts"], list)
        assert s["confidence"] is None or 0.0 <= s["confidence"] <= 1.0


def test_service_count_consistency_and_no_duplicate_hosts():
    doc = _doc()
    hosts = [s["host"] for s in doc["services"]]
    assert len(hosts) == len(set(hosts))                 # dedup by host: no duplicates
    assert doc["service_count"] == len(hosts)


# --- corpus coverage + dedup-merges-fronts ----------------------------------- #

def test_every_prc_endpoint_host_present_with_corpus_jurisdiction():
    by = _by_host(_doc())
    for host, (op, jur, conf) in corpus.PRC_ENDPOINTS.items():
        assert host in by, f"PRC host {host} missing from service catalog"
        row = by[host]
        # corpus jurisdiction is preserved for real PRC labels; "unknown" -> unresolved
        if jur in ("PRC", "PRC-operator"):
            assert row["jurisdiction"] == jur
        else:
            assert row["jurisdiction"] == "unresolved"


def test_every_aggregator_host_present_as_aggregator():
    by = _by_host(_doc())
    for host, op in corpus.AGGREGATOR_ENDPOINTS.items():
        assert host in by, f"aggregator host {host} missing"
        assert by[host]["jurisdiction"] == "aggregator"
        assert by[host]["kind"] == "aggregator"
        assert by[host]["operator"] == op


def test_dedup_by_host_merges_fronts():
    """z.ai is in corpus (PRC-operator, 0.90) AND has a known clientsrc finding
    (fronts GLM). It must appear ONCE, corpus attribution preserved, fronts merged."""
    by = _by_host(_doc())
    assert "z.ai" in by
    row = by["z.ai"]
    assert row["jurisdiction"] == "PRC-operator"          # corpus wins (authoritative)
    assert row["confidence"] == 0.90                       # corpus confidence preserved
    assert any("GLM" in f for f in row["fronts"])          # clientsrc fronts merged in
    assert "clientsrc" in row["evidence"].lower()          # clientsrc scan noted in evidence


# --- curated rows: spot-check a PRC app, a US app, an aggregator -------------- #

def test_curated_us_first_party_app():
    by = _by_host(_doc())
    assert "chatgpt.com" in by
    row = by["chatgpt.com"]
    assert row["operator"].startswith("OpenAI")
    assert row["jurisdiction"] == "first-party"
    assert row["source"] == "curated"


def test_curated_prc_app():
    by = _by_host(_doc())
    assert "chat.deepseek.com" in by
    row = by["chat.deepseek.com"]
    assert row["jurisdiction"] == "PRC"
    assert row["operator"].startswith("DeepSeek")
    assert row["source"] == "curated"


def test_curated_aggregator_app():
    by = _by_host(_doc())
    assert "perplexity.ai" in by
    row = by["perplexity.ai"]
    assert row["jurisdiction"] == "aggregator"
    assert row["source"] == "curated"


def test_curated_covers_the_major_apps():
    by = _by_host(_doc())
    # US first-party
    for h in ("chatgpt.com", "gemini.google.com", "claude.ai"):
        assert by[h]["jurisdiction"] == "first-party"
    # PRC consumer apps
    for h in ("chat.deepseek.com", "doubao.com"):
        assert by[h]["jurisdiction"] == "PRC"
    # a known clientsrc finding on a non-corpus host
    assert "replit.com" in by
    assert by["replit.com"]["source"] == "clientsrc"
    assert by["replit.com"]["fronts"]                      # references CN backends


# --- determinism + stable ordering + no-egress guard ------------------------- #

def test_deterministic_byte_identical():
    a = json.dumps(sc.build_service_catalog(), sort_keys=False, indent=2)
    b = json.dumps(sc.build_service_catalog(), sort_keys=False, indent=2)
    assert a == b


def test_stable_ordering_jurisdiction_then_name():
    svcs = _doc()["services"]
    keys = [(s["jurisdiction"], s["name"], s["host"]) for s in svcs]
    assert keys == sorted(keys)


def test_no_egress_in_generator_source():
    """Structural guard: the generator composes LOCAL data only. Its source must
    not import a network stack or contact a service."""
    import inspect
    src = inspect.getsource(sc)
    for forbidden in ("import requests", "import socket", "urllib.request",
                      "http.client", "urlopen", "requests.get", "session.get",
                      "session.post"):
        assert forbidden not in src, f"generator references network primitive: {forbidden}"


def test_no_egress_module_has_no_fetch():
    # unlike catalog.py (which has fetch_models_dev), the service catalog has NO
    # fetch/egress entry point at all.
    assert not hasattr(sc, "fetch")
    assert not any(n for n in dir(sc) if "fetch" in n.lower())


# --- CLI --------------------------------------------------------------------- #

def test_cli_build_service_catalog_out(tmp_path):
    from provenance_probe.cli import main
    out = tmp_path / "svc.json"
    assert main(["build-service-catalog", "--out", str(out)]) == 0
    doc = json.loads(out.read_text())
    assert doc["service_count"] == len(doc["services"])
    assert all(s["measured"] is False for s in doc["services"])


def test_cli_build_service_catalog_json_stdout(capsys):
    from provenance_probe.cli import main
    assert main(["build-service-catalog", "--json"]) == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert "services" in doc and doc["service_count"] == len(doc["services"])


def test_cli_print_sample(capsys):
    from provenance_probe.cli import main
    assert main(["build-service-catalog", "--print", "service-catalog-sample"]) == 0
    out = capsys.readouterr().out
    doc = json.loads(out)
    assert "services" in doc
