"""Catalog: the models.dev x corpus.py join, the flattened running table, search.

The join is asserted against the bundled corpus.py hosts (api.deepseek.com -> PRC,
api.openai.com -> US first-party, openrouter.ai -> aggregator) so a corpus change
that would silently drop an attribution is caught here.
"""
import json

import pytest

from provenance_probe import catalog

pytestmark = pytest.mark.unit


# A tiny models.dev-shaped fixture: one PRC provider, one US first-party, one
# aggregator, one host absent from corpus.py.
MODELS_DEV = {
    "deepseek": {
        "id": "deepseek", "name": "DeepSeek", "api": "https://api.deepseek.com/v1",
        "env": ["DEEPSEEK_API_KEY"], "doc": "https://api-docs.deepseek.com",
        "models": {
            "deepseek-chat": {
                "id": "deepseek-chat", "name": "DeepSeek V3", "family": "deepseek",
                "open_weights": True, "reasoning": False, "tool_call": True,
                "modalities": {"input": ["text"], "output": ["text"]},
                "limit": {"context": 128000, "output": 8192},
                "cost": {"input": 0.27, "output": 1.1}, "release_date": "2026-01-01",
            },
        },
    },
    "openai": {
        "id": "openai", "name": "OpenAI", "api": "https://api.openai.com/v1",
        "env": ["OPENAI_API_KEY"], "doc": "https://platform.openai.com/docs",
        "models": {
            "gpt-5": {
                "id": "gpt-5", "name": "GPT-5", "family": "gpt",
                "open_weights": False, "reasoning": True, "tool_call": True,
                "modalities": {"input": ["text", "image"], "output": ["text"]},
                "limit": {"context": 400000, "output": 128000},
                "cost": {"input": 1.25, "output": 10},
            },
        },
    },
    "openrouter": {
        "id": "openrouter", "name": "OpenRouter", "api": "https://openrouter.ai/api/v1",
        "models": {"auto": {"id": "auto", "name": "Auto Router"}},
    },
    "mystery": {
        "id": "mystery", "name": "Mystery Co", "api": "https://api.unknown-vendor.example/v1",
        "models": {"m1": {"id": "m1", "name": "M1"}},
    },
}


def _cat():
    return catalog.build_catalog(MODELS_DEV)


def test_build_joins_provenance_from_corpus():
    by_id = {p["provider_id"]: p for p in _cat()["providers"]}
    assert by_id["deepseek"]["provenance"]["kind"] == "prc"
    assert by_id["deepseek"]["provenance"]["jurisdiction"] == "PRC"
    assert by_id["deepseek"]["provenance"]["measured"] is False        # never a measured verdict
    assert by_id["openai"]["provenance"]["kind"] == "first-party"
    assert by_id["openai"]["provenance"]["jurisdiction"] == "US"
    assert by_id["openrouter"]["provenance"]["kind"] == "aggregator"
    assert by_id["openrouter"]["provenance"]["jurisdiction"] == "unresolved"
    assert by_id["mystery"]["provenance"] is None                      # not in corpus -> no pointer


def test_counts_and_determinism():
    c1, c2 = _cat(), _cat()
    assert c1["provider_count"] == 4 and c1["model_count"] == 4
    assert json.dumps(c1, sort_keys=True) == json.dumps(c2, sort_keys=True)   # deterministic
    # providers are sorted by id
    assert [p["provider_id"] for p in c1["providers"]] == ["deepseek", "mystery", "openai", "openrouter"]


def test_model_card_fields_carried():
    ds = [p for p in _cat()["providers"] if p["provider_id"] == "deepseek"][0]
    m = ds["models"][0]
    assert m["context"] == 128000 and m["max_output"] == 8192
    assert m["cost_input"] == 0.27 and m["cost_output"] == 1.1
    assert m["open_weights"] is True and m["modalities_in"] == ["text"]


def test_flatten_one_row_per_model():
    rows = catalog.flatten(_cat())
    assert len(rows) == 4                                              # 4 models total
    ds = [r for r in rows if r["provider_id"] == "deepseek"][0]
    assert ds["api_url"] == "https://api.deepseek.com/v1"
    assert ds["model_id"] == "deepseek-chat" and ds["cn_flagged"] is True
    assert ds["context"] == 128000


def test_search_free_text():
    rows = catalog.search(_cat(), query="deepseek")
    assert len(rows) == 1 and rows[0]["provider_id"] == "deepseek"
    # matches on api host too
    assert catalog.search(_cat(), query="openrouter.ai")[0]["provider_id"] == "openrouter"


def test_search_cn_only_and_jurisdiction():
    cn = catalog.search(_cat(), cn_only=True)
    assert [r["provider_id"] for r in cn] == ["deepseek"]
    us = catalog.search(_cat(), jurisdiction="US")
    assert [r["provider_id"] for r in us] == ["openai"]
    # 'CN' alias hits any Chinese-origin label
    assert catalog.search(_cat(), jurisdiction="CN")[0]["provider_id"] == "deepseek"


def test_search_kind_and_open_weights():
    assert [r["provider_id"] for r in catalog.search(_cat(), kind="aggregator")] == ["openrouter"]
    ow = catalog.search(_cat(), open_weights=True)
    assert [r["provider_id"] for r in ow] == ["deepseek"]
    closed = catalog.search(_cat(), open_weights=False)
    assert [r["provider_id"] for r in closed] == ["openai"]


def test_search_modality():
    img = catalog.search(_cat(), modality="image")
    assert [r["provider_id"] for r in img] == ["openai"]


def test_is_cn_origin():
    assert catalog.is_cn_origin("PRC") and catalog.is_cn_origin("PRC-operator")
    assert catalog.is_cn_origin("CN") and not catalog.is_cn_origin("US")


def test_load_path_rejects_non_catalog(tmp_path):
    p = tmp_path / "x.json"
    p.write_text('{"nope": 1}')
    assert catalog.load_path(str(p)) is None
    p.write_text('not json')
    assert catalog.load_path(str(p)) is None


# --- CLI + serve integration ------------------------------------------------- #

def test_cli_build_catalog_then_search(tmp_path, capsys):
    """build-catalog --input (offline) writes a catalog; catalog --file --cn searches it."""
    from provenance_probe.cli import main
    src = tmp_path / "src.json"
    src.write_text(json.dumps(MODELS_DEV))
    out = tmp_path / "cat.json"
    assert main(["build-catalog", "--input", str(src), "--out", str(out)]) == 0
    assert out.exists() and catalog.load_path(str(out)) is not None
    capsys.readouterr()                                       # clear
    assert main(["catalog", "--file", str(out), "--cn"]) == 0
    printed = capsys.readouterr().out
    assert "deepseek" in printed.lower() and "PRC" in printed
    assert "openai" not in printed.lower()                   # --cn excludes the US provider


def test_cli_catalog_missing_snapshot(tmp_path, capsys):
    from provenance_probe.cli import main
    missing = tmp_path / "nope.json"
    assert main(["catalog", "--file", str(missing)]) == 2    # honest failure, not a crash


def test_serve_catalog_page_escapes_external_data(monkeypatch):
    """models.dev is external/untrusted data — the /catalog page must escape it, not
    render provider/model strings as live HTML."""
    from provenance_probe import serve
    evil = {"x": {"id": "x", "name": "<script>alert(1)</script>",
                  "api": "https://api.deepseek.com/v1",       # so it flags CN and renders
                  "models": {"m": {"id": "<img src=x onerror=alert(1)>", "name": "m"}}}}
    monkeypatch.setitem(serve._CATALOG_CACHE, "doc", catalog.build_catalog(evil))
    page = serve.app.test_client().get("/catalog").get_data(as_text=True)
    assert "<script>alert(1)</script>" not in page            # not a live sink
    assert "&lt;script&gt;alert(1)&lt;/script&gt;" in page    # escaped instead
    assert "<img src=x onerror=alert(1)>" not in page
    serve._CATALOG_CACHE.clear()
