"""Network-layer jurisdiction classification via the endpoint registries
(offline / registry-only — no DNS or RDAP needed)."""
from provenance_probe.probes import network


def _j(host):
    return network.analyze_host(host, do_rdap=False)["jurisdiction"]


def test_prc_endpoint_flagged():
    r = network.analyze_host("api.deepseek.com", do_rdap=False)
    assert r["jurisdiction"] == "PRC"
    assert "DeepSeek" in (r["operator"] or "")


def test_cn_tld_flagged():
    assert _j("api.moonshot.cn") == "PRC"


def test_aggregator_classified_non_prc_operator():
    r = network.analyze_host("openrouter.ai", do_rdap=False)
    assert r["jurisdiction"] == "non-PRC-operator"


def test_first_party_classified():
    for host, op in [("api.openai.com", "OpenAI"), ("api.anthropic.com", "Anthropic"),
                     ("generativelanguage.googleapis.com", "Google"),
                     ("api.mistral.ai", "Mistral"), ("api.x.ai", "xAI")]:
        r = network.analyze_host(host, do_rdap=False)
        assert r["jurisdiction"] == "non-PRC-firstparty", host
        assert op.split()[0] in (r["operator"] or ""), host


def test_truly_unknown_host():
    assert _j("api.some-unlisted-vendor.example") == "unknown"


def test_first_party_does_not_override_prc():
    # a CN host that also contains a first-party-ish substring must stay PRC
    assert _j("api.deepseek.com") == "PRC"
