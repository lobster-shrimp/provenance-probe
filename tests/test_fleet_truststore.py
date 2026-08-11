"""Trust-store watch (B-phase): fingerprinting, baseline diff, interception
escalation, and the authorization gate."""
import base64
import hashlib

import pytest

from provenance_probe.cli import main
from provenance_probe.fleet import truststore as T


def _pem(payload: bytes) -> str:
    """A PEM-framed blob. fingerprint_pem base64-decodes the body and sha256s it,
    so an arbitrary payload exercises the pipeline without a cryptography dep."""
    return ("-----BEGIN CERTIFICATE-----\n"
            + base64.b64encode(payload).decode() + "\n"
            "-----END CERTIFICATE-----\n")


# --- fingerprinting ---------------------------------------------------------- #

@pytest.mark.unit
def test_fingerprint_pem_matches_sha256_of_der():
    fp = T.fingerprint_pem(_pem(b"hello-cert"))
    assert fp == hashlib.sha256(b"hello-cert").hexdigest()
    assert T.fingerprint_pem("not a pem") is None

@pytest.mark.unit
def test_roots_from_pem_bundle_splits_and_fingerprints():
    bundle = _pem(b"cert-a") + _pem(b"cert-b")
    cas = T.roots_from_pem_bundle(bundle, source="test")
    assert [c.sha256 for c in cas] == [
        hashlib.sha256(b"cert-a").hexdigest(), hashlib.sha256(b"cert-b").hexdigest()]
    assert all(c.source == "test" for c in cas)


def _der_with_cn(cn: bytes) -> bytes:
    # commonName OID + UTF8String(len)(value) — the AttributeTypeAndValue value
    return T._CN_OID + bytes([0x0c, len(cn)]) + cn


@pytest.mark.unit
def test_cn_is_extracted_from_der_so_interception_fires_on_the_real_path():
    # the loaders emit label-less PEM; the CN must come from the DER itself
    pem = _pem(_der_with_cn(b"mitmproxy"))
    ca = T.roots_from_pem_bundle(pem, source="system-keychain")[0]
    assert ca.label == "mitmproxy"                       # extracted, not injected
    assert T.classify_root(ca, set()).classification == T.INTERCEPTION_TOOL


# --- baseline parsing -------------------------------------------------------- #

@pytest.mark.unit
def test_load_baseline_parses_and_ignores_noise():
    fp = "ab" * 32
    text = f"# a comment\n{fp}  # some label\n{fp.upper()}\nnot-a-fingerprint\n\n"
    base = T.load_baseline(text)
    assert base == {fp}                       # deduped, lowercased, non-hex dropped


# --- classification ---------------------------------------------------------- #

@pytest.mark.unit
def test_classify_baseline_vs_unbaselined():
    good = T.RootCA(label="Corp Root", sha256="aa" * 32)
    bad = T.RootCA(label="Unknown Root", sha256="bb" * 32)
    base = {"aa" * 32}
    assert T.classify_root(good, base).classification == T.BASELINE
    assert T.classify_root(bad, base).classification == T.UNBASELINED

@pytest.mark.unit
def test_interception_tool_escalates_even_if_baselined():
    # a mitmproxy root must be flagged even if its fingerprint sits in the baseline
    ca = T.RootCA(label="mitmproxy", sha256="cc" * 32)
    f = T.classify_root(ca, {"cc" * 32})
    assert f.classification == T.INTERCEPTION_TOOL

@pytest.mark.unit
def test_no_baseline_notes_the_gap():
    f = T.classify_root(T.RootCA(label="x", sha256="dd" * 32), set())
    assert f.classification == T.UNBASELINED
    assert any("no baseline" in n for n in f.notes)


# --- scan aggregation -------------------------------------------------------- #

@pytest.mark.unit
def test_scan_trust_store_counts_and_headline():
    roots = [
        T.RootCA("Corp", "aa" * 32),        # baselined
        T.RootCA("Rogue", "bb" * 32),       # unbaselined
        T.RootCA("Charles Proxy CA", "cc" * 32),  # interception
    ]
    res = T.scan_trust_store(lambda: roots, {"aa" * 32})
    assert res.total == 3 and res.baseline == 1
    assert res.unbaselined == 1 and res.interception == 1
    assert "3 roots" in res.headline and "1 baselined" in res.headline


# --- no egress --------------------------------------------------------------- #

@pytest.mark.unit
def test_truststore_makes_no_network_import():
    assert not hasattr(T, "requests")


# --- CLI authorization gate + interception exit code ------------------------- #

@pytest.mark.unit
def test_cli_trust_store_requires_authorization(capsys):
    assert main(["fleet-scan", "--trust-store"]) == 1
    assert "i-am-authorized" in capsys.readouterr().err

@pytest.mark.unit
def test_cli_print_ca_baseline_requires_authorization(capsys):
    assert main(["fleet-scan", "--print", "ca-baseline"]) == 1
    assert "i-am-authorized" in capsys.readouterr().err

@pytest.mark.integration
def test_cli_trust_store_flags_interception(monkeypatch, capsys):
    import json
    monkeypatch.setattr(T, "default_load_certs",
                        lambda: [T.RootCA("mitmproxy", "ee" * 32, "test")])
    rc = main(["fleet-scan", "--trust-store", "--i-am-authorized", "--json", "--exit-code"])
    assert rc == 2                                    # drift present -> exit 2
    out = json.loads(capsys.readouterr().out)
    assert out["interception"] == 1
    assert out["findings"][0]["classification"] == T.INTERCEPTION_TOOL


# --- unreadable/unsupported host must REFUSE, never report clean -------------- #

@pytest.mark.unit
def test_default_load_certs_refuses_unsupported_platform(monkeypatch):
    import platform
    monkeypatch.setattr(platform, "system", lambda: "Windows")
    with pytest.raises(T.TrustStoreUnavailable):
        T.default_load_certs()

@pytest.mark.unit
def test_default_load_certs_refuses_when_security_errors(monkeypatch):
    # macOS `security` returning a non-zero exit is a read failure, not an empty
    # store — must refuse, not report clean.
    import platform
    import subprocess

    class _R:
        returncode = 1
        stdout = ""

    monkeypatch.setattr(platform, "system", lambda: "Darwin")
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())
    with pytest.raises(T.TrustStoreUnavailable):
        T.default_load_certs()

@pytest.mark.integration
def test_cli_trust_store_unavailable_returns_nonzero_not_clean(monkeypatch, capsys):
    def _raise():
        raise T.TrustStoreUnavailable("not implemented on Windows")
    monkeypatch.setattr(T, "default_load_certs", _raise)
    rc = main(["fleet-scan", "--trust-store", "--i-am-authorized", "--exit-code"])
    assert rc == 3                                    # NOT 0 — host not certified clean
    assert "not certified clean" in capsys.readouterr().err
