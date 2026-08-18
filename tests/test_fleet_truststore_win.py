"""Windows trust-store loader: the base64-DER -> PEM bridge and the
`default_load_certs` Windows branch.

The load-bearing property is *cross-platform fingerprint identity*: the Windows
path (base64 DER from PowerShell) must produce the SAME SHA-256 as the macOS/Linux
PEM path for the same certificate, so a golden baseline captured on one OS diffs
correctly against hosts on another.
"""
from __future__ import annotations

import base64
import hashlib

import pytest

from provenance_probe.fleet import truststore as T

# A real, minimal self-signed cert's DER, base64-encoded. Generated locally with:
#   openssl req -x509 -newkey rsa:1024 -nodes -days 1 \
#       -subj "/CN=provenance-test-root" -keyout k.pem -out c.pem
#   openssl x509 -in c.pem -outform DER -out c.der   # then base64 c.der
# No cryptography runtime dep is added; this is a static test fixture. This is
# exactly the shape PowerShell emits: [Convert]::ToBase64String($cert.RawData).
_CERT_DER_B64 = (
    "MIICGjCCAYOgAwIBAgIUCKI8DWm6ZSLpsd4jkennUTt7M9AwDQYJKoZIhvcNAQELBQAwHzEd"
    "MBsGA1UEAwwUcHJvdmVuYW5jZS10ZXN0LXJvb3QwHhcNMjYwODE4MjEwNTMxWhcNMjYwODE5"
    "MjEwNTMxWjAfMR0wGwYDVQQDDBRwcm92ZW5hbmNlLXRlc3Qtcm9vdDCBnzANBgkqhkiG9w0B"
    "AQEFAAOBjQAwgYkCgYEAoZk6LmQc2xk2RleYM0SvkNZd1HMT04lMFi4TySLrKiKxrVYMc7US"
    "Js5aQF6V2V5bCuwRdJN0CREr1AGLFnRLGkCgSrTCnI9iZNONaFk4dba12v4yz6ZBE/OAfZ3q"
    "D6JsvMQSaj2gl3oz7Gujz63Xisgb/ybsvdmMHAmgkiiEZcECAwEAAaNTMFEwHQYDVR0OBBYE"
    "FHo+By/E9GKUq4xkN/hfJf98f5QiMB8GA1UdIwQYMBaAFHo+By/E9GKUq4xkN/hfJf98f5Qi"
    "MA8GA1UdEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADgYEAhK/kSRMlRF71Efe86hXqNKYq"
    "Q3vHK+2HWAIC2xPIhSRTh5sbh2itMynhY2d+AhoojjLWAu/yAFeDgC9hb/rVZQnhE7QrP1TW"
    "H5FoxszD9+TKZoF1IyNEBGKHuLEbmFcLLESEUEVc+gFSYJEiQ1lxM7BrxeKmTAxs8dY1F9xQ"
    "buM="
)
_CERT_DER = base64.b64decode(_CERT_DER_B64)
_CERT_SHA256 = hashlib.sha256(_CERT_DER).hexdigest()


# --- round-trip identity (the load-bearing test) ----------------------------- #

@pytest.mark.unit
def test_pem_from_der_b64_matches_the_pem_path_fingerprint():
    """A base64 DER line must fingerprint IDENTICALLY to the same cert as PEM —
    same DER bytes -> same SHA-256 -> cross-platform-comparable baselines."""
    cas = T.pem_from_der_b64_lines(_CERT_DER_B64, "windows-localmachine-root")
    assert len(cas) == 1
    assert cas[0].sha256 == _CERT_SHA256
    assert cas[0].sha256 == hashlib.sha256(_CERT_DER).hexdigest()
    assert cas[0].source == "windows-localmachine-root"
    # CN was extracted from the DER itself (label-less input), same as the PEM path
    assert cas[0].label == "provenance-test-root"


@pytest.mark.unit
def test_pem_from_der_b64_equals_roots_from_pem_bundle():
    """The Windows bridge and the macOS/Linux PEM parser must agree byte-for-byte."""
    pem = ("-----BEGIN CERTIFICATE-----\n"
           + base64.b64encode(_CERT_DER).decode() + "\n"
           "-----END CERTIFICATE-----\n")
    via_pem = T.roots_from_pem_bundle(pem, "src")
    via_b64 = T.pem_from_der_b64_lines(_CERT_DER_B64, "src")
    assert [c.sha256 for c in via_pem] == [c.sha256 for c in via_b64]


# --- multi-line / blank / garbage robustness --------------------------------- #

@pytest.mark.unit
def test_multiple_lines_become_multiple_roots_blanks_ignored():
    a = base64.b64encode(b"cert-a").decode()
    b = base64.b64encode(b"cert-b").decode()
    text = f"{a}\n\n   \n{b}\n"
    cas = T.pem_from_der_b64_lines(text, "src")
    assert [c.sha256 for c in cas] == [
        hashlib.sha256(b"cert-a").hexdigest(),
        hashlib.sha256(b"cert-b").hexdigest(),
    ]


@pytest.mark.unit
def test_garbage_line_is_skipped_not_raised():
    a = base64.b64encode(b"cert-a").decode()
    b = base64.b64encode(b"cert-b").decode()
    # "hello" is 5 chars -> not a multiple of 4 -> b64decode raises -> der None ->
    # the bundle parser skips it. The valid certs on either side still parse.
    cas = T.pem_from_der_b64_lines(f"{a}\nhello\n{b}", "src")
    assert [c.sha256 for c in cas] == [
        hashlib.sha256(b"cert-a").hexdigest(),
        hashlib.sha256(b"cert-b").hexdigest(),
    ]


@pytest.mark.unit
def test_empty_input_returns_empty_list():
    assert T.pem_from_der_b64_lines("", "src") == []
    assert T.pem_from_der_b64_lines("   \n\n  \n", "src") == []


@pytest.mark.unit
def test_long_single_line_is_rewrapped_and_still_parses():
    # PowerShell emits one long unwrapped base64 string per cert; it must be
    # re-wrapped into a well-formed PEM and still fingerprint correctly.
    assert "\n" not in _CERT_DER_B64  # precondition: genuinely one long line
    cas = T.pem_from_der_b64_lines(_CERT_DER_B64, "src")
    assert len(cas) == 1 and cas[0].sha256 == _CERT_SHA256


# --- default_load_certs Windows branch --------------------------------------- #

class _Result:
    def __init__(self, returncode: int, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout


@pytest.mark.unit
def test_windows_branch_returns_certs_on_success(monkeypatch):
    import platform
    import subprocess

    monkeypatch.setattr(platform, "system", lambda: "Windows")

    calls: list[str] = []

    def _run(cmd, *a, **k):
        # cmd is [powershell, -NoProfile, -NonInteractive, -Command, <script>]
        script = cmd[-1]
        calls.append(script)
        if "LocalMachine" in script:
            return _Result(0, _CERT_DER_B64 + "\n")
        return _Result(0, "")  # CurrentUser: empty but ran ok

    monkeypatch.setattr(subprocess, "run", _run)
    cas = T.default_load_certs()
    assert [c.sha256 for c in cas] == [_CERT_SHA256]
    # both stores are queried; commands target the Root store
    assert any("LocalMachine" in c and "\\Root" in c for c in calls)
    assert any("CurrentUser" in c and "\\Root" in c for c in calls)


@pytest.mark.unit
def test_windows_branch_dedups_across_machine_and_user_stores(monkeypatch):
    import platform
    import subprocess

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    # same cert present in both stores -> de-duped by fingerprint to one root
    monkeypatch.setattr(subprocess, "run",
                        lambda *a, **k: _Result(0, _CERT_DER_B64 + "\n"))
    cas = T.default_load_certs()
    assert [c.sha256 for c in cas] == [_CERT_SHA256]


@pytest.mark.unit
def test_windows_localmachine_nonzero_exit_refuses(monkeypatch):
    import platform
    import subprocess

    monkeypatch.setattr(platform, "system", lambda: "Windows")
    # LocalMachine (queried first) returns non-zero -> refuse, never report clean
    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _Result(1, ""))
    with pytest.raises(T.TrustStoreUnavailable):
        T.default_load_certs()


@pytest.mark.unit
def test_windows_localmachine_oserror_refuses(monkeypatch):
    import platform
    import subprocess

    monkeypatch.setattr(platform, "system", lambda: "Windows")

    def _raise(*a, **k):
        raise FileNotFoundError("powershell not found")

    monkeypatch.setattr(subprocess, "run", _raise)
    with pytest.raises(T.TrustStoreUnavailable):
        T.default_load_certs()


@pytest.mark.unit
def test_windows_currentuser_failure_is_best_effort(monkeypatch):
    import platform
    import subprocess

    monkeypatch.setattr(platform, "system", lambda: "Windows")

    def _run(cmd, *a, **k):
        script = cmd[-1]
        if "LocalMachine" in script:
            return _Result(0, _CERT_DER_B64 + "\n")
        return _Result(1, "")  # CurrentUser fails -> ignored, not fatal

    monkeypatch.setattr(subprocess, "run", _run)
    cas = T.default_load_certs()
    assert [c.sha256 for c in cas] == [_CERT_SHA256]
