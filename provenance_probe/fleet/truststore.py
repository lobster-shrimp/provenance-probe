"""Trust-store watch (B-phase): find non-baseline root CAs on a host.

A MITM-capable AI gateway (transparent-proxy / TPROXY mode) must install a root
CA to terminate TLS — no fork removes that requirement. This collector enumerates
the host's trusted root CAs and flags any that are NOT in the org's known-good
baseline, escalating CAs from known interception tools (mitmproxy, Charles, Burp).

Two hard constraints, both from adversarial review:

* "Non-enterprise root" is NOT machine-computable. Zscaler/Netskope/corp-MDM/dev
  roots are legitimate and vary per org, so the operator supplies a BASELINE
  (capture a golden machine with `--print ca-baseline`, then diff every host
  against it). A root not in the baseline is the finding.
* This reads the system trust store — a privacy/labor-review surface. It is INERT
  until an authorization flag is set (documented policy), mirroring the prober's
  "authorization gates all active probing".

NO EGRESS: reads local trust stores only. Cert identity is a SHA-256 fingerprint
of the DER bytes (pure stdlib) — no cryptography dependency, no cert-internals
parsing. The INSTALLING PROCESS of a rogue CA is NOT captured here (the macOS
keychain records no PID); that needs an EDR/osquery event hook (see docs).
"""
from __future__ import annotations

import base64
import hashlib
import re
from collections.abc import Callable
from dataclasses import dataclass, field

# Classifications
BASELINE = "baseline"                    # in the operator's known-good set (not a finding)
UNBASELINED = "unbaselined"              # a root NOT in the baseline (finding)
INTERCEPTION_TOOL = "interception-tool"  # a known TLS-intercept tool CA (high-severity finding)

# Label substrings that identify a known TLS-interception tool's root CA. Matched
# case-insensitively against the cert's source-provided label. Escalated even if
# the fingerprint happens to sit in the baseline (a golden image should not ship one).
INTERCEPTION_LABELS = (
    "mitmproxy", "charles", "fiddler", "burp", "portswigger", "proxyman",
    "owasp zap", "zap root", "do not trust", "mkcert",
)

_PEM_BLOCK = re.compile(
    r"-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----", re.DOTALL)

# OID 2.5.4.3 (commonName), DER-encoded, followed by its string value. Used to
# pull the Subject/Issuer CN out of a cert WITHOUT a cryptography dependency, so
# interception-tool matching works on the real (label-less) loaders too.
_CN_OID = bytes([0x06, 0x03, 0x55, 0x04, 0x03])
_STRING_TAGS = {0x13, 0x0c, 0x16, 0x14}  # PrintableString, UTF8String, IA5, T61


class TrustStoreUnavailable(Exception):
    """The trust store could not be read (unsupported OS, or the reader failed).

    Raised instead of returning an empty list so an unreadable host is never
    reported as 'clean' — a silent false-clean is the worst failure here."""


def cn_strings_from_der(der: bytes) -> list[str]:
    """Best-effort extraction of commonName string values from a cert's DER.
    Finds each commonName OID immediately followed by a short-form string value
    (the AttributeTypeAndValue `SEQUENCE { OID, value }`). Good enough to spot an
    interception tool's CN ('mitmproxy', 'Charles Proxy CA'); not a full parser."""
    out: list[str] = []
    i = 0
    while True:
        j = der.find(_CN_OID, i)
        if j < 0:
            break
        k = j + len(_CN_OID)
        if k + 2 <= len(der) and der[k] in _STRING_TAGS:
            length = der[k + 1]
            if length < 128 and k + 2 + length <= len(der):
                out.append(der[k + 2:k + 2 + length].decode("utf-8", "replace"))
        i = k
    return out


@dataclass(frozen=True)
class RootCA:
    label: str          # source-provided (keychain label / filename); may be ""
    sha256: str         # fingerprint of the DER bytes
    source: str = ""    # where it was read from (keychain / cert dir)


@dataclass(frozen=True)
class RootCAFinding:
    ca: RootCA
    classification: str
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class TrustStoreResult:
    findings: list[RootCAFinding]
    total: int
    baseline: int
    unbaselined: int
    interception: int

    @property
    def headline(self) -> str:
        drift = self.unbaselined + self.interception
        return (f"trust store: {self.total} roots, {self.baseline} baselined, "
                f"{drift} unbaselined ({self.interception} known-interception)")


def der_from_pem(pem: str) -> bytes | None:
    """Extract the first certificate's DER bytes from a PEM string, or None."""
    m = _PEM_BLOCK.search(pem or "")
    if not m:
        return None
    try:
        return base64.b64decode("".join(m.group(1).split()))
    except (ValueError, base64.binascii.Error):
        return None


def fingerprint_pem(pem: str) -> str | None:
    """SHA-256 fingerprint (hex) of a PEM certificate's DER bytes, or None."""
    der = der_from_pem(pem)
    return hashlib.sha256(der).hexdigest() if der else None


def load_baseline(text: str) -> set[str]:
    """Parse a baseline file into a set of lowercased sha256 hex fingerprints.
    One fingerprint per line; `#` comments and blanks ignored; a trailing
    `# label` annotation (as emitted by --print ca-baseline) is stripped."""
    out: set[str] = set()
    for raw in (text or "").splitlines():
        line = raw.split("#", 1)[0].strip().lower().replace(":", "")
        if re.fullmatch(r"[0-9a-f]{64}", line):
            out.add(line)
    return out


def _is_interception(label: str) -> bool:
    low = (label or "").lower()
    return any(tag in low for tag in INTERCEPTION_LABELS)


def classify_root(ca: RootCA, baseline: set[str]) -> RootCAFinding:
    if _is_interception(ca.label):
        return RootCAFinding(ca, INTERCEPTION_TOOL,
                             ["label matches a known TLS-interception tool — a "
                              "MITM-capable root; review immediately"])
    if ca.sha256 in baseline:
        return RootCAFinding(ca, BASELINE, [])
    note = ("root CA not in the supplied baseline"
            if baseline else
            "no baseline supplied — cannot distinguish enterprise roots; capture a "
            "golden machine with `--print ca-baseline`")
    return RootCAFinding(ca, UNBASELINED, [note])


def scan_trust_store(load_certs: Callable[[], list[RootCA]],
                     baseline: set[str] | None = None) -> TrustStoreResult:
    """Enumerate root CAs via the injected loader, classify each vs the baseline.

    `load_certs()` returns the host's trusted roots (RootCA with a computed
    fingerprint). Injected so the pure classification logic is testable without a
    real trust store; the default platform loader is `default_load_certs`."""
    base = baseline or set()
    findings = [classify_root(ca, base) for ca in load_certs()]
    total = len(findings)
    n_base = sum(1 for f in findings if f.classification == BASELINE)
    n_intr = sum(1 for f in findings if f.classification == INTERCEPTION_TOOL)
    n_unbase = sum(1 for f in findings if f.classification == UNBASELINED)
    return TrustStoreResult(findings=findings, total=total, baseline=n_base,
                            unbaselined=n_unbase, interception=n_intr)


# --- platform loaders (best-effort, no network) ------------------------------ #

def roots_from_pem_bundle(text: str, source: str = "") -> list[RootCA]:
    """Split a concatenated-PEM bundle into RootCA records, fingerprinting each and
    deriving a label from the cert's DER commonName (so interception-tool matching
    works even though the loaders emit label-less PEM)."""
    out: list[RootCA] = []
    for m in _PEM_BLOCK.finditer(text or ""):
        pem = "-----BEGIN CERTIFICATE-----" + m.group(1) + "-----END CERTIFICATE-----"
        der = der_from_pem(pem)
        if der is None:
            continue
        fp = hashlib.sha256(der).hexdigest()
        label = "; ".join(dict.fromkeys(cn_strings_from_der(der)))  # de-dup, keep order
        out.append(RootCA(label=label, sha256=fp, source=source))
    return out


def default_load_certs() -> list[RootCA]:
    """Read the host's admin/user-added trusted roots (where a rogue CA lands).
    Platform-specific, local-only (no network — the `security` CLI / cert files).

    Raises TrustStoreUnavailable rather than returning [] when the store cannot be
    read (unsupported OS, or the macOS `security` reader could not run) — an
    unreadable host must never be reported as clean."""
    import platform
    import subprocess

    system = platform.system()
    roots: list[RootCA] = []
    if system == "Darwin":
        # Admin-added + user roots are the interesting surface (not the OS bundle).
        ran_ok = False
        for kc, src in ((["/Library/Keychains/System.keychain"], "system-keychain"),
                        ([], "login-keychain")):
            try:
                out = subprocess.run(["security", "find-certificate", "-a", "-p", *kc],
                                     capture_output=True, text=True, timeout=20)
            except (OSError, subprocess.SubprocessError):
                continue
            if out.returncode != 0:
                continue  # errored: a non-zero exit is a read failure, not an empty store
            ran_ok = True
            roots += roots_from_pem_bundle(out.stdout, src)
        if not ran_ok:
            raise TrustStoreUnavailable(
                "could not read the macOS trust store (`security` returned an error)")
    elif system == "Linux":
        # Admin-added CA dirs. An empty dir is a valid, genuinely-clean result.
        import glob
        for path in (glob.glob("/usr/local/share/ca-certificates/*.crt")
                     + glob.glob("/etc/pki/ca-trust/source/anchors/*")):
            try:
                with open(path, encoding="utf-8", errors="replace") as fh:
                    roots += roots_from_pem_bundle(fh.read(), path)
            except OSError:
                continue
    else:
        raise TrustStoreUnavailable(f"trust-store watch is not implemented on {system}")
    # de-dup by fingerprint, keeping the first (labelled) occurrence
    seen: set[str] = set()
    deduped: list[RootCA] = []
    for ca in roots:
        if ca.sha256 not in seen:
            seen.add(ca.sha256)
            deduped.append(ca)
    return deduped


def baseline_template(load_certs: Callable[[], list[RootCA]] | None = None) -> str:
    """Emit the current host's roots as a starter baseline (fingerprint  # label),
    to save from a GOLDEN machine and diff other hosts against."""
    cas = (load_certs or default_load_certs)()
    lines = [
        "# provenance-probe fleet-scan — trusted-root CA baseline (capture on a",
        "# GOLDEN machine, then: fleet-scan --trust-store --ca-baseline this-file).",
        "# One SHA-256 DER fingerprint per line; '# label' is an ignored annotation.",
        "",
    ]
    for ca in cas:
        lines.append(f"{ca.sha256}" + (f"  # {ca.label or ca.source}" if (ca.label or ca.source) else ""))
    return "\n".join(lines) + "\n"
