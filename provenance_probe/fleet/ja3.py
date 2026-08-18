"""JA3 TLS-client fingerprint (B-phase, Tier-2): the deterministic core.

JA3 (Salesforce) fingerprints a TLS *client* from the fields of its ClientHello:
which cipher suites, extensions, elliptic curves and point formats it offers, in
order. Different client libraries (curl vs a browser vs Go net/http) produce
distinct fingerprints, so a JA3 is a **SUB-CONFIRMED pointer**, never a measured
provenance verdict — it says "this connection looks like curl" or "a known
interception proxy is terminating TLS here", complementing the trust-store watch.
It never says what *model* served (that needs a tokenizer fingerprint).

What this module is used for (honest scope):
  * spotting a **known interception proxy's** ClientHello on the wire, and
  * spotting an **unexpected/second distinct JA3** on connections to a sanctioned
    upstream (a possible transparent MITM re-originating TLS).
An unknown JA3 is NOT suspicious by itself — JA3s vary by library *version*, so
`KNOWN_JA3` is a small, non-exhaustive, deliberately-conservative pointer map.

Fleet invariants honored here (see docs/fleet-posture.md):
  * NO EGRESS, pure + stdlib only. The pure core (JA3 math, ClientHello parser,
    pcap reader) makes no network call and never raises on hostile wire bytes —
    it returns None / skips. `capture_ja3` is the ONLY impure entry point.
  * Live capture needs raw packet capture (pcap/root), so it follows the fleet
    REFUSE contract: on an unsupported OS / missing `tcpdump` / non-root euid it
    raises `Ja3Unavailable` rather than returning `[]` (never a false-clean).

JA3 algorithm (implemented exactly, Salesforce spec):
  ja3_string = "SSLVersion,Ciphers,Extensions,EllipticCurves,ECPointFormats"
    SSLVersion       ClientHello legacy_version, uint16 decimal (771 == 0x0303).
    Ciphers          cipher_suites,        uint16 decimal, '-'-joined.
    Extensions       extension type list,  uint16 decimal, '-'-joined.
    EllipticCurves   supported_groups (ext 10) values, uint16 decimal, '-'-joined.
    ECPointFormats   ec_point_formats (ext 11) values, uint8  decimal, '-'-joined.
  An absent field is the empty string, so a bare hello can be "771,,,,".
  GREASE values (v & 0x0f0f == 0x0a0a) are stripped from Ciphers, Extensions and
  EllipticCurves BEFORE joining — NOT from ECPointFormats.
  ja3_hash = md5(ja3_string) as lowercase hex.
"""
from __future__ import annotations

import hashlib
import struct
from collections.abc import Callable
from dataclasses import dataclass

# --- constants --------------------------------------------------------------- #

# GREASE (RFC 8701) reserved values follow the pattern 0x0a0a, 0x1a1a … 0xfafa —
# every value v with (v & 0x0f0f) == 0x0a0a. Stripped from ciphers/extensions/curves.
_GREASE_MASK = 0x0F0F
_GREASE_VALUE = 0x0A0A

EXT_SUPPORTED_GROUPS = 10   # "elliptic_curves" / supported_groups
EXT_EC_POINT_FORMATS = 11

_HANDSHAKE_RECORD = 22      # TLS record content_type for handshake
_CLIENT_HELLO = 1          # handshake message type


def _is_grease(v: int) -> bool:
    return (v & _GREASE_MASK) == _GREASE_VALUE


def _strip_grease(values: list[int]) -> list[int]:
    return [v for v in values if not _is_grease(v)]


# --- 1. pure JA3 computation ------------------------------------------------- #

def ja3_string(version: int, ciphers: list[int], extensions: list[int],
               curves: list[int], point_formats: list[int]) -> str:
    """Build the canonical JA3 string (does the GREASE strip + field join)."""
    fields = [
        str(version),
        "-".join(str(v) for v in _strip_grease(ciphers)),
        "-".join(str(v) for v in _strip_grease(extensions)),
        "-".join(str(v) for v in _strip_grease(curves)),
        "-".join(str(v) for v in point_formats),  # NOT GREASE-stripped
    ]
    return ",".join(fields)


def ja3_hash(s: str) -> str:
    """Lowercase-hex MD5 of a JA3 string (the customary JA3 fingerprint id)."""
    return hashlib.md5(s.encode()).hexdigest()  # noqa: S324 (JA3 spec mandates MD5)


# --- 2. ClientHello parser (pure, robust on hostile bytes) ------------------- #

@dataclass(frozen=True)
class ClientHello:
    version: int                 # legacy_version
    ciphers: list[int]
    extensions: list[int]        # extension type list, in order
    curves: list[int]            # supported_groups values (ext 10), or []
    point_formats: list[int]     # ec_point_formats values (ext 11), or []

    def ja3(self) -> str:
        return ja3_string(self.version, self.ciphers, self.extensions,
                          self.curves, self.point_formats)


class _Reader:
    """Bounds-checked big-endian cursor over untrusted wire bytes.

    Every read validates length first and raises _Truncated on overrun, so the
    parser can convert any malformed input into a clean `None` without IndexError.
    """

    __slots__ = ("b", "i", "n")

    def __init__(self, b: bytes):
        self.b = b
        self.i = 0
        self.n = len(b)

    def _need(self, k: int) -> int:
        if k < 0 or self.i + k > self.n:
            raise _Truncated
        j = self.i
        self.i += k
        return j

    def u8(self) -> int:
        j = self._need(1)
        return self.b[j]

    def u16(self) -> int:
        j = self._need(2)
        return (self.b[j] << 8) | self.b[j + 1]

    def u24(self) -> int:
        j = self._need(3)
        return (self.b[j] << 16) | (self.b[j + 1] << 8) | self.b[j + 2]

    def take(self, k: int) -> bytes:
        j = self._need(k)
        return self.b[j:j + k]

    def remaining(self) -> int:
        return self.n - self.i


class _Truncated(Exception):
    """Internal: a length field ran past the buffer — malformed/truncated input."""


def _u16_list(block: bytes) -> list[int]:
    """A tightly-packed list of uint16s (drops a trailing odd byte defensively)."""
    return [(block[i] << 8) | block[i + 1] for i in range(0, len(block) - 1, 2)]


def parse_client_hello(payload: bytes) -> ClientHello | None:
    """Parse a TLS **record** whose payload is a ClientHello → ClientHello | None.

    `payload` MUST start at the TLS record header (content_type=22 handshake,
    version, length); this is exactly the TCP payload the pcap reader hands over.
    Returns None (never raises) on any truncation / non-ClientHello / garbage —
    robustness is required since this parses untrusted wire bytes.
    """
    try:
        r = _Reader(payload)
        if r.u8() != _HANDSHAKE_RECORD:      # TLS record content_type
            return None
        r.u16()                              # record legacy_version (ignored)
        rec_len = r.u16()
        body = r.take(rec_len) if rec_len <= r.remaining() else r.take(r.remaining())

        h = _Reader(body)
        if h.u8() != _CLIENT_HELLO:          # handshake msg type
            return None
        h.u24()                              # handshake length (bounds enforced by reads)

        version = h.u16()                    # legacy_version
        h.take(32)                           # random
        h.take(h.u8())                       # session_id
        ciphers = _u16_list(h.take(h.u16()))   # cipher_suites (len in bytes)
        h.take(h.u8())                       # compression_methods

        extensions: list[int] = []
        curves: list[int] = []
        point_formats: list[int] = []
        if h.remaining() >= 2:               # extensions block is optional in TLS 1.2
            ext_block = _Reader(h.take(h.u16()))
            while ext_block.remaining() >= 4:
                etype = ext_block.u16()
                edata = ext_block.take(ext_block.u16())
                extensions.append(etype)
                if etype == EXT_SUPPORTED_GROUPS and len(edata) >= 2:
                    curves = _u16_list(edata[2:2 + ((edata[0] << 8) | edata[1])])
                elif etype == EXT_EC_POINT_FORMATS and len(edata) >= 1:
                    point_formats = list(edata[1:1 + edata[0]])
        return ClientHello(version, ciphers, extensions, curves, point_formats)
    except _Truncated:
        return None


def ja3_from_client_hello(hello: ClientHello) -> tuple[str, str]:
    """(ja3_string, ja3_hash) for a parsed ClientHello."""
    s = hello.ja3()
    return s, ja3_hash(s)


# --- 3. minimal pcap reader (pure) ------------------------------------------- #

# Link-layer header types we understand (libpcap DLT_*).
_DLT_NULL = 0        # BSD loopback: 4-byte address-family header
_DLT_EN10MB = 1      # Ethernet: 14-byte header
_DLT_RAW_A = 12      # raw IP (some captures)
_DLT_RAW_B = 101     # raw IP (libpcap DLT_RAW)
_DLT_LOOP = 108      # OpenBSD/macOS loopback: 4-byte (big-endian) family header

# Read as big-endian: a big-endian-written pcap yields the magic as-is; a
# little-endian-written pcap yields the byte-swapped magic (→ read records LE).
_PCAP_MAGIC_BE = 0xA1B2C3D4   # file written big-endian
_PCAP_MAGIC_SWAPPED = 0xD4C3B2A1  # file written little-endian (bytes swapped)

_ETHERTYPE_IPV4 = 0x0800
_ETHERTYPE_IPV6 = 0x86DD
_IPPROTO_TCP = 6


@dataclass(frozen=True)
class Ja3Observation:
    src_ip: str
    dst_ip: str
    dst_port: int
    ja3: str
    ja3_hash: str


def _ip_str(family: int, raw: bytes) -> str:
    import socket
    try:
        return socket.inet_ntop(family, raw)
    except (OSError, ValueError):
        return ""


def _parse_l3(payload: bytes) -> tuple[str, str, int, bytes] | None:
    """IPv4/IPv6 → (src_ip, dst_ip, dst_port, tcp_payload) for TCP, else None."""
    import socket
    if not payload:
        return None
    version = payload[0] >> 4
    try:
        if version == 4:
            if len(payload) < 20:
                return None
            ihl = (payload[0] & 0x0F) * 4
            if ihl < 20 or len(payload) < ihl:
                return None
            if payload[9] != _IPPROTO_TCP:
                return None
            src = _ip_str(socket.AF_INET, payload[12:16])
            dst = _ip_str(socket.AF_INET, payload[16:20])
            l4 = payload[ihl:]
        elif version == 6:
            if len(payload) < 40:
                return None
            if payload[6] != _IPPROTO_TCP:   # skip if extension headers present
                return None
            src = _ip_str(socket.AF_INET6, payload[8:24])
            dst = _ip_str(socket.AF_INET6, payload[24:40])
            l4 = payload[40:]
        else:
            return None
    except (OSError, ValueError):
        return None

    if len(l4) < 20:
        return None
    data_off = (l4[12] >> 4) * 4
    if data_off < 20 or len(l4) < data_off:
        return None
    dst_port = (l4[2] << 8) | l4[3]
    return src, dst, dst_port, l4[data_off:]


def _parse_link(linktype: int, frame: bytes) -> bytes | None:
    """Strip the link-layer header → the L3 (IP) payload, or None if unhandled."""
    if linktype == _DLT_EN10MB:
        if len(frame) < 14:
            return None
        ethertype = (frame[12] << 8) | frame[13]
        if ethertype in (_ETHERTYPE_IPV4, _ETHERTYPE_IPV6):
            return frame[14:]
        return None   # VLAN-tagged / non-IP — skipped, best-effort
    if linktype in (_DLT_NULL, _DLT_LOOP):
        # 4-byte address-family header (NULL=host order, LOOP=network order); rather
        # than trust the family int, read the IP version from the first nibble.
        return frame[4:] if len(frame) > 4 else None
    if linktype in (_DLT_RAW_A, _DLT_RAW_B):
        return frame
    return None


def read_client_hellos(pcap_bytes: bytes) -> list[Ja3Observation]:
    """Parse a classic-format pcap → JA3 observations for each ClientHello seen.

    Best-effort and total: any record it cannot parse (unhandled link type,
    non-TCP, non-ClientHello, or a ClientHello spanning multiple TCP segments —
    reassembly is intentionally not done) is skipped, never raised on.
    """
    obs: list[Ja3Observation] = []
    if len(pcap_bytes) < 24:
        return obs
    magic = struct.unpack(">I", pcap_bytes[:4])[0]
    if magic == _PCAP_MAGIC_BE:
        endian = ">"
    elif magic == _PCAP_MAGIC_SWAPPED:
        endian = "<"
    else:
        return obs   # not a classic pcap (pcapng has a different magic) — skip

    # global header: magic(4) verMaj(2) verMin(2) thiszone(4) sigfigs(4) snaplen(4) network(4)
    linktype = struct.unpack(endian + "I", pcap_bytes[20:24])[0]
    off = 24
    n = len(pcap_bytes)
    rec_hdr = struct.Struct(endian + "IIII")
    while off + 16 <= n:
        _ts_sec, _ts_usec, incl_len, _orig_len = rec_hdr.unpack(pcap_bytes[off:off + 16])
        off += 16
        if incl_len < 0 or off + incl_len > n:
            break   # truncated final record
        frame = pcap_bytes[off:off + incl_len]
        off += incl_len

        l3 = _parse_link(linktype, frame)
        if l3 is None:
            continue
        parsed = _parse_l3(l3)
        if parsed is None:
            continue
        src, dst, dst_port, tcp_payload = parsed
        hello = parse_client_hello(tcp_payload)
        if hello is None:
            continue
        s, h = ja3_from_client_hello(hello)
        obs.append(Ja3Observation(src, dst, dst_port, s, h))
    return obs


# --- 4. known-fingerprint pointer (small, honest, non-exhaustive) ------------ #

# JA3 md5 → human label. DELIBERATELY SMALL and conservative: a JA3 changes with a
# client library's *version and build options*, so this map is a NON-EXHAUSTIVE
# pointer — an unknown JA3 is NOT suspicious. Its value is (a) recognising a known
# interception proxy's ClientHello, and (b) flagging a second, unexpected JA3 on
# connections to a sanctioned upstream (a possible transparent MITM).
#
# It ships EMPTY on purpose. A correct JA3→client map must be built by capturing the
# ClientHello of each client on the actual OS/build in scope (JA3s are version- and
# build-specific, and this project's honesty invariant forbids publishing a
# fingerprint we cannot verify — a wrong "this is curl" is worse than "unknown").
# Populate it from your own golden captures (`capture_ja3` on a known-clean host),
# the same way the trust-store watch takes an operator-supplied baseline. Candidates
# worth capturing (do NOT add unverified):
#   curl            — varies by OpenSSL/LibreSSL/Schannel build + HTTP/2 flags
#   python-requests / urllib3 — varies by the linked OpenSSL
#   Go net/http     — varies by the Go version's crypto/tls cipher/curve ordering
#   mitmproxy / Charles / Burp / Proxyman — interception-tool client ClientHellos
KNOWN_JA3: dict[str, str] = {}


def classify_ja3(ja3_hash_hex: str) -> str | None:
    """Return a known-client label for a JA3 md5, or None if unknown.

    None is the common, non-suspicious case — see KNOWN_JA3's docstring. The
    high-value signals are a KNOWN interception-tool match or an *unexpected*
    second JA3 to a sanctioned upstream, not mere absence from this map.
    """
    return KNOWN_JA3.get((ja3_hash_hex or "").lower())


# --- 5. capture front-end (gated; refuse, never false-clean) ----------------- #

class Ja3Unavailable(Exception):
    """Live JA3 capture could not run (unsupported OS / no `tcpdump` / not root).

    Raised — never an empty list — so a host where capture could not run is never
    reported as 'no interception seen'. Mirrors the trust-store / egress collectors.
    """


# A runner takes the tcpdump argv and the pcap output path and produces the pcap
# file at that path. Injectable so tests exercise capture+parse with a fixture pcap
# and no real capture / no root.
Runner = Callable[[list[str], str], None]


def _default_runner(argv: list[str], _out_path: str, *, timeout: int = 600) -> None:
    """Run tcpdump. A capture that STARTS but fails at runtime (bad --iface, iface
    down, runtime EPERM) must REFUSE, not leave an empty pcap that reads as clean —
    so a non-zero exit or a timeout raises `Ja3Unavailable` (never a false-clean)."""
    import subprocess
    try:
        r = subprocess.run(argv, capture_output=True, timeout=timeout, check=False)  # noqa: S603
    except subprocess.TimeoutExpired as e:
        raise Ja3Unavailable(f"tcpdump capture did not finish within {timeout}s") from e
    if r.returncode != 0:
        err = (r.stderr or b"").decode("utf-8", "replace").strip().splitlines()
        detail = f": {err[-1][:200]}" if err else " (raw capture failed)"
        raise Ja3Unavailable(f"tcpdump exited {r.returncode}{detail}")


def _preflight() -> None:
    """Refuse (raise Ja3Unavailable) if the real host cannot do raw capture."""
    import os
    import platform
    import shutil
    system = platform.system()
    if system not in ("Darwin", "Linux"):
        raise Ja3Unavailable(f"live JA3 capture is not implemented on {system}")
    if shutil.which("tcpdump") is None:
        raise Ja3Unavailable("`tcpdump` is not on PATH — cannot capture ClientHellos")
    if not (hasattr(os, "geteuid") and os.geteuid() == 0):
        raise Ja3Unavailable(
            "raw packet capture needs root — re-run with privilege "
            "(refusing rather than reporting a false-clean)")


def capture_ja3(*, seconds: int = 5, iface: str | None = None,
                runner: Runner | None = None) -> list[Ja3Observation]:
    """Capture ClientHellos for `seconds` and return their JA3 observations.

    Shells out to `tcpdump` writing a pcap to a temp file, then parses it purely.
    REFUSES (raises `Ja3Unavailable`) on an unsupported OS, missing `tcpdump`, or a
    non-root euid — never returns `[]` to mean "clean".

    `runner` is injectable for tests (write a fixture pcap to the given path); when
    injected the real-host preflight is bypassed since the runner IS the capture.
    """
    import os
    import tempfile

    if runner is None:
        _preflight()

    fd, path = tempfile.mkstemp(prefix="pp-ja3-", suffix=".pcap")
    os.close(fd)
    try:
        argv = [
            "tcpdump", "-i", iface or "any", "-s", "0", "-n",
            "-w", path, "-G", str(int(seconds)), "-W", "1", "tcp port 443",
        ]
        # Bound the real capture's hard timeout to the window (not a fixed 600s, which
        # a larger --ja3-seconds would trip). Injected test runners keep (argv, path).
        if runner is None:
            _default_runner(argv, path, timeout=int(seconds) + 15)
        else:
            runner(argv, path)
        try:
            with open(path, "rb") as fh:
                data = fh.read()
        except OSError as e:
            raise Ja3Unavailable(f"capture produced no readable pcap: {e}")
        return read_client_hellos(data)
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


__all__ = [
    "ClientHello",
    "Ja3Observation",
    "Ja3Unavailable",
    "KNOWN_JA3",
    "capture_ja3",
    "classify_ja3",
    "ja3_from_client_hello",
    "ja3_hash",
    "ja3_string",
    "parse_client_hello",
    "read_client_hellos",
]
