"""JA3 TLS-client fingerprint core: the pure JA3 math (with a published test
vector), the robust ClientHello parser (static byte fixtures + truncation), the
minimal pcap reader (crafted fixture), the known-fingerprint pointer, and the
gated capture front-end's refuse-don't-false-clean contract."""
from __future__ import annotations

import hashlib
import struct

import pytest

from provenance_probe.fleet import ja3 as J


# --- 1. pure JA3 computation ------------------------------------------------- #

@pytest.mark.unit
def test_ja3_hash_published_vector():
    # Documented published JA3 example string (Salesforce ja3 spec form).
    s = ("771,4865-4866-4867-49195-49199-49196-49200-52393-52392-49171-49172-"
         "156-157-47-53,0-23-65281-10-11-35-16-5-13-18-51-45-43-27-21,29-23-24,0")
    digest = J.ja3_hash(s)
    # (a) matches a fresh md5 of the exact string, and
    assert digest == hashlib.md5(s.encode()).hexdigest()
    # (b) equals the hard-coded literal, so a formatting regression is caught.
    assert digest == "b32309a26951912be7dba376398abc3b"


@pytest.mark.unit
def test_ja3_hash_minimal_vector():
    s = "771,,,,"
    assert J.ja3_hash(s) == hashlib.md5(s.encode()).hexdigest()
    assert J.ja3_hash(s) == "bddda940f9963577c41d7c28b1a5f65f"


@pytest.mark.unit
def test_ja3_string_empty_fields():
    assert J.ja3_string(771, [], [], [], []) == "771,,,,"


@pytest.mark.unit
def test_ja3_string_grease_stripped_from_all_but_point_formats():
    # 0x0a0a, 0x1a1a, 0xfafa, 0x2a2a are all GREASE — stripped from ciphers /
    # extensions / curves. Point formats are uint8s (GREASE can't occur), so they
    # pass through verbatim.
    s = J.ja3_string(
        version=771,
        ciphers=[0x0A0A, 4865, 0x1A1A, 4866],
        extensions=[0xFAFA, 0, 0x2A2A, 23],
        curves=[0x0A0A, 29, 23],
        point_formats=[0, 1, 2],   # NOT stripped
    )
    assert s == "771,4865-4866,0-23,29-23,0-1-2"


@pytest.mark.unit
def test_is_grease_pattern():
    for v in (0x0A0A, 0x1A1A, 0x2A2A, 0xFAFA):
        assert J._is_grease(v)
    for v in (0x0303, 0x1301, 4865, 771, 0):
        assert not J._is_grease(v)


# --- 2. ClientHello parser (static byte fixtures) ---------------------------- #

def _u16(n: int) -> bytes:
    return struct.pack(">H", n)


def _ext(etype: int, data: bytes) -> bytes:
    return _u16(etype) + _u16(len(data)) + data


def _supported_groups(curves: list[int]) -> bytes:
    body = b"".join(_u16(c) for c in curves)
    return _ext(10, _u16(len(body)) + body)


def _ec_point_formats(formats: list[int]) -> bytes:
    body = bytes(formats)
    return _ext(11, bytes([len(body)]) + body)


def _client_hello(version: int, ciphers: list[int], extensions: list[bytes]) -> bytes:
    """Hand-build a minimal but valid TLS record wrapping a ClientHello.

    Layout (all lengths big-endian):
      record:    content_type=22, legacy_version, record_length
      handshake: msg_type=1, length(3)
      body:      legacy_version, random[32], session_id(len+bytes),
                 cipher_suites(len+bytes), compression_methods(len+bytes),
                 extensions(len + concatenated extensions)
    """
    cipher_bytes = b"".join(_u16(c) for c in ciphers)
    ext_bytes = b"".join(extensions)
    body = (
        _u16(version)
        + b"\x00" * 32                       # random
        + b"\x00"                            # session_id length 0
        + _u16(len(cipher_bytes)) + cipher_bytes
        + b"\x01\x00"                        # compression_methods: len 1, [null]
        + _u16(len(ext_bytes)) + ext_bytes
    )
    handshake = b"\x01" + struct.pack(">I", len(body))[1:] + body   # type + u24 len
    record = b"\x16" + _u16(version) + _u16(len(handshake)) + handshake
    return record


@pytest.mark.unit
def test_parse_client_hello_basic():
    # ciphers 4865,4866 ; extensions 10 (curves 29,23) + 11 (formats 0)
    fixture = _client_hello(
        version=771,
        ciphers=[4865, 4866],
        extensions=[_supported_groups([29, 23]), _ec_point_formats([0])],
    )
    hello = J.parse_client_hello(fixture)
    assert hello is not None
    # Field-by-field derivation:
    #   version 771 ; ciphers 4865-4866 ; extensions 10-11 ; curves 29-23 ; formats 0
    assert hello.version == 771
    assert hello.ciphers == [4865, 4866]
    assert hello.extensions == [10, 11]
    assert hello.curves == [29, 23]
    assert hello.point_formats == [0]
    assert hello.ja3() == "771,4865-4866,10-11,29-23,0"


@pytest.mark.unit
def test_parse_client_hello_with_grease_strips_in_ja3():
    # A leading GREASE cipher + GREASE extension are parsed but stripped from JA3.
    fixture = _client_hello(
        version=771,
        ciphers=[0x0A0A, 4865],
        extensions=[_ext(0x1A1A, b""), _supported_groups([29])],
    )
    hello = J.parse_client_hello(fixture)
    assert hello is not None
    assert hello.ciphers == [0x0A0A, 4865]        # raw parse keeps GREASE
    assert hello.extensions == [0x1A1A, 10]
    assert hello.ja3() == "771,4865,10,29,"       # GREASE gone, no point-formats ext


@pytest.mark.unit
def test_parse_client_hello_no_extensions():
    fixture = _client_hello(version=771, ciphers=[4865], extensions=[])
    hello = J.parse_client_hello(fixture)
    assert hello is not None
    assert hello.ja3() == "771,4865,,,"


@pytest.mark.unit
def test_parse_client_hello_truncated_returns_none():
    full = _client_hello(771, [4865, 4866], [_supported_groups([29])])
    # Chop mid-body — every length field points past the buffer end.
    assert J.parse_client_hello(full[:20]) is None


@pytest.mark.unit
def test_parse_client_hello_rejects_non_handshake_and_garbage():
    assert J.parse_client_hello(b"") is None
    assert J.parse_client_hello(b"\x17\x03\x03\x00\x05hello") is None   # app-data record
    assert J.parse_client_hello(bytes(range(40))) is None


# --- 3. minimal pcap reader (crafted fixture) -------------------------------- #

def _pcap(linktype: int, *frames: bytes) -> bytes:
    """Classic little-endian pcap: 24-byte global header + per-record frames."""
    gh = struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, linktype)
    out = [gh]
    for fr in frames:
        out.append(struct.pack("<IIII", 0, 0, len(fr), len(fr)) + fr)
    return b"".join(out)


def _eth_ipv4_tcp(payload: bytes, *, src="10.0.0.5", dst="140.82.1.2",
                  dport=443) -> bytes:
    import socket
    eth = b"\xaa" * 6 + b"\xbb" * 6 + _u16(0x0800)          # dst, src, IPv4
    tcp = (_u16(52345) + _u16(dport) + b"\x00" * 8          # sports/seq/ack
           + b"\x50" + b"\x18" + _u16(65535) + b"\x00" * 4  # data-off=5(*4), flags
           + payload)
    ip_body_len = 20 + len(tcp)
    ipv4 = (bytes([0x45, 0x00]) + _u16(ip_body_len) + b"\x00" * 4
            + bytes([64, socket.IPPROTO_TCP]) + b"\x00\x00"
            + socket.inet_aton(src) + socket.inet_aton(dst))
    return eth + ipv4 + tcp


@pytest.mark.unit
def test_read_client_hellos_from_crafted_pcap():
    hello = _client_hello(771, [4865, 4866], [_supported_groups([29, 23]),
                                              _ec_point_formats([0])])
    pcap = _pcap(J._DLT_EN10MB, _eth_ipv4_tcp(hello, dst="140.82.1.2", dport=443))
    obs = J.read_client_hellos(pcap)
    assert len(obs) == 1
    o = obs[0]
    assert o.dst_ip == "140.82.1.2"
    assert o.src_ip == "10.0.0.5"
    assert o.dst_port == 443
    assert o.ja3 == "771,4865-4866,10-11,29-23,0"
    # ja3_hash is the md5 of that string
    assert o.ja3_hash == hashlib.md5(o.ja3.encode()).hexdigest()


@pytest.mark.unit
def test_read_client_hellos_loopback_null_linktype():
    hello = _client_hello(771, [4865], [])
    import socket
    tcp = (_u16(52345) + _u16(443) + b"\x00" * 8 + b"\x50\x18" + _u16(65535)
           + b"\x00" * 4 + hello)
    ipv4 = (bytes([0x45, 0x00]) + _u16(20 + len(tcp)) + b"\x00" * 4
            + bytes([64, socket.IPPROTO_TCP]) + b"\x00\x00"
            + socket.inet_aton("127.0.0.1") + socket.inet_aton("127.0.0.1"))
    frame = struct.pack("<I", 2) + ipv4 + tcp    # DLT_NULL 4-byte AF_INET header
    obs = J.read_client_hellos(_pcap(J._DLT_NULL, frame))
    assert len(obs) == 1 and obs[0].dst_ip == "127.0.0.1"
    assert obs[0].ja3 == "771,4865,,,"


@pytest.mark.unit
def test_read_client_hellos_skips_junk_and_bad_magic():
    assert J.read_client_hellos(b"") == []
    assert J.read_client_hellos(b"not a pcap file at all........") == []
    # Valid header, but a non-TCP / non-hello frame → skipped, no crash.
    junk = _pcap(J._DLT_EN10MB, b"\xaa" * 6 + b"\xbb" * 6 + _u16(0x0806) + b"\x00" * 8)
    assert J.read_client_hellos(junk) == []


# --- 4. known-fingerprint pointer -------------------------------------------- #

@pytest.mark.unit
def test_known_ja3_ships_empty_by_design():
    # Honesty invariant: no unverified fingerprints are published — the map is
    # operator-populated from golden captures (see KNOWN_JA3 docstring).
    assert J.KNOWN_JA3 == {}


@pytest.mark.unit
def test_classify_ja3_unknown_is_none():
    assert J.classify_ja3("0" * 32) is None    # unknown is the common, non-suspicious case
    assert J.classify_ja3("") is None


@pytest.mark.unit
def test_classify_ja3_lookup_mechanism(monkeypatch):
    # The lookup consults KNOWN_JA3 and is case-insensitive. Tested against an
    # INJECTED map so the shipped map stays honestly empty.
    fake = {"abc123": "example-client"}
    monkeypatch.setattr(J, "KNOWN_JA3", fake)
    assert J.classify_ja3("abc123") == "example-client"
    assert J.classify_ja3("ABC123") == "example-client"   # case-insensitive
    assert J.classify_ja3("deadbeef") is None


# --- 5. capture front-end (refuse; never false-clean) ------------------------ #

@pytest.mark.unit
def test_capture_ja3_refuses_on_unsupported_os(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Windows")
    with pytest.raises(J.Ja3Unavailable):
        J.capture_ja3()


@pytest.mark.unit
def test_capture_ja3_refuses_without_tcpdump(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr("shutil.which", lambda _n: None)
    with pytest.raises(J.Ja3Unavailable):
        J.capture_ja3()


@pytest.mark.unit
def test_capture_ja3_refuses_without_root(monkeypatch):
    monkeypatch.setattr("platform.system", lambda: "Linux")
    monkeypatch.setattr("shutil.which", lambda _n: "/usr/bin/tcpdump")
    import os
    monkeypatch.setattr(os, "geteuid", lambda: 1000, raising=False)
    with pytest.raises(J.Ja3Unavailable):
        J.capture_ja3()


@pytest.mark.unit
def test_capture_ja3_happy_path_with_injected_runner(tmp_path):
    hello = _client_hello(771, [4865, 4866], [_supported_groups([29, 23]),
                                              _ec_point_formats([0])])
    pcap = _pcap(J._DLT_EN10MB, _eth_ipv4_tcp(hello))

    captured_argv: list[list[str]] = []

    def fake_runner(argv: list[str], out_path: str) -> None:
        captured_argv.append(argv)
        with open(out_path, "wb") as fh:      # write the fixture where tcpdump would
            fh.write(pcap)

    obs = J.capture_ja3(seconds=1, iface="lo0", runner=fake_runner)
    assert len(obs) == 1
    assert obs[0].ja3 == "771,4865-4866,10-11,29-23,0"
    # argv sanity: it targets the interface and writes a pcap
    assert captured_argv and "lo0" in captured_argv[0] and "-w" in captured_argv[0]


@pytest.mark.unit
def test_capture_ja3_missing_pcap_refuses(tmp_path):
    def runner_that_writes_nothing(argv: list[str], out_path: str) -> None:
        import os
        os.remove(out_path)      # simulate tcpdump producing no file

    with pytest.raises(J.Ja3Unavailable):
        J.capture_ja3(runner=runner_that_writes_nothing)


# --- 6. runtime capture failure must REFUSE, not false-clean ----------------- #

@pytest.mark.unit
def test_default_runner_refuses_on_nonzero_tcpdump_exit(monkeypatch):
    """tcpdump that STARTS but fails at runtime (bad iface, runtime EPERM) exits
    non-zero → Ja3Unavailable, never a silent empty pcap that reads as clean."""
    import subprocess

    class _R:
        returncode = 1
        stderr = b"tcpdump: en9: No such device exists"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())
    with pytest.raises(J.Ja3Unavailable):
        J._default_runner(["tcpdump"], "/tmp/pp-ja3-x.pcap", timeout=5)


@pytest.mark.unit
def test_default_runner_refuses_on_timeout(monkeypatch):
    import subprocess

    def _timeout(*a, **k):
        raise subprocess.TimeoutExpired(cmd="tcpdump", timeout=5)

    monkeypatch.setattr(subprocess, "run", _timeout)
    with pytest.raises(J.Ja3Unavailable):
        J._default_runner(["tcpdump"], "/tmp/pp-ja3-x.pcap", timeout=5)


@pytest.mark.unit
def test_default_runner_ok_on_clean_exit(monkeypatch):
    import subprocess

    class _R:
        returncode = 0
        stderr = b"0 packets captured"

    monkeypatch.setattr(subprocess, "run", lambda *a, **k: _R())
    J._default_runner(["tcpdump"], "/tmp/pp-ja3-x.pcap", timeout=5)  # no raise
