"""Windows observed-egress: netstat/tasklist parse, and proof the Windows parse
drives the SAME analyzer (fan-out + routed-via-gateway) as the lsof path."""
from __future__ import annotations

import pytest

from provenance_probe.fleet import connections as C

# A realistic `netstat -ano -p TCP` capture, banner + header included.
_NETSTAT = """
Active Connections

  Proto  Local Address          Foreign Address        State           PID
  TCP    0.0.0.0:20128          0.0.0.0:0              LISTENING       4242
  TCP    10.0.0.5:5555          140.82.1.2:443         ESTABLISHED     4242
  TCP    [::]:443               [::]:0                 LISTENING       1234
  TCP    10.0.0.5:6001          93.184.216.34:443      ESTABLISHED     9999
  TCP    10.0.0.5:6002          52.1.2.3:443           TIME_WAIT       9999
"""

# `tasklist /fo csv /nh` — quoted CSV, a comma inside the mem field, one bad row.
_TASKLIST = (
    '"omniroute.exe","4242","Console","1","250,000 K"\n'
    '"chrome.exe","9999","Console","1","12,345 K"\n'
    '"svc.exe","1234","Services","0","4,000 K"\n'
    'garbage-single-column\n'
)


# --- parse_netstat ----------------------------------------------------------- #

@pytest.mark.unit
def test_parse_netstat_states_addrs_and_ipv6():
    conns = C.parse_netstat(_NETSTAT)
    # 5 TCP rows parse (banner/header skipped).
    assert len(conns) == 5

    listen = next(c for c in conns if c.laddr_port == 20128)
    assert listen.state == "LISTEN"                 # LISTENING -> LISTEN
    assert listen.laddr_host == "0.0.0.0"           # a router-listener host
    assert listen.raddr_host == "" and listen.raddr_port is None  # 0.0.0.0:0 emptied

    est = next(c for c in conns if c.laddr_port == 5555)
    assert est.state == "ESTABLISHED"
    assert est.raddr_host == "140.82.1.2" and est.raddr_port == 443

    v6 = next(c for c in conns if c.laddr_port == 443)
    assert v6.state == "LISTEN"
    assert v6.laddr_host == "::"                     # [::]:443 -> host "::"
    assert v6.raddr_host == "" and v6.raddr_port is None

    # No name map → command falls back to the PID string.
    assert listen.command == "4242"


@pytest.mark.unit
def test_parse_netstat_uses_name_map():
    names = {"4242": "omniroute.exe", "9999": "chrome.exe"}
    conns = C.parse_netstat(_NETSTAT, names=names)
    listen = next(c for c in conns if c.laddr_port == 20128)
    assert listen.command == "omniroute.exe"
    est = next(c for c in conns if c.laddr_port == 6001)
    assert est.command == "chrome.exe"
    # A PID absent from the map still falls back to the PID.
    svc = next(c for c in conns if c.laddr_port == 443)
    assert svc.command == "1234"


@pytest.mark.unit
def test_parse_netstat_malformed_and_empty_never_raise():
    assert C.parse_netstat("") == []
    assert C.parse_netstat(None) == []  # type: ignore[arg-type]
    # UDP rows, short rows, and non-numeric PIDs are all skipped, not raised.
    junk = (
        "  UDP    0.0.0.0:5353           *:*                                    5\n"
        "  TCP    10.0.0.5:1                                              \n"   # too few cols
        "  TCP    10.0.0.5:2   1.2.3.4:5   ESTABLISHED   notapid\n"
        "random banner line\n"
    )
    assert C.parse_netstat(junk) == []


# --- parse_tasklist ---------------------------------------------------------- #

@pytest.mark.unit
def test_parse_tasklist_maps_pid_to_image_and_skips_bad_rows():
    names = C.parse_tasklist(_TASKLIST)
    assert names == {
        "4242": "omniroute.exe",
        "9999": "chrome.exe",
        "1234": "svc.exe",
    }
    # The single-column garbage row was skipped, not raised.
    assert "garbage-single-column" not in names.values()


@pytest.mark.unit
def test_parse_tasklist_empty_is_empty():
    assert C.parse_tasklist("") == {}
    assert C.parse_tasklist(None) == {}  # type: ignore[arg-type]


# --- the Windows parse drives the SAME analyzer ------------------------------ #

def _fanout_netstat(n_upstreams: int) -> str:
    rows = [
        "Active Connections",
        "",
        "  Proto  Local Address          Foreign Address        State           PID",
        "  TCP    0.0.0.0:20128          0.0.0.0:0              LISTENING       4242",
    ]
    for i in range(n_upstreams):
        rows.append(f"  TCP    10.0.0.5:{5001 + i}      140.82.{i}.{i}:443     ESTABLISHED     4242")
    # A client routing through the local gateway port.
    rows.append("  TCP    127.0.0.1:5555         127.0.0.1:20128        ESTABLISHED     9999")
    return "\n".join(rows) + "\n"


@pytest.mark.unit
def test_windows_parse_feeds_analyzer_fanout_and_gateway():
    names = {"4242": "omniroute.exe", "9999": "node.exe"}
    res = C.analyze(C.parse_netstat(_fanout_netstat(8), names=names), min_upstreams=1)

    fan = [f for f in res.findings if f.classification == C.ROUTER_FANOUT]
    via = [f for f in res.findings if f.classification == C.ROUTED_VIA_GATEWAY]
    assert len(fan) == 1
    assert fan[0].command == "omniroute.exe" and fan[0].upstreams == 8
    assert len(via) == 1 and via[0].command == "node.exe"
    assert "1 router fan-out" in res.headline and "1 routed-via-gateway" in res.headline


# --- default_connections() Windows branch (mocked; never shells out live) ---- #

class _FakeRun:
    def __init__(self, returncode: int, stdout: str = "") -> None:
        self.returncode = returncode
        self.stdout = stdout


@pytest.mark.unit
def test_default_connections_windows_ok(monkeypatch):
    # `default_connections` does `import platform`/`import subprocess` inside the
    # function body, so those resolve to the global module singletons — patch there.
    import platform as _pf
    import subprocess as _sp

    import provenance_probe.fleet.connections as mod

    seen_cmds = []

    def fake_run(cmd, **_kw):
        seen_cmds.append(cmd)
        if cmd[0] == "netstat":
            return _FakeRun(0, _fanout_netstat(8))
        if cmd[0] == "tasklist":
            return _FakeRun(0, _TASKLIST)
        raise AssertionError(f"unexpected command {cmd}")

    monkeypatch.setattr(_pf, "system", lambda: "Windows")
    monkeypatch.setattr(_sp, "run", fake_run)

    conns = mod.default_connections()
    # LISTEN on 20128 + 8 upstreams + 1 gateway client = 10 conns; names applied.
    assert len(conns) == 10
    listen = next(c for c in conns if c.laddr_port == 20128)
    assert listen.command == "omniroute.exe"
    # netstat must NOT filter `-p TCP` — that drops IPv6 on Windows (a false-clean).
    netstat_cmd = next(c for c in seen_cmds if c[0] == "netstat")
    assert "-p" not in netstat_cmd
    # and a Windows scan sees the whole-system table (no "current user only" caveat).
    assert mod.is_privileged() is True


@pytest.mark.unit
def test_default_connections_windows_netstat_failure_refuses(monkeypatch):
    import platform as _pf
    import subprocess as _sp

    import provenance_probe.fleet.connections as mod

    def fake_run(cmd, **_kw):
        if cmd[0] == "netstat":
            return _FakeRun(1, "")  # non-zero → must refuse, never []
        return _FakeRun(0, _TASKLIST)

    monkeypatch.setattr(_pf, "system", lambda: "Windows")
    monkeypatch.setattr(_sp, "run", fake_run)

    with pytest.raises(C.EgressUnavailable):
        mod.default_connections()
