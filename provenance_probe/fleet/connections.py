"""Tier-2 observed-egress signal (B-phase): the loopback fan-out shape.

The config scan sees a `base_url=localhost:20128`; this sees the matching NETWORK
shape from the OS connection table: a local process that fans out from a loopback
port to many distinct upstreams is a router regardless of what it's named, and a
process connected to a known local-gateway port (OmniRoute/LiteLLM) is a client
using one. That is the `observed` evidence tier — stronger than `configured`.

Deliberate no-egress scope (see docs/fleet-posture.md): this reads the connection
table (`lsof -n`, no DNS) and never makes a network call. Two Tier-2 signals are
therefore OUT of scope here and stay deferred:
  * IP→operator attribution — a snapshot yields upstream IPs, and resolving an IP
    to a PRC operator needs reverse-DNS/RDAP (egress) — that is the prober's
    authorized `assess`/`network` path, not this no-egress collector.
  * JA3/TLS ClientHello fingerprint — needs raw packet capture (pcap/root).

Like the trust-store watch, this reads a privacy surface (per-process connections),
so it is inert until `--i-am-authorized`, and it REFUSES (never reports clean) when
the connection table cannot be read.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

from ..gateways import KNOWN_LOCAL_GATEWAYS

# Loopback remote addresses (lsof -n emits IPs, not "localhost").
_LOOPBACK = {"127.0.0.1", "::1"}
# A router's LISTEN side may be loopback OR a wildcard bind; lsof -nP renders an
# all-interfaces bind as `*` (or `::`), NOT `0.0.0.0` — the standard LiteLLM
# `--host 0.0.0.0` deployment shows as `*:4000`. Missing this hid the router shape.
_LISTEN_ROUTER_HOSTS = _LOOPBACK | {"*", "0.0.0.0", "::"}  # noqa: S104 (recognition, not a bind)
# Loopback ports of known local gateways (a connection whose remote is one of
# these is a client routing through that gateway).
_GATEWAY_PORTS = {port for _h, port in KNOWN_LOCAL_GATEWAYS.values()}

# Default: how many distinct non-loopback upstreams from one loopback listener
# reads as a router fan-out rather than incidental.
DEFAULT_MIN_UPSTREAMS = 8

# cmd + pid at the start; the `addr-pair (STATE)` at the end of an lsof -nP line.
_CONN = re.compile(
    r"^(?P<cmd>\S+)\s+(?P<pid>\d+)\b.*\s(?P<name>\S+->\S+|\S+)\s+\((?P<state>[A-Z]+)\)\s*$")

# Classifications
ROUTER_FANOUT = "router-fanout"          # a loopback listener fanning out to many upstreams
ROUTED_VIA_GATEWAY = "routed-via-gateway"  # a client connected to a known local-gateway port


class EgressUnavailable(Exception):
    """The connection table could not be read (unsupported OS / reader failed).
    Raised instead of returning [] so an unreadable host is never reported clean."""


@dataclass(frozen=True)
class Conn:
    command: str
    pid: str
    laddr_host: str
    laddr_port: int | None
    raddr_host: str          # "" for a LISTEN line
    raddr_port: int | None
    state: str


@dataclass(frozen=True)
class EgressFinding:
    classification: str
    command: str
    pid: str
    detail: str
    upstreams: int = 0
    notes: list[str] = field(default_factory=list)


@dataclass(frozen=True)
class EgressResult:
    findings: list[EgressFinding]
    connections: int
    privileged: bool = True   # False = only the current user's sockets were visible

    @property
    def headline(self) -> str:
        fan = sum(1 for f in self.findings if f.classification == ROUTER_FANOUT)
        via = sum(1 for f in self.findings if f.classification == ROUTED_VIA_GATEWAY)
        scope = "" if self.privileged else " (current user's sockets only)"
        return (f"observed egress: {self.connections} connections{scope}, "
                f"{fan} router fan-out, {via} routed-via-gateway")


def is_privileged() -> bool:
    """True if the process can see all sockets (root). An unprivileged scan sees
    only the current user's connections, so a zero-finding result must be qualified
    (a router running as root/another user is otherwise invisible)."""
    import os
    return hasattr(os, "geteuid") and os.geteuid() == 0


def _split_addr(a: str) -> tuple[str, int | None]:
    """`host:port` / `[v6]:port` / `*:port` -> (host, port|None)."""
    a = a.strip()
    if "]" in a:                                   # [v6]:port
        host, _, port = a.rpartition("]:")
        host = host.lstrip("[")
    else:
        host, _, port = a.rpartition(":")
    try:
        return host, int(port)
    except ValueError:
        return (host or a), None


def parse_lsof(text: str) -> list[Conn]:
    """Parse `lsof -nP -iTCP` output into Conn records (ESTABLISHED + LISTEN)."""
    conns: list[Conn] = []
    for line in (text or "").splitlines():
        m = _CONN.match(line)
        if not m:
            continue
        name, state = m.group("name"), m.group("state")
        if "->" in name:
            local, remote = name.split("->", 1)
            lh, lp = _split_addr(local)
            rh, rp = _split_addr(remote)
        else:
            lh, lp = _split_addr(name)
            rh, rp = "", None
        conns.append(Conn(m.group("cmd"), m.group("pid"), lh, lp, rh, rp, state))
    return conns


def analyze(conns: list[Conn], *, min_upstreams: int = DEFAULT_MIN_UPSTREAMS,
            privileged: bool = True) -> EgressResult:
    """Derive the loopback/wildcard fan-out + routed-via-gateway findings."""
    findings: list[EgressFinding] = []

    # 1. Router fan-out: a process LISTENing on a loopback OR wildcard port with
    #    many distinct non-loopback upstream hosts (the gateway itself).
    listens_router: dict[tuple[str, str], set[int]] = {}
    upstreams: dict[tuple[str, str], set[str]] = {}
    for c in conns:
        key = (c.command, c.pid)
        if c.state == "LISTEN" and c.laddr_host in _LISTEN_ROUTER_HOSTS:
            listens_router.setdefault(key, set()).add(c.laddr_port or 0)
        if c.state == "ESTABLISHED" and c.raddr_host and c.raddr_host not in _LOOPBACK:
            upstreams.setdefault(key, set()).add(c.raddr_host)
    for key, ports in listens_router.items():
        n = len(upstreams.get(key, set()))
        if n >= min_upstreams:
            cmd, pid = key
            findings.append(EgressFinding(
                ROUTER_FANOUT, cmd, pid,
                f"listener on {sorted(ports)} fans out to {n} distinct upstream hosts",
                upstreams=n,
                notes=["router shape regardless of name; upstream IPs need an active "
                       "probe to attribute (no-egress collector)"]))

    # 2. Routed-via-gateway: any process connected to a known local-gateway port.
    #    Port 20128 is safely-unusual (OmniRoute); 4000 is a common dev port, so
    #    hedge that call rather than auto-accuse (never over-claim).
    seen: set[tuple[str, str, int]] = set()
    for c in conns:
        if (c.state == "ESTABLISHED" and c.raddr_host in _LOOPBACK
                and c.raddr_port in _GATEWAY_PORTS):
            k = (c.command, c.pid, c.raddr_port)
            if k in seen:
                continue
            seen.add(k)
            if c.raddr_port == 4000:
                detail = ("connected to local port 4000 — a port LiteLLM commonly uses, "
                          "but also a generic dev port; corroborate with the config scan "
                          "before treating as a gateway")
            else:
                detail = (f"connected to local gateway port {c.raddr_port} "
                          f"({c.raddr_host}) — routing AI traffic through a local gateway")
            findings.append(EgressFinding(ROUTED_VIA_GATEWAY, c.command, c.pid, detail))

    return EgressResult(findings=findings, connections=len(conns), privileged=privileged)


def default_connections() -> list[Conn]:
    """Read the host's TCP connection table (local-only, no DNS → no egress).
    Raises EgressUnavailable on an unsupported OS or a reader failure."""
    import platform
    import subprocess

    if platform.system() not in ("Darwin", "Linux"):
        raise EgressUnavailable(
            f"observed-egress scan is not implemented on {platform.system()}")
    try:
        out = subprocess.run(
            ["lsof", "-nP", "-iTCP", "-sTCP:ESTABLISHED,LISTEN"],
            capture_output=True, text=True, timeout=30)
    except (OSError, subprocess.SubprocessError) as e:
        raise EgressUnavailable(f"could not run `lsof` to read the connection table: {e}")
    if out.returncode not in (0, 1):
        raise EgressUnavailable(f"`lsof` returned an error (exit {out.returncode})")
    # lsof exits 1 both for "found nothing" AND on errors. A real host always has
    # listeners, so exit 1 with EMPTY output is far more likely a blocked/errored
    # read than a genuinely empty table — refuse rather than report clean.
    if out.returncode == 1 and not out.stdout.strip():
        raise EgressUnavailable("`lsof` exited 1 with no output — likely a read error, "
                                "not an empty connection table")
    return parse_lsof(out.stdout)
