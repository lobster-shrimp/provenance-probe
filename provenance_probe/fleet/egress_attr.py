"""Tier-2 egress attribution (opt-in, EGRESS path): resolve observed upstream IPs.

The no-egress collector (`connections.py`) sees that a process is talking to a set
of remote IPs but deliberately stops there — turning an IP into an operator needs
reverse-DNS + RDAP, which is a network call. This module is that step, kept in a
SEPARATE file so `connections.py` keeps its structural no-egress guarantee: the bare
`fleet-scan --egress` makes no network calls; only `--egress --rdap` (opt-in, and
still gated on `--i-am-authorized`) reaches here. Same boundary shape as
`catalog` (offline) vs `build-catalog` (explicit egress).

It reuses the hardened `probes.network` RDAP path — SSRF denylist (`_blocked_ip`),
the `PRC_ASN_HINTS` heuristic, the vCard `fn` fallback — so there is one audited
lookup path, and joins the PTR hostname to `corpus.py` (`fleet.attribute`) for
"who this host is registered to". Every result is a SUB-CONFIRMED pointer
(`measured=False`): who an IP is registered to, never which model served.
"""
from __future__ import annotations

from dataclasses import dataclass, field

from ..probes import network
from .attribute import attribute, is_aggregator
from .connections import _LOOPBACK

# Cap how many distinct upstream IPs we will RDAP in one run. A network call per IP
# is real egress; an unbounded fan-out (a busy host, or a router with hundreds of
# upstreams) should not silently blast RDAP. Anything beyond the cap is reported as
# dropped (no silent truncation), never hidden.
DEFAULT_MAX_IPS = 64


@dataclass(frozen=True)
class EgressAttribution:
    """One upstream IP resolved to a jurisdiction/operator pointer."""
    ip: str
    ptr: str | None
    country: str | None
    asn_name: str | None
    jurisdiction: str            # RDAP-derived: "PRC" / "PRC-operator" / "unknown"
    operator: str | None         # corpus PTR join: who the host is registered to
    origin: str | None           # corpus origin: "PRC" / "US" / "EU" / ... / None
    confidence: float
    prc_hint: bool               # matched a PRC ASN/operator heuristic (not a geo cert.)
    corpus_source: str | None    # "corpus:<ptr>" when the PTR joined corpus, else None
    processes: list[str] = field(default_factory=list)  # "cmd/pid" holding the connection
    measured: bool = False       # invariant: attribution is never a measured verdict

    @property
    def flagged(self) -> bool:
        """A PRC pointer from EITHER the RDAP geo/ASN signal or a corpus PTR match."""
        return (self.jurisdiction.upper().startswith("PRC")
                or (self.origin or "").upper().startswith(("PRC", "CN")))


@dataclass(frozen=True)
class EgressAttrResult:
    attributions: list[EgressAttribution]
    ips_total: int               # distinct non-loopback remote IPs observed
    ips_resolved: int            # how many were actually looked up (<= cap)
    dropped: int                 # ips_total - ips_resolved (over the cap), surfaced not hidden

    @property
    def flagged(self) -> int:
        return sum(1 for a in self.attributions if a.flagged)

    @property
    def headline(self) -> str:
        tail = f"; {self.dropped} not looked up (over the {DEFAULT_MAX_IPS} cap)" if self.dropped else ""
        return (f"egress attribution: {self.ips_resolved}/{self.ips_total} upstream IPs "
                f"resolved, {self.flagged} PRC-pointing{tail}")


def _distinct_upstreams(conns) -> dict[str, list[str]]:
    """Distinct non-loopback ESTABLISHED remote IPs -> sorted ["cmd/pid", ...]."""
    ips: dict[str, set[str]] = {}
    for c in conns:
        if c.state == "ESTABLISHED" and c.raddr_host and c.raddr_host not in _LOOPBACK:
            ips.setdefault(c.raddr_host, set()).add(f"{c.command}/{c.pid}")
    return {ip: sorted(procs) for ip, procs in ips.items()}


def attribute_egress(conns, *, resolver=None, session=None,
                     do_rdap: bool = True, max_ips: int = DEFAULT_MAX_IPS) -> EgressAttrResult:
    """Resolve the distinct upstream IPs in `conns` to jurisdiction/operator pointers.

    `resolver(ip, session=, do_rdap=)` is injectable so tests need no real network;
    it is resolved LATE (default `network.attribute_ip`) so a monkeypatch of that
    function takes effect (a def-time default would freeze the original reference).
    A private/reserved upstream (rec['skipped']) is dropped from the attributed set
    (nothing to attribute). Deterministic: IPs processed in sorted order.
    """
    resolver = resolver or network.attribute_ip
    upstreams = _distinct_upstreams(conns)
    ips_total = len(upstreams)
    ordered = sorted(upstreams)
    resolved = ordered[:max_ips]
    dropped = ips_total - len(resolved)

    out: list[EgressAttribution] = []
    for ip in resolved:
        # A resolver crash (or a hostile RDAP body slipping past the resolver's own
        # guards) degrades THIS ip to a visible `unknown`, never sinks the batch.
        try:
            rec = resolver(ip, session=session, do_rdap=do_rdap)
        except Exception:
            rec = None
        if not isinstance(rec, dict):
            out.append(EgressAttribution(
                ip=ip, ptr=None, country=None, asn_name=None, jurisdiction="unknown",
                operator=None, origin=None, confidence=0.0, prc_hint=False,
                corpus_source=None, processes=upstreams[ip]))
            continue
        if rec.get("skipped"):
            continue
        ptr = rec.get("ptr")
        operator = origin = corpus_source = None
        if ptr:
            attr = attribute(ptr)
            if attr is not None:
                operator, origin, corpus_source = attr.operator, attr.origin, f"corpus:{ptr}"
            else:
                agg = is_aggregator(ptr)
                if agg is not None:
                    operator, corpus_source = agg, f"corpus:{ptr}"  # aggregator: origin unresolved
        out.append(EgressAttribution(
            ip=ip, ptr=ptr, country=rec.get("country"), asn_name=rec.get("asn_name"),
            jurisdiction=rec.get("jurisdiction", "unknown"), operator=operator, origin=origin,
            confidence=float(rec.get("confidence") or 0.0), prc_hint=bool(rec.get("prc_hint")),
            corpus_source=corpus_source, processes=upstreams[ip]))
    return EgressAttrResult(attributions=out, ips_total=ips_total,
                            ips_resolved=len(resolved), dropped=dropped)
