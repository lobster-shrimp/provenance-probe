"""Sub-agent call graph (E6).

An agent spawns sub-agents (and tools); each does model calls. When the trace
carries span parentage (OpenTelemetry `spanId`/`parentSpanId`) or the proxy
carries `X-Provenance-Parent`, we can nest the flat per-step board into the tree
that actually ran — so you see *which* step spawned the sub-call that switched
models or leaked data.

    build_tree(rows) -> [root nodes], each {**row, "children": [...]}

Blind spot (documented): a sub-agent that calls a DIFFERENT, un-proxied backend,
or whose spans aren't exported, never reaches the recorder — it can't appear in
the graph. Steps whose parent id is unknown are attached at the root so nothing
is silently dropped.
"""
from __future__ import annotations


def build_tree(rows: list[dict]) -> list[dict]:
    """Nest scored step rows by `parent_id` -> `span_id`. Rows without a span id,
    or whose parent is missing/cyclic, are roots (nothing is dropped)."""
    by_id: dict[str, dict] = {}
    for r in rows:                       # first span wins (adversarial dup span ids)
        sid = r.get("span_id")
        if sid and sid not in by_id:
            by_id[sid] = r
    nodes = {id(r): {**r, "children": []} for r in rows}

    def in_cycle(r: dict) -> bool:
        seen, cur = set(), r
        while cur is not None:
            sid = cur.get("span_id")
            if sid in seen:
                return True
            seen.add(sid)
            cur = by_id.get(cur.get("parent_id"))
        return False

    roots: list[dict] = []
    for r in rows:
        node = nodes[id(r)]
        parent_row = by_id.get(r.get("parent_id"))
        if parent_row is not None and parent_row is not r and not in_cycle(r):
            nodes[id(parent_row)]["children"].append(node)
        else:
            roots.append(node)   # missing/self/cyclic parent -> attach at root
    return roots or list(nodes.values())


def has_structure(rows: list[dict]) -> bool:
    """True when any row carries a resolvable parent link (a real tree exists)."""
    ids = {r["span_id"] for r in rows if r.get("span_id")}
    return any(r.get("parent_id") in ids for r in rows)


def flatten(tree: list[dict]) -> list[dict]:
    """Depth-first flatten (roots then children), ITERATIVE (explicit stack) so an
    arbitrarily deep chain can't raise RecursionError. Depth is reported, not capped
    — the caller renders a flat list, so there's no nesting to overflow."""
    out: list[dict] = []
    stack = [(root, 0) for root in reversed(tree)]
    while stack:
        node, depth = stack.pop()
        out.append({**{k: v for k, v in node.items() if k != "children"}, "depth": depth})
        for child in reversed(node.get("children", [])):
            stack.append((child, depth + 1))
    return out
