# app/diffing.py
from __future__ import annotations

from typing import Dict, Any, List, Tuple


def _index_resources(state: Dict[str, Any]) -> Dict[str, Dict[str, Any]]:
    res = state.get("resources", [])
    out: Dict[str, Dict[str, Any]] = {}
    for r in res:
        rid = r.get("id")
        if rid:
            out[str(rid)] = r
    return out


def diff_resources(
    baseline_state: Dict[str, Any],
    current_state: Dict[str, Any],
) -> Dict[str, Any]:
    """
    Compare resources between 2 snapshots.
    Returns:
      - added: [resource_id]
      - removed: [resource_id]
      - changed: [{resource_id, changed_fields}]
    """
    b = _index_resources(baseline_state)
    c = _index_resources(current_state)

    b_ids = set(b.keys())
    c_ids = set(c.keys())

    added = sorted(list(c_ids - b_ids))
    removed = sorted(list(b_ids - c_ids))

    changed: List[Dict[str, Any]] = []
    common = sorted(list(b_ids & c_ids))

    for rid in common:
        br = b[rid]
        cr = c[rid]

        # shallow diff on fields (good enough for PFA)
        fields = set(br.keys()) | set(cr.keys())
        diffs = []
        for f in sorted(fields):
            if br.get(f) != cr.get(f):
                diffs.append({"field": f, "before": br.get(f), "after": cr.get(f)})

        if diffs:
            changed.append({"resource_id": rid, "changes": diffs})

    return {
        "added": added,
        "removed": removed,
        "changed": changed,
        "baseline_count": len(b_ids),
        "current_count": len(c_ids),
    }


def _finding_key(f: Dict[str, Any]) -> Tuple[str, str]:
    return (str(f.get("rule_id")), str(f.get("resource_id")))


def diff_findings(baseline_findings, current_findings) -> Dict[str, Any]:
    # ✅ ignore suppressed findings (covered by composites)
    bset = {_finding_key(f) for f in baseline_findings if not f.get("suppressed", False)}
    cset = {_finding_key(f) for f in current_findings if not f.get("suppressed", False)}

    added = sorted(list(cset - bset))
    removed = sorted(list(bset - cset))
    persisted = sorted(list(bset & cset))

    return {
        "added": [{"rule_id": a[0], "resource_id": a[1]} for a in added],
        "removed": [{"rule_id": r[0], "resource_id": r[1]} for r in removed],
        "persisted": [{"rule_id": p[0], "resource_id": p[1]} for p in persisted],
        "baseline_count": len(bset),
        "current_count": len(cset),
    }

def build_diff_graph_dot(current_rg, baseline_rg, resource_delta: dict) -> str:
    """
    Build a DOT graph highlighting resource differences.
    resource_delta expected shape:
      - added:   list[str] or list[dict]
      - removed: list[str] or list[dict]
      - changed: list[dict] (typical) or list[str]
    """

    def _to_id_set(x):
        if not x:
            return set()
        if isinstance(x, dict):
            # if some implementation returns dict instead of list
            x = [x]
        out = set()
        for item in x:
            if isinstance(item, str):
                out.add(item)
            elif isinstance(item, dict):
                # try common keys
                rid = item.get("id") or item.get("resource_id") or item.get("resourceId") or item.get("name")
                if rid is not None:
                    out.add(str(rid))
        return out

    added = _to_id_set(resource_delta.get("added", []))
    removed = _to_id_set(resource_delta.get("removed", []))
    changed = _to_id_set(resource_delta.get("changed", []))

    dot = ["digraph G {"]
    dot.append('  node [shape=box];')

    # Baseline nodes (removed/changed highlighted)
    for node in baseline_rg.graph.nodes():
        n = str(node)
        if n in removed:
            dot.append(f'"{n}" [style=filled, fillcolor="red"];')
        elif n in changed:
            dot.append(f'"{n}" [style=filled, fillcolor="yellow"];')
        else:
            dot.append(f'"{n}";')

    # Current nodes (added highlighted)
    for node in current_rg.graph.nodes():
        n = str(node)
        if n in added:
            dot.append(f'"{n}" [style=filled, fillcolor="green"];')

    # Edges (current graph)
    for u, v in current_rg.graph.edges():
        dot.append(f'"{str(u)}" -> "{str(v)}";')

    dot.append("}")
    return "\n".join(dot)