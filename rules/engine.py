# rules/engine.py
from __future__ import annotations

from dataclasses import dataclass, field, asdict
from typing import Callable, Any, Optional, List, Dict, Union
import inspect


# --- Finding enriched for audit-grade explainability + WAF traceability ---
@dataclass
class Finding:
    rule_id: str
    resource_id: str
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    responsibility: str    # CUSTOMER | CSP | SHARED
    message: str
    evidence: dict

    # Explainability fields
    risk: float = 0.0                 # normalized 0..1
    confidence: float = 1.0           # 0..1
    impact: List[str] = field(default_factory=list)       # e.g. ["data_exposure", "initial_access"]
    context: Dict[str, Any] = field(default_factory=dict) # path, tags, compartment, etc.

    # --- Well-Architected Framework mapping (explicit) ---
    # primary pillar used by scoring (simple + aligned with prof remarks)
    primary_pillar: str = "SECURITY"  # SECURITY | RELIABILITY | PERFORMANCE | COST | OPERATIONAL_EXCELLENCE
    # optional multi-pillar tagging (future-proof)
    pillars: List[str] = field(default_factory=list)

    # --- Standards traceability ---
    # each ref should look like:
    # {"framework":"WAF|CIS|ISO27001|OCI", "control_id":"SEC-01", "title":"...", "url":"..."}
    references: List[Dict[str, str]] = field(default_factory=list)

    # Dedup/suppression helpers
    suppressed: bool = False
    covered_by: List[str] = field(default_factory=list)   # list of composite rule_ids that cover it

    def to_dict(self):
        # Ensure pillars always contains primary_pillar at minimum (nice invariant for UI/export)
        if not self.pillars:
            self.pillars = [self.primary_pillar]
        elif self.primary_pillar not in self.pillars:
            self.pillars.insert(0, self.primary_pillar)
        return asdict(self)


NodeRule = Callable[..., Optional[Finding]]
GraphRule = Callable[..., List[Finding]]


class RuleEngine:
    """
    Supports:
      - node rules: rule(node_id, attrs) OR rule(node_id, attrs, graph)
      - graph rules: rule(graph) -> list[Finding]
    Also supports post-processing for composite coverage/suppression.
    """

    def __init__(self):
        self.node_rules: List[NodeRule] = []
        self.graph_rules: List[GraphRule] = []

    def register(self, rule_fn: Union[NodeRule, GraphRule], kind: str = "node"):
        if kind not in ("node", "graph"):
            raise ValueError("kind must be 'node' or 'graph'")
        if kind == "node":
            self.node_rules.append(rule_fn)  # type: ignore
        else:
            self.graph_rules.append(rule_fn)  # type: ignore

    def run(self, graph) -> List[Finding]:
        findings: List[Finding] = []

        # 1) Node-based rules (backward compatible signatures)
        for node_id, attrs in graph.nodes(data=True):
            for rule in self.node_rules:
                f = self._call_node_rule(rule, node_id, attrs, graph)
                if f is not None:
                    findings.append(f)

        # 2) Graph-based rules
        for grule in self.graph_rules:
            out = grule(graph)
            if out:
                findings.extend(out)

        # 3) Post-processing: apply composite coverage/suppression
        self._apply_composite_coverage(findings)

        # 4) Optional: sort by severity then risk
        # NOTE: we sort LOW->CRITICAL by rank, and higher risk first inside same severity
        findings.sort(key=lambda f: (self._severity_rank(f.severity), -float(getattr(f, "risk", 0.0))), reverse=False)

        return findings

    def _call_node_rule(self, rule: NodeRule, node_id: str, attrs: dict, graph) -> Optional[Finding]:
        # Allow rule(node_id, attrs) or rule(node_id, attrs, graph)
        sig = inspect.signature(rule)
        if len(sig.parameters) >= 3:
            return rule(node_id, attrs, graph)  # type: ignore
        return rule(node_id, attrs)  # type: ignore

    def _severity_rank(self, sev: str) -> int:
        return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 0)

    def _apply_composite_coverage(self, findings: List[Finding]) -> None:
        """
        If a composite finding exists, suppress covered atomic ones on same resource_id.
        Convention: composite rules set context['covers'] = ["RULE_ID_1", "RULE_ID_2", ...]
        """
        by_resource: Dict[str, List[Finding]] = {}
        for f in findings:
            by_resource.setdefault(f.resource_id, []).append(f)

        for rid, flist in by_resource.items():
            composites = [f for f in flist if f.context.get("covers")]
            if not composites:
                continue

            covered_rule_ids: List[str] = []
            for cf in composites:
                covers = cf.context.get("covers", [])
                if isinstance(covers, list):
                    covered_rule_ids.extend([str(x) for x in covers])

            # suppress atomics covered by any composite
            for f in flist:
                if f.rule_id in covered_rule_ids and not f.context.get("covers"):
                    f.suppressed = True
                    f.covered_by = sorted(set([c.rule_id for c in composites]))
