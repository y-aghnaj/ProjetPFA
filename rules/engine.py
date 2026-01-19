from dataclasses import dataclass, asdict
from typing import Callable, Any


@dataclass
class Finding:
    rule_id: str
    resource_id: str
    severity: str          # LOW | MEDIUM | HIGH | CRITICAL
    responsibility: str    # CUSTOMER | CSP | SHARED
    message: str
    evidence: dict

    def to_dict(self):
        return asdict(self)


class RuleEngine:
    def __init__(self):
        self.rules: list[Callable[[str, dict], Finding | None]] = []

    def register(self, rule_fn: Callable[[str, dict], Finding | None]):
        self.rules.append(rule_fn)

    def run(self, graph) -> list[Finding]:
        findings: list[Finding] = []
        for node_id, attrs in graph.nodes(data=True):
            for rule in self.rules:
                f = rule(node_id, attrs)
                if f is not None:
                    findings.append(f)
        return findings
