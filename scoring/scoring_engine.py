from dataclasses import dataclass
from typing import List, Dict

SEVERITY_RISK = {
    "LOW": 0.05,
    "MEDIUM": 0.12,
    "HIGH": 0.25,
    "CRITICAL": 0.40
}

@dataclass
class ScoreReport:
    security_score: int
    performance_score: int
    global_score: int
    weights: Dict[str, float]
    evidence: List[dict]  # explainability pack

    def to_dict(self):
        return {
            "security_score": self.security_score,
            "performance_score": self.performance_score,
            "global_score": self.global_score,
            "weights": self.weights,
            "evidence": self.evidence
        }

def clamp(x: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, x))

def aggregate_risk(risks: List[float]) -> float:
    """
    Aggregation with saturation:
    Risk = 1 - Π(1 - r_i)
    """
    prod = 1.0
    for r in risks:
        prod *= (1.0 - r)
    return 1.0 - prod

class ScoringEngine:
    def __init__(self, security_weight: float = 0.7, performance_weight: float = 0.3):
        if abs((security_weight + performance_weight) - 1.0) > 1e-9:
            raise ValueError("Weights must sum to 1.0")
        self.security_weight = security_weight
        self.performance_weight = performance_weight

    def compute(self, findings) -> ScoreReport:
        security_findings = []
        performance_findings = []

        explain = []

        for f in findings:
            r = SEVERITY_RISK.get(f.severity, 0.10)

            entry = {
                "rule_id": f.rule_id,
                "resource_id": f.resource_id,
                "severity": f.severity,
                "risk": r,
                "message": f.message,
                "responsibility": f.responsibility
            }

            if f.rule_id.startswith("OCI.SEC."):
                security_findings.append(f)
                entry["pillar"] = "security"
            elif f.rule_id.startswith("OCI.PERF."):
                performance_findings.append(f)
                entry["pillar"] = "performance"
            else:
                security_findings.append(f)
                entry["pillar"] = "security"

            explain.append(entry)

        security_risk = aggregate_risk([SEVERITY_RISK.get(f.severity, 0.10) for f in security_findings])
        performance_risk = aggregate_risk([SEVERITY_RISK.get(f.severity, 0.10) for f in performance_findings])

        security_score = clamp(int(round(100 * (1.0 - security_risk))))
        performance_score = clamp(int(round(100 * (1.0 - performance_risk))))

        global_score = int(round(
            security_score * self.security_weight +
            performance_score * self.performance_weight
        ))

        return ScoreReport(
            security_score=security_score,
            performance_score=performance_score,
            global_score=global_score,
            weights={"security": self.security_weight, "performance": self.performance_weight},
            evidence=explain
        )
