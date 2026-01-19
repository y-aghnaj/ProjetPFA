from dataclasses import dataclass
from typing import List, Dict

SEVERITY_PENALTY = {
    "LOW": 3,
    "MEDIUM": 7,
    "HIGH": 15,
    "CRITICAL": 25
}

@dataclass
class ScoreReport:
    security_score: int
    performance_score: int
    global_score: int
    weights: Dict[str, float]
    penalties: List[dict]

    def to_dict(self):
        return {
            "security_score": self.security_score,
            "performance_score": self.performance_score,
            "global_score": self.global_score,
            "weights": self.weights,
            "penalties": self.penalties
        }

def clamp(x: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, x))

class ScoringEngine:
    def __init__(self, security_weight: float = 0.7, performance_weight: float = 0.3):
        if abs((security_weight + performance_weight) - 1.0) > 1e-9:
            raise ValueError("Weights must sum to 1.0")
        self.security_weight = security_weight
        self.performance_weight = performance_weight

    def compute(self, findings) -> ScoreReport:
        # For now: classify by rule_id prefix
        security_penalties = []
        performance_penalties = []

        for f in findings:
            penalty = SEVERITY_PENALTY.get(f.severity, 5)
            entry = {
                "rule_id": f.rule_id,
                "resource_id": f.resource_id,
                "severity": f.severity,
                "penalty": penalty,
                "message": f.message,
                "responsibility": f.responsibility
            }

            if f.rule_id.startswith("OCI.SEC."):
                security_penalties.append(entry)
            elif f.rule_id.startswith("OCI.PERF."):
                performance_penalties.append(entry)
            else:
                # default: count as security
                security_penalties.append(entry)

        security_score = 100 - sum(p["penalty"] for p in security_penalties)
        performance_score = 100 - sum(p["penalty"] for p in performance_penalties)

        security_score = clamp(security_score)
        performance_score = clamp(performance_score)

        global_score = int(
            round(security_score * self.security_weight + performance_score * self.performance_weight)
        )

        penalties = security_penalties + performance_penalties

        return ScoreReport(
            security_score=security_score,
            performance_score=performance_score,
            global_score=global_score,
            weights={"security": self.security_weight, "performance": self.performance_weight},
            penalties=penalties
        )
