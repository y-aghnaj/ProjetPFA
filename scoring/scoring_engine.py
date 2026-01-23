# scoring/waf_scoring_engine.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, List, Any

SEVERITY_BASE = {
    "LOW": 3,
    "MEDIUM": 7,
    "HIGH": 15,
    "CRITICAL": 25,
}

PILLARS = ["SECURITY", "RELIABILITY", "PERFORMANCE", "COST", "OPERATIONAL_EXCELLENCE"]

def clamp(x: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, x))

@dataclass
class WAFScoreReport:
    pillar_scores: Dict[str, int]
    global_score: int
    weights: Dict[str, float]
    penalties: List[dict]

    # Backward-compat for old UI/LLM fields
    security_score: int
    performance_score: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pillar_scores": self.pillar_scores,
            "global_score": self.global_score,
            "weights": self.weights,
            "penalties": self.penalties,
            # compatibility
            "security_score": self.security_score,
            "performance_score": self.performance_score,
        }

class WAFScoringEngine:
    """
    WAF pillar-based scoring:
    - Start each pillar at 100
    - Each finding produces a penalty
    - Penalty is distributed across its pillars (equal split)
    - Risk/confidence can modulate penalty
    """

    def __init__(self, weights: Dict[str, float] | None = None):
        if weights is None:
            # sensible defaults (sum=1)
            weights = {
                "SECURITY": 0.30,
                "RELIABILITY": 0.20,
                "PERFORMANCE": 0.15,
                "COST": 0.15,
                "OPERATIONAL_EXCELLENCE": 0.20,
            }
        self.weights = self._normalize_weights(weights)

    def _normalize_weights(self, w: Dict[str, float]) -> Dict[str, float]:
        cleaned = {p: float(w.get(p, 0.0)) for p in PILLARS}
        s = sum(cleaned.values())
        if s <= 0:
            raise ValueError("At least one WAF pillar weight must be > 0")
        return {p: cleaned[p] / s for p in PILLARS}

    def _penalty_for(self, f) -> int:
        base = SEVERITY_BASE.get(getattr(f, "severity", "MEDIUM"), 7)

        risk = float(getattr(f, "risk", 0.0) or 0.0)          # 0..1
        conf = float(getattr(f, "confidence", 1.0) or 1.0)    # 0..1

        mult = 0.75 + 1.5 * max(0.0, min(1.0, risk))
        pen = int(round(base * mult * max(0.0, min(1.0, conf))))
        return max(1, pen)

    def compute(self, findings: List[Any]) -> WAFScoreReport:
        pillar_penalties: Dict[str, int] = {p: 0 for p in PILLARS}
        explain: List[dict] = []

        for f in findings:
            pillars = getattr(f, "pillars", None) or []
            if not pillars:
                rid = getattr(f, "rule_id", "")
                if rid.startswith("OCI.SEC."):
                    pillars = ["SECURITY"]
                elif rid.startswith("OCI.PERF."):
                    pillars = ["PERFORMANCE", "COST"]
                else:
                    pillars = ["SECURITY"]

            pillars = [p for p in pillars if p in PILLARS]
            if not pillars:
                pillars = ["SECURITY"]

            penalty = self._penalty_for(f)
            share = penalty / len(pillars)

            for p in pillars:
                pillar_penalties[p] += int(round(share))

            explain.append({
                "rule_id": getattr(f, "rule_id", ""),
                "resource_id": getattr(f, "resource_id", ""),
                "severity": getattr(f, "severity", ""),
                "risk": float(getattr(f, "risk", 0.0) or 0.0),
                "confidence": float(getattr(f, "confidence", 1.0) or 1.0),
                "pillars": pillars,
                "penalty": penalty,
                "message": getattr(f, "message", ""),
                "responsibility": getattr(f, "responsibility", ""),
            })

        pillar_scores = {p: clamp(100 - pillar_penalties[p]) for p in PILLARS}
        global_score = int(round(sum(pillar_scores[p] * self.weights[p] for p in PILLARS)))

        security_score = pillar_scores["SECURITY"]
        performance_score = pillar_scores["PERFORMANCE"]

        return WAFScoreReport(
            pillar_scores=pillar_scores,
            global_score=global_score,
            weights=self.weights,
            penalties=explain,
            security_score=security_score,
            performance_score=performance_score,
        )
