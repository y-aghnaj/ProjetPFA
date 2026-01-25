# scoring_engine.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any, Optional

from waf import DEFAULT_WAF_WEIGHTS, normalize_weights

SEVERITY_PENALTY = {
    "LOW": 3,
    "MEDIUM": 7,
    "HIGH": 15,
    "CRITICAL": 25
}

DEFAULT_PILLAR = "SECURITY"

def clamp(x: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, x))

@dataclass
class ScoreReport:
    # Backward-compatible fields
    security_score: int
    performance_score: int
    global_score: int

    # New WAF fields
    pillar_scores: Dict[str, int]
    waf_weights: Dict[str, float]
    penalties: List[dict]
    penalties_by_pillar: Dict[str, List[dict]]

    def to_dict(self) -> Dict[str, Any]:
        return {
            "security_score": self.security_score,
            "performance_score": self.performance_score,
            "global_score": self.global_score,
            "pillar_scores": self.pillar_scores,
            "waf_weights": self.waf_weights,
            "penalties": self.penalties,
            "penalties_by_pillar": self.penalties_by_pillar,
        }

class ScoringEngine:
    """
    WAF-aligned scoring:
      - Each finding may map to 1..N pillars (finding.pillars)
      - Severity -> base penalty
      - If multiple pillars, split penalty evenly (avoid double counting)
    Keeps compatibility:
      - security_score = pillar SECURITY
      - performance_score = pillar PERFORMANCE
      - global_score = weighted sum of all pillar scores
    """

    def __init__(self, waf_weights: Optional[Dict[str, float]] = None):
        self.waf_weights = normalize_weights(waf_weights or DEFAULT_WAF_WEIGHTS)

    def compute(self, findings) -> ScoreReport:
        penalties_by_pillar: Dict[str, List[dict]] = {p: [] for p in self.waf_weights.keys()}
        all_penalties: List[dict] = []

        for f in findings:
            base_penalty = SEVERITY_PENALTY.get(getattr(f, "severity", "MEDIUM"), 7)

            pillars = getattr(f, "pillars", None)
            if not pillars or not isinstance(pillars, list) or len(pillars) == 0:
                pillars = [DEFAULT_PILLAR]

            # keep only known pillars
            pillars = [p for p in pillars if p in self.waf_weights]
            if not pillars:
                pillars = [DEFAULT_PILLAR]

            split_penalty = base_penalty / float(len(pillars))

            base_entry = {
                "rule_id": f.rule_id,
                "resource_id": f.resource_id,
                "severity": f.severity,
                "responsibility": f.responsibility,
                "message": f.message,
                "risk": getattr(f, "risk", 0.0),
                "confidence": getattr(f, "confidence", 1.0),
                "pillars": pillars,
                "references": getattr(f, "references", []),
            }

            # global (shown once)
            all_penalties.append({**base_entry, "penalty": base_penalty})

            # per pillar (split)
            for p in pillars:
                penalties_by_pillar[p].append({**base_entry, "penalty": split_penalty})

        # pillar scores
        pillar_scores: Dict[str, int] = {}
        for pillar, plist in penalties_by_pillar.items():
            pillar_penalty_sum = sum(float(x["penalty"]) for x in plist)
            pillar_scores[pillar] = clamp(int(round(100 - pillar_penalty_sum)))

        # global WAF weighted score
        global_score = 0.0
        for pillar, w in self.waf_weights.items():
            global_score += pillar_scores.get(pillar, 100) * float(w)
        global_score_int = int(round(global_score))

        security_score = pillar_scores.get("SECURITY", 100)
        performance_score = pillar_scores.get("PERFORMANCE", 100)

        return ScoreReport(
            security_score=security_score,
            performance_score=performance_score,
            global_score=global_score_int,
            pillar_scores=pillar_scores,
            waf_weights=self.waf_weights,
            penalties=all_penalties,
            penalties_by_pillar=penalties_by_pillar,
        )
