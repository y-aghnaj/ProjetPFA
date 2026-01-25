# scoring/scoring_engine.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any, Optional

# Default WAF pillar weights (sum to 1.0)
DEFAULT_WAF_WEIGHTS: Dict[str, float] = {
    "SECURITY": 0.30,
    "RELIABILITY": 0.20,
    "PERFORMANCE": 0.15,
    "COST": 0.15,
    "OPERATIONAL_EXCELLENCE": 0.20,
}

# Fallback if a finding has no pillars
DEFAULT_PILLAR = "SECURITY"

SEVERITY_PENALTY = {
    "LOW": 3,
    "MEDIUM": 7,
    "HIGH": 15,
    "CRITICAL": 25
}

def clamp(x: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, x))

def _normalize_weights(w: Dict[str, float]) -> Dict[str, float]:
    total = sum(float(v) for v in w.values())
    if total <= 0:
        raise ValueError("Weights sum must be > 0")
    return {k: float(v) / total for k, v in w.items()}

@dataclass
class ScoreReport:
    # Backward compatibility fields
    security_score: int
    performance_score: int
    global_score: int

    # New WAF-aligned fields
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
    - Each finding can map to 1..N pillars (finding.pillars)
    - Penalty is derived from severity (SEVERITY_PENALTY)
    - If multiple pillars, penalty is split equally across them (no double counting)

    Still outputs:
      security_score, performance_score, global_score (compat)
    plus:
      pillar_scores, waf_weights, penalties_by_pillar
    """

    def __init__(self, waf_weights: Optional[Dict[str, float]] = None):
        self.waf_weights = _normalize_weights(waf_weights or DEFAULT_WAF_WEIGHTS)

    def compute(self, findings) -> ScoreReport:
        # penalties_by_pillar[pillar] = list of penalty entries attributed to this pillar
        penalties_by_pillar: Dict[str, List[dict]] = {p: [] for p in self.waf_weights.keys()}

        all_penalties: List[dict] = []

        for f in findings:
            base_penalty = SEVERITY_PENALTY.get(getattr(f, "severity", "MEDIUM"), 7)

            # Determine pillars from finding, fallback if missing
            pillars = getattr(f, "pillars", None)
            if not pillars or not isinstance(pillars, list) or len(pillars) == 0:
                pillars = [DEFAULT_PILLAR]

            # Keep only known pillars (avoid typos)
            pillars = [p for p in pillars if p in self.waf_weights]
            if not pillars:
                pillars = [DEFAULT_PILLAR]

            # Split penalty across pillars to avoid double counting
            split_penalty = base_penalty / float(len(pillars))

            # common entry
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

            # store a global penalty entry (full base penalty shown once)
            all_penalties.append({**base_entry, "penalty": base_penalty})

            # attribute split penalties to each pillar
            for p in pillars:
                penalties_by_pillar[p].append({**base_entry, "penalty": split_penalty})

        # Compute pillar scores
        pillar_scores: Dict[str, int] = {}
        for pillar, plist in penalties_by_pillar.items():
            pillar_penalty_sum = sum(float(x["penalty"]) for x in plist)
            pillar_scores[pillar] = clamp(int(round(100 - pillar_penalty_sum)))

        # WAF global score
        global_score = 0.0
        for pillar, w in self.waf_weights.items():
            global_score += pillar_scores.get(pillar, 100) * float(w)
        global_score_int = int(round(global_score))

        # Backward compatibility:
        # security_score ~= WAF SECURITY pillar
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
