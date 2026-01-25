# scoring/scoring_engine.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any

from governance.waf import WAFScoringEngine, WAFScoreReport


@dataclass
class ScoreReport:
    """
    Backward-compatible wrapper so the rest of the project can keep using:
      - report.security_score
      - report.performance_score
      - report.global_score
      - report.weights
      - report.penalties
    While also exposing:
      - report.pillar_scores (WAF)
    """
    pillar_scores: Dict[str, int]
    global_score: int
    weights: Dict[str, float]
    penalties: List[dict]

    # compatibility fields
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


class ScoringEngine:
    """
    Scoring engine aligned with the Well-Architected Framework (WAF).
    - Uses governance.waf.WAFScoringEngine internally.
    - Keeps backward compatibility for UI/reporting.
    """

    def __init__(self, waf_weights: Dict[str, float] | None = None, **_ignored):
        self._engine = WAFScoringEngine(weights=waf_weights)

    def compute(self, findings: List[Any]) -> ScoreReport:
        waf: WAFScoreReport = self._engine.compute(findings)

        return ScoreReport(
            pillar_scores=waf.pillar_scores,
            global_score=waf.global_score,
            weights=waf.weights,
            penalties=waf.penalties,
            security_score=waf.security_score,
            performance_score=waf.performance_score,
        )
