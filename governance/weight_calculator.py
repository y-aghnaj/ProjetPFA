#weight_calculator.py
from __future__ import annotations
from dataclasses import dataclass
from typing import Dict, Any

from governance.waf import PILLARS

# ✅ source unique de vérité
DEFAULT_PILLAR_WEIGHTS: Dict[str, float] = {
    "SECURITY": 0.30,
    "RELIABILITY": 0.20,
    "PERFORMANCE": 0.15,
    "COST": 0.15,
    "OPERATIONAL_EXCELLENCE": 0.20,
}


@dataclass
class WeightContext:
    provider: str
    snapshot: Dict[str, Any]
    # graph: Any | None = None
    # findings: list | None = None


def normalize(weights: Dict[str, float]) -> Dict[str, float]:
    cleaned = {p: float(weights.get(p, 0.0)) for p in PILLARS}
    for k, v in cleaned.items():
        if v < 0:
            cleaned[k] = 0.0
    total = sum(cleaned.values())
    if total <= 0:
        raise ValueError("Invalid pillar weights: sum must be > 0")
    return {k: v / total for k, v in cleaned.items()}


class WeightCalculator:
    """Seul composant autorisé à gérer les poids des piliers."""
    def compute_pillar_weights(self, ctx: WeightContext) -> Dict[str, float]:
        # Algo plus tard. Pour le moment: poids par défaut.
        return normalize(DEFAULT_PILLAR_WEIGHTS)