# waf.py
from __future__ import annotations

from typing import Dict, List, Any

# Canonical pillar names
P_SECURITY = "SECURITY"
P_RELIABILITY = "RELIABILITY"
P_PERFORMANCE = "PERFORMANCE"
P_COST = "COST"
P_OPS = "OPERATIONAL_EXCELLENCE"

PILLARS = [P_SECURITY, P_RELIABILITY, P_PERFORMANCE, P_COST, P_OPS]

# Default weights (sum to 1.0)
DEFAULT_WAF_WEIGHTS: Dict[str, float] = {
    P_SECURITY: 0.30,
    P_RELIABILITY: 0.20,
    P_PERFORMANCE: 0.15,
    P_COST: 0.15,
    P_OPS: 0.20,
}

def normalize_weights(w: Dict[str, float]) -> Dict[str, float]:
    total = sum(float(v) for v in w.values())
    if total <= 0:
        raise ValueError("Weights sum must be > 0")
    return {k: float(v) / total for k, v in w.items()}

def rule_trace(
    waf_id: str,
    waf_name: str,
    cis_id: str | None = None,
    cis_name: str | None = None,
    iso_id: str | None = None,
    iso_name: str | None = None,
) -> List[Dict[str, str]]:
    refs: List[Dict[str, str]] = [{"standard": "WAF", "id": waf_id, "name": waf_name}]
    if cis_id and cis_name:
        refs.append({"standard": "CIS", "id": cis_id, "name": cis_name})
    if iso_id and iso_name:
        refs.append({"standard": "ISO27001", "id": iso_id, "name": iso_name})
    return refs
