# governance/waf.py
from __future__ import annotations

from dataclasses import dataclass
from typing import Dict, List, Any, Optional

PILLARS = ["SECURITY", "RELIABILITY", "PERFORMANCE", "COST", "OPERATIONAL_EXCELLENCE"]

# Base penalty per severity (kept simple + explainable)
SEVERITY_BASE = {
    "LOW": 3,
    "MEDIUM": 7,
    "HIGH": 15,
    "CRITICAL": 25,
}

DEFAULT_WAF_WEIGHTS = {
    "SECURITY": 0.30,
    "RELIABILITY": 0.20,
    "PERFORMANCE": 0.15,
    "COST": 0.15,
    "OPERATIONAL_EXCELLENCE": 0.20,
}

# --- Standards traceability (minimal but explicit) ---
# You can enrich these IDs later with OCI WAF/CIS/ISO mappings.
RULE_STANDARD_MAP: Dict[str, Dict[str, Any]] = {
    # Buckets
    "OCI.SEC.BUCKET.PUBLIC": {
        "pillars": ["SECURITY"],
        "references": [
            {"standard": "WAF", "id": "SEC-01", "name": "Protect data at rest and in transit"},
            {"standard": "CIS", "id": "CIS-OCI-ObjectStorage-1", "name": "Restrict public bucket access"},
            {"standard": "ISO27001", "id": "A.8.2", "name": "Information classification & handling"},
        ],
    },
    "OCI.SEC.BUCKET.ENCRYPTION": {
        "pillars": ["SECURITY"],
        "references": [
            {"standard": "WAF", "id": "SEC-01", "name": "Protect data at rest and in transit"},
            {"standard": "ISO27001", "id": "A.10.1", "name": "Cryptographic controls"},
        ],
    },
    "OCI.SEC.BUCKET.LOGGING_DISABLED": {
        "pillars": ["OPERATIONAL_EXCELLENCE", "SECURITY"],
        "references": [
            {"standard": "WAF", "id": "OPS-02", "name": "Observe and monitor systems"},
            {"standard": "ISO27001", "id": "A.12.4", "name": "Logging and monitoring"},
        ],
    },
    "OCI.SEC.BUCKET.VERSIONING_DISABLED": {
        "pillars": ["RELIABILITY"],
        "references": [
            {"standard": "WAF", "id": "REL-01", "name": "Plan for failure and recovery"},
        ],
    },

    # DB
    "OCI.SEC.DB.ENCRYPTION": {
        "pillars": ["SECURITY"],
        "references": [
            {"standard": "WAF", "id": "SEC-01", "name": "Protect data at rest and in transit"},
            {"standard": "ISO27001", "id": "A.10.1", "name": "Cryptographic controls"},
        ],
    },
    "OCI.SEC.DB.PUBLIC_ENDPOINT": {
        "pillars": ["SECURITY", "RELIABILITY"],
        "references": [
            {"standard": "WAF", "id": "SEC-02", "name": "Network segmentation and least privilege"},
            {"standard": "WAF", "id": "REL-02", "name": "Reduce blast radius"},
        ],
    },
    "OCI.SEC.DB.BACKUP_DISABLED": {
        "pillars": ["RELIABILITY"],
        "references": [
            {"standard": "WAF", "id": "REL-01", "name": "Backups and disaster recovery"},
        ],
    },

    # Network exposure
    "OCI.SEC.NET.SSH_PUBLIC": {
        "pillars": ["SECURITY"],
        "references": [
            {"standard": "WAF", "id": "SEC-02", "name": "Network security / minimize exposure"},
            {"standard": "CIS", "id": "CIS-Network-1", "name": "Restrict management ports"},
        ],
    },
    "OCI.SEC.NET.RDP_PUBLIC": {
        "pillars": ["SECURITY"],
        "references": [
            {"standard": "WAF", "id": "SEC-02", "name": "Network security / minimize exposure"},
        ],
    },

    # Graph/path based
    "OCI.SEC.PATH.PUBLIC_SSH_TO_DB": {
        "pillars": ["SECURITY", "RELIABILITY"],
        "references": [
            {"standard": "WAF", "id": "SEC-03", "name": "Detect and respond to threats"},
            {"standard": "WAF", "id": "REL-02", "name": "Limit lateral movement / blast radius"},
        ],
    },

    # Perf/cost
    "OCI.PERF.COMPUTE.RIGHTSIZING": {
        "pillars": ["PERFORMANCE", "COST"],
        "references": [
            {"standard": "WAF", "id": "PERF-01", "name": "Use efficient resources"},
            {"standard": "WAF", "id": "COST-01", "name": "Adopt a consumption model"},
        ],
    },
}


def clamp(x: int, low: int = 0, high: int = 100) -> int:
    return max(low, min(high, x))


def infer_waf_metadata(rule_id: str) -> Dict[str, Any]:
    """
    Returns:
      - pillars: List[str]
      - references: List[Dict[str,str]]
    Defaults to SECURITY if unknown.
    """
    meta = RULE_STANDARD_MAP.get(rule_id, None)
    if not meta:
        return {"pillars": ["SECURITY"], "references": [{"standard": "WAF", "id": "SEC-UNK", "name": "Unmapped control"}]}
    return {"pillars": meta.get("pillars", ["SECURITY"]), "references": meta.get("references", [])}


@dataclass
class WAFScoreReport:
    pillar_scores: Dict[str, int]
    global_score: int
    weights: Dict[str, float]
    penalties: List[dict]

    # Backward-compat (UI + report template)
    security_score: int
    performance_score: int

    def to_dict(self) -> Dict[str, Any]:
        return {
            "pillar_scores": self.pillar_scores,
            "global_score": self.global_score,
            "weights": self.weights,
            "penalties": self.penalties,
            "security_score": self.security_score,
            "performance_score": self.performance_score,
        }


class WAFScoringEngine:
    """
    WAF pillar-based scoring:
      - Each pillar starts at 100.
      - Each finding produces a penalty (severity-based) modulated by risk/confidence.
      - Penalty is split across the finding's pillars.
      - Global score is weighted sum of pillar scores.
    """

    def __init__(self, weights: Optional[Dict[str, float]] = None):
        self.weights = self._normalize_weights(weights or DEFAULT_WAF_WEIGHTS)

    def _normalize_weights(self, w: Dict[str, float]) -> Dict[str, float]:
        cleaned = {p: float(w.get(p, 0.0)) for p in PILLARS}
        s = sum(cleaned.values())
        if s <= 0:
            raise ValueError("At least one WAF pillar weight must be > 0")
        return {p: cleaned[p] / s for p in PILLARS}

    def _penalty_for(self, f) -> int:
        base = SEVERITY_BASE.get(str(getattr(f, "severity", "MEDIUM")).upper(), 7)

        risk = float(getattr(f, "risk", 0.0) or 0.0)       # 0..1
        conf = float(getattr(f, "confidence", 1.0) or 1.0) # 0..1

        risk = max(0.0, min(1.0, risk))
        conf = max(0.0, min(1.0, conf))

        # explainable multiplier (simple and stable)
        # risk=0 -> 0.75x, risk=1 -> 2.25x
        mult = 0.75 + 1.5 * risk
        pen = int(round(base * mult * conf))
        return max(1, pen)

    def compute(self, findings: List[Any]) -> WAFScoreReport:
        pillar_penalties: Dict[str, int] = {p: 0 for p in PILLARS}
        explain: List[dict] = []

        for f in findings:
            if getattr(f, "suppressed", False):
                continue

            pillars = list(getattr(f, "pillars", None) or [])
            if not pillars:
                meta = infer_waf_metadata(getattr(f, "rule_id", ""))
                pillars = list(meta.get("pillars", ["SECURITY"]))

            pillars = [p for p in pillars if p in PILLARS] or ["SECURITY"]

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
                "references": getattr(f, "references", []) or [],
            })

        pillar_scores = {p: clamp(100 - pillar_penalties[p]) for p in PILLARS}
        global_score = int(round(sum(pillar_scores[p] * self.weights[p] for p in PILLARS)))

        return WAFScoreReport(
            pillar_scores=pillar_scores,
            global_score=global_score,
            weights=self.weights,
            penalties=explain,
            security_score=pillar_scores["SECURITY"],
            performance_score=pillar_scores["PERFORMANCE"],
        )
