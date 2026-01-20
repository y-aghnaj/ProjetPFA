import json
import os
from pathlib import Path
from typing import Any, Dict, List

from graph.resource_graph import ResourceGraph
from rules.engine import RuleEngine
from rules.security_rules import (
    rule_public_object_storage_bucket,
    rule_bucket_encryption,
    rule_db_encryption,
    rule_ssh_open_to_world,
)
from scoring.scoring_engine import ScoringEngine
from recommendations.generator import generate_recommendations


def load_state(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def scenario_path(name_or_path: str) -> str:
    p = Path(name_or_path)
    if p.exists():
        return str(p)
    return str(Path("data") / "scenarios" / f"{name_or_path}.json")


def build_resource_graph(state: dict) -> ResourceGraph:
    rg = ResourceGraph()
    rg.load_from_state(state)
    return rg


def build_rule_engine() -> RuleEngine:
    engine = RuleEngine()
    engine.register(rule_public_object_storage_bucket)
    engine.register(rule_bucket_encryption)
    engine.register(rule_db_encryption)
    engine.register(rule_ssh_open_to_world)
    # add perf rules later (optional)
    return engine


def run_audit(
    scenario: str,
    security_weight: float = 0.7,
    performance_weight: float = 0.3,
    export_json: bool = True,
    report_json_path: str = "reports/report.json",
) -> Dict[str, Any]:
    """
    Runs the full governance audit pipeline and returns a structured dict:
    - summary
    - findings
    - scores
    - recommendations
    """
    state = load_state(scenario_path(scenario))
    rg = build_resource_graph(state)

    engine = build_rule_engine()
    findings = engine.run(rg.graph)

    scorer = ScoringEngine(security_weight=security_weight, performance_weight=performance_weight)
    score_report = scorer.compute(findings)

    recos = generate_recommendations(findings)

    result = {
        "provider": state.get("account", {}).get("provider", "OCI"),
        "scenario": scenario,
        "summary": rg.summary(),
        "findings": [f.to_dict() for f in findings],
        "scores": score_report.to_dict(),
        "recommendations": [r.to_dict() for r in recos],
    }

    if export_json:
        os.makedirs(Path(report_json_path).parent, exist_ok=True)
        with open(report_json_path, "w", encoding="utf-8") as fp:
            json.dump(result, fp, indent=2)

    return result
