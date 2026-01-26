# app/pipeline.py
import json
import os
from pathlib import Path
from typing import Any, Dict, Optional

from graph.resource_graph import ResourceGraph
from rules.engine import RuleEngine
from rules.security_rules import (
    rule_public_object_storage_bucket,
    rule_bucket_encryption,
    rule_bucket_logging_disabled,
    rule_bucket_versioning_disabled,
    rule_db_encryption,
    rule_db_public_endpoint,
    rule_db_backup_disabled,
    rule_ssh_open_to_world,
    rule_rdp_open_to_world,
    rule_bucket_public_no_encrypt_composite,
    rule_db_public_and_no_encrypt,
    graph_rule_public_ssh_path_to_database,
)
from rules.perf_rules import rule_right_sizing_compute
from scoring.scoring_engine import ScoringEngine
from recommendations.generator import generate_recommendations
from recommendations.llm_recommender import generate_llm_recommendations

from app.diffing import diff_resources, diff_findings


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

    # composite first
    engine.register(rule_bucket_public_no_encrypt_composite, kind="node")
    engine.register(rule_db_public_and_no_encrypt, kind="node")

    # atomics
    engine.register(rule_public_object_storage_bucket, kind="node")
    engine.register(rule_bucket_encryption, kind="node")
    engine.register(rule_bucket_logging_disabled, kind="node")
    engine.register(rule_bucket_versioning_disabled, kind="node")

    engine.register(rule_db_encryption, kind="node")
    engine.register(rule_db_public_endpoint, kind="node")
    engine.register(rule_db_backup_disabled, kind="node")

    engine.register(rule_ssh_open_to_world, kind="node")
    engine.register(rule_rdp_open_to_world, kind="node")

    # graph rule
    engine.register(graph_rule_public_ssh_path_to_database, kind="graph")

    # perf
    engine.register(rule_right_sizing_compute, kind="node")

    return engine


def _run_single_audit(
    state: dict,
    scenario_label: str,
    security_weight: float,
    performance_weight: float,
    use_llm_recos: bool,
    llm_model: str,
) -> Dict[str, Any]:
    rg = build_resource_graph(state)
    engine = build_rule_engine()
    findings_objs = engine.run(rg.graph)

    scorer = ScoringEngine()
    score_report = scorer.compute(findings_objs)

    static_recos = generate_recommendations(findings_objs)
    recos = [r.to_dict() for r in static_recos]

    if use_llm_recos and findings_objs:
        try:
            llm_recos = generate_llm_recommendations(
                audit_result={
                    "provider": state.get("account", {}).get("provider", "OCI"),
                    "scenario": scenario_label,
                    "summary": rg.summary(),
                    "findings": [f.to_dict() for f in findings_objs],
                    "scores": score_report.to_dict(),
                },
                model_name=llm_model,
            )
            if llm_recos:
                recos = llm_recos
        except Exception:
            pass

    return {
        "provider": state.get("account", {}).get("provider", "OCI"),
        "scenario": scenario_label,
        "summary": rg.summary(),
        "findings": [f.to_dict() for f in findings_objs],
        "scores": score_report.to_dict(),
        "recommendations": recos,
        "graph_dot": rg.to_dot(),
    }


def run_audit(
    scenario: str,
    security_weight: float = 0.7,
    performance_weight: float = 0.3,
    export_json: bool = True,
    report_json_path: str = "reports/report.json",
    use_llm_recos: bool = False,
    llm_model: str = "llama3.1",
    baseline_scenario: Optional[str] = None,
) -> Dict[str, Any]:
    """
    If baseline_scenario is provided, runs:
      - baseline audit
      - current audit
      - computes deltas (resources + findings)
    Otherwise runs a single audit.
    """
    current_state = load_state(scenario_path(scenario))
    current = _run_single_audit(
        state=current_state,
        scenario_label=scenario,
        security_weight=security_weight,
        performance_weight=performance_weight,
        use_llm_recos=use_llm_recos,
        llm_model=llm_model,
    )

    result = current

    if baseline_scenario:
        baseline_state = load_state(scenario_path(baseline_scenario))
        baseline = _run_single_audit(
            state=baseline_state,
            scenario_label=baseline_scenario,
            security_weight=security_weight,
            performance_weight=performance_weight,
            use_llm_recos=False,  # keep baseline deterministic
            llm_model=llm_model,
        )

        delta = {
            "resources": diff_resources(baseline_state, current_state),
            "findings": diff_findings(baseline["findings"], current["findings"]),
            "scores": {
                "baseline_global": baseline["scores"]["global_score"],
                "current_global": current["scores"]["global_score"],
                "delta_global": current["scores"]["global_score"] - baseline["scores"]["global_score"],
            },
        }

        result = {
            **current,
            "baseline": {
                "scenario": baseline_scenario,
                "summary": baseline["summary"],
                "scores": baseline["scores"],
            },
            "delta": delta,
        }

    if export_json:
        os.makedirs(Path(report_json_path).parent, exist_ok=True)
        with open(report_json_path, "w", encoding="utf-8") as fp:
            json.dump(result, fp, indent=2)

    return result
