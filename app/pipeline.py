# app/pipeline.py
import json
import os
from pathlib import Path
from typing import Any, Dict

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

    # --- composites first ---
    engine.register(rule_bucket_public_no_encrypt_composite, kind="node")
    engine.register(rule_db_public_and_no_encrypt, kind="node")

    # --- bucket ---
    engine.register(rule_public_object_storage_bucket, kind="node")
    engine.register(rule_bucket_encryption, kind="node")
    engine.register(rule_bucket_logging_disabled, kind="node")
    engine.register(rule_bucket_versioning_disabled, kind="node")

    # --- database ---
    engine.register(rule_db_encryption, kind="node")
    engine.register(rule_db_public_endpoint, kind="node")
    engine.register(rule_db_backup_disabled, kind="node")

    # --- network ---
    engine.register(rule_ssh_open_to_world, kind="node")
    engine.register(rule_rdp_open_to_world, kind="node")

    # --- graph-based exposure path ---
    engine.register(graph_rule_public_ssh_path_to_database, kind="graph")

    # --- performance/cost (optional) ---
    engine.register(rule_right_sizing_compute, kind="node")

    return engine


def run_audit(
    scenario: str,
    export_json: bool = True,
    report_json_path: str = "reports/report.json",
    use_llm_recos: bool = False,
    llm_model: str = "llama3.1",
    waf_weights: Dict[str, float] | None = None,
) -> Dict[str, Any]:
    """
    Runs the full governance audit pipeline and returns a structured dict:
    - provider, scenario, summary, findings, scores, recommendations, graph_dot
    """

    state = load_state(scenario_path(scenario))
    rg = build_resource_graph(state)

    engine = build_rule_engine()
    findings = engine.run(rg.graph)

    # WAF-aligned scoring (still backward compatible fields)
    scorer = ScoringEngine(waf_weights=waf_weights)
    score_report = scorer.compute(findings)

    # recommendations: static first
    static_recos = generate_recommendations(findings)
    recos = [r.to_dict() for r in static_recos]

    # optional: LLM recommendations
    if use_llm_recos and findings:
        try:
            llm_recos = generate_llm_recommendations(
                audit_result={
                    "provider": state.get("account", {}).get("provider", "OCI"),
                    "scenario": scenario,
                    "summary": rg.summary(),
                    "findings": [f.to_dict() for f in findings],
                    "scores": score_report.to_dict(),
                },
                model_name=llm_model,
            )
            if llm_recos:
                recos = llm_recos
        except Exception:
            # keep static fallback
            pass

    result = {
        "provider": state.get("account", {}).get("provider", "OCI"),
        "scenario": scenario,
        "summary": rg.summary(),
        "findings": [f.to_dict() for f in findings],
        "scores": score_report.to_dict(),
        "recommendations": recos,
        "graph_dot": rg.to_dot(),
    }

    if export_json:
        os.makedirs(Path(report_json_path).parent, exist_ok=True)
        with open(report_json_path, "w", encoding="utf-8") as fp:
            json.dump(result, fp, indent=2)

    return result
