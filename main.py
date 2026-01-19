import os
from recommendations.generator import generate_recommendations
import json
from graph.resource_graph import ResourceGraph
from scoring.scoring_engine import ScoringEngine
from rules.engine import RuleEngine
from rules.perf_rules import rule_right_sizing_compute
from rules.security_rules import (
    rule_public_object_storage_bucket,
    rule_bucket_encryption,
    rule_db_encryption,
    rule_ssh_open_to_world
)

def load_state(path: str):
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)

if __name__ == "__main__":
    state = load_state("data/oci_mock.json")

    rg = ResourceGraph()
    rg.load_from_state(state)

    print("=== Resource Graph Loaded ===")
    print("Summary:", rg.summary())

    engine = RuleEngine()
    engine.register(rule_public_object_storage_bucket)
    engine.register(rule_bucket_encryption)
    engine.register(rule_db_encryption)
    engine.register(rule_ssh_open_to_world)
    engine.register(rule_right_sizing_compute)

    findings = engine.run(rg.graph)

    print("\n=== Findings ===")
    if not findings:
        print("No findings.")
    else:
        for f in findings:
            print(f"- [{f.severity}] {f.rule_id} on {f.resource_id}")
            print(f"  Responsibility: {f.responsibility}")
            print(f"  Message: {f.message}")
            print(f"  Evidence: {f.evidence}")
    scorer = ScoringEngine(security_weight=0.7, performance_weight=0.3)
    report = scorer.compute(findings)

    print("\n=== Scores ===")
    print("Security score:", report.security_score, "/ 100")
    print("Performance score:", report.performance_score, "/ 100")
    print("Global score:", report.global_score, "/ 100")
    print("Weights:", report.weights)

    print("\n=== Explainability Pack (Penalties) ===")
    for p in report.penalties:
        print(f"- {p['rule_id']} ({p['severity']}) => -{p['penalty']} on {p['resource_id']}")
    recos = generate_recommendations(findings)

    print("\n=== Recommendations ===")
    for r in recos:
        print(f"- {r.title} ({r.responsibility}) for {r.resource_id}")
        for step in r.steps:
            print(f"  - {step}")

    # Export JSON report
    os.makedirs("reports", exist_ok=True)

    report_json = {
        "provider": state["account"]["provider"],
        "summary": rg.summary(),
        "scores": report.to_dict(),
        "findings": [f.to_dict() for f in findings],
        "recommendations": [r.to_dict() for r in recos]
    }

    with open("reports/report.json", "w", encoding="utf-8") as fp:
        import json
        json.dump(report_json, fp, indent=2)

    print("\nReport exported to: reports/report.json")
