# rules/perf_rules.py
from __future__ import annotations

from rules.engine import Finding
from governance.waf import rule_trace

SEV_TO_RISK = {
    "LOW": 0.03,
    "MEDIUM": 0.08,
    "HIGH": 0.18,
    "CRITICAL": 0.30,
}

def _risk_for(sev: str) -> float:
    return SEV_TO_RISK.get(sev, 0.08)

def rule_right_sizing_compute(node_id: str, r: dict):
    if r.get("type") != "compute_instance":
        return None

    avg_cpu = r.get("avg_cpu_utilization")
    ocpus = r.get("ocpus", 0)

    if avg_cpu is not None and avg_cpu < 5.0 and ocpus >= 4:
        sev = "MEDIUM"
        return Finding(
            rule_id="OCI.PERF.COMPUTE.RIGHTSIZING",
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Compute instance may be over-provisioned (low average CPU). Consider right-sizing.",
            evidence={
                "avg_cpu_utilization": avg_cpu,
                "ocpus": ocpus,
                "memory_gb": r.get("memory_gb"),
                "shape": r.get("shape"),
                "name": r.get("name"),
            },

            risk=_risk_for(sev),
            impact=["cost_inefficiency", "performance_waste"],
            context={"tags": r.get("tags", {})},
            primary_pillar="PERFORMANCE",
            pillars=["PERFORMANCE", "COST"],
            references=rule_trace(
                waf_id="PERF-01",
                waf_name="Right-size resources to meet workload demands efficiently",
                cis_id="Cost-1",
                cis_name="Ensure resources are right-sized / avoid over-provisioning",
                iso_id="A.12.1",
                iso_name="Operational procedures and responsibilities (resource management)",
            ),
        )
    return None
