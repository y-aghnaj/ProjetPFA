from rules.engine import Finding

def rule_right_sizing_compute(node_id: str, r: dict):
    if r.get("type") != "compute_instance":
        return None

    avg_cpu = r.get("avg_cpu_utilization")
    ocpus = r.get("ocpus", 0)

    if avg_cpu is not None and avg_cpu < 5.0 and ocpus >= 4:
        return Finding(
            rule_id="OCI.PERF.COMPUTE.RIGHTSIZING",
            resource_id=node_id,
            severity="MEDIUM",
            responsibility="CUSTOMER",
            message="Compute instance may be over-provisioned (low average CPU). Consider right-sizing.",
            evidence={
                "avg_cpu_utilization": avg_cpu,
                "ocpus": ocpus,
                "memory_gb": r.get("memory_gb"),
                "shape": r.get("shape"),
                "name": r.get("name")
            }
        )
    return None
