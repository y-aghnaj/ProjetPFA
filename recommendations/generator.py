from __future__ import annotations
from dataclasses import dataclass, asdict, field
from typing import List, Dict

@dataclass
class Recommendation:
    rule_id: str
    resource_id: str
    title: str
    steps: List[str]
    responsibility: str
    rationale: str

    # ✅ governance-grade fields
    risk_if_ignored: str = ""
    verification: List[str] = field(default_factory=list)

    # ✅ traceability (inherit from finding)
    pillars: List[str] = field(default_factory=list)
    references: List[Dict[str, str]] = field(default_factory=list)

    source: str = "STATIC"

    def to_dict(self):
        return asdict(self)

RECO_MAP = {
    "OCI.SEC.BUCKET.PUBLIC_NO_ENCRYPT": {
        "title": "Make bucket private and enable encryption (combined exposure)",
        "steps": [
            "Disable public access on the bucket.",
            "Enable encryption at rest (provider-managed or customer-managed keys).",
            "Apply least-privilege IAM policies to restrict access.",
            "Enable bucket logging and versioning to improve auditability and recovery."
        ],
        "rationale": "A public bucket without encryption is a high-impact data exposure risk.",
        "risk_if_ignored": "Sensitive data leakage, regulatory non-compliance, incident response complexity.",
        "verification": [
            "Confirm bucket public access is disabled.",
            "Confirm encryption is enabled for new objects by default.",
            "Review access logs for unexpected public reads.",
            "Test object restore/rollback using versioning."
        ],
    },

    "OCI.SEC.BUCKET.PUBLIC": {
        "title": "Make Object Storage bucket private",
        "steps": [
            "Disable public access on the bucket.",
            "Use signed URLs / pre-authenticated requests for controlled sharing.",
            "Restrict access via IAM policies and compartments."
        ],
        "rationale": "Public buckets are a common cause of cloud data leaks.",
        "risk_if_ignored": "Unauthorized access to sensitive data; reputational and compliance impact.",
        "verification": [
            "Attempt unauthenticated access to bucket/object and confirm it is denied.",
            "Review IAM policies granting bucket access."
        ],
    },

    "OCI.SEC.BUCKET.ENCRYPTION": {
        "title": "Enable encryption at rest for Object Storage bucket",
        "steps": [
            "Enable server-side encryption for the bucket.",
            "Choose key management strategy (provider-managed vs customer-managed).",
            "Ensure encryption is enforced for all new objects."
        ],
        "rationale": "Encryption reduces the impact of unauthorized access and supports compliance.",
        "risk_if_ignored": "Data exposure in case of unauthorized access, snapshot leakage, or misconfiguration.",
        "verification": [
            "Confirm bucket encryption settings are enabled.",
            "Upload a test object and verify encryption metadata."
        ],
    },

    "OCI.SEC.BUCKET.LOGGING_DISABLED": {
        "title": "Enable access logging for Object Storage bucket",
        "steps": [
            "Enable bucket access logging.",
            "Centralize logs in a dedicated audit bucket with restricted access.",
            "Create alerts for anomalous access patterns."
        ],
        "rationale": "Without logging, investigations and incident response are degraded.",
        "risk_if_ignored": "Undetected data access, lack of forensic evidence, delayed containment.",
        "verification": [
            "Generate test access events and confirm they appear in logs.",
            "Validate retention and access controls on audit log storage."
        ],
    },

    "OCI.SEC.BUCKET.VERSIONING_DISABLED": {
        "title": "Enable bucket versioning (recovery and anti-ransomware)",
        "steps": [
            "Enable object versioning.",
            "Define retention/lifecycle policies to control storage growth.",
            "Test restore/rollback for critical objects."
        ],
        "rationale": "Versioning improves recovery from accidental deletion and ransomware.",
        "risk_if_ignored": "Irreversible loss of data; prolonged downtime after incidents.",
        "verification": [
            "Upload and overwrite a test object, then restore a previous version.",
            "Confirm lifecycle policy behavior on old versions."
        ],
    },

    "OCI.SEC.DB.PUBLIC_ENDPOINT": {
        "title": "Disable public endpoint and enforce private access for the database",
        "steps": [
            "Disable the public endpoint for the database.",
            "Restrict access to private subnets / approved CIDRs only.",
            "Require secure connectivity (private endpoints, VPN, bastion)."
        ],
        "rationale": "Public database endpoints increase exposure to external threats.",
        "risk_if_ignored": "Increased attack surface, brute-force attempts, data exfiltration risk.",
        "verification": [
            "Confirm the DB endpoint is not reachable from the public internet.",
            "Validate only approved network paths can connect."
        ],
    },

    "OCI.SEC.DB.BACKUP_DISABLED": {
        "title": "Enable database backups and recovery testing",
        "steps": [
            "Enable automated backups.",
            "Define retention objectives aligned with RPO/RTO.",
            "Perform periodic restore tests and document results."
        ],
        "rationale": "Backups are essential for resilience and incident recovery.",
        "risk_if_ignored": "Data loss after incident; inability to restore service within RTO.",
        "verification": [
            "Confirm backup schedule is active.",
            "Execute a restore test to a staging environment."
        ],
    },

    "OCI.SEC.NET.RDP_PUBLIC": {
        "title": "Restrict RDP exposure (remove 0.0.0.0/0)",
        "steps": [
            "Remove inbound RDP (3389) from 0.0.0.0/0.",
            "Allow access only from a bastion/VPN or trusted corporate IP ranges.",
            "Enforce MFA and hardening on administrative access paths."
        ],
        "rationale": "Public RDP is a frequent initial access vector.",
        "risk_if_ignored": "Account compromise, ransomware, lateral movement into private network.",
        "verification": [
            "Confirm 3389 is not reachable from the internet.",
            "Validate admin access works only through approved channels."
        ],
    },

    "OCI.PERF.COMPUTE.RIGHTSIZING": {
        "title": "Right-size compute resources to reduce waste and improve efficiency",
        "steps": [
            "Review CPU/memory metrics over an appropriate observation window.",
            "Downsize the instance shape (or reduce OCPUs) based on sustained utilization.",
            "Implement autoscaling if workload is bursty.",
            "Track cost savings and ensure performance SLOs remain met."
        ],
        "rationale": "Sustained low CPU on large shapes indicates over-provisioning.",
        "risk_if_ignored": "Unnecessary spend, resource waste, inefficient capacity planning.",
        "verification": [
            "Re-check utilization after resizing.",
            "Verify latency/SLOs remain within targets."
        ],
    },
}

def generate_recommendations(findings):
    recos = []
    for f in findings:
        # skip suppressed: composite already covers it
        if getattr(f, "suppressed", False):
            continue

        tpl = RECO_MAP.get(f.rule_id)

        pillars = getattr(f, "pillars", []) or [getattr(f, "primary_pillar", "SECURITY")]
        references = getattr(f, "references", []) or []

        if not tpl:
            # still provide structured fallback, but no generic "best practices" wording
            recos.append(Recommendation(
                rule_id=f.rule_id,
                resource_id=f.resource_id,
                title="Remediate the detected governance issue",
                steps=[
                    "Review the configuration evidence that triggered the finding.",
                    "Apply the relevant control remediations aligned with the referenced standards.",
                    "Re-scan the environment to confirm closure.",
                ],
                responsibility=f.responsibility,
                rationale=f.message,
                risk_if_ignored="Governance gap may persist and impact compliance and risk posture.",
                verification=["Re-run audit and confirm the finding is resolved."],
                pillars=pillars,
                references=references,
            ))
        else:
            recos.append(Recommendation(
                rule_id=f.rule_id,
                resource_id=f.resource_id,
                title=tpl["title"],
                steps=tpl["steps"],
                responsibility=f.responsibility,
                rationale=tpl["rationale"],
                risk_if_ignored=tpl.get("risk_if_ignored", ""),
                verification=tpl.get("verification", []),
                pillars=pillars,
                references=references,
            ))
    return recos
