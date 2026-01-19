from dataclasses import dataclass, asdict

@dataclass
class Recommendation:
    rule_id: str
    resource_id: str
    title: str
    steps: list[str]
    responsibility: str
    rationale: str

    def to_dict(self):
        return asdict(self)

# Simple "RAG-lite": mapping rule_id -> recommendation template
RECO_MAP = {
    "OCI.SEC.BUCKET.PUBLIC": {
        "title": "Make Object Storage bucket private",
        "steps": [
            "Disable public access on the bucket.",
            "Apply least-privilege IAM policies to restrict access.",
            "Use pre-authenticated requests or signed URLs for controlled sharing.",
            "Enable logging and monitor access events."
        ],
        "rationale": "Public buckets can expose sensitive data and are a common cause of cloud data leaks."
    },
    "OCI.SEC.BUCKET.ENCRYPTION": {
        "title": "Enable encryption at rest for Object Storage bucket",
        "steps": [
            "Enable server-side encryption for the bucket.",
            "Verify encryption settings for new objects by default.",
            "Review key management strategy (provider-managed or customer-managed keys)."
        ],
        "rationale": "Encryption reduces the impact of unauthorized access and helps meet compliance requirements."
    },
    "OCI.SEC.DB.ENCRYPTION": {
        "title": "Enable database encryption",
        "steps": [
            "Enable encryption at rest for the database.",
            "Ensure backups and replicas are encrypted.",
            "Restrict access via network controls and IAM.",
            "Enable auditing/logging for database access."
        ],
        "rationale": "Database encryption protects sensitive records against unauthorized access or snapshot exposure."
    }
}

def generate_recommendations(findings):
    recos = []
    for f in findings:
        tpl = RECO_MAP.get(f.rule_id)
        if not tpl:
            # fallback if no template exists
            recos.append(Recommendation(
                rule_id=f.rule_id,
                resource_id=f.resource_id,
                title="Review configuration and apply best practices",
                steps=["Review the resource configuration and apply cloud security best practices."],
                responsibility=f.responsibility,
                rationale=f.message
            ))
        else:
            recos.append(Recommendation(
                rule_id=f.rule_id,
                resource_id=f.resource_id,
                title=tpl["title"],
                steps=tpl["steps"],
                responsibility=f.responsibility,
                rationale=tpl["rationale"]
            ))
    return recos
