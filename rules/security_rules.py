from rules.engine import Finding


def rule_public_object_storage_bucket(node_id: str, r: dict):
    # OCI: Object Storage bucket should not be public by default
    if r.get("type") == "object_storage_bucket" and r.get("public") is True:
        return Finding(
            rule_id="OCI.SEC.BUCKET.PUBLIC",
            resource_id=node_id,
            severity="HIGH",
            responsibility="CUSTOMER",
            message="Object Storage bucket is public. This may expose sensitive data.",
            evidence={"public": r.get("public"), "name": r.get("name"), "compartment": r.get("compartment")}
        )
    return None


def rule_bucket_encryption(node_id: str, r: dict):
    if r.get("type") == "object_storage_bucket" and r.get("encrypted") is False:
        return Finding(
            rule_id="OCI.SEC.BUCKET.ENCRYPTION",
            resource_id=node_id,
            severity="MEDIUM",
            responsibility="CUSTOMER",
            message="Object Storage bucket encryption is disabled.",
            evidence={"encrypted": r.get("encrypted"), "name": r.get("name")}
        )
    return None


def rule_db_encryption(node_id: str, r: dict):
    if r.get("type") == "autonomous_database" and r.get("encrypted") is False:
        return Finding(
            rule_id="OCI.SEC.DB.ENCRYPTION",
            resource_id=node_id,
            severity="HIGH",
            responsibility="CUSTOMER",
            message="Database encryption is disabled. This increases data exposure risk.",
            evidence={"encrypted": r.get("encrypted"), "name": r.get("name")}
        )
    return None

def rule_ssh_open_to_world(node_id: str, r: dict):
    if r.get("type") != "network_security_group":
        return None

    for rule in r.get("ingress_rules", []):
        if (
            rule.get("protocol") == "tcp"
            and rule.get("port") == 22
            and rule.get("source") == "0.0.0.0/0"
        ):
            return Finding(
                rule_id="OCI.SEC.NET.SSH_PUBLIC",
                resource_id=node_id,
                severity="HIGH",
                responsibility="CUSTOMER",
                message="SSH port 22 is open to the internet (0.0.0.0/0). This increases brute-force attack risk.",
                evidence={
                    "protocol": rule.get("protocol"),
                    "port": rule.get("port"),
                    "source": rule.get("source"),
                    "nsg": r.get("name"),
                },
            )
    return None