# rules/security_rules.py
from __future__ import annotations
from rules.engine import Finding
from governance.waf import infer_waf_metadata

SEV_TO_RISK = {
    "LOW": 0.05,
    "MEDIUM": 0.12,
    "HIGH": 0.25,
    "CRITICAL": 0.40,
}

def _tags(r: dict) -> dict:
    return r.get("tags", {}) if isinstance(r.get("tags"), dict) else {}

def _env_is_prod(r: dict) -> bool:
    return _tags(r).get("environment") == "prod" or r.get("environment") == "prod"

def _is_confidential(r: dict) -> bool:
    return _tags(r).get("data_classification") in ("confidential", "restricted", "secret")

def _risk_for(sev: str) -> float:
    return SEV_TO_RISK.get(sev, 0.10)

def _waf_meta(rule_id: str):
    meta = infer_waf_metadata(rule_id)
    return meta.get("pillars", ["SECURITY"]), meta.get("references", [])


# ---- Atomic rules (node-based) ----
def rule_public_object_storage_bucket(node_id: str, r: dict):
    if r.get("type") == "object_storage_bucket" and r.get("public") is True:
        sev = "CRITICAL" if (_env_is_prod(r) and _is_confidential(r)) else "HIGH"
        rid = "OCI.SEC.BUCKET.PUBLIC"
        pillars, refs = _waf_meta(rid)
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Object Storage bucket is public. This may expose sensitive data.",
            evidence={"public": True, "name": r.get("name"), "compartment": r.get("compartment")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["data_exposure"],
            context={"tags": _tags(r), "env": "prod" if _env_is_prod(r) else "non-prod"},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_bucket_encryption(node_id: str, r: dict):
    if r.get("type") == "object_storage_bucket" and r.get("encrypted") is False:
        sev = "HIGH" if (_env_is_prod(r) and _is_confidential(r)) else "MEDIUM"
        rid = "OCI.SEC.BUCKET.ENCRYPTION"
        pillars, refs = _waf_meta(rid)
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Object Storage bucket encryption is disabled.",
            evidence={"encrypted": False, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["data_exposure"],
            context={"tags": _tags(r)},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_bucket_logging_disabled(node_id: str, r: dict):
    if r.get("type") == "object_storage_bucket" and r.get("logging_enabled") is False:
        sev = "MEDIUM" if _env_is_prod(r) else "LOW"
        rid = "OCI.SEC.BUCKET.LOGGING_DISABLED"
        pillars, refs = _waf_meta(rid)
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Bucket logging is disabled. This reduces auditability and incident response capability.",
            evidence={"logging_enabled": False, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["detection_gap"],
            context={"tags": _tags(r)},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_bucket_versioning_disabled(node_id: str, r: dict):
    if r.get("type") == "object_storage_bucket" and r.get("versioning") is False:
        sev = "MEDIUM" if _env_is_prod(r) else "LOW"
        rid = "OCI.SEC.BUCKET.VERSIONING_DISABLED"
        pillars, refs = _waf_meta(rid)
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Bucket versioning is disabled. This increases risk of irreversible deletion or ransomware impact.",
            evidence={"versioning": False, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["availability", "recovery_gap"],
            context={"tags": _tags(r)},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_db_encryption(node_id: str, r: dict):
    if r.get("type") == "autonomous_database" and r.get("encrypted") is False:
        sev = "CRITICAL" if (_env_is_prod(r) and _is_confidential(r)) else "HIGH"
        rid = "OCI.SEC.DB.ENCRYPTION"
        pillars, refs = _waf_meta(rid)
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Database encryption is disabled. This increases data exposure risk.",
            evidence={"encrypted": False, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["data_exposure"],
            context={"tags": _tags(r)},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_db_public_endpoint(node_id: str, r: dict):
    if r.get("type") == "autonomous_database" and r.get("public_endpoint") is True:
        sev = "CRITICAL" if _env_is_prod(r) else "HIGH"
        rid = "OCI.SEC.DB.PUBLIC_ENDPOINT"
        pillars, refs = _waf_meta(rid)
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Database has a public endpoint enabled. This increases exposure to external threats.",
            evidence={"public_endpoint": True, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["initial_access", "data_exposure"],
            context={"tags": _tags(r)},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_db_backup_disabled(node_id: str, r: dict):
    if r.get("type") == "autonomous_database" and r.get("backups_enabled") is False:
        sev = "HIGH" if _env_is_prod(r) else "MEDIUM"
        rid = "OCI.SEC.DB.BACKUP_DISABLED"
        pillars, refs = _waf_meta(rid)
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Database backups are disabled. This increases recovery time and data loss risk.",
            evidence={"backups_enabled": False, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["availability", "recovery_gap"],
            context={"tags": _tags(r)},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_ssh_open_to_world(node_id: str, r: dict):
    if r.get("type") != "network_security_group":
        return None

    for rule in r.get("ingress_rules", []):
        if rule.get("protocol") == "tcp" and rule.get("port") == 22 and rule.get("source") == "0.0.0.0/0":
            sev = "CRITICAL" if _env_is_prod(r) else "HIGH"
            rid = "OCI.SEC.NET.SSH_PUBLIC"
            pillars, refs = _waf_meta(rid)
            return Finding(
                rule_id=rid,
                resource_id=node_id,
                severity=sev,
                responsibility="CUSTOMER",
                message="SSH port 22 is open to the internet (0.0.0.0/0). This increases brute-force attack risk.",
                evidence={"protocol": "tcp", "port": 22, "source": "0.0.0.0/0", "nsg": r.get("name")},
                risk=_risk_for(sev),
                confidence=1.0,
                impact=["initial_access"],
                context={"tags": _tags(r)},
                pillars=pillars,
                references=refs,
            )
    return None


def rule_rdp_open_to_world(node_id: str, r: dict):
    if r.get("type") != "network_security_group":
        return None

    for rule in r.get("ingress_rules", []):
        if rule.get("protocol") == "tcp" and rule.get("port") == 3389 and rule.get("source") == "0.0.0.0/0":
            sev = "CRITICAL" if _env_is_prod(r) else "HIGH"
            rid = "OCI.SEC.NET.RDP_PUBLIC"
            pillars, refs = _waf_meta(rid)
            return Finding(
                rule_id=rid,
                resource_id=node_id,
                severity=sev,
                responsibility="CUSTOMER",
                message="RDP port 3389 is open to the internet (0.0.0.0/0). This increases compromise risk.",
                evidence={"protocol": "tcp", "port": 3389, "source": "0.0.0.0/0", "nsg": r.get("name")},
                risk=_risk_for(sev),
                confidence=1.0,
                impact=["initial_access"],
                context={"tags": _tags(r)},
                pillars=pillars,
                references=refs,
            )
    return None


# ---- Composite rules (node-based) ----
def rule_bucket_public_no_encrypt_composite(node_id: str, r: dict):
    if r.get("type") != "object_storage_bucket":
        return None
    if r.get("public") is True and r.get("encrypted") is False:
        sev = "CRITICAL" if (_env_is_prod(r) or _is_confidential(r)) else "HIGH"
        rid = "OCI.SEC.BUCKET.PUBLIC_NO_ENCRYPT"
        pillars, refs = _waf_meta("OCI.SEC.BUCKET.PUBLIC")  # composite still maps to security controls
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Bucket is public and encryption is disabled. Combined misconfiguration increases data exposure risk.",
            evidence={"public": True, "encrypted": False, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["data_exposure"],
            context={"tags": _tags(r), "covers": ["OCI.SEC.BUCKET.PUBLIC", "OCI.SEC.BUCKET.ENCRYPTION"]},
            pillars=pillars,
            references=refs,
        )
    return None


def rule_db_public_and_no_encrypt(node_id: str, r: dict):
    if r.get("type") != "autonomous_database":
        return None
    if r.get("public_endpoint") is True and r.get("encrypted") is False:
        sev = "CRITICAL"
        rid = "OCI.SEC.DB.PUBLIC_AND_NO_ENCRYPT"
        pillars, refs = _waf_meta("OCI.SEC.DB.PUBLIC_ENDPOINT")
        return Finding(
            rule_id=rid,
            resource_id=node_id,
            severity=sev,
            responsibility="CUSTOMER",
            message="Database is publicly reachable and encryption is disabled. This is a critical exposure.",
            evidence={"public_endpoint": True, "encrypted": False, "name": r.get("name")},
            risk=_risk_for(sev),
            confidence=1.0,
            impact=["initial_access", "data_exposure"],
            context={"tags": _tags(r), "covers": ["OCI.SEC.DB.PUBLIC_ENDPOINT", "OCI.SEC.DB.ENCRYPTION"]},
            pillars=pillars,
            references=refs,
        )
    return None

def graph_rule_public_ssh_path_to_database(graph):
    """
    Detects if an NSG with public SSH can reach a database within a few hops.

    Requires scenarios to define relations such as:
      nsg -> compute (protects)
      compute -> subnet (in_subnet)
      subnet -> db (connects_to)
    """
    findings = []

    # Collect DB nodes
    db_nodes = []
    for nid, attrs in graph.nodes(data=True):
        if attrs.get("type") == "autonomous_database":
            db_nodes.append((nid, attrs))

    # For each NSG with public SSH, search descendants up to depth 4 for DB
    for nsg_id, nsg in graph.nodes(data=True):
        if nsg.get("type") != "network_security_group":
            continue

        ssh_public = False
        for rule in nsg.get("ingress_rules", []):
            if rule.get("protocol") == "tcp" and rule.get("port") == 22 and rule.get("source") == "0.0.0.0/0":
                ssh_public = True
                break
        if not ssh_public:
            continue

        # BFS limited depth
        frontier = [(nsg_id, [nsg_id], 0)]
        visited = {nsg_id}

        while frontier:
            cur, path, depth = frontier.pop(0)
            if depth >= 4:
                continue

            for nxt in graph.successors(cur):
                if nxt in visited:
                    continue
                visited.add(nxt)

                nxt_attrs = graph.nodes[nxt]
                new_path = path + [nxt]

                if nxt_attrs.get("type") == "autonomous_database":
                    sev = "CRITICAL" if (_env_is_prod(nxt_attrs) or _is_confidential(nxt_attrs)) else "HIGH"
                    findings.append(
                        Finding(
                            rule_id="OCI.SEC.PATH.PUBLIC_SSH_TO_DB",
                            resource_id=nxt,  # attach finding to DB (critical asset)
                            severity=sev,
                            responsibility="CUSTOMER",
                            message="A public SSH exposure provides a potential path to a database (multi-hop exposure).",
                            evidence={"entrypoint_nsg": nsg_id, "path": new_path},
                            risk=_risk_for(sev),
                            impact=["initial_access", "lateral_movement", "data_exposure"],
                            context={"path": new_path, "entrypoint": nsg_id, "db_tags": _tags(nxt_attrs)},
                            pillars=["SECURITY", "RELIABILITY"],
                            references=[
                                {"standard": "WAF", "id": "SEC-07", "name": "Minimize exposure paths / reduce attack surface"},
                                {"standard": "CIS", "id": "Network-1", "name": "Restrict management ports and exposure"},
                            ],
                        )
                    )
                else:
                    frontier.append((nxt, new_path, depth + 1))

    return findings