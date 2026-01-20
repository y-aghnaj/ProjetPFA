import json
import subprocess
from typing import List, Dict, Any

RECO_PROMPT = """You are a cloud governance remediation assistant for Oracle Cloud Infrastructure (OCI).

You will receive JSON containing:
- provider
- scenario
- findings (with rule_id, resource_id, severity, responsibility, message, evidence)
- scores (security/performance/global)

Your task: Generate recommendations ONLY for the provided findings.
Hard constraints:
- Do NOT invent new findings, resources, scores, or services.
- Do NOT reference rule_ids or resource_ids that are not in the input.
- Every recommendation must map to exactly one finding (same rule_id and resource_id).
- Keep SRM responsibility exactly as provided (CUSTOMER/CSP/SHARED).
- Output MUST be valid JSON only (no markdown, no extra text).

Output JSON schema:
{
  "recommendations": [
    {
      "rule_id": "...",
      "resource_id": "...",
      "responsibility": "CUSTOMER|CSP|SHARED",
      "title": "...",
      "rationale": "...",
      "steps": ["...", "...", "..."],
      "risk_if_ignored": "...",
      "verification": ["...", "..."]
    }
  ]
}

INPUT JSON:
{json_data}
"""

def _run_ollama_json(prompt: str, model_name: str) -> str:
    # UTF-8 safe on Windows
    result = subprocess.run(
        ["ollama", "run", model_name],
        input=prompt,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
    )
    if result.returncode != 0:
        raise RuntimeError(f"Ollama failed: {result.stderr}")
    return result.stdout.strip()

def _safe_json_loads(s: str) -> Dict[str, Any]:
    """
    Best-effort JSON parsing. If Ollama outputs surrounding text,
    try to extract the first JSON object.
    """
    s = s.strip()
    try:
        return json.loads(s)
    except json.JSONDecodeError:
        # try to locate first '{' and last '}'
        start = s.find("{")
        end = s.rfind("}")
        if start != -1 and end != -1 and end > start:
            return json.loads(s[start:end+1])
        raise

def validate_llm_recos(input_findings: List[dict], llm_output: Dict[str, Any]) -> List[dict]:
    """
    Enforce guardrails:
    - one recommendation per finding
    - rule_id/resource_id must exist
    """
    findings_set = {(f["rule_id"], f["resource_id"]) for f in input_findings}

    recos = llm_output.get("recommendations", [])
    if not isinstance(recos, list):
        raise ValueError("LLM output missing 'recommendations' list")

    cleaned = []
    for r in recos:
        key = (r.get("rule_id"), r.get("resource_id"))
        if key not in findings_set:
            # drop hallucinated or mismatched entries
            continue
        # minimal required fields
        cleaned.append({
            "rule_id": r.get("rule_id"),
            "resource_id": r.get("resource_id"),
            "responsibility": r.get("responsibility"),
            "title": r.get("title") or "Recommendation",
            "rationale": r.get("rationale") or "",
            "steps": r.get("steps") if isinstance(r.get("steps"), list) else [],
            "risk_if_ignored": r.get("risk_if_ignored") or "",
            "verification": r.get("verification") if isinstance(r.get("verification"), list) else [],
            "source": "LLM"
        })

    # Ensure coverage: if LLM missed findings, caller can fall back to static templates.
    return cleaned

def generate_llm_recommendations(
    audit_result: Dict[str, Any],
    model_name: str = "llama3.1"
) -> List[dict]:
    """
    audit_result is the dict returned by run_audit() (provider, scenario, findings, scores, ...).
    Returns validated recommendations list (may be empty if LLM fails/returns invalid).
    """
    findings = audit_result.get("findings", [])
    payload = {
        "provider": audit_result.get("provider"),
        "scenario": audit_result.get("scenario"),
        "scores": audit_result.get("scores"),
        "findings": findings,
    }
    prompt = RECO_PROMPT.format(json_data=json.dumps(payload, indent=2))

    raw = _run_ollama_json(prompt, model_name=model_name)
    parsed = _safe_json_loads(raw)
    return validate_llm_recos(findings, parsed)
