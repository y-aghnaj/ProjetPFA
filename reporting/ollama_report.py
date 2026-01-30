# ollama_report.py
from __future__ import annotations

import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Dict, Any, List

MAX_FINDINGS_FOR_LLM = 30  # keep prompt small
OLLAMA_TIMEOUT_SEC = 1800   # 15 min max (adjust)

PROMPT_TEMPLATE = """You are a cloud governance auditor specializing in Cloud Infrastructure (OCI, AWS or Azure).

Write a professional assessment report based ONLY on the JSON input below.

Hard constraints:
- Do NOT invent any resources, findings, scores, recommendations, or standards mappings.
- Use an audit-style tone.
- Include sections:
  1) Executive Summary
  2) Environment Overview (By provider form the json)
  3) Well-Architected Scores (Security, Reliability, Performance, Cost, Operational Excellence) with brief interpretation
  4) Key Findings (ordered by severity, then risk)
  5) Standards Traceability (WAF/CIS/ISO) (summarize what each major finding maps to)
  6) Shared Responsibility Model (Customer vs CSP vs Shared)
     - Always mention BOTH CSP and Customer responsibilities.
     - If findings are customer-side, state CSP responsibilities remain baseline and are not directly remediated by the customer.
     - Do NOT say CSP responsibilities are "not applicable".
  7) Recommendations (actionable, step-by-step)
  8) Next Steps and Re-scan Plan
- Keep it clear and structured, with bullet points where useful.

JSON INPUT:
{json_data}
"""

def _run_ollama(prompt: str, model_name: str) -> str:
    """
    Run a local Ollama model safely on Windows.
    Forces UTF-8 decoding to avoid cp1252 Unicode errors.
    Includes a timeout to prevent infinite hangs.
    """
    result = subprocess.run(
        ["ollama", "run", model_name],
        input=prompt,
        text=True,
        capture_output=True,
        encoding="utf-8",
        errors="replace",
        timeout=OLLAMA_TIMEOUT_SEC,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Ollama failed: {result.stderr}")
    return result.stdout.strip()

def _timestamped_report_path() -> Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return Path("reports") / f"report_llm_{ts}.md"

def _severity_rank(sev: str) -> int:
    return {"LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}.get(sev, 0)

def _slim_report_data(report_data: Dict[str, Any]) -> Dict[str, Any]:
    """
    Keep only the essentials to speed up generation.
    """
    findings: List[Dict[str, Any]] = report_data.get("findings", [])
    # sort severity desc then risk desc
    findings_sorted = sorted(
        findings,
        key=lambda f: (_severity_rank(f.get("severity", "")), float(f.get("risk", 0.0))),
        reverse=True,
    )

    slim_findings = []
    for f in findings_sorted[:MAX_FINDINGS_FOR_LLM]:
        slim_findings.append({
            "rule_id": f.get("rule_id"),
            "resource_id": f.get("resource_id"),
            "severity": f.get("severity"),
            "message": f.get("message"),
            "responsibility": f.get("responsibility"),
            "risk": f.get("risk", 0.0),
            "confidence": f.get("confidence", 1.0),
            "pillars": f.get("pillars", []),
            "references": f.get("references", []),
            # evidence can explode; keep it small
            "evidence": f.get("evidence", {}),
            # optional: indicate suppressed/covered_by
            "suppressed": f.get("suppressed", False),
            "covered_by": f.get("covered_by", []),
        })

    scores = report_data.get("scores", {})
    slim_scores = {
        "pillar_scores": scores.get("pillar_scores", {}),
        "global_score": scores.get("global_score"),
        "waf_weights": scores.get("waf_weights", {}),
    }

    # recommendations can also be large; keep 1..N matching slim findings
    recos = report_data.get("recommendations", [])
    keyset = {(f["rule_id"], f["resource_id"]) for f in slim_findings}
    slim_recos = []
    for r in recos:
        if (r.get("rule_id"), r.get("resource_id")) in keyset:
            slim_recos.append({
                "rule_id": r.get("rule_id"),
                "resource_id": r.get("resource_id"),
                "responsibility": r.get("responsibility"),
                "title": r.get("title"),
                "rationale": r.get("rationale", ""),
                "steps": r.get("steps", []),
                "source": r.get("source", "STATIC"),
            })

    return {
        "provider": report_data.get("provider", "OCI"),
        "scenario": report_data.get("scenario"),
        "summary": report_data.get("summary", {}),
        "scores": slim_scores,
        "findings": slim_findings,
        "recommendations": slim_recos,
        "notes": {
            "input_trimmed": True,
            "max_findings_for_llm": MAX_FINDINGS_FOR_LLM,
        }
    }

def generate_llm_report(report_json_path: str = "reports/report.json", model_name: str = "llama3.1") -> str:
    report_path = Path(report_json_path)
    if not report_path.exists():
        raise FileNotFoundError(f"{report_json_path} not found. Run main.py first.")

    data = json.loads(report_path.read_text(encoding="utf-8"))
    slim = _slim_report_data(data)

    prompt = PROMPT_TEMPLATE.format(json_data=json.dumps(slim, indent=2))
    output = _run_ollama(prompt, model_name)

    out_path = _timestamped_report_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output, encoding="utf-8")
    return str(out_path)

def generate_llm_report_from_dict(report_data: dict, model_name: str = "llama3.1") -> str:
    slim = _slim_report_data(report_data)
    prompt = PROMPT_TEMPLATE.format(json_data=json.dumps(slim, indent=2))
    return _run_ollama(prompt, model_name)

if __name__ == "__main__":
    out = generate_llm_report()
    print("LLM report generated:", out)
