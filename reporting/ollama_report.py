# reporting/ollama_report.py
import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

PROMPT_TEMPLATE_FAST = """You are a cloud governance auditor.
This project is a conceptual audit framework applied to Oracle Cloud Infrastructure (OCI) as a case study.

Write a professional assessment report based ONLY on the JSON input below.

Hard constraints:
- Do NOT invent any resources, findings, scores, or recommendations.
- Audit-style tone. Clear headings.
- Include sections:
  1) Executive Summary
  2) Environment Overview (OCI)
  3) Scores (WAF pillars + Global) with brief interpretation
  4) Key Findings (ordered by severity)
  5) Shared Responsibility Assignment (Customer/CSP/Shared)
  6) Recommendations (actionable, step-by-step)
  7) Next Steps and Re-scan Plan
- In SRM: always mention BOTH CSP and Customer responsibilities.
  If findings are customer-side, state CSP responsibilities remain baseline (shared responsibility model)
  and are not directly remediated by the customer.

JSON INPUT:
{json_data}
"""

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _run_ollama(prompt: str, model_name: str, timeout_s: Optional[int] = None) -> str:
    try:
        result = subprocess.run(
            ["ollama", "run", model_name],
            input=prompt,
            text=True,
            capture_output=True,
            encoding="utf-8",
            errors="replace",
            timeout=timeout_s,
        )
    except subprocess.TimeoutExpired as e:
        raise TimeoutError(f"Ollama timed out after {timeout_s}s") from e

    if result.returncode != 0:
        raise RuntimeError(f"Ollama failed: {result.stderr}")
    return (result.stdout or "").strip()


def _timestamped_report_path() -> Path:
    ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return Path("reports") / f"report_llm_{ts}.md"


def _trim_text(v: Any, max_chars: int = 220) -> Any:
    if isinstance(v, str) and len(v) > max_chars:
        return v[:max_chars] + "…"
    return v


def _compact_findings(findings: List[Dict[str, Any]], max_findings: int) -> List[Dict[str, Any]]:
    clean = [f for f in findings if not f.get("suppressed", False)]
    clean.sort(
        key=lambda f: (
            -SEV_RANK.get(str(f.get("severity", "")).upper(), 0),
            -float(f.get("risk", 0.0) or 0.0),
        )
    )
    clean = clean[:max_findings]

    out = []
    for f in clean:
        out.append({
            "rule_id": f.get("rule_id"),
            "resource_id": f.get("resource_id"),
            "severity": f.get("severity"),
            "responsibility": f.get("responsibility"),
            "message": _trim_text(f.get("message"), 350),
            "risk": f.get("risk", None),
            "impact": f.get("impact", None),
            "pillars": f.get("pillars", None),
            "references": f.get("references", None),
            # keep evidence but trim hard
            "evidence": {k: _trim_text(v, 120) for k, v in (f.get("evidence") or {}).items()},
            # context can explode -> keep minimal
            "context": {k: _trim_text(v, 120) for k, v in (f.get("context") or {}).items()},
        })
    return out


def _compact_recommendations(recos: List[Dict[str, Any]], max_recos: int) -> List[Dict[str, Any]]:
    recos = recos[:max_recos]
    out = []
    for r in recos:
        steps = r.get("steps") or []
        if isinstance(steps, list):
            steps = steps[:6]
        out.append({
            "rule_id": r.get("rule_id"),
            "resource_id": r.get("resource_id"),
            "responsibility": r.get("responsibility"),
            "title": _trim_text(r.get("title"), 180),
            "rationale": _trim_text(r.get("rationale"), 320),
            "steps": [_trim_text(s, 140) for s in steps] if isinstance(steps, list) else steps,
            "source": r.get("source", "STATIC"),
        })
    return out


def compact_audit_result_for_llm(
    audit: Dict[str, Any],
    max_findings: int = 18,
    max_recos: int = 12,
) -> Dict[str, Any]:
    out: Dict[str, Any] = {
        "provider": audit.get("provider"),
        "scenario": audit.get("scenario"),
        "summary": audit.get("summary"),
        "scores": audit.get("scores"),
    }

    findings = audit.get("findings") or []
    if isinstance(findings, list):
        out["findings_total"] = len([f for f in findings if not f.get("suppressed", False)])
        out["findings"] = _compact_findings(findings, max_findings=max_findings)

    recos = audit.get("recommendations") or []
    if isinstance(recos, list) and recos:
        out["recommendations"] = _compact_recommendations(recos, max_recos=max_recos)

    # Drop heavy fields explicitly if present in audit dict
    # graph_dot, raw_state, resources, relations, etc. are intentionally not included.
    return out


def generate_llm_report(
    report_json_path: str = "reports/report.json",
    model_name: str = "llama3.1",
    timeout_s: int = 480,      # 8 minutes
    max_findings: int = 18,
    max_recos: int = 12,
) -> str:
    report_path = Path(report_json_path)
    if not report_path.exists():
        raise FileNotFoundError(f"{report_json_path} not found. Run the audit first.")

    data = json.loads(report_path.read_text(encoding="utf-8"))
    compact = compact_audit_result_for_llm(data, max_findings=max_findings, max_recos=max_recos)

    prompt = PROMPT_TEMPLATE_FAST.format(json_data=json.dumps(compact, indent=2, ensure_ascii=False))
    output = _run_ollama(prompt, model_name, timeout_s=timeout_s)

    out_path = _timestamped_report_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output, encoding="utf-8")
    return str(out_path)


def generate_llm_report_from_dict(
    report_data: dict,
    model_name: str = "llama3.1",
    timeout_s: int = 480,
    max_findings: int = 18,
    max_recos: int = 12,
) -> str:
    compact = compact_audit_result_for_llm(report_data, max_findings=max_findings, max_recos=max_recos)
    prompt = PROMPT_TEMPLATE_FAST.format(json_data=json.dumps(compact, indent=2, ensure_ascii=False))
    return _run_ollama(prompt, model_name, timeout_s=timeout_s)


if __name__ == "__main__":
    out = generate_llm_report()
    print("LLM report generated:", out)
