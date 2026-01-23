import json
import subprocess
from pathlib import Path
from datetime import datetime
from typing import Any, Dict, List, Optional

PROMPT_TEMPLATE = """You are a cloud governance auditor specializing in Oracle Cloud Infrastructure (OCI).

Write a professional assessment report based ONLY on the JSON input below.

Hard constraints:
- Do NOT invent any resources, findings, scores, or recommendations.
- Use an audit-style tone.
- Include sections:
  1) Executive Summary
  2) Environment Overview (OCI)
  3) Scores (Security, Performance, Global) with brief interpretation
  4) Key Findings (ordered by severity)
  5) Shared Responsibility Assignment (Customer/CSP/Shared)
  6) Recommendations (actionable, step-by-step)
  7) Next Steps and Re-scan Plan
- Keep it clear and structured, with bullet points where useful.
- In the SRM section, always mention both CSP and Customer responsibilities.
  If findings are customer-side, state that CSP responsibilities remain baseline
  and are not directly remediated by the customer.
  Do NOT say CSP responsibilities are "not applicable".

JSON INPUT:
{json_data}
"""

SEV_RANK = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}


def _run_ollama(prompt: str, model_name: str, timeout_s: Optional[int] = None) -> str:
    """
    Run a local Ollama model safely on Windows.
    Forces UTF-8 decoding to avoid cp1252 Unicode errors.
    Adds optional timeout to avoid hanging forever.
    """
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
    return result.stdout.strip()


def _timestamped_report_path() -> Path:
    timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
    return Path("reports") / f"report_llm_{timestamp}.md"


def _trim_text(s: Any, max_chars: int = 400) -> Any:
    if isinstance(s, str) and len(s) > max_chars:
        return s[:max_chars] + "…"
    return s


def _compact_findings(findings: List[Dict[str, Any]], max_findings: int = 25) -> List[Dict[str, Any]]:
    # remove suppressed + sort by severity then risk if present
    clean = [f for f in findings if not f.get("suppressed", False)]
    clean.sort(
        key=lambda f: (
            -SEV_RANK.get(str(f.get("severity", "")).upper(), 0),
            -float(f.get("risk", 0.0)),
        )
    )
    clean = clean[:max_findings]

    compacted = []
    for f in clean:
        compacted.append({
            "rule_id": f.get("rule_id"),
            "resource_id": f.get("resource_id"),
            "severity": f.get("severity"),
            "responsibility": f.get("responsibility"),
            "message": _trim_text(f.get("message"), 500),
            "risk": f.get("risk", None),
            "impact": f.get("impact", None),
            "evidence": {k: _trim_text(v, 200) for k, v in (f.get("evidence") or {}).items()},
            "context": {k: _trim_text(v, 200) for k, v in (f.get("context") or {}).items()},
        })
    return compacted


def _compact_recommendations(recos: List[Dict[str, Any]], max_recos: int = 15) -> List[Dict[str, Any]]:
    recos = recos[:max_recos]
    compacted = []
    for r in recos:
        steps = r.get("steps") or []
        if isinstance(steps, list):
            steps = steps[:7]
        compacted.append({
            "rule_id": r.get("rule_id"),
            "resource_id": r.get("resource_id"),
            "title": _trim_text(r.get("title"), 200),
            "responsibility": r.get("responsibility"),
            "rationale": _trim_text(r.get("rationale"), 400),
            "steps": [ _trim_text(s, 200) for s in steps ] if isinstance(steps, list) else steps,
            "source": r.get("source"),
        })
    return compacted


def compact_audit_result_for_llm(audit: Dict[str, Any]) -> Dict[str, Any]:
    """
    Keeps only what the LLM needs.
    Removes huge fields like graph_dot/resources/relations when present.
    """
    out = {
        "provider": audit.get("provider"),
        "scenario": audit.get("scenario"),
        "metadata": audit.get("metadata", None),
        "summary": audit.get("summary"),
        "scores": audit.get("scores"),
    }

    findings = audit.get("findings") or []
    if isinstance(findings, list):
        out["findings"] = _compact_findings(findings, max_findings=25)
        out["findings_total"] = len([f for f in findings if not f.get("suppressed", False)])

    recos = audit.get("recommendations") or []
    if isinstance(recos, list) and recos:
        out["recommendations"] = _compact_recommendations(recos, max_recos=15)

    # Explicitly drop heavy fields if they exist
    # (keeping them out prevents huge prompts)
    # graph_dot, resources, relations, raw_state, etc.
    return out


def generate_llm_report(
    report_json_path: str = "reports/report.json",
    model_name: str = "llama3.1",
    timeout_s: int = 480,  # 8 minutes
) -> str:
    """
    Generate a timestamped Markdown audit report from the JSON report.
    Filename ALWAYS includes a timestamp.
    """
    report_path = Path(report_json_path)
    if not report_path.exists():
        raise FileNotFoundError(f"{report_json_path} not found. Run main.py first.")

    data = json.loads(report_path.read_text(encoding="utf-8"))
    compact = compact_audit_result_for_llm(data)

    prompt = PROMPT_TEMPLATE.format(json_data=json.dumps(compact, indent=2, ensure_ascii=False))
    output = _run_ollama(prompt, model_name, timeout_s=timeout_s)

    out_path = _timestamped_report_path()
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(output, encoding="utf-8")
    return str(out_path)


def generate_llm_report_from_dict(
    report_data: dict,
    model_name: str = "llama3.1",
    timeout_s: int = 480,
) -> str:
    """
    Generate Markdown audit report directly from an in-memory dict.
    Returns the markdown text.
    """
    compact = compact_audit_result_for_llm(report_data)
    prompt = PROMPT_TEMPLATE.format(json_data=json.dumps(compact, indent=2, ensure_ascii=False))
    return _run_ollama(prompt, model_name, timeout_s=timeout_s)


if __name__ == "__main__":
    out = generate_llm_report()
    print("LLM report generated:", out)
