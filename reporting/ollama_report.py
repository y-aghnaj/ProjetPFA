import json
import subprocess
from pathlib import Path
from datetime import datetime

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

JSON INPUT:
{json_data}
"""


def _run_ollama(prompt: str, model_name: str) -> str:
    result = subprocess.run(
        ["ollama", "run", model_name],
        input=prompt,
        text=True,
        capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"Ollama failed: {result.stderr}")
    return result.stdout.strip()


def out_path_():
    timestamp = datetime.now().strftime("%Y-%m-%d %H-%M-%S")
    return "reports/report_llm " + timestamp + ".md"


def generate_llm_report(
        report_json_path: str = "reports/report.json",
        out_md_path: str = out_path_(),
        model_name: str = "llama3.1"
) -> str:
    report_path = Path(report_json_path)
    if not report_path.exists():
        raise FileNotFoundError(f"{report_json_path} not found. Run main.py first.")

    data = json.loads(report_path.read_text(encoding="utf-8"))
    prompt = PROMPT_TEMPLATE.format(json_data=json.dumps(data, indent=2))

    output = _run_ollama(prompt, model_name)

    out_path = Path(out_md_path)
    out_path.write_text(output, encoding="utf-8")
    return str(out_path)


if __name__ == "__main__":
    out = generate_llm_report()
    print("LLM report generated:", out)
