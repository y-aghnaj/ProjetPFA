import json
import subprocess
from pathlib import Path

MODEL_NAME = "llama3.1"

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

def run_ollama(prompt: str, model_name: str) -> str:
    # Calls: ollama run <model>
    result = subprocess.run(
        ["ollama", "run", model_name],
        input=prompt,
        text=True,
        capture_output=True
    )
    if result.returncode != 0:
        raise RuntimeError(f"Ollama failed: {result.stderr}")
    return result.stdout.strip()

def main():
    report_json_path = Path("reports/report.json")
    if not report_json_path.exists():
        raise FileNotFoundError("reports/report.json not found. Run `python main.py` first.")

    data = json.loads(report_json_path.read_text(encoding="utf-8"))
    prompt = PROMPT_TEMPLATE.format(json_data=json.dumps(data, indent=2))

    output = run_ollama(prompt, MODEL_NAME)

    out_path = Path("reports/report_llm.md")
    out_path.write_text(output, encoding="utf-8")
    print("LLM report generated:", out_path)

if __name__ == "__main__":
    main()
