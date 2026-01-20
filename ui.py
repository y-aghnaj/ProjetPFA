import json
from pathlib import Path
from datetime import datetime

import streamlit as st

from app.pipeline import run_audit
from reporting.ollama_report import generate_llm_report_from_dict


@st.cache_data(show_spinner=False)
def cached_llm_report(report_data: dict, model: str) -> str:
    """
    Cache LLM generation so it won't re-generate if the same report_data + model are used again.
    """
    return generate_llm_report_from_dict(report_data, model_name=model)


st.set_page_config(page_title="OCI Cloud Governance Audit", layout="wide")

st.title("OCI Cloud Governance Audit Prototype")
st.caption("Graph-based assessment + rule engine + risk-based scoring + explainable output")

# ---- Sidebar controls ----
st.sidebar.header("Run settings")

# Scenario list (auto-discover)
scenario_dir = Path("data/scenarios")
scenario_names = []
if scenario_dir.exists():
    scenario_names = sorted([p.stem for p in scenario_dir.glob("*.json")])

scenario = st.sidebar.selectbox(
    "Scenario",
    options=scenario_names if scenario_names else ["data/oci_mock.json"],
    index=0
)

security_w = st.sidebar.slider("Security weight", 0.0, 1.0, 0.7, 0.05)
performance_w = 1.0 - security_w
st.sidebar.write(f"Performance weight: **{performance_w:.2f}**")

export_json = st.sidebar.checkbox("Export reports/report.json", value=True)

st.sidebar.subheader("Local LLM (Ollama)")
use_llm = st.sidebar.checkbox("Enable LLM report generation", value=False)
llm_model = st.sidebar.text_input("Ollama model", value="llama3.1")

st.sidebar.subheader("Recommendations")
use_llm_recos = st.sidebar.checkbox("Generate recommendations with LLM", value=False)

run_btn = st.sidebar.button("Run Audit", type="primary")

# ---- Persist last audit result across Streamlit reruns ----
result = st.session_state.get("last_result")

# ---- Run audit when requested ----
if run_btn:
    with st.spinner("Running audit..."):
        result = run_audit(
            scenario=scenario,
            security_weight=security_w,
            performance_weight=performance_w,
            export_json=export_json,
            report_json_path="reports/report.json",
            use_llm_recos=use_llm_recos,
            llm_model=llm_model,
        )
    st.session_state["last_result"] = result
    st.success("Audit complete.")

# ---- Main area rendering ----
if result is None:
    st.info("Select a scenario and click **Run Audit** from the sidebar.")
else:
    # Scores
    scores = result["scores"]
    c1, c2, c3 = st.columns(3)
    c1.metric("Security Score", scores["security_score"])
    c2.metric("Performance Score", scores["performance_score"])
    c3.metric("Global Score", scores["global_score"])

    st.divider()

    # Findings
    st.subheader("Findings")
    findings = result["findings"]
    if not findings:
        st.info("No findings detected.")
    else:
        severities = sorted(set(f["severity"] for f in findings))
        sel = st.multiselect("Filter by severity", severities, default=severities)
        filtered = [f for f in findings if f["severity"] in sel]
        st.dataframe(filtered, use_container_width=True)

    st.divider()

    # Recommendations
    st.subheader("Recommendations")
    recos = result["recommendations"]
    if not recos:
        st.info("No recommendations.")
    else:
        for r in recos:
            src = r.get("source", "STATIC")
            with st.expander(f"{r['title']} — {r['resource_id']} ({r['responsibility']}) [{src}]"):
                st.write(r.get("rationale", ""))
                st.markdown("**Steps:**")
                for step in r.get("steps", []):
                    st.markdown(f"- {step}")

    st.divider()

    # Exports
    st.subheader("Exports")
    st.download_button(
        label="Download report.json",
        data=json.dumps(result, indent=2).encode("utf-8"),
        file_name="report.json",
        mime="application/json",
    )

    st.divider()

    # LLM report generation
    st.subheader("LLM Audit Report (Ollama)")

    if use_llm:
        gen_btn = st.button("Generate LLM Report", type="primary")

        if gen_btn:
            with st.spinner("Generating report with Ollama... this may take a few minutes."):
                md_text = cached_llm_report(result, llm_model)

            st.success("LLM report generated.")

            # Save timestamped file
            ts = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
            out_path = Path("reports") / f"report_llm_{ts}.md"
            out_path.parent.mkdir(parents=True, exist_ok=True)
            out_path.write_text(md_text, encoding="utf-8")

            st.markdown("### Preview")
            st.markdown(md_text)

            st.download_button(
                label="Download report_llm.md",
                data=md_text.encode("utf-8"),
                file_name=out_path.name,
                mime="text/markdown",
            )
            st.caption(f"Saved locally as: {out_path}")
    else:
        st.info("Enable LLM report generation in the sidebar to generate an audit report.")
