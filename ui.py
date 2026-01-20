import json
from pathlib import Path

import streamlit as st

from app.pipeline import run_audit

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

run_btn = st.sidebar.button("Run Audit", type="primary")

# ---- Main area ----
if run_btn:
    with st.spinner("Running audit..."):
        result = run_audit(
            scenario=scenario,
            security_weight=security_w,
            performance_weight=performance_w,
            export_json=export_json,
            report_json_path="reports/report.json",
        )

    st.success("Audit complete.")

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
        # Simple filter
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
            with st.expander(f"{r['title']}  —  {r['resource_id']}  ({r['responsibility']})", expanded=False):
                st.write(r["rationale"])
                st.markdown("**Steps:**")
                for step in r["steps"]:
                    st.markdown(f"- {step}")

    st.divider()

    # Download report.json (from memory)
    st.subheader("Exports")
    st.download_button(
        label="Download report.json",
        data=json.dumps(result, indent=2).encode("utf-8"),
        file_name="report.json",
        mime="application/json",
    )

else:
    st.info("Select a scenario and click **Run Audit** from the sidebar.")
