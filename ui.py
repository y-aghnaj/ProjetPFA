# ui.py
import json
from pathlib import Path
from datetime import datetime

import streamlit as st

from app.pipeline import run_audit
from reporting.ollama_report import generate_llm_report_from_dict


@st.cache_data(show_spinner=False)
def cached_llm_report(report_data: dict, model: str) -> str:
    return generate_llm_report_from_dict(report_data, model_name=model)


st.set_page_config(page_title="Cloud Governance Audit ", layout="wide")

st.title("Cloud Governance Audit Framework")

# ---- Sidebar controls ----
st.sidebar.header("Run settings")

scenario_dir = Path("data/scenarios")
scenario_names = sorted([p.stem for p in scenario_dir.glob("*.json")]) if scenario_dir.exists() else []
scenario = st.sidebar.selectbox(
    "Scenario",
    options=scenario_names if scenario_names else ["data/oci_mock.json"],
    index=0,
)

baseline = st.sidebar.selectbox(
    "Baseline (optional)",
    options=[""] + scenario_names,
    index=0
)
baseline = baseline if baseline != "" else None

export_json = st.sidebar.checkbox("Export reports/report.json", value=True)

st.sidebar.subheader("Local LLM (Ollama)")
use_llm = st.sidebar.checkbox("Enable LLM report generation", value=False)
llm_model = st.sidebar.text_input("Ollama model", value="llama3.1")

st.sidebar.subheader("Recommendations")
use_llm_recos = st.sidebar.checkbox("Generate recommendations with LLM", value=False)

run_btn = st.sidebar.button("Run Audit", type="primary")

# ---- Persist last audit result across reruns ----
result = st.session_state.get("last_result")

if run_btn:
    result = run_audit(
        scenario=scenario,
        export_json=export_json,
        report_json_path="reports/report.json",
        use_llm_recos=use_llm_recos,
        llm_model=llm_model,
        baseline_scenario=baseline,
    )

    st.session_state["last_result"] = result
    st.success("Audit complete.")

if result is None:
    st.info("Select a scenario and click **Run Audit** from the sidebar.")
else:
    scores = result["scores"]
    pillar_scores = scores.get("pillar_scores", {})

    # ---- Scores summary ----
    c1, c2, c3 = st.columns(3)
    c1.metric("Global Score", scores.get("global_score"))
    c2.metric("Security (compat)", scores.get("security_score"))
    c3.metric("Performance (compat)", scores.get("performance_score"))

    if "delta" in result:
        st.subheader("Dynamic Evolution (Diff Scan)")
        st.caption("Comparison between baseline snapshot and current snapshot.")

        d = result["delta"]

        c1, c2, c3 = st.columns(3)
        c1.metric("Resources added", len(d["resources"]["added"]))
        c2.metric("Resources removed", len(d["resources"]["removed"]))
        c3.metric("Findings added", len(d["findings"]["added"]))

        with st.expander("Resources diff details"):
            st.json(d["resources"])
        with st.expander("Findings diff details"):
            st.json(d["findings"])

    st.divider()

    st.subheader("Well-Architected Pillar Scores")
    if pillar_scores:
        cols = st.columns(5)
        pillars = ["SECURITY", "RELIABILITY", "PERFORMANCE", "COST", "OPERATIONAL_EXCELLENCE"]
        for i, p in enumerate(pillars):
            cols[i].metric(p, pillar_scores.get(p, 0))
    else:
        st.info("No pillar_scores found (check scoring engine).")

    st.divider()

    # ---- Graph ----
    st.subheader("Resource Graph")
    st.graphviz_chart(result.get("graph_dot", ""))

    st.divider()

    # ---- Findings ----
    st.subheader("Findings")
    findings = result.get("findings", [])

    if not findings:
        st.info("No findings detected.")
    else:
        show_suppressed = st.checkbox("Show suppressed findings (covered by composites)", value=False)

        severities = sorted(set(f.get("severity") for f in findings if f.get("severity")))
        sel = st.multiselect("Filter by severity", severities, default=severities)

        filtered = []
        for f in findings:
            if f.get("severity") not in sel:
                continue
            if (not show_suppressed) and f.get("suppressed", False):
                continue
            filtered.append(f)

        st.dataframe(filtered, use_container_width=True)

        with st.expander("Explainability / Traceability (per finding)"):
            for f in filtered:
                title = f"[{f.get('severity')}] {f.get('rule_id')} on {f.get('resource_id')}"
                st.markdown(f"**{title}**")
                st.write(f.get("message", ""))
                st.write("Pillars:", f.get("pillars", []))
                refs = f.get("references", [])
                if refs:
                    st.markdown("**References:**")
                    for r in refs:
                        st.markdown(f"- {r.get('standard','')} {r.get('id','')}: {r.get('name','')}")
                st.markdown("---")

    st.divider()

    # ---- Recommendations ----
    st.subheader("Recommendations")
    recos = result.get("recommendations", [])
    if not recos:
        st.info("No recommendations.")
    else:
        for r in recos:
            src = r.get("source", "STATIC")
            with st.expander(f"{r.get('title')} — {r.get('resource_id')} ({r.get('responsibility')}) [{src}]"):
                st.write(r.get("rationale", ""))
                st.markdown("**Steps:**")
                for step in r.get("steps", []):
                    st.markdown(f"- {step}")

                # optional fields for LLM recos
                if r.get("verification"):
                    st.markdown("**Verification:**")
                    for v in r.get("verification", []):
                        st.markdown(f"- {v}")
                if r.get("risk_if_ignored"):
                    st.markdown("**Risk if ignored:**")
                    st.write(r.get("risk_if_ignored"))

    st.divider()

    # ---- Export ----
    st.subheader("Exports")
    st.download_button(
        label="Download report.json",
        data=json.dumps(result, indent=2).encode("utf-8"),
        file_name="report.json",
        mime="application/json",
    )

    st.divider()

    # ---- LLM Report ----
    st.subheader("LLM Audit Report (Ollama)")
    if use_llm:
        gen_btn = st.button("Generate LLM Report", type="primary")
        if gen_btn:
            with st.spinner("Generating report with Ollama... this may take a few minutes."):
                md_text = cached_llm_report(result, llm_model)

            st.success("LLM report generated.")

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
