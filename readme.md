# Cloud Governance Audit Framework

Cloud Governance Audit Framework is a deterministic, graph-based prototype for cloud governance auditing. Its current implementation focuses on structured JSON scenario snapshots, graph modeling, rule-based finding generation, weighted scoring aligned with the Well-Architected Framework (WAF), recommendation generation, and a Streamlit-based visualization layer. The project is intended primarily as an academic and engineering prototype rather than a production-ready cloud governance platform.

## Current Scope

In its current state, the framework operates on local scenario snapshots rather than live cloud API collection. A scenario is loaded from JSON, normalized through a provider adapter layer, transformed into a directed resource graph, evaluated by a deterministic rule engine, scored through a weighted pillar-based scoring model, and finally exposed through JSON export and a Streamlit user interface. Baseline comparison is also supported, allowing the platform to compare two snapshots and highlight deltas in resources, findings, and scores.

This means the platform already provides a full end-to-end audit workflow, but only for prebuilt or manually prepared input states. The adapters for OCI, AWS, and Azure exist, but they are still v0 pass-through implementations. In other words, multi-cloud support is scaffolded architecturally, but not yet mature from a data-ingestion perspective.

## What Is Actually Implemented

### 1. Scenario-based audit execution

The platform can run an audit from a selected scenario file, optionally compare it against a baseline scenario, and export the result as a structured JSON report. The execution pipeline is centralized in `app/pipeline.py`, which orchestrates loading, normalization, graph construction, rule evaluation, scoring, recommendation generation, and export.

### 2. Resource graph construction

The platform models cloud resources and their relationships as a directed graph. This graph is used both for visualization and for contextual reasoning during rule execution. The graph is exported in DOT format, which is then rendered in the Streamlit UI and can also be downloaded as PNG.

### 3. Deterministic rule engine

The audit core is rule-based and deterministic. The current public implementation includes:
- atomic security rules,
- composite rules,
- one graph-based exposure rule,
- and one performance/cost-oriented rule.

The security checks currently implemented cover public object storage exposure, bucket encryption, bucket logging, bucket versioning, database encryption, database public endpoint exposure, database backup status, SSH exposure, and RDP exposure. Composite rules exist to merge and suppress redundant atomic findings in selected high-risk combinations.

### 4. Explainable findings

Each finding is structured and traceable. Findings include a rule identifier, resource identifier, severity, responsibility attribution, message, pillar mapping, risk/confidence metadata, and references to governance/control sources where available. Suppressed findings are preserved in the data model, which allows the platform to reduce duplicate noise while still keeping audit traceability.

### 5. WAF-aligned scoring

The current scoring model is deterministic and pillar-based. Findings are converted into penalties through a severity-to-penalty mapping, and penalties are aggregated per pillar. If a finding affects multiple pillars, the penalty is split across them to avoid double counting. The framework computes:
- a score per pillar,
- a weighted global score,
- a backward-compatible security score,
- and a backward-compatible performance score.

### 6. Centralized pillar weighting

Pillar weights are currently managed only through `governance/weight_calculator.py`. This is a meaningful architectural improvement because the scoring engine no longer owns the weight logic directly. However, the current implementation is still simple: the `WeightCalculator` returns fixed default weights. A dynamic or data-driven weighting algorithm is not implemented yet.

The default weights currently used are:
- SECURITY: 0.30
- RELIABILITY: 0.20
- PERFORMANCE: 0.15
- COST: 0.15
- OPERATIONAL_EXCELLENCE: 0.20

So the platform has already removed weight duplication from the scoring layer, but it has not yet removed conceptual arbitrariness entirely, since the current values are still static defaults.

### 7. Recommendations

The platform generates static recommendations from findings through a rule-to-recommendation mapping. These recommendations include titles, rationale, remediation steps, verification guidance, and risk-if-ignored fields when available. There is also optional LLM-based recommendation generation, but this is an augmentation layer, not the primary audit logic.

### 8. Baseline comparison and differential analysis

If a baseline scenario is selected, the platform computes differences between the baseline and the current state. This includes:
- added resources,
- removed resources,
- changed resources,
- added findings,
- removed findings,
- persisted findings,
- and a global score delta.

The current resource diff implementation is shallow: it compares fields directly and records changed fields per resource. This is useful for prototype-level governance drift detection, but it is not yet a full semantic infrastructure diff engine.

### 9. Graph visualization

The Streamlit interface currently supports:
- current graph visualization,
- baseline graph visualization,
- differential graph visualization.

The differential graph highlights resource changes visually:
- green for added nodes,
- red for removed nodes,
- yellow for changed nodes.

The graphs can also be downloaded as PNG files from the UI.

### 10. Streamlit interface

The public UI already includes:
- scenario selection,
- optional baseline selection,
- audit execution,
- optional JSON export,
- optional LLM report generation,
- optional LLM recommendation generation,
- graph rendering,
- findings filtering,
- recommendation display,
- report download,
- and a local “Stop Streamlit” button.

The UI is therefore already usable for demonstrations and guided experimentation.

### 11. LLM-assisted reporting

The platform includes optional Markdown report generation through Ollama. This reporting layer is intentionally separated from the core audit logic. The LLM consumes structured audit output and produces a narrative report. The implementation also trims the report input for practicality, including a maximum number of findings in the LLM payload.

This means AI is present in the platform, but currently only as a reporting/recommendation assistant rather than a decision-making component.

## What Exists but Is Still Partial

### Multi-cloud support

OCI, AWS, and Azure adapters exist structurally, but they are currently pass-through implementations. That means the architecture is ready for provider-specific normalization, but true canonical cross-cloud normalization is not yet implemented.

### Weighting methodology

The platform now has a dedicated `WeightCalculator`, which is a strong architectural step. However, it still returns fixed defaults. There is no contextual, statistical, or risk-adaptive weighting algorithm yet.

### Differential graphing

The diff graph is already useful and visually clear, but it currently focuses on node-level differences. It does not yet provide a richer semantic diff for relationships, edge-level changes, or high-level impact summarization.

### LLM integration

LLM-based reporting and recommendation generation are available, but they remain optional and depend on a local Ollama setup. This is useful for controlled experimentation, but it is not yet a production-strength reporting subsystem with validation, orchestration, and hardened operational safeguards.

## What Is Not Yet Implemented

The current platform does **not** yet provide:
- live integration with OCI, AWS, or Azure APIs,
- real-time cloud inventory collection,
- automatic remediation,
- mature canonical multi-cloud normalization,
- advanced edge-level graph diffing,
- temporal trend analysis across many snapshots,
- dynamic or learned pillar weighting,
- production-ready authentication, RBAC, or multi-user operation,
- or a complete observability/logging subsystem exposed as a first-class feature in the public UI.

These are natural next steps, but they should not be confused with already completed capabilities.

## Design Positioning

This repository is best understood as an explainable cloud governance audit prototype. Its main strength is not breadth of cloud coverage, but rather architectural clarity:
- graph-based contextual modeling,
- deterministic rule execution,
- explicit findings,
- transparent weighted scoring,
- and clean separation between core audit logic and optional AI assistance.

That makes it suitable for academic work, governance experimentation, and demonstrative prototypes, especially where explainability matters more than automation scale.

## Repository Structure

- `app/` – orchestration and diffing
- `graph/` – resource graph construction and export
- `rules/` – deterministic audit rules
- `governance/` – WAF-related logic and weight calculation
- `scoring/` – score computation
- `recommendations/` – static and optional LLM-based recommendations
- `reporting/` – Ollama-based Markdown report generation
- `providers/` – provider adapter layer
- `data/` – local scenario snapshots
- `ui.py` – Streamlit interface
- `main.py` – CLI entry point

## Summary

Today, the platform is a working deterministic audit prototype with:
- usable rule execution,
- graph-based contextualization,
- baseline/current comparison,
- weighted scoring,
- JSON export,
- UI-based graph visualization,
- PNG graph download,
- and optional local LLM reporting.

Its strongest implemented areas are the audit pipeline, scoring flow, and graph-driven visualization. Its weakest or least mature areas are live cloud integration, multi-cloud normalization depth, dynamic weighting, and production-grade operationalization.