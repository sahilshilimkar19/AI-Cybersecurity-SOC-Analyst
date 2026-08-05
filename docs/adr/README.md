# Architecture Decision Records (ADRs)

This directory records **engineering decisions** made during implementation — the ones the
governing documents (`PROJECT_CONTEXT.md`, `TECHNICAL_ARCHITECTURE.md`,
`ENGINEERING_DESIGN_SPEC.md`) leave to the implementing team, or that warrant an explicit,
durable rationale.

ADRs do **not** override the governing documents; they capture decisions *within* their
constraints. If a decision would change the architecture or technology choices, it must be
escalated as a change to the governing documents, not resolved in an ADR.

## Format
Each ADR is a numbered file (`NNNN-title.md`) with: **Status**, **Context**, **Decision**,
**Consequences**. Statuses: Proposed · Accepted · Superseded.

## Index
| ADR | Title | Status |
|---|---|---|
| [0001](0001-bootstrap-and-tooling.md) | Bootstrap toolchain and project layout | Accepted |
| [0002](0002-persistence-and-migrations.md) | Persistence layer and migrations | Accepted |
| [0003](0003-authentication.md) | Authentication and authorization | Accepted |
| [0004](0004-langgraph-core.md) | LangGraph orchestration core | Accepted |
| [0005](0005-memory-layer.md) | Tiered memory layer | Accepted |
| [0006](0006-rag-pipeline.md) | RAG pipeline | Accepted |
| [0007](0007-log-analyzer-agent.md) | Log Analyzer agent, tools, and prompt assets | Accepted |
| [0008](0008-threat-detector-agent.md) | Threat Detector agent, detection tools, and threat-intel enrichment | Accepted |
| [0009](0009-cve-research-agent.md) | CVE Research agent, vulnerability tools, and the NVD feed | Accepted |
| [0010](0010-incident-reporter-agent.md) | Incident Reporter agent, report assembly, and rendering | Accepted |
| [0011](0011-patch-recommendation-agent.md) | Patch Recommendation agent, risk prioritization, and advisories | Accepted |
| [0012](0012-analyst-dashboard.md) | Analyst dashboard, investigation API, and live streaming | Accepted |
