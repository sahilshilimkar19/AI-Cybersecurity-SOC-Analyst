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
