# AI Cybersecurity SOC Analyst

An enterprise-grade **Agentic AI Security Operations Center (SOC) Analyst** that assists
cybersecurity teams by autonomously investigating security incidents with a team of
collaborating specialized AI agents — while keeping a **human analyst in control**.

> **Positioning:** the system *assists, it does not replace*. Agents investigate and
> recommend; humans decide and act. See [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md).

---

## Status

Early implementation. This repository is being built **sprint by sprint** per
[`docs/SPRINT_ROADMAP.md`](docs/SPRINT_ROADMAP.md).

**Current milestone: Sprint 1 — Bootstrap Project.**
The monorepo structure, tooling, configuration foundation, local dev stack, and CI are in
place. Domain models, persistence, the orchestration graph, agents, RAG, the frontend, and
deployment are delivered in later sprints and are intentionally **not** implemented yet.

---

## Governing documents (source of truth)

| Document | Purpose |
|---|---|
| [`docs/PROJECT_CONTEXT.md`](docs/PROJECT_CONTEXT.md) | What we are building and why |
| [`docs/TECHNICAL_ARCHITECTURE.md`](docs/TECHNICAL_ARCHITECTURE.md) | The Software Architecture Document (how) |
| [`docs/ENGINEERING_DESIGN_SPEC.md`](docs/ENGINEERING_DESIGN_SPEC.md) | The Engineering Design Specification (build-level) |
| [`docs/SPRINT_ROADMAP.md`](docs/SPRINT_ROADMAP.md) | Sprint-by-sprint delivery plan |

These documents are **immutable** during implementation. Code adheres to them; it does not
modify them.

---

## Repository layout

The monorepo mirrors the architecture layers (see `ENGINEERING_DESIGN_SPEC.md` §10):

```
backend/        Application backend: API, services, middleware, workers (sole write boundary)
frontend/       Analyst-facing SPA (built from the Frontend sprint)
agents/         The specialized AI agents + shared agent contracts
graph/          LangGraph orchestration: nodes, edges, checkpoints, human-approval gates
memory/         Tiered memory managers (working/session/long-term/knowledge/...)
rag/            Retrieval-Augmented Generation pipeline (grounding + citations)
tools/          Deterministic agent tools (parsers, extractors, scorers, lookups)
prompts/        Versioned prompt assets and their contracts
services/       Cross-cutting domain services (scoring, prioritization, ...)
models/         Canonical typed schemas & contracts
config/         Typed, validated configuration + structured logging foundation
integrations/   Isolated adapters to external systems (threat intel, SIEM, ...)
tests/          Unit / integration / agent / eval / security / performance suites
docs/           Governing documents, ADRs, runbooks
scripts/        Operational & developer scripts
deploy/         Dockerfiles, Kubernetes manifests, CI/CD (from the Deployment sprint)
logs/           Runtime log output (git-ignored)
```

---

## Prerequisites

- **Python** 3.11+
- **Docker** + Docker Compose (for the local dependency stack)
- **Node.js** 20+ (only needed from the Frontend sprint)

---

## Quick start (local development)

```bash
# 1. Create and activate a virtual environment
python -m venv .venv
source .venv/bin/activate        # Windows: .venv\Scripts\activate

# 2. Install the project with development tooling
pip install -e ".[dev]"

# 3. Copy the environment template and adjust as needed
cp .env.example .env             # Windows: copy .env.example .env

# 4. Start local infrastructure (PostgreSQL + pgvector, Redis, object storage)
docker compose up -d

# 5. Run the quality gates
ruff check .                     # lint
ruff format --check .            # format check
mypy .                           # type check
pytest                           # tests
```

A `Makefile` provides shortcuts (`make install-dev`, `make lint`, `make typecheck`,
`make test`, `make up`, `make down`). See [`CONTRIBUTING.md`](CONTRIBUTING.md) for the full
developer workflow and engineering standards.

---

## Engineering principles

Modular, contract-first, test-first, and secure-by-construction. The full set of standards
lives in `ENGINEERING_DESIGN_SPEC.md` §11 and is summarized in [`CONTRIBUTING.md`](CONTRIBUTING.md).
The seven governing invariants (human-in-the-loop, agents-recommend-only, untrusted-input
boundary, grounded-and-cited, deterministic-control, degrade-never-collapse, single-write-boundary)
hold across every module and sprint.
