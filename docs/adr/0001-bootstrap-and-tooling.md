# ADR 0001 — Bootstrap toolchain and project layout

- **Status:** Accepted
- **Sprint:** Sprint 1 — Bootstrap Project
- **Deciders:** Lead Engineer

## Context

Sprint 1 establishes the engineering substrate that every later sprint builds on. The
governing documents fix the architecture and the major technologies (Python backend, React/TS
frontend, LangGraph orchestration, PostgreSQL + pgvector, Redis, object storage, cloud-agnostic
Docker/Kubernetes) but intentionally leave the concrete developer toolchain and packaging to
implementation. Those choices must be made once, explicitly, so the team works consistently and
CI can enforce quality from the first commit.

The choices below are constrained by `ENGINEERING_DESIGN_SPEC.md` — §10 (folder structure),
§11 (coding standards: strong typing, structured logging, fail-fast config), §12 (testing), and
§3.14 (configuration).

## Decision

1. **Monorepo layout** exactly as defined in EDS §10: flat top-level packages (`backend/`,
   `agents/`, `graph/`, `memory/`, `rag/`, `tools/`, `services/`, `models/`, `config/`,
   `integrations/`) plus `frontend/`, `tests/`, `docs/`, `scripts/`, `deploy/`, `prompts/`,
   `logs/`. Package discovery is declared explicitly in `pyproject.toml` to support the flat
   multi-package layout.
2. **Python 3.11** as the baseline runtime (matches the development environment; `requires-python
   >= 3.11`).
3. **Tooling:** `ruff` (lint + format), `mypy` (static typing), `pytest` (+ `pytest-cov`) for
   tests, `pre-commit` for local enforcement. A `Makefile` provides task shortcuts.
4. **Configuration:** `pydantic-settings` for typed, validated, fail-fast settings
   (`SOC_`-prefixed env + `.env`); **structlog** for structured logging (JSON or console).
5. **Local infrastructure:** `docker-compose.yml` provisions PostgreSQL + pgvector, Redis, and
   MinIO (S3-compatible object storage) — the backing services later sprints require. The app
   is run directly during development and containerized for production in the Deployment sprint.
6. **CI:** GitHub Actions runs lint, format check, type check, and tests on every push/PR to
   `main` — the "green CI skeleton".

## Consequences

- **Positive:** consistent standards enforced from commit one; contract-first, type-safe
  foundation enables parallel workstreams; a one-command local stack; quality gates block
  regressions early.
- **Trade-offs:** generic top-level package names (e.g. `config`, `models`) are unusual but are
  mandated by EDS §10 and are safe within an isolated application virtualenv; `make` requires a
  POSIX shell on Windows (documented in `CONTRIBUTING.md`).
- **Scope discipline:** no domain models, persistence, orchestration, agents, RAG, frontend, or
  production deployment are implemented in this sprint; those arrive in their own sprints.
