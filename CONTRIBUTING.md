# Contributing & Engineering Standards

This guide describes how to work in this repository. The authoritative, detailed standards
are in [`docs/ENGINEERING_DESIGN_SPEC.md`](docs/ENGINEERING_DESIGN_SPEC.md) §11; this file
is the practical, day-to-day summary. The governing documents in `docs/` are **immutable**
during implementation — code adheres to them; it does not change them.

---

## Development environment

```bash
python -m venv .venv
source .venv/bin/activate          # Windows: .venv\Scripts\activate
pip install -e ".[dev]"
pre-commit install                 # enable pre-commit hooks
cp .env.example .env               # Windows: copy .env.example .env
docker compose up -d               # local infrastructure
```

## Quality gates (must pass before every commit)

| Gate | Command | Enforced by |
|---|---|---|
| Lint | `ruff check .` | pre-commit + CI |
| Format | `ruff format --check .` | pre-commit + CI |
| Types | `mypy .` | pre-commit + CI |
| Tests | `pytest` | CI |

`make lint`, `make typecheck`, and `make test` wrap these commands.

---

## Engineering standards (summary of EDS §11)

- **Naming** — intent-revealing; domain terms match `models/` vocabulary; no abbreviations
  for security-critical concepts (spell out `investigation`, `assessment`).
- **Typing** — strong, explicit types at every module boundary; no untyped public interfaces.
- **Error handling** — typed errors, propagated explicitly, never swallowed; boundaries
  fail-closed; validate all external input before use.
- **Logging** — structured (key-value) via `config/logging.py`; never log secrets/PII;
  escape untrusted content.
- **Comments** — explain *why*, not *what*; document invariants and security assumptions.
- **Imports** — dependencies point inward (clean architecture); no upward/lateral imports
  that break layering; third-party SDKs isolated behind adapters.
- **Configuration** — all environment-specific behavior via `config/`; fail-fast on invalid
  config; never commit secrets.
- **Secrets** — never in code, config files, logs, or payloads; injected at runtime.

## The seven governing invariants (never violate)

1. Human-in-the-loop for all consequential actions, recorded in tamper-evident audit.
2. Agents recommend; the system never enforces.
3. All ingested content is untrusted; data can never become instructions.
4. Everything grounded and cited; un-sourced security claims are flagged.
5. Deterministic control (orchestration), non-deterministic reasoning (agents).
6. Degrade, never collapse; fail toward the human, not toward silence.
7. The backend is the single write boundary to the system of record.

---

## Branching & commits

- Work on short-lived feature branches; open a PR into `main`.
- Keep commits small, logically scoped, and independently reviewable.
- Use [Conventional Commits](https://www.conventionalcommits.org/):
  `feat:`, `fix:`, `chore:`, `build:`, `docs:`, `test:`, `refactor:`, `ci:`.
- Every sprint's work is committed incrementally, not as a single squash.

## Definition of Done (per EDS §18)

A change is done only when it is **implemented, tested, documented, integrated, monitored**
(where applicable), and **reviewed**, with the standards above satisfied.

## Scope discipline

Build only the current sprint's scope (see `docs/SPRINT_ROADMAP.md`). Do not implement
features belonging to later sprints.
