# `backend/`

The application backend and the **sole write boundary** to the system of record
(governing invariant #7).

## Responsibilities
Validate input, enforce authentication/authorization, persist data and audit, invoke the
orchestration graph, and dispatch notifications. No other layer writes to the database.

## Sub-packages
| Path | Purpose |
|---|---|
| `api/` | Endpoint/route definitions (design in `TECHNICAL_ARCHITECTURE.md` §12). |
| `api/schemas/` | Request/response contracts — projections, deliberately narrower than the domain models. |
| `api/stream.py` | Server-Sent Events for live investigation progress. |
| `services/` | Application services (investigation, report, notification, user, knowledge). |
| `middleware/` | Auth, validation, rate limiting, request logging & tracing. |
| `workers/` | Async runners for long investigations and ingestion. |
| `db/` | ORM models, repositories, session management, and migrations. |

## The seam between the graph and the screen

The graph *produces*; the backend *writes*; the frontend reads what was written.
`services/investigations.py` owns that seam, and `workers/investigations.py` runs
the pipeline, persisting each agent's output the moment it lands rather than at
the end — so progress is visible while a run is going, and a run that dies leaves
the work already done behind it (invariant #6).

Two properties are worth knowing before changing anything here. **Progress is
recorded, not inferred**: `investigations.pipeline` stores which stages ran,
because deriving that from which artifacts exist cannot tell research that found
nothing from research that never ran. And **a human decision is committed before
the graph is resumed**, so an orchestration failure cannot erase the record of
what a person decided (invariant #1).

## Ownership
Backend squad.

## Built in
From the **Authentication** sprint onward (see `docs/SPRINT_ROADMAP.md`). Not implemented
during Bootstrap.

## Testing
Unit tests for services/middleware; integration tests for API ↔ data ↔ graph, asserting
persistence and audit side-effects (EDS §12).
