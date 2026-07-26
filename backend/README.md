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
| `services/` | Application services (investigation, report, notification, user, knowledge). |
| `middleware/` | Auth, validation, rate limiting, request logging & tracing. |
| `workers/` | Async runners for long investigations and ingestion. |

## Ownership
Backend squad.

## Built in
From the **Authentication** sprint onward (see `docs/SPRINT_ROADMAP.md`). Not implemented
during Bootstrap.

## Testing
Unit tests for services/middleware; integration tests for API ↔ data ↔ graph, asserting
persistence and audit side-effects (EDS §12).
