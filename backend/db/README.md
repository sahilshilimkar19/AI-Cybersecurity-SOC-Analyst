# `backend/db/`

The persistence layer — SQLAlchemy ORM, session management, repositories, the audit writer,
and object storage. It lives under `backend/` because the **backend is the sole write
boundary** to the system of record (governing invariant #7).

## Contents
| Path | Purpose |
|---|---|
| `base.py` | Declarative `Base`, naming convention, and identity/timestamp/soft-delete mixins. |
| `orm/` | ORM models for the 13 core tables (importing registers them on `Base.metadata`). |
| `session.py` | Engine + session factories and a transactional `session_scope`. |
| `repositories/` | Data-access: generic `Repository` + append-only `AuditLogRepository`. |
| `object_store.py` | `ObjectStore` interface + in-memory and MinIO/S3 implementations. |
| `migrations/` | Alembic environment and versioned migrations. |

## Design notes
- **SQLAlchemy 2.0 sync + psycopg3** — see `docs/adr/0002-persistence-and-migrations.md`.
- Enums are stored by their **string value** (matching `models/`).
- The **audit trail is append-only** and tamper-evident (SHA-256 content signature).
- Raw evidence lives in **object storage**, referenced from `log_events.raw_ref`.

## Ownership
Backend squad.

## Testing
ORM metadata tests (no DB), object-store in-memory tests, and DB integration tests against a
real PostgreSQL (run in CI via a Postgres service; skipped locally when no database is
reachable).
