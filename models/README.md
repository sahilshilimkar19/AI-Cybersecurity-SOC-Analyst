# `models/`

The canonical typed **contracts** shared across every layer (EDS §3.13). Everything depends
inward on these shapes, so this layer has no dependencies on other layers.

## Contents (Sprint 2)
| File | Contents |
|---|---|
| `base.py` | `DomainModel`, `IdentifiedModel` base classes (`from_attributes`, strict). |
| `enums.py` | Shared enumerations (roles, statuses, severities, verdicts, channels, ...). |
| `values.py` | Embedded value objects: `Cvss`, `Ioc`, `AttackTechnique`, `Citation`. |
| `user.py` | `User`. |
| `investigation.py` | `Investigation`, `Asset`. |
| `evidence.py` | `LogEvent`. |
| `analysis.py` | `ThreatAssessment`, `CveFinding`. |
| `reporting.py` | `Report`, `Recommendation`. |
| `conversation.py` | `Conversation`, `Message`, `HumanDecision`. |
| `notification.py` | `Notification`. |
| `audit.py` | `AuditLog` (immutable, tamper-evident). |

These are transport-agnostic domain contracts. The SQLAlchemy ORM mapping and persistence
live in `backend/db/` (the backend is the sole write boundary, invariant #7); ORM rows are
converted to these contracts via `from_attributes`.

## Rules
Backward-compatible evolution or an explicit version bump; enum **values** are stable
storage representations — renaming one is a breaking change requiring a migration.

## Ownership
Shared (all squads).

## Later sprints
Graph-state, agent I/O, and event schemas are added by the sprints that introduce them.

## Testing
`tests/models/` covers enum values, validation rules, and construction from ORM-like objects.
