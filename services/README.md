# `services/`

Cross-cutting **domain** logic reused beyond a single agent or the HTTP layer — for example
severity scoring, risk prioritization, and correlation helpers (EDS §3.8).

Distinct from `backend/services/` (application/use-case services): this layer holds pure
domain rules with no dependency on transport or a specific agent.

## Shipped
| Module | Covers |
|---|---|
| `risk.py` | Risk scoring and remediation priority — one definition shared by the agent and the analyst queue |
| `notifications.py` | Who is worth alerting, in what order, and the derived dedupe key that makes dispatch idempotent |

## Rules
Deterministic and side-effect-free where possible; inputs validated against domain schemas.

## Ownership
Backend + AI / Agents squads.

## Built in
As shared domain rules are introduced by the sprints that need them.

## Testing
Deterministic unit tests; score/priority calibration monitored.
