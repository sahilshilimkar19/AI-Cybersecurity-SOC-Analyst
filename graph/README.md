# `graph/`

The LangGraph orchestration — the **deterministic conductor** of an investigation.

## Responsibilities
Define nodes/edges/conditional routing; own retry, fallback, and circuit-breaking policy;
checkpoint state after every transition; pause at human-approval interrupts; resume and roll
back; coordinate parallel vs. sequential execution (EDS §5).

## Key properties
- Checkpoint-per-transition for full replayability and forensic provenance.
- Human-approval interrupts are first-class — no consequential action node is reachable
  without traversing a gate (invariant #1).
- Writer-isolated state sub-objects make parallel fan-out safe without locks.

## Ownership
AI / Agents + Backend squads.

## Built in
The **LangGraph Core** sprint (skeleton + checkpointing + interrupts), then wired to agents
in later sprints.

## Testing
Graph tests: routing branches, resume, rollback, parallel join, gate pause/resume — and a
test proving no path bypasses the human gate.
