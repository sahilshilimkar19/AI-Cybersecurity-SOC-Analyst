# ADR 0004 — LangGraph orchestration core

- **Status:** Accepted
- **Sprint:** Sprint 4 — LangGraph Core
- **Deciders:** Lead Engineer

## Context

Sprint 4 builds the **deterministic control plane** the agents will later plug into
(SAD §4, EDS §5). The governing documents fix the model: LangGraph is the conductor;
state is a single typed object checkpointed at every transition; nodes are
ownership-scoped; human gates are first-class interrupts; control is deterministic
while reasoning (added later) is not (invariants #1 and #5).

This sprint delivers the **skeleton only** — the machinery, not the agents. The
nodes are empty/system nodes and a stub pipeline; the Log Analyzer, Threat Detector,
CVE Research, Reporter, Patch, Planner, Evaluator, and Summarizer nodes are built in
their own sprints and attach to this skeleton. Memory, RAG, and the AI layer are also
later sprints, so nothing here depends on them.

## Decision

1. **Use LangGraph as the orchestration engine** (pinned `langgraph>=1.1`), not a
   hand-rolled state machine. It is the technology named by the SAD/EDS and provides
   checkpointing, interrupts, conditional routing, and per-node retry out of the box.

2. **A single typed `GraphState`** (SAD §4) composed of ownership-scoped sub-states
   (global / shared / agents / investigation / report / notification / conversation).
   Reducers implement **append-and-checkpoint**: the node-transition log grows
   append-only with a reducer-stamped monotonic `sequence`; sub-states merge
   field-by-field (lists append, nested mappings merge, scalars are overwritten by
   their owning node). Because each node writes only its designated keys, concurrent
   writers to different keys never contend (**writer isolation**). The state module
   deliberately avoids `from __future__ import annotations` because LangGraph resolves
   the reducer metadata on these annotations at runtime.

3. **A pluggable checkpointer** selected by configuration (`BaseCheckpointSaver`),
   mirroring the object-store / session-store pattern (ADR 0002/0003). Only the
   **in-memory** backend ships now. A **durable Postgres** checkpointer is introduced
   with the two-tier durable memory in the Memory sprint (EDS §7), so the durable path
   lands together with the rest of the durable tier rather than half-wired here. This
   sprint therefore adds **no database tables or migrations**.

4. **First-class human interrupt gate.** The graph pauses at an `interrupt`, persists a
   resumable checkpoint, and surfaces "awaiting human" to the backend/UI. Resume
   consumes a recorded decision: approve/edit → close, reject → close, redirect →
   re-enter the pipeline. A **redirect is rollback-by-retain** — it re-runs forward and
   the prior checkpoints are retained, never destroyed (EDS §5). No consequential
   action node is reachable without traversing a gate (invariant #1).

5. **A declarative node registry** is the who-writes-what contract (SAD §5 node
   ownership): each node names its single owner and whether it participates in retry.
   The builder consumes the registry so ownership and retry behavior have one source of
   truth. Agent nodes register here in later sprints.

6. **Per-node retry policy:** exponential backoff + jitter, bounded attempts,
   idempotent re-run from checkpoint. Only `TransientNodeError` is retried; every other
   error fails fast so it can be routed to a human gate rather than silently retried
   (EDS §5 error recovery). The interrupt gate is explicitly **not** retriable.

7. **A runtime service** (`InvestigationGraphService`) is the backend-facing seam
   (EDS §3.3 start/resume/rollback): it keys every investigation to a LangGraph
   `thread_id`, validates human decisions at the boundary (fail-fast on an invalid or
   not-awaited resume), and exposes state inspection, checkpoint history, and rollback.

## Consequences

- **Positive:** the deterministic control plane is provable end-to-end today — a stub
  investigation runs to the gate, pauses, and resumes/redirects/rolls back on a
  recorded decision, with every transition checkpointed and sequenced. Because the
  checkpointer is in-memory, the entire suite runs with **no database or Redis**, so
  graph correctness is fast and portable to verify. The registry + reducers make
  ownership and provenance explicit before any agent exists.
- **Trade-offs:**
  - Durable (Postgres) checkpointing is deferred to the Memory sprint; the in-memory
    checkpointer is per-process and does not survive a restart or span workers. That is
    acceptable for a skeleton and is superseded when the durable tier lands.
  - One targeted `# type: ignore[call-overload]` remains where mypy cannot solve
    LangGraph's contravariant `_Node` protocol union against a stored node callable
    (it resolves fine for a literal `def`); the call is correct and the node signatures
    match. It is the single boundary concession and is documented at the call site.
- **No schema change:** checkpoints live in memory, so Sprint 4 adds no database tables
  or migrations (`alembic check` reports no drift). It introduces the `graph/` package
  and its configuration only.
