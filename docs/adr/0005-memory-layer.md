# ADR 0005 — Tiered memory layer

- **Status:** Accepted
- **Sprint:** Sprint 5 — Memory Layer
- **Deciders:** Lead Engineer

## Context

The governing documents specify **six memory tiers** with distinct lifetimes, stores,
and eviction rules (SAD §5, EDS §7), all sitting behind the Memory module's interface
(EDS §3.4) so agents never touch a store directly. Two properties are load-bearing:
an investigation must **survive a worker restart** (invariant #6), and knowledge
memory must be **read-only to agents** — the prompt-injection safety boundary
(invariant #3).

ADR 0004 deferred the durable graph checkpointer to this sprint so it would land
together with the rest of the durable tier. That commitment is honored here.

The AI layer does not exist yet (it arrives with the agents), so the summarization
hook must be usable without a model.

## Decision

1. **Six tier managers behind protocols**, each with an in-process implementation
   (tests/local) and a real one, following the object-store and session-store pattern
   (ADR 0002/0003). `MemoryService` composes them and is the only thing agents will
   see.

2. **Session memory is two-tier and durable-first.** Writes go to PostgreSQL *before*
   Redis, so the cache can never be ahead of the source of truth; if the hot write
   fails the fact is still recorded and the next read repopulates. Reads try hot, then
   fall back to durable. `rebuild()` reloads the whole working set, which is how an
   investigation survives a restart or a flushed Redis.

3. **Durable session writes are append-only revisions**, not updates. What an earlier
   node saw stays inspectable, which is what makes provenance and replay real rather
   than aspirational. Every entry carries a non-optional `source`.

4. **Two new tables, and only two.** `session_memory_entries` (durable session tier)
   and `investigation_memory_index` (recall by asset/IoC/technique/CVE). Conversation
   and long-term memory are **read models over the existing investigation entities** —
   the system of record already holds the dialogue, verdicts, and closures, and copying
   them would create a second truth to keep in sync. Knowledge memory has no table
   here because RAG owns its index.

5. **Working memory is in-process and bounded** by a token budget plus an entry cap,
   evicting oldest-first through the summarizer. It is created fresh per turn and never
   shared laterally between nodes. Its recovery story is rebuilding from session memory,
   so persisting a per-turn scratchpad would add cost and a failure mode without buying
   durability.

6. **The summarization hook is a protocol with a deterministic, model-free default**
   (`ReferenceSummarizer`). Summaries are **lossless by reference**: every evicted key
   and its source are named, and the full values remain resolvable from durable memory.
   The model-backed summarizer implements the same protocol later without touching
   callers. Token cost uses a documented characters-per-token heuristic until the AI
   layer supplies a real tokenizer.

7. **Knowledge memory exposes retrieval only**, and its explicit `write` method always
   raises `MemoryAccessError`. Until the RAG index exists the tier reports itself
   unavailable and returns nothing, so callers mark the context **degraded** rather
   than mistaking "not built yet" for "nothing relevant found".

8. **`materialize_context` degrades tier by tier.** An unreachable tier is recorded in
   `degraded_tiers` and the turn proceeds with what is available; the bundle is then
   trimmed to its token budget, with trimmed entries replaced by a reference summary.

9. **Durable graph checkpointer (PostgreSQL)** via LangGraph's `PostgresSaver`,
   selected by `graph_checkpoint_backend`. It owns and migrates its own tables, so they
   are deliberately **outside Alembic** and excluded from autogenerate comparison by an
   `include_name` filter in the migration environment — without it, autogenerate would
   see them as dropped tables.

## Consequences

- **Positive:** restart survival is demonstrated, not asserted — tests resume a paused
  investigation from a *new* runtime against PostgreSQL, and recover session memory
  with a cold cache. The knowledge boundary is enforced by the type surface and tested.
  Every tier has an in-process implementation, so the whole layer is exercisable without
  infrastructure while the real paths are covered by integration tests.
- **Trade-offs:**
  - Conversation and long-term memory as read models mean a cross-investigation
    analytics query costs a join rather than a single denormalized row. That is the
    right trade while volumes are modest; a materialized projection can be added later
    without changing the interface.
  - The token estimator is a heuristic and will disagree with a real tokenizer at the
    margin. The budget is therefore conservative, and the estimator is a single function
    to replace.
  - The hot tier holds one Redis hash per investigation, so a very large working set is
    fetched whole on `get_all`. Acceptable at investigation scale; paging would be the
    fix if it stops being true.
  - `PostgresSaver` holds a long-lived connection owned by the process, unlike the
    pooled SQLAlchemy engine.
- **Schema change:** one migration adding the two tables; it applies, fully reverses,
  and leaves no drift (`alembic check` clean, including with LangGraph's checkpoint
  tables present).
