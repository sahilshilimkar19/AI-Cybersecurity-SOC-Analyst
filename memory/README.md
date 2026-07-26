# `memory/`

Tiered memory managers, layered by lifetime and scope (EDS §7). Agents access memory only
through these managers — never the underlying stores.

| Tier | Store | Lifetime |
|---|---|---|
| Working | in-process + Redis | one agent turn |
| Session | Redis (hot) + PostgreSQL (durable) | one investigation |
| Conversation | PostgreSQL | per session, retained |
| Long-term | PostgreSQL | persistent, cross-investigation |
| Knowledge | pgvector + PostgreSQL | persistent, curated (read-only to agents) |
| Investigation history | PostgreSQL (+ vector index) | persistent, queryable |

## Ownership
Backend + AI / Agents squads.

## Built in
The **Memory Layer** sprint.

## Testing
Read/write/evict/sync/recover per tier; session survives worker restart; knowledge tier is
read-only to agents (a prompt-injection safety boundary, invariant #3).
