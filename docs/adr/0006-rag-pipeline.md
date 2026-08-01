# ADR 0006 — RAG pipeline

- **Status:** Accepted
- **Sprint:** Sprint 6 — RAG Pipeline
- **Deciders:** Lead Engineer

## Context

RAG is the mechanism behind invariant #4: every security claim must be grounded and
**cited**. The governing documents fix the design (SAD §6, EDS §8, §3.5): allow-listed
sources with trust tiers, boundary-aware chunking, a pluggable embedding provider,
a pgvector index, **hybrid** retrieval (dense + keyword + metadata filters),
freshness/trust re-ranking, citation binding, versioned indexes, and cache fallback.

Sprint 5 left knowledge memory as a read-only placeholder that reported itself
unavailable "until the RAG index exists". This sprint builds that index and closes
the placeholder.

The AI layer is not a sprint in this plan, so embeddings need the same treatment the
summarizer got in Sprint 5: a port with a usable default.

## Decision

1. **Embedding provider is a port with a deterministic default.** The shipped provider
   is a model-free hashing embedder, which makes the entire pipeline reproducible and
   testable offline. It is not semantic and is not pretending to be; a model-backed
   provider implements the same protocol later, and its arrival is precisely an
   index-version change. One model is **pinned per index version** — a corpus embedded
   by two models is not comparable, so re-embedding happens under a new version rather
   than in place.

2. **Allow-listed sources only, with trust tiers.** `SourceRegistry` is the allow-list;
   a document whose source is unknown — or which claims a source other than the one it
   was fetched for — is **refused**, not ranked low. This is a security control: the
   corpus agents reason from is the one thing that must stay trustworthy (invariant #3).

3. **Fetching is a port.** A filesystem fetcher serves curated internal knowledge
   (runbooks, detection rules, policies) and offline snapshots; an in-process fetcher
   serves tests. **Live HTTP adapters for NVD, MITRE, and vendor advisories are
   deliberately out of scope here** — they belong to `integrations/` and land with the
   agents that consume them. They satisfy this same protocol, so nothing in the
   pipeline changes when they arrive.

4. **Chunking follows the document's own structure** (headings, then blank-line blocks),
   packing small sections together and splitting only genuinely oversized ones. Split
   parts carry a shared `parent_chunk_id`, so the whole stays resolvable: the corpus is
   compressed for retrieval, never truncated.

5. **Chunk metadata is flattened into columns**, not stored as a blob, so the filters
   that make security retrieval precise (CVE, CWE, technique, product, publication date,
   trust tier) are indexable.

6. **Indexes are versioned and swapped atomically per source**, with the version derived
   from `(embedding model, corpus content)` — so re-ingesting unchanged documents is a
   no-op and reproducibility is a property of the data rather than of a clock. Superseded
   chunks are **retired, not deleted**: a citation recorded before a refresh still
   resolves. Ingestion failures are isolated per source, leaving the previously active
   version serving.

7. **Retrieval is hybrid and the fusion is weighted toward the keyword path** (0.55 vs
   0.45), because security queries are frequently exact and a lexical hit on an
   identifier is stronger evidence than semantic nearness. A record that *owns* an
   identifier outranks one that merely mentions it.

8. **Freshness is a bounded modifier, not a multiplier.** This was found by the eval
   harness rather than assumed: raw exponential decay is unbounded, so over a multi-year
   corpus a five-year-old CVE record decayed to ~0.001 and became unrankable no matter
   how exactly it matched — an irrelevant recent runbook outranked the canonical
   Log4Shell record. Decay is now compressed into `[0.5, 1.0]`, so newer advisories are
   *preferred* without older canonical records (foundational CVEs, ATT&CK techniques)
   becoming invisible.

9. **Every retrieved chunk yields a citation** using the shared `Citation` contract, so
   what the binder emits is what the Reporter compiles. Citations resolve to the exact
   passage, including retired chunks.

10. **The cache is the degradation path.** Keyed by `query + filters + index version`, so
    a refresh invalidates naturally. If the index is unreachable, the last good answer is
    served with `stale=True` — an investigation continues on explicitly-flagged knowledge
    rather than stopping (invariant #6).

11. **A retrieval eval harness gates the build.** A labeled query→document set asserts
    precision@1 and recall@k against explicit baselines, so a regression in chunking,
    embedding, fusion, or ranking fails CI instead of quietly degrading every agent.
    Current scores on this corpus: **precision@1 = 1.00, recall@k = 1.00**.

12. **Knowledge memory is now RAG-backed.** `RagKnowledgeMemory` satisfies the Sprint 5
    read-only contract, and it is **injected into** `build_memory_service` rather than
    imported by it — the memory layer does not depend on RAG, the composition root wires
    them. Writes are still refused.

## Consequences

- **Positive:** grounding is real and measured, not asserted. Reproducibility is
  concrete (recorded index versions, deterministic embeddings, content-derived version
  ids). The eval harness already earned its place by catching the freshness-decay bug.
  The whole pipeline runs in-process for tests while the pgvector paths are covered by
  integration tests.
- **Trade-offs:**
  - The default embedder is lexical, not semantic, so "dense" recall is really shared
    vocabulary. Hybrid retrieval and the eval baselines are structured so that swapping
    in a real model should raise scores, not reshuffle the design.
  - The keyword path scores candidates in Python over a SQL-bounded set rather than
    using PostgreSQL full-text ranking. That keeps scoring identical between the
    in-process and pgvector stores; a `tsvector` index is the optimization if corpus
    size demands it.
  - The vector column is declared at 384 dimensions, so a provider with different
    dimensions needs a migration alongside its new index version.
  - The retrieval cache is per-process, like the rate limiter (ADR 0003).
- **Schema change:** one migration adding `knowledge_chunks` and
  `knowledge_index_versions`, creating the `vector` extension itself so it is
  self-contained. It applies from a bare database, fully reverses, and leaves no drift.
