# `rag/`

The Retrieval-Augmented Generation pipeline — grounds agents in authoritative security
knowledge and produces the citations that every security claim must carry (invariant #4).

## Pipeline (EDS §8)
Ingest → clean → chunk → enrich metadata → embed → index (pgvector) → hybrid retrieve
(dense + keyword + metadata filter) → re-rank (freshness/trust) → bind citations.

## Knowledge sources
NVD CVE feeds, MITRE ATT&CK/CWE, vendor & GitHub security advisories, curated internal
runbooks and detection rules.

## Ownership
AI / Agents squad.

## Built in
The **RAG Pipeline** sprint.

## Testing
Retrieval evaluation (precision/recall on a labeled set), citation resolution, freshness/
trust weighting, index-version reproducibility, and cache-fallback with staleness flags.
