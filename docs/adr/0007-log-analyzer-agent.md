# ADR 0007 — Log Analyzer agent, tools, and prompt assets

- **Status:** Accepted
- **Sprint:** Sprint 7 — Log Analyzer Agent
- **Deciders:** Lead Engineer

## Context

The first agent. The governing documents specify it tightly (SAD §2.1, EDS §4.2):
normalize and correlate heterogeneous logs into a **provenance-tagged timeline**, with
per-source partial failure tolerated, malformed records **quarantined not dropped**, and
one constraint above all — *"structure only; do not infer threats."*

It needs the tools layer (EDS §3.7), log source connectors (SAD §7), and the prompt
assets module (EDS §3.6, §9), none of which existed yet. Those land here because this is
the sprint that first requires them.

## Decision

1. **The Log Analyzer is deterministic.** Parse → extract → correlate → score, with no
   model call. This is not a shortcut: its mandate is to *structure* evidence, which is
   mechanical work, and determinism is what makes golden fixtures meaningful, event ids
   stable across re-runs, and the resulting timeline defensible as evidence rather than
   as an opinion. The model-assisted notability pass arrives with the AI layer and
   inherits the same contract.

2. **Structure-only is enforced in the types, not just the prompt.** There is no
   severity or verdict field anywhere in `LogAnalysisResult`, so the agent *cannot*
   express a threat judgement even by accident. Classification is descriptive
   (`auth_failure`, `process_start`), and a test asserts that overtly hostile text still
   classifies by action rather than verdict.

3. **Parsers are a chain tried in order of specificity** (Windows → JSON → RFC 5424 →
   RFC 3164 → CEF → key=value), with a declared format preferred when the source
   supplies one and a fallback to sniffing when it lies. Field names are matched on a
   **folded key** (`TimeCreated` ≡ `time_created` ≡ `time-created`) — without this, two
   thirds of real-world spellings silently miss.

4. **Timestamps are never invented.** RFC 3164 omits the year, so it is taken from the
   record's **ingestion time**, not the wall clock: reading it from `now()` silently
   misdates every historical log replayed into an investigation. A record with no usable
   time at all is quarantined rather than placed in the sequence at a guessed position;
   one whose time had to be inferred from ingestion is kept but **confidence-penalized**.

5. **Everything missing is an output, not an exception.** An unreadable source becomes a
   typed `LogFetchFailure` → a `SOURCE_UNAVAILABLE` gap; a requested source that returned
   nothing becomes `SOURCE_EMPTY` (deliberately distinguished from failure — silence and
   absence are different facts); unparseable records become `PARSE_FAILURE` gaps with the
   originals retained; a sparsely-covered window becomes `WINDOW_UNCOVERED`.

6. **Correlation splits on time gaps.** Events sharing a host, actor, address, or process
   are grouped, then split wherever consecutive events exceed the window — so a host
   active on Monday and Friday yields two episodes rather than one implausible five-day
   cluster.

7. **Tools enforce least privilege and typed failures.** The registry denies by default;
   an agent may invoke only its granted tools. Operational problems return `ToolResult`
   failures, so a caller can never mistake "it broke" for "there was nothing".

8. **Prompts become versioned assets** with a shared preamble carrying the invariants.
   Assembly wraps untrusted content in delimited blocks and **neutralizes delimiter
   lookalikes** — without that, a crafted log line could close the block early and have
   its remainder read as trusted instruction. Tested with an explicit injection payload.

9. **The agent produces; the backend persists.** The graph node emits normalized events
   into state, and `backend/services/evidence.py` writes them to `log_events`, preserving
   the sole-write-boundary invariant (#7) and keeping agents free of database concerns.

10. **Graph state gains an `evidence` sub-state** (schema version 1 → 2) holding raw
    records, requested sources, and collection failures. Inputs are kept separate from
    findings so what was *ingested* stays distinguishable from what analysis *concluded*.

## Consequences

- **Positive:** the first end-to-end investigative capability, verified by golden
  fixtures across six formats. The pipeline still pauses at the human gate — a test
  asserts adding an agent created no path around it. Everything is reproducible: stable
  event ids, deterministic correlation, no wall-clock dependence.
- **Trade-offs:**
  - Event classification is regex-driven, so it covers common phrasings well and unusual
    vendor prose falls through to `other` rather than being misclassified — the safer
    failure direction, and the patterns are one table to extend.
  - Notability weights are a hand-calibrated triage prior. They are pinned by tests and
    should be re-calibrated against labeled data when it exists.
  - Live SIEM adapters (Elastic, Splunk) are not built here; they satisfy the existing
    `LogSource` protocol and land with the sprints that need them. File and in-process
    connectors ship now.
  - The graph node persists nothing itself; wiring the backend's write into the node's
    lifecycle happens when the backend orchestration endpoints land.
- **No schema change:** the existing `log_events` table already fits normalized events,
  so this sprint adds no migration (`alembic check` clean).
