# ADR 0010 — Incident Reporter agent, report assembly, and rendering

- **Status:** Accepted
- **Sprint:** Sprint 10 — Incident Reporter
- **Deciders:** Lead Engineer

## Context

The fourth agent, and the first whose output a human reads as prose. The
governing documents specify it tightly (SAD §2.4, EDS §4.5): an executive summary
and a technical section, a timeline, affected assets, indicators, techniques,
CVEs, caveats, and citations — under two constraints that shape everything below.
**Only claims supported by upstream state, no new findings**, and **gaps marked
explicitly rather than omitted**.

It needs the report/timeline assembler, the citation compiler, and the template
renderer (SAD §2.4 required tools), none of which existed. It is also where the
graph gains the artifact the human gate has been asking analysts to approve
without.

## Decision

1. **"Only supported claims" is enforced in the contract.** `ReportFinding`
   requires a `FindingSupport` naming the events, detections, techniques, CVEs,
   or indicators it rests on, and a validator refuses a finding with none.
   Synthesis is where fabrication happens, because prose is fluent in a way
   structured output is not: a sentence that smooths over a gap reads better than
   one that names it, and the smoother sentence is the one that survives review.
   Requiring each finding to point at something makes the invention impossible
   rather than merely discouraged.

2. **Findings are restatements, not compositions.** Each detection signal, each
   confirmed hostile indicator, and each confirmed CVE becomes one finding
   carrying that artifact's own identifiers. The reporter never writes a
   free-form claim, so there is no code path through which one could appear.

3. **The reporter does not re-assess.** Verdict, severity, and applicability were
   decided upstream and are carried through unchanged. A synthesis layer that can
   revise a conclusion is a second, unaudited detector.

4. **A skipped section is not a missing section.** CVE research correctly skipped
   on a benign verdict is not a gap, and reporting it as one would make every
   routine investigation read as incomplete — which is how caveats stop being
   read at all. The reporter computes which sections were *expected* from the
   verdict and faults the report only for those.

5. **Everything else that weakens the report is a stated caveat**, each naming a
   specific limitation rather than a general disclaimer: coverage gaps carried
   through verbatim, low upstream confidence, degraded enrichment, stale
   research, unconfirmed CVE candidates, a required escalation, and a truncated
   timeline. "Confidence may vary" tells a reader nothing; "the SIEM was
   unreachable for this window" tells them what to go and get.

6. **Caveats appear in the executive summary, not only in an appendix.** The
   summary states the count and points at the section. A caveated investigation
   becoming a confident one somewhere between the analyst and the board is a
   failure mode of *document structure*, not of analysis.

7. **Rendering is a security boundary.** Almost everything in a report
   originates in attacker-influenceable content — log messages, command lines,
   indicator values, CVE descriptions. Written into Markdown unescaped, a crafted
   value can forge a heading, close a table and start prose of its own, or open a
   code fence that swallows the rest of the document. Every untrusted value is
   escaped or fenced, so hostile content is *displayed* rather than *interpreted*
   (invariant #3). A missing value renders as a placeholder rather than the
   literal word "None", which a reader cannot distinguish from a real value.

8. **Truncation is reported, never silent.** A long timeline is bounded so the
   document stays readable, and the count of omitted entries becomes a caveat. A
   reader who cannot tell a complete timeline from a truncated one reads its last
   row as the end of the incident. When truncating, the *most notable* entries
   are kept rather than the first N — an attack's important moments are rarely
   its earliest — and the retained set is re-sorted chronologically so the
   narrative still reads forwards.

9. **Timeline rows carry the raw reference.** A timeline a reader cannot walk
   back to the original log line is a story rather than a record, and the report
   has to survive someone disagreeing with it.

10. **Citations are compiled once and numbered stably.** The same source cited
    from three findings is one reference, and first-seen ordering means a
    regenerated report numbers identically — which is what makes `[3]` a stable
    thing to quote.

11. **Only confirmed CVEs reach the vulnerabilities table.** Candidates are
    surfaced as a caveat instead: listing them beside confirmations invites a
    reader to treat "might apply" as "applies".

12. **The report runs on both arms of the verdict branch.** A benign
    investigation still produces a record — "we looked and found nothing" is a
    conclusion someone may have to defend later, and an investigation that leaves
    no document behind cannot be reviewed at all.

13. **The report is always a draft; only a human makes it final.** The persistence
    service writes `DRAFT` regardless of what the agent produced, and
    `finalize_report` is a separate operation driven by a recorded decision. A
    `final` status an agent could set would mean nothing (invariant #1).

14. **Regeneration adds a version; it never replaces one.** A report is
    reproducible from investigation state, but the document an analyst actually
    read has to stay readable, because that is what their decision rested on. The
    unique constraint on `(investigation_id, version)` enforces this in the
    database rather than by convention.

15. **The gate carries the executive summary.** An analyst approves a document,
    not a percentage, so the interrupt payload now includes the summary and the
    report's status.

## Consequences

- **Positive:** an investigation now runs end to end from raw log to a cited,
  caveated, human-readable report — the product promise, minus remediation. The
  pipeline still pauses at the human gate; a test asserts a fourth agent created
  no path around it. Reports are reproducible: the same state renders the same
  document, byte for byte.
- **Trade-offs:**
  - The rendered Markdown is stored rather than re-derived at read time. A
    template change therefore does not retroactively alter documents already
    signed off — which is the point — but improving the template requires
    regenerating to see it applied.
  - Every threat finding inherits the assessment's overall confidence rather than
    carrying a per-detection figure, because a deterministic rule match has no
    independent confidence of its own. The number repeats across findings; the
    alternative was inventing per-finding precision that does not exist.
  - The report is Markdown only. PDF/HTML export and audience-tailored variants
    (EDS §4.5 future improvements) land with the frontend that needs them.
  - The graph node persists nothing itself; wiring the backend's write into the
    node lifecycle happens when the backend orchestration endpoints land.
- **No schema change:** `reports` already fits the document and the `report`
  sub-state already exists in the graph state schema, so this sprint adds no
  migration (`alembic check` clean against a database migrated from bare).
