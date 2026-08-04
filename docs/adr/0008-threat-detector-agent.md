# ADR 0008 — Threat Detector agent, detection tools, and threat-intel enrichment

- **Status:** Accepted
- **Sprint:** Sprint 8 — Threat Detector Agent
- **Deciders:** Lead Engineer

## Context

The second agent, and the first that renders a *judgement*. The governing
documents specify it tightly (SAD §2.2, EDS §4.3): verdict, IoCs, ATT&CK mapping,
severity, triage priority — with three constraints that shape every decision
below. Evidence must stay separate from inference; IoC reputation must never be
fabricated; ambiguous high-impact cases must escalate.

It needs the detection/IoC/ATT&CK/severity tools (EDS §4.3 required tools) and
the first live external enrichment adapter (SAD §7), which in turn needs the
cache / rate-limiter / circuit-breaker pattern every integration is supposed to
have (EDS §3.12). Those land here because this is the sprint that first requires
them.

## Decision

1. **The Threat Detector is deterministic**, like the Log Analyzer before it:
   extract → enrich → detect → map → score. Reproducibility is what makes an
   assessment defensible when it is disputed, and what lets the labeled fixtures
   in the test suite function as *calibration* rather than as snapshots. The
   model-assisted pass arrives with the AI layer and inherits this contract.

2. **Reputation is never invented — enforced structurally.** `IocIndicator`
   starts at `UNKNOWN` with `enriched=False`, and no code path sets a reputation
   without also recording the source that asserted it. The default provider is
   `UnavailableReputationProvider`, which *fails* every lookup with a named
   reason rather than returning a clean-looking nothing. An unconfigured
   deployment therefore produces assessments explicitly flagged
   `enrichment_status=unavailable` with lowered confidence. "We did not check"
   can never render as "it is clean".

3. **Evidence and inference are separated in the output type.** Every statement
   is an `AssessmentClaim` tagged `observation` or `inference`, in the order the
   reasoning was made. Splitting them into two unrelated fields would let one be
   displayed without the other; tagging them keeps the distinction attached to
   each step. The verdict itself is recorded as an inference.

4. **Detection rules are data, not control flow.** A rule is a record — id, name,
   description, weight, techniques, evaluator — so the catalogue can be
   inspected, weighted, documented, and extended without touching the engine.
   Fifteen rules ship, each individually tested both for what it detects *and*
   for the ordinary activity it must not fire on.

5. **Common behavior scores low, not zero, and does not corroborate.** A
   PowerShell launch is administration; an *encoded* PowerShell launch is not.
   They are separate rules an order of magnitude apart in weight. Critically,
   rules below a weight threshold are **context-only**: they appear in the
   assessment and map to techniques, but they do not raise the score or harden
   the verdict. Without that line a heavy rule and the low-weight rule that fired
   on the *same event* would corroborate each other, and one event would
   manufacture its own second opinion.

6. **One strong rule is suspicious; corroboration makes it malicious.** A
   malicious verdict requires either confirmed hostile intelligence — an external
   assertion about a specific indicator — or a high score plus at least two
   substantive rules. This is what keeps a single noisy heuristic from declaring
   an incident.

7. **Missing evidence lowers confidence, never severity.** Scoring gaps as
   mitigation would systematically under-rate exactly the incidents where an
   attacker succeeded in destroying the record. Gaps, degraded enrichment, and
   poor parse quality are all confidence factors; none of them touch the score.

8. **The ATT&CK vocabulary is pinned.** Names and tactics come only from a
   curated catalogue, and an identifier not in it is dropped rather than
   described. Every mapping carries a citation to its ATT&CK page, so the claim
   "this is T1110" is checkable by following a link rather than by trusting the
   platform (invariant #4). A crafted log line naming `T9999` produces nothing.

9. **Hosts and accounts are correlation keys, not indicators.** Treating every
   username as an IoC floods the assessment and makes internal identities look
   like findings. Indicators are addresses, domains, URLs, hashes, paths, and
   processes — and all of them are stored **defanged** as well as raw, so
   anything that renders one has an inert form without having to remember to
   neutralize it at the edge.

10. **Estate-internal indicators are never submitted to a third party.**
    Enrichment must not leak internal topology. Internal is defined explicitly as
    RFC 1918 / unique-local / CGNAT / loopback / link-local plus configured
    CIDRs — deliberately *not* `ipaddress.is_private`, which also covers the
    documentation ranges. Marking an external address internal fails silently in
    the dangerous direction: it is neither enriched nor scrutinized. File paths
    and process names are excluded too; they routinely embed usernames.

11. **Resilience primitives are shared, not per-adapter.** One TTL cache, one
    token-bucket rate limiter, one circuit breaker, each with an injectable
    monotonic clock. Time-dependent behavior verified with `sleep` is verified
    badly, and expiry, refill, and half-open recovery are precisely the paths
    that must not be left to chance. An outage degrades to a **stale cached
    verdict flagged stale**, never to a guess.

12. **The benign path still traverses the human gate.** SAD §5 anticipates
    branching on the verdict once the downstream fan-out exists. What it must not
    become is an automatic close: closing an investigation is itself a
    consequential outcome, and invariant #1 reserves those for a person. So the
    verdict is consumed by `triage` and surfaced in the gate payload — verdict,
    severity, priority, confidence, and an explicit `escalation_required` flag —
    and every disposition, including benign, pauses for a human.

13. **Escalation is part of the contract.** "Ambiguous high-impact cases
    escalate" is implemented as a computed field with a stated reason, not as an
    expectation that a caller notices. Certainty about something small is
    routine; uncertainty about something small is noise; it is uncertainty about
    something that would *hurt* that needs a senior human.

14. **The agent produces; the backend persists.** `backend/services/assessment.py`
    writes assessments, preserving the sole-write-boundary invariant (#7).
    Assessments are **versioned, never overwritten**: an investigation's
    understanding changes, and the record of what was believed at each point is
    what makes the decision defensible afterwards.

## Consequences

- **Positive:** the first end-to-end investigative *verdict*, calibrated against
  labeled benign / suspicious / malicious fixtures that assert the severity
  *band* rather than the exact number — so the scoring constants can be re-tuned
  without rewriting the suite, but a scenario cannot silently change category.
  The pipeline still pauses at the human gate; a test asserts that adding a
  second agent created no path around it. Assessments are reproducible, and every
  finding walks back to the events that produced it.
- **Trade-offs:**
  - Detection rules are regex- and threshold-driven, so they cover common
    phrasings well and unusual vendor prose falls through to no signal rather
    than to a wrong one — the safer failure direction, and the catalogue is one
    table to extend.
  - Rule weights and the corroboration threshold are hand-calibrated triage
    priors pinned by fixtures. They should be re-calibrated against labeled
    incident data when it exists.
  - The ATT&CK catalogue is a curated subset covering the shipped rules, not the
    full matrix. It grows with the rules; the RAG corpus supplies the surrounding
    narrative.
  - VirusTotal is the only live intel adapter. Others satisfy the same
    `ReputationProvider` protocol and land with the sprints that need them.
  - The graph node persists nothing itself; wiring the backend's write into the
    node lifecycle happens when the backend orchestration endpoints land.
- **No schema change:** `threat_assessments` already fits the assessment, so this
  sprint adds no migration (`alembic check` clean against a database migrated
  from bare).
- **Coverage scope widened:** `agents`, `tools`, `integrations`, `prompts`, and
  `services` were missing from the default coverage source. Agent and tool code
  carries the platform's safety behavior, so leaving it out let untested
  guardrails look covered.
