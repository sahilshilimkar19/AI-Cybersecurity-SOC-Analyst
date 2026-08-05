# ADR 0011 — Patch Recommendation agent, risk prioritization, and advisories

- **Status:** Accepted
- **Sprint:** Sprint 11 — Patch Recommendation Agent
- **Deciders:** Lead Engineer

## Context

The fifth and last agent, and the only one that proposes changing the world
rather than describing it. Everything before it produced statements about what
happened; this one produces a work list — which is precisely the point at which
an assistive platform can quietly become an autonomous one.

The governing documents specify it tightly (SAD §2.5, EDS §4.6): prioritized,
justified remediation with citations, framed explicitly as recommendations
requiring human approval, never recommending an automated destructive action, and
falling back to conservative general guidance — flagged as such — when
remediation knowledge is thin.

It needs the risk prioritizer, the remediation guidance catalogue, and an
advisory lookup for fixed versions (SAD §2.5 required tools), none of which
existed. It is also where `services/` finally earns its place in the folder map.

## Decision

1. **The central invariant is enforced as a shape, not a policy.**
   `RemediationRecommendation` has **no field capable of holding something a
   machine could run** — no `command`, `script`, or `playbook_id` — and a test
   asserts that. `steps` are instructions for a person. A structure that cannot
   hold a runnable artifact cannot be wired to a runner by a later change that
   nobody reviewed carefully, and "we have a policy against that" has never
   stopped anyone.

2. **Human approval is not a flag that can be cleared.**
   `requires_human_approval` is `Literal[True]` — not a default a caller may
   override but the only value the type admits — and a validator refuses a
   recommendation constructed with any approval status other than `PENDING`. An
   agent may propose; only a human may approve (invariants #1, #2).

3. **Nothing is proposed without a reason and a source.** A validator refuses an
   empty rationale or an empty citation list. "Patch it" is not guidance;
   guidance says what to change, why, what it will break, and on whose authority.
   An unjustified change request is one an analyst either applies blindly or
   ignores, and both outcomes are bad.

4. **Risk is not severity, and it lives in `services/`.** Severity says how bad
   the flaw is; risk says how much it matters *here*. Four factors raise it —
   observed exploitation (weighted most, because it is the only one in the
   present tense), internet reachability, asset criticality — and unconfirmed
   applicability *discounts* rather than adds, because a candidate is a lead to
   check rather than an exposure to fix. It sits in `services/` rather than
   `tools/` because the analyst's queue will order itself with the same function:
   one definition of "what first", not two that drift.

5. **The plan takes its worst finding, not its average.** Averaging lets a pile
   of low-risk items dilute the one that matters into invisibility.

6. **Observed exploitation forces urgency regardless of score.** A live intrusion
   does not queue behind a higher-scoring vulnerability nobody is touching.

7. **Behavioral mitigations are scored from the strongest detection that mapped
   to them**, not from the investigation's overall severity. Using the overall
   figure gave every behavioral recommendation identical risk, and a plan where
   everything is equally urgent tells an analyst nothing about what to do first —
   which is the entire job of a prioritized plan.

8. **The guidance catalogue is pinned, like ATT&CK and CWE before it.** Invented
   remediation steps are worse than absent ones: plausible, specific, and wrong,
   and someone will run them on a production host at 2am. Three tiers of
   grounding are stated on every item — vendor-specific (a named fixed version),
   class-specific (a MITRE mitigation for the observed technique or weakness
   class), and generic — so a stopgap is never mistaken for a fix.

9. **A missing fixed version is never invented.** With no advisory the guidance
   names the CVE and points at the advisory rather than guessing a release. A
   fabricated version number is worse than no advice, because someone deploys it.

10. **Advisory fixes are ranked, not first-matched.** Product matching is
    deliberately generous, which is right for deciding whether to look at a
    candidate and wrong for choosing between several packages in one family:
    `log4j-api` matches `log4j-core` well enough to be picked first while carrying
    the wrong version. Attaching the wrong fixed version to a finding is worse
    than attaching none, because it looks authoritative.

11. **A candidate CVE becomes a check, not a patch.** Telling someone to patch
    software you never established they run wastes a change window and erodes
    trust in the whole list. The reason it stayed a candidate is carried through,
    so the analyst knows what to go and establish.

12. **Confidence follows what each recommendation actually rests on.** A
    behavioral mitigation derived from the threat assessment does not become less
    trustworthy because CVE research found nothing; averaging in that zero would
    say something untrue about advice the dossier never touched.

13. **The node runs on every path, including benign.** Unlike the CVE branch —
    which skips external API work nobody asked for — there is nothing to save
    here: an investigation with no findings makes no advisory lookups. What it
    produces instead is an explicit "there is nothing to remediate", which is a
    statement someone may later have to defend.

14. **Only a recorded human decision moves an approval status**, it requires an
    actor, and re-deciding is refused. A second approval is a duplicate or a
    race, and silently accepting it would make the audit trail lie about who
    authorized what. Approving records a decision; there is no dispatcher
    anywhere in the path.

15. **The graph has no edge from remediation to anything that acts.** The plan's
    only route onward is the human gate, and a test asserts no registered node is
    named for an action.

## Consequences

- **Positive:** the agent pipeline is complete. An investigation now runs from
  raw log to a cited report *and* a prioritized, justified, human-gated work
  list. Every safety property that matters here is structural rather than
  behavioral — the types refuse rather than the prose discouraging — so the
  guarantees survive contributors who have not read this document.
- **Trade-offs:**
  - The remediation catalogue is a curated subset covering the shipped detection
    rules and common weakness classes. A technique without an entry falls through
    to labelled generic hardening rather than to silence, and the catalogue is one
    table to extend.
  - Risk weights are hand-calibrated priors pinned by tests. They should be
    re-calibrated against remediation outcomes — which recommendations analysts
    actually accepted — once that data exists.
  - GitHub is the only advisory source. Vendor feeds satisfy the same
    `AdvisorySource` protocol and land with the sprints that need them.
  - Recommendation steps are prose. That is deliberate and costs machine
    actionability, which is exactly the cost this platform intends to pay.
  - The graph node persists nothing itself; wiring the backend's write into the
    node lifecycle happens when the backend orchestration endpoints land.
- **No schema change:** `recommendations` already fits the plan and
  `investigation.remediation_plan` already exists in the state schema, so this
  sprint adds no migration (`alembic check` clean against a database migrated
  from bare).
