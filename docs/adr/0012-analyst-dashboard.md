# ADR 0012 — The analyst dashboard, the investigation API, and live streaming

- **Status:** Accepted
- **Sprint:** Sprint 12 — Frontend Dashboard
- **Deciders:** Lead Engineer

## Context

Eleven sprints produced a pipeline that runs from raw log to a cited report and a
prioritized, human-gated work list — and no way for a human to see any of it. The
human gate has been a first-class construct since Sprint 4 and, until now, one
that only a test could pass through.

This sprint builds the surface an analyst actually uses (SAD §13): seven screens,
live investigation progress, and the approval moment itself. It also has to build
what those screens read. The backend had auth and health endpoints and nothing
else; SAD §12 specifies the investigation, human-gate, report, and notification
resources, and none existed. ADR 0011 explicitly deferred wiring the backend's
writes into the graph node lifecycle "when the backend orchestration endpoints
land" — this is where they land.

## Decision

1. **The backend is where the graph's output becomes a record, and the frontend
   reads only the record.** Nothing in `frontend/` talks to the graph and nothing
   in `graph/` talks to the database (invariant #7). The seam is
   `backend/services/investigations.py`, which writes and projects, and
   `backend/workers/investigations.py`, which runs the pipeline and persists each
   agent's output as it lands.

2. **Triggering an investigation returns a handle; the work proceeds in the
   background.** 202, not 201: the case record exists, the analysis it will carry
   does not yet (SAD §12). Holding an HTTP request open for the length of a
   pipeline run is a design that fails the first time an investigation takes a
   minute.

3. **Each stage is persisted the moment it finishes, in its own transaction.**
   Two things follow. The dashboard has something true to show while the run is
   still going — a stream over a run that only writes at the end has nothing to
   stream. And a run that dies at the fourth stage leaves the first three stages'
   work in the record rather than discarding an investigation's worth of analysis
   (invariant #6). The graph gained an `on_node` callback to make this possible;
   a callback that raises costs its own report, never the run.

4. **Progress is recorded, not inferred, and that needed a column.** Deriving
   stage completion from which artifacts exist cannot distinguish research that
   found nothing from research that never ran, and a progress bar that lies about
   what was checked is worse than no progress bar. `investigations.pipeline`
   records what actually ran. It is also why a skipped stage is a *third* state
   rather than a variant of complete or pending: CVE research on a benign verdict
   was correctly not performed, and shown as either of the others it says
   something false about an estate.

5. **A recorded decision and its consequence are two steps, committed
   separately.** The human decision is written and committed *before* the graph
   is resumed. What a person decided is a fact about the past; whether the
   machine then managed to act on it is a separate fact, and an orchestration
   failure must not be able to erase an accountability record (invariant #1).

6. **Only a plain approval promotes a report from draft to final.** "Request
   changes" means the analyst has not signed off on the document in front of
   them, so it stays a draft.

7. **The event stream is Server-Sent Events, and every event is a whole
   snapshot.** SSE because the traffic is strictly one-way — the server reports,
   and every command goes back over an ordinary audited POST, where a
   bidirectional socket would add a second unaudited path into the write
   boundary. Whole snapshots because that makes stream loss a non-event: a client
   that reconnects after any gap gets the complete current truth on the next
   message, so there is no replay log to keep and no divergence to reconcile. It
   costs bandwidth a delta protocol would save; on a security console that is not
   a trade worth making the other way.

8. **The stream's producer polls the database, and the contract hides that.**
   There is no message bus yet. What the client is written against is the
   *contract* — snapshot events, monotonic ids, keep-alives, a bounded connection
   — so the producer can be replaced without the SPA noticing. Connections are
   bounded on purpose: one that lives forever is one nobody notices leaking.

9. **The SPA consumes the stream with `fetch`, not `EventSource`.** This is not a
   preference. `EventSource` cannot send an `Authorization` header, so using it
   would mean putting a bearer token in a query string, where it lands in access
   logs, proxy logs, and browser history. The cost is parsing the wire format in
   the client, and the parser is exact about one thing: a frame is dispatched
   only once a blank line terminates it, because half a snapshot looks like state.

10. **Untrusted content is never rendered as markup.** Report bodies are Markdown
    that quotes raw log lines; converting them to HTML in the browser is
    precisely how a quoted log line becomes an executing script on the console of
    the person investigating it. They render as preformatted text.
    `dangerouslySetInnerHTML` is a lint error, `SafeLink` refuses any scheme
    other than http(s), and a refused link renders as visibly refused rather than
    silently dropped — a citation that vanishes reads as a claim with no source.

11. **The client asks the server what it may do.** `/system/capabilities` rather
    than a copy of the RBAC table compiled into the bundle: a second copy of an
    access-control rule is one that drifts, and the browser's copy would be the
    one the interface obeys. Hiding a control is a usability decision, never a
    security one.

12. **The approval panel is built to make approving deliberate.** No primary
    button and no preselected decision, so a rubber stamp costs the same effort
    as a refusal. Confidence, verdict, and the stages that did not complete are
    on screen next to the buttons. A rationale is required for anything other
    than a plain approval, because an instruction to do something different with
    no reason attached is one the next person cannot act on. And the panel says
    out loud that approving authorizes work rather than performing it (invariant
    #2) — an analyst who believes otherwise will not go and do it.

13. **Three states are never rendered the same way:** still loading, nothing
    here, and could not tell. On a console where an empty list can mean "no
    threats found", collapsing them is how someone comes to believe something
    untrue. The same reasoning drives `researched` being separate from a finding
    count, and `enriched` travelling with every indicator: an indicator nothing
    asserted a reputation for is *unchecked*, not clean.

14. **Notification history is readable and nothing here can send.** Dispatch
    arrives with the Notifications sprint, together with the post-approval
    enforcement built to guard it; shipping a way to send ahead of the controls
    on sending would be exactly the wrong order. A test asserts no notification
    route accepts anything but `GET`.

15. **Settings shows identity and capabilities, and names what is not yet
    configurable.** Integration config, notification channels, model selection,
    and auto-approval policy each configure a subsystem that has not shipped; a
    form that writes configuration for something not yet built lies about what it
    controls. They are listed as pending rather than omitted, so an analyst can
    tell "not available to you" from "not built yet".

16. **CORS names explicit origins and refuses a wildcard, in every environment.**
    The browser rejects `*` with credentials anyway; the config validator refuses
    it so the misconfiguration fails at startup rather than at the first
    cross-origin request.

17. **The session lives in `sessionStorage`, and this ADR states the limit
    honestly.** It dies with the tab rather than persisting on a shared
    workstation. Neither browser store survives XSS, and pretending otherwise
    would be dishonest — the actual defense is decision 10. Moving the refresh
    token into an httpOnly cookie is the next hardening step and belongs to the
    Security sprint, because it changes the auth endpoints' contract.

18. **A known-vulnerable frontend dependency is a release blocker.** `npm audit`
    is a CI gate at moderate and above. It forced `react-router` to 8.3 (a
    published CSRF advisory) and `vite`/`vitest` forward (esbuild) during this
    sprint rather than after a release. "We do not use that code path" is exactly
    the reasoning that ages badly.

## Consequences

- **Positive:** the platform is usable. An analyst can trigger an investigation,
  watch the pipeline run, read the timeline with provenance, examine the
  assessment with its enrichment caveats, read the report, and record a decision
  at the gate — with confidence and provenance visible throughout. The human gate
  is now reachable by a human, which is the point the previous eleven sprints
  were building toward.
- **Trade-offs:**
  - The stream polls. It is bounded, heartbeated, and behind a contract that
    hides the mechanism, but it is polling, and the poll interval is the latency
    floor until a message bus exists.
  - Report bodies render as preformatted text. That costs typography and is the
    price of not running a Markdown renderer over attacker-influenced content.
  - The background run uses FastAPI background tasks, so an investigation is tied
    to the process that started it. A restart mid-run leaves the stages already
    persisted and the case in progress rather than resuming it; durable job
    execution belongs with the Deployment sprint's worker topology.
  - Settings is thin. Four of its five specified areas configure subsystems that
    do not exist yet.
  - The client's contract types are hand-written mirrors of the response models.
    They are deliberately narrow — a backend addition is not a breaking change,
    while a removal surfaces as a type error — but they are a second copy, and
    generating them from the OpenAPI schema is the obvious later improvement.
- **Schema change:** one migration adds `investigations.pipeline` (JSONB, NOT
  NULL, server default `'{}'`). The server default is load-bearing: investigations
  already exist in deployed environments, and adding the column without one would
  fail on the first row. An investigation that predates the column correctly
  reports no stage information rather than claiming stages it has no record of.
