# ADR 0013 — Human-gated outbound notifications

- **Status:** Accepted
- **Sprint:** Sprint 13 — Notifications
- **Deciders:** Lead Engineer

## Context

Twelve sprints built a platform that reads the world and tells an analyst what it
found. This one gives it a voice: Slack and email delivery of approved alerts,
with dedupe, delivery tracking, cross-channel failover, and a dead-letter queue
(SAD §3.5 pre-notification gate, §7; EDS §3.10).

That makes it a different kind of sprint. SAD §7 states the rule every previous
integration obeyed — *read-only by default; integrations pull data; none are
granted write authority* — and this is the exception. A notification lands in
someone's Slack, someone's inbox, someone's night, and it cannot be retracted.
The design question is not "how do we send" but "what has to be true before we
can".

## Decision

1. **The authority to alert is part of what an alert is.**
   `AlertRequest.approval_id` is required and non-optional — no default, no
   `None`, no constructor that omits it. A code path that assembles an alert
   nobody approved does not compile. The corresponding column is **NOT NULL**, so
   an unapproved notification is not representable as a row either.

2. **Carrying an approval id is not the same as having an approval.** The
   dispatcher looks the decision up and checks three separate things, because
   each fails differently: it must exist (not fabricated), it must belong to
   *this* investigation (not borrowed from another case someone did approve), and
   it must be an approval (not the rejection that said *do not tell anyone*). The
   required field stops the accident; the lookup stops the forgery.

3. **The graph makes the rule structural.** `notify` has exactly one inbound
   edge — the human gate's *approve* arm — so no path from START reaches an
   outbound alert without traversing a recorded human decision. A test searches
   the compiled graph for such a path rather than trusting the edge list to stay
   as written.

4. **Only a plain approval alerts.** Edit and reject both close the
   investigation and tell nobody. A rejection means the findings were not
   accepted, and paging an on-call engineer about findings an analyst just
   declined is worse than silence; an edit means "change this first", so there is
   nothing settled to announce — the same rule that keeps an edited report a
   draft.

5. **The node assembles; the backend sends.** Delivery is a side effect on the
   outside world, and side effects belong to the sole write boundary (invariant
   #7). The node writes the alert into state; the decision route collects it and
   dispatches behind the response. A replayed checkpoint therefore reproduces the
   *message* rather than re-sending it.

6. **The approval id comes from the recorded decision, never from the payload.**
   That payload is derived from ingested log content, and ingested content must
   not be able to nominate its own authorization (invariant #3). A test feeds a
   payload claiming a different approval and asserts the recorded one wins.

7. **Dispatch runs behind the response.** An SMTP relay can hang until its
   timeout, and holding the analyst's decision request open for that would make
   approving feel broken exactly when the platform most needs to feel dependable.
   The cost is that the response cannot say whether the alert arrived — which is
   the right way round: whether a *person decided* is what the response is about,
   and whether a *message landed* has its own record, screen, and queue.

8. **Idempotency is the database's job.** The dedupe key is derived — never
   assigned — from investigation, approval, channel, and recipient, and the
   column is unique. A retried dispatch is a no-op rather than a second page at
   3am, and a check-then-act in application code would lose that race. Binding
   the *approval* rather than the investigation is what lets a redirect and a
   second review alert again.

9. **Failover is between channels; fan-out is within one.** Every recipient on a
   channel is attempted, because three on-call addresses are three people who
   each need the message. The next channel is tried only if the previous one
   reached nobody — which is what makes Slack→email a fallback rather than a
   duplicate page.

10. **A refusal is not a failure.** An open circuit, an exhausted rate limit, a
    missing credential — none of these are evidence about the channel's health,
    and counting them as failures is how a breaker trips on its own governor and
    never closes again. Refusals are also not retried on the same channel: an
    open circuit will not have changed in two seconds, and retrying into it only
    delays the failover that would have worked.

11. **The ops alert is a record, not another notification.** When every channel
    fails, the deliveries are marked dead-letter, an audit entry is written with
    the per-channel reasons, and an error is logged. Routing the news of a
    delivery failure through the channels that just failed would be a joke at the
    expense of whoever needed to know. What an operator can act on is the record,
    so the failure is loud *there* — including a standing dead-letter count on
    the screen.

12. **Suppression is never reported as failure.** An investigation below the
    alerting floor, or a deployment with no channel configured, produces no
    delivery and says exactly that. Conflating "nobody needed to be told" with
    "we tried and failed" is how a team learns to ignore its own dead-letter
    queue. The floor exists because an alert that fires on every approved
    investigation trains its recipients to ignore it, and an ignored channel is
    worse than no channel — it looks like coverage.

13. **Rendering is an escaping boundary, per channel.** Everything interesting in
    an alert came from a log line. Slack interprets `&`, `<`, `>`, so a crafted
    hostname could forge a link or an `<!channel>` that pages an entire
    workspace. Email clients linkify aggressively and headers end at a newline,
    so URLs are defanged and CRLF is collapsed — an unescaped summary could
    otherwise append a `Bcc` and copy an incident to an attacker.

14. **Email is `text/plain`, never HTML.** An alert about a phishing URL that
    arrives as a clickable phishing link has performed the attacker's last step.
    The adapter never calls `add_alternative`, and a test asserts the sent message
    is not multipart.

15. **A channel named without its credentials is refused at startup.** A failover
    chain that looks two deep and is one deep fails at the exact moment the
    fallback was supposed to work. Unknown and duplicated channel names are
    refused for the same reason: a typo that removes a channel is a typo that
    removes an alert. `webhook` is refused explicitly because no adapter backs it
    yet, and a configured channel with nothing behind it would swallow alerts
    silently.

16. **Retry is narrow, and named "retry" rather than "resend".** It re-attempts a
    delivery that *failed*, on the channel and authority already recorded, and
    reconstructs the message from the record rather than from a request body —
    accepting client content would turn "resend what was approved" into "send
    whatever you like on the authority of something that was approved". A
    delivered alert cannot be retried: sending it again is a new notification and
    needs a new decision. The approval is re-verified on every retry, because the
    row was written by an earlier request and a retry is a fresh act.

17. **There is no send endpoint, and a test asserts it.** Alerting is initiated
    by an approval at the human gate; a send route would be a second entrance to
    the outbound path that a client could drive without a decision. The test
    reads the OpenAPI schema rather than walking `app.routes` — this FastAPI
    version keeps included routers wrapped, so the route walk finds nothing and
    the assertion passes by being vacuous, which is the failure mode a security
    test can least afford. (The Sprint 12 version of this test had exactly that
    bug and is fixed here.)

## Consequences

- **Positive:** the pre-notification gate from SAD §3.5 is real, and it is real
  in three independent places — the type, the schema, and the graph's shape.
  Delivery is tracked per channel with reasons, failover is honest about which
  channel reached whom, and an alert that reaches nobody is impossible to miss.
- **Trade-offs:**
  - Dispatch uses FastAPI background tasks, so an alert is tied to the process
    that recorded the decision. A restart between the decision and the dispatch
    loses the send but not the decision, and the delivery is retryable from the
    screen. Durable job execution belongs with the Deployment sprint's worker
    topology.
  - Email is plain text. That costs formatting and is the price of not handing a
    mail client attacker-influenced markup.
  - The dead-letter ops alert is a log line and an audit entry. A dedicated
    always-up ops channel would be better and needs an operator to nominate one;
    routing it through the failed channels would not.
  - Slack uses an incoming webhook rather than the Web API, so the platform
    cannot post to a channel chosen per investigation. Per-tenant channel policy
    is listed in EDS §3.10 as a future extension and is where that belongs.
  - Alert *content* is fixed by the template. That is deliberate — a generated
    alert is one whose wording nobody reviewed in advance — and it means tuning
    what an alert says is a code change.
- **Schema change:** one migration makes `notifications.approval_id` NOT NULL and
  adds a unique `dedupe_key`, a `priority`, and a `failure_reason`. It asserts
  the table is empty first and fails with an explanation otherwise: a server
  default for a *unique* column would break the constraint, and deleting rows to
  make the migration pass would destroy delivery history. No dispatcher existed
  before this revision, so in every real deployment the table is empty — and if
  it is not, the rows are unapproved notifications, which is a finding rather
  than an obstacle.
