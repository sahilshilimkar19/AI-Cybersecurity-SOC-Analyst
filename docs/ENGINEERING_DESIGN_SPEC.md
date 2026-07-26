# AI Cybersecurity SOC Analyst — Engineering Design Specification (EDS)

| Field | Detail |
|---|---|
| **Document Title** | Engineering Design Specification — AI Cybersecurity SOC Analyst |
| **Document Type** | Implementation-ready engineering specification (final planning artifact before build) |
| **Authored By** | Lead Engineer / Technical Program Lead (Principal Software Engineer · Principal AI Architect · Staff Cybersecurity Engineer) |
| **Audience** | Implementing senior engineers, tech leads, QA, SRE/platform, security engineering |
| **Date** | 24 July 2026 |
| **Status** | Approved for implementation planning |
| **Source of Truth** | `PROJECT_CONTEXT.md` (what/why) and `TECHNICAL_ARCHITECTURE.md` (the SAD, how). This EDS bridges them to implementation. |
| **Core Principle** | Human-in-the-loop. Agents investigate and recommend; humans decide and act. (Inherited, non-negotiable.) |

> **Scope & guardrails.** This document is *engineering documentation*, not code. It contains **no code, no pseudocode, no SQL/DDL, no prompt text, no new API endpoints beyond the SAD, and no LangGraph code**. Schemas and interfaces are *described* (fields, purpose, constraints) in tables/prose, never declared. Nothing here modifies, redesigns, or substitutes the architecture — the EDS operationalizes the SAD **as-is**. Every material engineering decision states its rationale.

### Planning Conventions (used throughout §2, §17, §18)

| Convention | Value | Note |
|---|---|---|
| **Estimation unit** | Relative complexity tier (XS/S/M/L/XL) + story points (Fibonacci: 1/2/3/5/8/13) | Team-agnostic; **no calendar dates**. Points reflect effort + uncertainty, not hours. |
| **Team model** | One cross-functional squad, ~4–6 engineers (backend, AI/agents, frontend, security/platform, shared QA) | Used only to size how much fits per sprint. |
| **Sprint cadence** | 2-week timeboxes; assumed sustainable velocity ~20–26 points/sprint | Cadence is a convention; roadmap phases carry no deadlines. |
| **Complexity → points guide** | XS≈1–2, S≈3, M≈5, L≈8, XL≈13 (split XL before committing) | XL items are decomposed in Sprint Planning. |

### Inherited Invariants (from SAD Appendix A — must hold in every module)

1. Human-in-the-loop for all consequential actions (notification, remediation), recorded in tamper-evident audit.
2. Agents recommend; the system never enforces (no destructive capability by construction).
3. All ingested content is untrusted; data can never become instructions.
4. Everything is grounded and cited; un-sourced security claims are flagged.
5. Deterministic control (LangGraph), non-deterministic reasoning (agents).
6. Degrade, never collapse; fail toward the human, not toward silence.
7. The backend is the single write boundary to the system of record.

---

## 1. Implementation Philosophy

The platform is a deterministic control plane wrapping non-deterministic reasoning. That duality dictates the engineering philosophy: **the control, data, and security paths are engineered like a bank; the reasoning path is engineered like a fallible, replaceable, continuously-evaluated component.** Every engineer internalizes that AI output is *untrusted until validated*, and that the system's trustworthiness comes from the deterministic scaffolding around the model, not the model itself.

| Principle | How it is applied here | Rationale |
|---|---|---|
| **Modularity** | Each module (§3) is a bounded unit with an explicit public interface and hidden internals; agents are contract-bounded graph nodes that never call each other. | Independent build, test, replace, and reason-about; an agent or adapter can be swapped without touching neighbors. |
| **Scalability** | Stateless services behind the API; the compute-heavy tier (graph/agent workers, RAG ingestion) scales horizontally; data stores are HA. | The elastic bottleneck is agent execution; the design lets that tier absorb alert surges independently. |
| **Maintainability** | Small, single-purpose units; versioned prompts and schemas; ADRs for decisions; consistent standards (§11). | A multi-year security platform must be safely changeable by engineers who did not write it. |
| **Separation of concerns** | Reasoning (agents/AI) vs. control (graph) vs. persistence/audit (backend+data) vs. presentation (frontend) are strictly separated. | Prevents an LLM-driven component from ever corrupting state or bypassing audit. |
| **SOLID** | *S*: one responsibility per agent/module. *O*: new agents/integrations added by extension, not modification. *L*: all model providers/adapters honor a common contract and are substitutable. *I*: narrow, role-specific interfaces (least-privilege tools). *D*: modules depend on abstractions (model provider, vector store, adapter, memory) not concretions. | The abstractions the SAD already chose (model abstraction, adapter interface, pluggable vector store) are the SOLID seams; engineers must code to them. |
| **Clean architecture** | Dependencies point inward: domain models and contracts at the core; frameworks, providers, and I/O at the edges behind ports/adapters. | Business/security rules never depend on a vendor SDK; providers are edge details. |
| **Dependency inversion** | High-level orchestration depends on interfaces (LLM provider, embedding provider, vector store, notification channel, log source) resolved by configuration/DI. | Enables the Claude-primary-but-pluggable strategy and local-model option without code churn. |
| **Contract-first** | Schemas for state, agent I/O, DTOs, and events are defined and versioned *before* implementation; the graph validates against them. | Parallel workstreams integrate against stable contracts; invalid AI output is rejected deterministically. |
| **Test-first mindset** | Contracts and acceptance criteria drive tests written alongside (or before) code; agents/prompts/RAG have evaluation harnesses, not just assertions. | AI regresses silently; test-first + eval harnesses make behavior a gated, observable property. |

**How every engineer approaches development.** Start from the contract (schema/interface) and the acceptance criteria. Treat every external input — logs, tool results, model output — as untrusted; validate at the boundary. Write the test/eval first. Keep the module's public surface minimal and its internals hidden. Emit structured logs, metrics, and traces from day one (observability is not a later phase). Never let an agent gain a write path or a destructive capability. When a decision has architectural weight, it is already decided in the SAD — implement it; if the SAD is genuinely silent, raise an ADR rather than improvising.

---

## 2. Development Roadmap

Phases are dependency-ordered. Each is independently demonstrable and leaves the system in a working, tested state. Complexity is the relative tier (§ conventions); "points" is the phase's aggregate story-point estimate.

| # | Phase | Purpose | Key Deliverables | Dependencies | Acceptance Criteria | Complexity (pts) | Primary Risks |
|---|---|---|---|---|---|---|---|
| 1 | **Project Bootstrap** | Establish the monorepo, standards, CI skeleton, local stack. | Repo structure (§10), coding standards enforced in CI, local compose stack, secret-store wiring, base observability. | — | `make`/one-command local stack runs; CI green on lint + empty test suites; secrets resolve from store. | M (8) | Under-investing in CI/standards early; scope creep. |
| 2 | **Backend Foundation** | The sole write boundary + service/gateway skeleton. | API gateway skeleton, service layer scaffolding, request validation + middleware pipeline, structured logging/tracing, health/readiness. | 1 | Authenticated no-op endpoints pass; middleware (validation, logging, rate-limit stub) exercised by tests. | M (8) | Middleware ordering/security gaps. |
| 3 | **Authentication & Authorization** | Identity, session, RBAC across every request. | OIDC/SSO integration, JWT issuance/rotation, RBAC policy enforcement, session management, auth audit events. | 2 | RBAC boundary tests pass for all roles; unauthorized paths denied; auth events audited. | L (8) | IdP integration friction; token/session edge cases. |
| 4 | **Database & Persistence** | System of record + audit substrate. | Entity schemas (§6), migrations, data-access layer, append-only audit log, object-store integration for raw evidence. | 2 | CRUD + audit round-trip tested; migrations reversible; audit entries tamper-evident. | L (8) | Audit-completeness gaps; migration discipline. |
| 5 | **LangGraph Orchestration Core** | Deterministic control plane (empty nodes). | Graph skeleton with checkpointer, shared-state schema, retry/interrupt scaffolding, resume/rollback, node registry. | 2,4 | Graph runs a stub pipeline end-to-end; checkpoint/resume verified; interrupt pauses & resumes. | L (13) | State-schema churn; checkpoint correctness. |
| 6 | **Memory Layer** | Tiered memory managers behind interfaces. | Working/session/conversation/long-term/knowledge/investigation memory managers; Redis+Postgres two-tier session; summarization hook. | 4,5 | Memory read/write/eviction/recovery tested; session survives worker restart. | M (8) | Sync bugs between hot/durable tiers. |
| 7 | **RAG Pipeline** | Grounding + citations substrate. | Ingestion workers, chunking, embedding provider abstraction, pgvector index, hybrid retriever, re-rank, citation binding. | 4,6 | Retrieval eval on labeled set meets baseline; citations resolve to sources; freshness weighting verified. | XL (13) | Retrieval quality; embedding/version drift. |
| 8 | **AI Layer (Model Abstraction)** | Provider-agnostic model + embeddings + guardrails. | LLM provider port (Claude primary), streaming, token/cost accounting, output validation, secondary-model failover. | 2 | Provider swap via config with no caller change; failover triggers on induced failure; cost/token metrics emitted. | L (8) | Provider quirks leaking through abstraction. |
| 9 | **Log Analyzer Agent** | First agent: normalize + correlate. | Agent node, tool bindings (parsers/connectors), input/output schemas, validation, tests + fixtures. | 5,6,8 | Golden-fixture tests pass; produces provenance-tagged timeline; coverage-gap reporting works. | L (8) | Log-format diversity; correlation accuracy. |
| 10 | **Threat Detector Agent** | Verdict, IoCs, ATT&CK, severity. | Agent node, IoC/ATT&CK/severity tools, enrichment adapters (VirusTotal/MITRE), RAG use. | 7,8,9 | Verdict + severity within calibrated tolerance on fixtures; enrichment-degraded path flagged. | L (8) | Enrichment API variability; confidence calibration. |
| 11 | **CVE Research Agent** | Relevant CVEs + CVSS + applicability. | Agent node, NVD adapter, CVE corpus retrieval, applicability logic, citation enforcement. | 7,8,10 | Confirmed vs. candidate applicability correct on fixtures; live→cache fallback verified; all claims cited. | L (8) | CVE applicability false positives. |
| 12 | **Evaluator & Summarizer** | Quality/grounding gate + context compression. | Evaluator node (schema/citation/hallucination checks), Summarizer node (lossless-by-reference). | 8,9,10,11 | Evaluator rejects un-sourced/unsupported claims on adversarial fixtures; summaries preserve IDs/provenance. | M (5) | Over/under-blocking by Evaluator. |
| 13 | **Incident Reporter Agent** | Executive + technical report synthesis. | Agent node, report/timeline assembler, citation compiler, persistence of report artifacts. | 4,11,12 | Report contains only supported claims; gaps marked; citations compiled; regenerable from state. | M (5) | Hallucinated findings (mitigated by Evaluator). |
| 14 | **Patch Recommendation Agent** | Prioritized, justified remediation. | Agent node, remediation RAG, advisory lookups, risk prioritizer, human-approval framing. | 11,12,13 | Recommendations prioritized + justified + cited; flagged requires-human-approval; no destructive actions. | M (5) | Over-broad or unsafe recommendations. |
| 15 | **Planner & Full Orchestration Wiring** | End-to-end graph with parallel fan-out + gates. | Planner node, conditional routing, parallel CVE/enrichment join, human-approval interrupts wired to backend. | 5,9–14 | Full investigation runs benign & threat paths; human gate pauses/resumes; parallel join correct. | L (8) | Routing/branch bugs; join races. |
| 16 | **Notification Layer** | Human-gated outbound alerting. | Slack + SMTP channels, templating, dedupe, delivery tracking, cross-channel failover, post-approval dispatch only. | 4,15 | No notification sent pre-approval; delivery recorded; Slack→email failover verified. | M (5) | Missed critical alerts on channel failure. |
| 17 | **Frontend** | Analyst workspace + approval UX. | Dashboard, Investigation, Timeline, Threat Details, Reports, Notifications, Settings; live streaming; approval panel. | 2,3,15 | Analyst can run, watch, and approve/redirect an investigation; confidence/provenance visible. | XL (13) | Real-time UX complexity; approval clarity. |
| 18 | **Observability & Cost Controls** | Production-grade telemetry. | Dashboards, alerting, per-agent latency/cost, LLM usage analytics, failure analytics, SLO wiring. | all prior | Dashboards live; alerts fire on induced faults; cost/latency per investigation visible. | M (5) | Alert fatigue; metric gaps. |
| 19 | **Security Hardening & Red-Team** | Verify invariants under attack. | Prompt-injection red-team suite, RBAC/secret audits, dependency/vuln scans, pen-test remediation. | all prior | Injection corpus fails to escalate to action; scans clean or risk-accepted; audit complete. | L (8) | Undiscovered injection vectors. |
| 20 | **Production Deployment** | Ship to production, cloud-agnostic. | K8s manifests, CI/CD gates (incl. prompt/RAG evals), progressive rollout + rollback, runbooks, on-call. | all prior | Progressive deploy + rollback rehearsed; SLOs met in staging load test; runbooks validated. | L (8) | Rollout/rollback correctness; capacity. |

**Roadmap rationale.** Deterministic foundations (backend, auth, DB, graph) precede any AI so that agents are built on a trustworthy, auditable substrate. Memory and RAG precede agents because agents depend on grounding and shared context. Agents are built in dependency order (Log → Threat → CVE → Evaluator/Summarizer → Reporter → Patch) so each has its inputs ready. The Planner and full wiring come after the agents exist. Notification and Frontend follow the working pipeline. Observability and security hardening are continuous but get a dedicated hardening pass before production.

---

## 3. Module Breakdown

Each module below is specified across the 12 required attributes. "Public Interfaces" are *described* (operations + intent), never declared as code. All modules inherit the coding standards (§11) and DoD (§18).

### 3.1 Backend

| Attribute | Specification |
|---|---|
| **Purpose** | The application tier and **sole writer** to the system of record; validates, authorizes, persists, orchestrates, and dispatches. |
| **Responsibilities** | Expose the API surface (SAD §12); enforce auth/RBAC; validate all input; invoke the graph; own all persistence + audit writes; dispatch notifications; run async investigation/ingestion workers. |
| **Internal components** | API gateway, application services (investigation, report, notification, user, knowledge), middleware pipeline (auth, validation, rate-limit, logging/trace), async worker runners, DI/composition root. |
| **Public interfaces** | Command/query operations per SAD endpoint plan; internal service operations consumed by the gateway and workers; an "start/resume investigation" operation to the graph. |
| **Dependencies** | Auth, Database, Graph, Notifications, Integrations (ingestion), Models, Configuration. |
| **Expected inputs** | Authenticated HTTP requests, streamed client subscriptions, queued jobs, ingestion events. |
| **Expected outputs** | Persisted records + audit entries, streamed investigation updates, dispatched notifications, job results. |
| **Validation rules** | Every request schema-validated + authorized before side effects; idempotency keys on mutating operations; reject oversized/malformed payloads at the edge. |
| **Failure handling** | Typed error taxonomy; no partial writes committed as final; transient failures retried idempotently; unrecoverable graph paths surface to the human gate. |
| **Logging** | Structured request/audit logs with correlation + investigation IDs; no secrets/PII beyond policy. |
| **Metrics** | Request rate/latency/error, per-endpoint auth denials, queue depth, investigation throughput. |
| **Future extension points** | New services behind the gateway; new async workers; multi-tenant scoping middleware (SAD §18). |

### 3.2 Frontend

| Attribute | Specification |
|---|---|
| **Purpose** | Analyst-facing SPA: triage, drill-down, and unambiguous human approval. Server-authoritative state. |
| **Responsibilities** | Render the seven screens (SAD §13); stream live investigation state; capture human decisions; surface confidence + provenance everywhere. |
| **Internal components** | Pages, reusable components, client state/data-fetching layer, realtime (WS/SSE) client, auth/session handling, approval-panel component. |
| **Public interfaces** | Consumes backend commands/queries + the investigation stream; emits human-decision commands. |
| **Dependencies** | Backend API, Auth. |
| **Expected inputs** | API responses, streamed updates, user interactions. |
| **Expected outputs** | Rendered UI, human-decision commands, export requests. |
| **Validation rules** | Client-side validation for UX only (never authoritative); render only server-confirmed state; escape/encode all displayed untrusted content (log data). |
| **Failure handling** | Graceful degradation on stream loss (reconnect + reconcile); clear error states; never present optimistic security outcomes as final. |
| **Logging** | Client error/telemetry to backend; no sensitive data in client logs. |
| **Metrics** | Screen load, stream health, approval-latency (time to human decision), error rate. |
| **Future extension points** | Voice front-end over the same API (SAD §18); richer hunting/compliance dashboards. |

### 3.3 Graph (LangGraph Orchestration)

| Attribute | Specification |
|---|---|
| **Purpose** | Deterministic conductor of the investigation: routing, retries, checkpoints, human interrupts. |
| **Responsibilities** | Define nodes/edges/conditional routing; own retries/fallback policy; checkpoint state; pause at human gates; resume/rollback; coordinate parallel vs. sequential execution. (Full spec §5.) |
| **Internal components** | Node registry, edge/routing definitions, checkpointer, interrupt manager, retry/backoff policy, parallel join coordinator, state reducer. |
| **Public interfaces** | Start/resume/rollback operations (called by Backend); node contracts (called by agents). |
| **Dependencies** | Memory, AI Layer, Integrations (via tools), Models (state schema), Database (checkpoint persistence via backend). |
| **Expected inputs** | Seeded state (trigger + scope + config snapshot), human decisions on resume. |
| **Expected outputs** | Advanced/validated state, checkpoints, terminal investigation status. |
| **Validation rules** | State validated against schema at every transition; refuse to advance on invalid node output (bounded self-repair, then human). |
| **Failure handling** | Resume from last checkpoint; circuit-break external calls; route unrecoverable nodes to human gate; never silent-drop an investigation. |
| **Logging** | Per-node transition logs with node ownership + retry counts; decision-branch traces. |
| **Metrics** | Per-node latency/success/retry, gate wait time, parallel-join duration, resume/rollback counts. |
| **Future extension points** | Additional nodes/agents; distributed A2A execution; MCP tool nodes (SAD §18). |

### 3.4 Memory

| Attribute | Specification |
|---|---|
| **Purpose** | Provide tiered memory (working/session/conversation/long-term/knowledge/investigation) behind clean interfaces. (Full spec §7.) |
| **Responsibilities** | Store/retrieve/evict/synchronize/recover each memory tier; enforce access rules; provide summarization to fit context budgets. |
| **Internal components** | Per-tier managers, two-tier session sync (Redis↔Postgres), summarizer hook, eviction policies, recovery/rebuild logic. |
| **Public interfaces** | Read/write/append/evict operations per tier; "materialize context for agent" operation. |
| **Dependencies** | Redis, Postgres, object store, AI Layer (summarization/embeddings via RAG for knowledge tier). |
| **Expected inputs** | Investigation-scoped writes, retrieval queries, eviction triggers. |
| **Expected outputs** | Context objects, durable/hot reads, rebuilt state on recovery. |
| **Validation rules** | Tier access scoped to authorized callers; append semantics preserve provenance; summaries retain source IDs. |
| **Failure handling** | Rebuild hot memory from durable tier or raw evidence; validate on read; quarantine corrupt entries. |
| **Logging** | Memory op logs with tier + investigation ID; eviction/recovery events. |
| **Metrics** | Hit/miss ratio, eviction rate, sync lag, recovery events, context token size. |
| **Future extension points** | Per-tenant memory partitioning; alternative hot stores. |

### 3.5 RAG

| Attribute | Specification |
|---|---|
| **Purpose** | Ground agents in authoritative security knowledge and enable citations. (Full spec §8.) |
| **Responsibilities** | Ingest/clean/chunk/enrich sources; embed; index; hybrid-retrieve; re-rank with freshness; bind citations; refresh knowledge. |
| **Internal components** | Ingestion workers, chunker, embedding-provider adapter, vector index (pgvector), hybrid retriever, re-ranker, citation binder, refresh scheduler. |
| **Public interfaces** | "Retrieve grounded context for query+filters" operation; "ingest/refresh source" operation. |
| **Dependencies** | AI Layer (embeddings), Database/pgvector, Integrations (NVD/MITRE/advisories), Configuration. |
| **Expected inputs** | Source documents/feeds; agent retrieval queries with metadata filters. |
| **Expected outputs** | Ranked, source-tagged context chunks; index/version metadata. |
| **Validation rules** | Trusted-source allow-list; embedding-model version pinned per index; retrieved chunks carry source IDs. |
| **Failure handling** | Ingestion failures isolated per source; retrieval degrades to cache with staleness flag; never inject un-tagged context. |
| **Logging** | Ingestion runs (source/version/counts), retrieval traces (query→chunks→scores). |
| **Metrics** | Retrieval precision/recall (offline), latency, index freshness, citation-resolution rate, cache hit ratio. |
| **Future extension points** | Dedicated vector DB swap; re-ranker model upgrade; new curated sources. |

### 3.6 Prompts

| Attribute | Specification |
|---|---|
| **Purpose** | House versioned prompt assets and their contracts (not the prompt text here). (Full spec §9.) |
| **Responsibilities** | Provide per-agent system/task prompts as versioned, evaluated assets; enforce shared preamble (invariants); manage change control. |
| **Internal components** | Shared preamble, per-prompt templates, output-contract bindings, prompt-eval suites, version manifest. |
| **Public interfaces** | "Assemble prompt for agent X with context Y" operation (consumed by AI Layer/agents). |
| **Dependencies** | Models (output schemas), AI Layer, Testing (prompt-eval). |
| **Expected inputs** | Agent context (validated, quoted untrusted data), retrieved citations. |
| **Expected outputs** | Assembled prompt payloads bound to output schemas. |
| **Validation rules** | Untrusted data strictly separated from instructions; every prompt maps to a validated output schema; version pinned per release. |
| **Failure handling** | On output-contract violation, trigger bounded self-repair then Evaluator/human; never accept free-form where schema is required. |
| **Logging** | Prompt version + template ID per invocation (not raw sensitive content beyond policy). |
| **Metrics** | Per-prompt output-validity rate, self-repair rate, eval scores over versions. |
| **Future extension points** | New agent prompts; A/B prompt evaluation; localized/audience variants. |

### 3.7 Tools

| Attribute | Specification |
|---|---|
| **Purpose** | Deterministic capabilities agents invoke (parsing, extraction, scoring, lookups) — separated from reasoning. |
| **Responsibilities** | Provide log parsers/normalizers, entity/IoC extractors, CVSS interpreter, correlators, and integration-lookup wrappers as unit-testable functions. |
| **Internal components** | Tool registry, per-tool implementations, allow-list bindings per agent, input/output validators. |
| **Public interfaces** | Tool-invocation contracts (name, typed inputs, typed outputs) consumed by agents via the graph. |
| **Dependencies** | Integrations (for lookup tools), Models, Configuration. |
| **Expected inputs** | Validated tool arguments from agents. |
| **Expected outputs** | Deterministic structured results with provenance. |
| **Validation rules** | Least-privilege: each agent may call only its allow-listed tools; validate args/results; treat external data as untrusted. |
| **Failure handling** | Tool errors returned as typed failures (not exceptions swallowed); enable agent fallback/degradation. |
| **Logging** | Tool-call logs with args hash + latency + outcome. |
| **Metrics** | Per-tool call rate/latency/error, cache hit ratio (lookups). |
| **Future extension points** | New tools; MCP-exposed tools (SAD §18). |

### 3.8 Services

| Attribute | Specification |
|---|---|
| **Purpose** | Cross-cutting domain logic reused beyond a single agent or the HTTP layer (e.g., severity scoring, prioritization). |
| **Responsibilities** | Encapsulate shared domain rules with no dependency on transport or a specific agent. |
| **Internal components** | Domain service units (scoring, risk prioritization, correlation helpers), shared domain policies. |
| **Public interfaces** | Pure domain operations invoked by backend/agents/graph. |
| **Dependencies** | Models; possibly Knowledge memory (read-only). |
| **Expected inputs** | Domain objects (assessments, findings, assets). |
| **Expected outputs** | Derived domain values (scores, priorities). |
| **Validation rules** | Deterministic + side-effect-free where possible; inputs validated against domain schemas. |
| **Failure handling** | Total functions with explicit error results; no hidden state. |
| **Logging** | Minimal; decision inputs/outputs at debug for auditability of scoring. |
| **Metrics** | Invocation counts; score distributions (for calibration monitoring). |
| **Future extension points** | New domain services (e.g., compliance mapping). |

### 3.9 Database

| Attribute | Specification |
|---|---|
| **Purpose** | System of record + audit substrate (Postgres) with object-store references for raw evidence. (Full spec §6.) |
| **Responsibilities** | Persist investigations/evidence/assessments/reports/recommendations/conversations/notifications/audit/users; enforce integrity; support archival/versioning. |
| **Internal components** | Schema/migrations, data-access layer, audit-write path, object-store client, indexing strategy. |
| **Public interfaces** | Repository-style operations consumed **only** by backend services (invariant #7). |
| **Dependencies** | Backend (sole caller), object store. |
| **Expected inputs** | Validated domain writes from services. |
| **Expected outputs** | Query results, audit entries, archival records. |
| **Validation rules** | Constraints + referential integrity at the DB; application-level schema validation before write; audit entries append-only. |
| **Failure handling** | Transactional writes; reversible migrations; no partial-final commits; corruption isolated by validation on read. |
| **Logging** | DDL/migration logs; slow-query logs; audit is data, not log. |
| **Metrics** | Query latency, connection pool saturation, table growth, archival lag. |
| **Future extension points** | Partitioning/sharding at scale; per-tenant schemas; dedicated vector store. |

### 3.10 Notifications

| Attribute | Specification |
|---|---|
| **Purpose** | Human-gated outbound alerting (Slack, email) with delivery guarantees. |
| **Responsibilities** | Template, deduplicate, dispatch **only after human approval**, track delivery, fail over across channels for high-priority alerts. |
| **Internal components** | Channel adapters (Slack/SMTP/webhook), templating, dedupe, delivery tracker, retry/failover, dead-letter. |
| **Public interfaces** | "Dispatch approved notification" operation (backend-invoked, post-gate). |
| **Dependencies** | Backend, external Slack/SMTP, Configuration/secrets, Database (delivery records). |
| **Expected inputs** | Approved notification payloads + recipients/channels. |
| **Expected outputs** | Delivered messages + recorded delivery status. |
| **Validation rules** | Refuse dispatch without a linked human approval; validate recipients/channels; idempotent by dedupe key. |
| **Failure handling** | Per-channel retry; Slack→email failover; dead-letter + ops alert if all channels fail (never silent). |
| **Logging** | Dispatch attempts, channel results, dedupe hits. |
| **Metrics** | Delivery success/latency per channel, failover rate, dead-letter count. |
| **Future extension points** | New channels (SMS/PagerDuty); per-tenant channel policy. |

### 3.11 Authentication

| Attribute | Specification |
|---|---|
| **Purpose** | Identity, session, and RBAC enforcement across every request (cross-cutting). (Full spec §14.) |
| **Responsibilities** | Federate OIDC/SSO; issue/rotate JWTs; manage sessions; enforce RBAC + object-level checks; emit auth audit events. |
| **Internal components** | OIDC client, token service, session store, RBAC policy engine, auth middleware. |
| **Public interfaces** | Auth/session operations (SAD §12); "authorize(actor, action, resource)" check used by services. |
| **Dependencies** | External IdP, Redis (sessions), Database (users/roles/audit), Configuration/secrets. |
| **Expected inputs** | Login flows, tokens, authorization checks. |
| **Expected outputs** | Sessions/tokens, allow/deny decisions, audit events. |
| **Validation rules** | Verify token signature/expiry/rotation; deny by default; least privilege; MFA enforced at IdP. |
| **Failure handling** | Fail-closed on auth errors; token/session edge cases handled explicitly; lockout/anomaly signals. |
| **Logging** | Auth successes/denials, role changes, session lifecycle — all audited. |
| **Metrics** | Auth success/deny rates, token refresh rate, session count, anomalous-auth signals. |
| **Future extension points** | Per-tenant IdP federation; step-up auth for sensitive approvals. |

### 3.12 Integrations

| Attribute | Specification |
|---|---|
| **Purpose** | Isolated adapters to external/enterprise systems (SAD §7), each its own failure domain. |
| **Responsibilities** | Provide read-only adapters for NVD, MITRE, VirusTotal, GitHub advisories, SIEM (Splunk/Elastic), log files, Windows Event Log, Linux syslog; resilience per adapter. |
| **Internal components** | Per-integration client, cache, rate limiter, circuit breaker, response normalizer, health probe. |
| **Public interfaces** | Uniform adapter contract (query/fetch/normalize) consumed by tools/backend ingestion. |
| **Dependencies** | External services, Configuration/secrets, Models. |
| **Expected inputs** | Adapter queries (with scope/filters). |
| **Expected outputs** | Normalized, provenance-tagged data + freshness metadata. |
| **Validation rules** | Read-only by construction; validate/normalize external data as untrusted; enforce per-integration rate limits. |
| **Failure handling** | Circuit breaker + cache fallback + explicit staleness flag; one adapter's outage degrades one capability only. |
| **Logging** | Per-call logs (endpoint, latency, cache/circuit state, outcome). |
| **Metrics** | Call rate/latency/error, circuit-open events, cache hit ratio, quota consumption. |
| **Future extension points** | New sources via the same contract; MCP-based sources. |

### 3.13 Models (Schemas & Contracts)

| Attribute | Specification |
|---|---|
| **Purpose** | Canonical typed contracts shared across layers: state, agent I/O, DTOs, events, domain entities. |
| **Responsibilities** | Be the single source of truth for shapes; version schemas; enable contract-first parallel work + validation. |
| **Internal components** | Domain entity schemas, graph-state schema, agent I/O schemas, API DTOs, event schemas, schema version manifest. |
| **Public interfaces** | Importable schema definitions + validators used everywhere (described, not declared here). |
| **Dependencies** | None (core of clean architecture — everything depends inward on this). |
| **Expected inputs** | N/A (definitional). |
| **Expected outputs** | Validation results; typed contracts. |
| **Validation rules** | Backward-compatible evolution or explicit version bump; no breaking change without migration + consumers updated. |
| **Failure handling** | Validation failures are typed and surfaced at boundaries. |
| **Logging** | Schema-version usage (for migration tracking). |
| **Metrics** | Validation failure rates by schema (signals contract drift). |
| **Future extension points** | New entity/agent schemas; multi-tenant fields. |

### 3.14 Configuration

| Attribute | Specification |
|---|---|
| **Purpose** | Environment-specific config, feature flags, integration/model settings — no secrets committed. |
| **Responsibilities** | Provide typed, validated config per environment; resolve secrets from the external store at runtime; drive DI/provider selection. |
| **Internal components** | Config schema/loader, environment profiles, feature-flag registry, secret-resolution client. |
| **Public interfaces** | "Get validated config" operation; provider/flag lookups. |
| **Dependencies** | Secret manager/KMS, Models. |
| **Expected inputs** | Env vars, config files/profiles, secret references. |
| **Expected outputs** | Validated config objects; resolved provider/flag choices. |
| **Validation rules** | Fail fast on missing/invalid config at startup; secrets never in files/logs/API; strict env separation. |
| **Failure handling** | Startup abort on invalid config; safe defaults only where non-security-relevant. |
| **Logging** | Config load (non-secret) + effective flags; never secret values. |
| **Metrics** | Config-load success; flag-evaluation counts. |
| **Future extension points** | Per-tenant config; dynamic flag delivery. |

### 3.15 Testing

| Attribute | Specification |
|---|---|
| **Purpose** | House and run all test/eval categories mirroring the source tree. (Full spec §12.) |
| **Responsibilities** | Provide unit/integration/agent/prompt-eval/graph/security/performance/regression/acceptance/CI suites + fixtures + labeled eval datasets. |
| **Internal components** | Test suites per module, golden fixtures, prompt/RAG eval harnesses, injection red-team corpus, load-test scenarios. |
| **Public interfaces** | CI-invoked test entry points; local test runners. |
| **Dependencies** | All modules (as targets), CI. |
| **Expected inputs** | Code/prompts/knowledge under test; fixtures/datasets. |
| **Expected outputs** | Pass/fail + eval scores + coverage; CI gate signals. |
| **Validation rules** | Deterministic tests must be stable; AI evals scored against thresholds; no flaky tests merged. |
| **Failure handling** | CI blocks on failure/threshold miss; quarantine lane for known-flaky under triage. |
| **Logging** | Test/eval run reports; trend history. |
| **Metrics** | Coverage, eval scores over time, flake rate, suite duration. |
| **Future extension points** | New eval dimensions; expanded red-team corpus. |

### 3.16 Deployment

| Attribute | Specification |
|---|---|
| **Purpose** | Package and ship the platform cloud-agnostically (Docker + K8s). (Full spec §15.) |
| **Responsibilities** | Provide Dockerfiles, K8s manifests, CI/CD pipeline (with eval gates), progressive rollout + rollback, secret injection, observability wiring. |
| **Internal components** | Image build defs, K8s manifests (services, HPA, ingress/TLS), pipeline stages, rollout/rollback config, runbooks. |
| **Public interfaces** | Pipeline triggers; deployment/rollback operations (ops). |
| **Dependencies** | All modules (as artifacts), secret manager, observability, container registry. |
| **Expected inputs** | Built + tested artifacts; environment config. |
| **Expected outputs** | Running services; rollout status; rollback capability. |
| **Validation rules** | Signed images; eval + security gates must pass; staging load-test before prod; no proprietary-cloud lock-in on critical path. |
| **Failure handling** | Automated rollback on failed health/SLO gates; canary/progressive deploy. |
| **Logging** | Deploy/rollback events; image provenance. |
| **Metrics** | Deploy frequency, rollout success, rollback rate, time-to-rollback. |
| **Future extension points** | Multi-region/multi-tenant deployment; on-prem packaging. |

---

## 4. Agent Implementation Specification

The five specialists were defined at responsibility level in SAD §2 — here the focus is *implementation-level* detail (workflow, described schemas, retry/fallback/confidence/recovery/observability/testing). Planner, Evaluator, Summarizer, and Human Review receive fuller treatment as orchestration-support agents. **Schemas are described (field · meaning · constraint), not declared.** All agents inherit: contract-validated I/O, evidence-vs-inference separation, confidence emission, least-privilege tools, and no lateral calls.

### Cross-agent implementation defaults (apply unless overridden per agent)

| Concern | Default policy |
|---|---|
| **Retry** | Transient failures (timeout/429/network): exponential backoff + jitter, max 3 attempts, resume from node checkpoint (idempotent). |
| **Fallback** | On tool/enrichment failure: proceed with available evidence, lower confidence, set explicit degradation flag; on model failure: AI-Layer secondary-model failover. |
| **Confidence scoring** | 0–1 composite from evidence completeness, source corroboration, and self-reported certainty; low confidence → route toward Evaluator/human. |
| **Error recovery** | Bounded self-repair on schema-invalid output (≤2 repair attempts), then Evaluator, then human gate; never fabricate missing sections. |
| **Logging** | Per-invocation: agent, investigation ID, tool calls, retry count, confidence, output-validity, latency, token/cost. |
| **Metrics** | Success rate, output-validity rate, confidence distribution, retry/fallback rate, latency, cost per invocation. |
| **Testing** | Golden-fixture I/O tests + schema-validity + guardrail adherence + confidence calibration; adversarial injection cases. |

### 4.1 Planner

| Attribute | Specification |
|---|---|
| **Purpose** | Decompose a trigger into an ordered investigation plan; decide which agents/steps run and their sequence. |
| **Responsibilities** | Interpret trigger/scope; select pipeline path (benign short-circuit vs. full); set parallel fan-out expectations; request more data when evidence is insufficient rather than assuming. |
| **Workflow** | Receive seeded state → assess scope/available evidence → produce ordered plan + rationale → hand to graph router. |
| **Input schema (described)** | `trigger_source` (enum), `scope` (assets/time window), `available_sources` (list), `config_snapshot` (ref). |
| **Output schema (described)** | `plan_steps[]` (agent, order, rationale), `parallelizable[]`, `data_requests[]` (if insufficient), `confidence`. |
| **Required tools** | None external; reads scope/asset context. |
| **Required memory** | Session (scope), knowledge (playbook heuristics). |
| **Validation rules** | Plan references only existing agents/steps; must justify each step; may not skip mandatory human gate. |
| **Retry / Fallback** | Standard retry; fallback to the default full-pipeline plan if planning is low-confidence. |
| **Confidence scoring** | Based on scope clarity + evidence sufficiency; low confidence yields a conservative full plan. |
| **Error recovery / Logging / Metrics** | Standard; additionally log chosen path + rationale; metric on path distribution (benign vs. full). |
| **Testing strategy** | Fixtures mapping trigger types → expected plan shape; ensure human gate always present. |
| **Future improvements** | Learned planning from investigation history; cost-aware planning. |

### 4.2 Log Analyzer

| Attribute | Specification |
|---|---|
| **Purpose / Responsibilities** | Per SAD §2.1 — normalize + correlate heterogeneous logs into a provenance-tagged timeline. |
| **Workflow** | Fetch/receive logs (tools) → parse/normalize → extract salient events → correlate across sources → emit event set + timeline + coverage gaps. |
| **Input schema (described)** | `raw_records[]` (with source metadata), `time_window`, `scope`, `prior_correlation` (session ref). |
| **Output schema (described)** | `events[]` (normalized: source, ts, host, actor, type, raw_ref, notability, confidence), `timeline[]`, `correlations[]`, `coverage_gaps[]`, `confidence`. |
| **Required tools** | Log connectors (files, SIEM query, Windows Event Log, syslog), parsers/normalizers, entity extractor, time-window correlator. |
| **Required memory** | Short-term (window), session (correlation state), knowledge (format/field mappings). |
| **Validation rules** | "Structure only — do not infer threats"; every event provenance-tagged; malformed records quarantined not dropped. |
| **Retry / Fallback** | Per-source partial failure tolerated (proceed + record gap); parser uncertainty → low-confidence flagged event. |
| **Confidence scoring** | Per-event notability + overall based on source coverage + parse certainty. |
| **Error recovery / Logging / Metrics** | Standard; metric on parse-failure rate, source coverage %, event volume. |
| **Testing strategy** | Golden fixtures across log formats; correlation-accuracy tests; quarantine-path tests. |
| **Future improvements** | Broader source coverage; learned correlation; anomaly baselines. |

### 4.3 Threat Detector

| Attribute | Specification |
|---|---|
| **Purpose / Responsibilities** | Per SAD §2.2 — verdict, IoCs, ATT&CK mapping, severity, triage. |
| **Workflow** | Consume event set/timeline → retrieve detection knowledge (RAG) → enrich IoCs (VirusTotal/MITRE) → assess verdict + severity → triage priority. |
| **Input schema (described)** | `events[]`, `timeline[]`, `retrieved_context[]`, `enrichment` (optional). |
| **Output schema (described)** | `verdict` (benign/suspicious/malicious), `iocs[]` (type, value, reputation, source), `attack_techniques[]` (id, rationale), `severity` (score, rationale), `triage_priority`, `enrichment_status`, `confidence`. |
| **Required tools** | IoC extractor, VirusTotal lookup, MITRE mapper, severity scorer, RAG retriever. |
| **Required memory** | Session, knowledge (heuristics, ATT&CK), short-term. |
| **Validation rules** | Evidence vs. inference separated; never fabricate IoC reputation; ambiguous high-impact → escalate. |
| **Retry / Fallback** | Enrichment unavailable → assess from evidence + "enrichment degraded" flag + lower confidence. |
| **Confidence scoring** | Corroboration across sources + enrichment presence + evidence strength. |
| **Error recovery / Logging / Metrics** | Standard; metric on verdict distribution, enrichment-degraded rate, severity calibration. |
| **Testing strategy** | Fixtures with labeled verdict/severity; degraded-enrichment path; calibration checks vs. ground truth. |
| **Future improvements** | Behavioral baselining; more intel feeds; ML-assisted anomaly priors. |

### 4.4 CVE Research

| Attribute | Specification |
|---|---|
| **Purpose / Responsibilities** | Per SAD §2.3 — relevant CVEs, plain explanations, exploit mapping, CVSS, applicability. |
| **Workflow** | Consume threat assessment + asset/software context → retrieve CVE corpus (RAG) + query NVD → assess applicability → attach CVSS + citations. |
| **Input schema (described)** | `threat_assessment`, `assets[]` (software/versions), `iocs[]`, `attack_techniques[]`. |
| **Output schema (described)** | `cves[]` (id, cvss, summary, applicability, exploit_mapping, citations[]), `candidates[]`, `source_freshness`, `confidence`. |
| **Required tools** | NVD client, MITRE/CWE mapper, CVE-corpus retriever, CVSS interpreter. |
| **Required memory** | Session, knowledge (CVE/MITRE corpus). |
| **Validation rules** | No CVE asserted applicable without asset/version evidence (else "candidate"); every claim cited. |
| **Retry / Fallback** | Live NVD failure → indexed corpus + staleness flag. |
| **Confidence scoring** | Applicability certainty + source freshness + corroboration. |
| **Error recovery / Logging / Metrics** | Standard; metric on confirmed vs. candidate ratio, citation-coverage, source freshness. |
| **Testing strategy** | Fixtures with known CVE applicability; fallback-to-cache tests; citation-enforcement tests. |
| **Future improvements** | Exploit-availability signals; vendor advisory breadth; SBOM-driven applicability. |

### 4.5 Incident Reporter

| Attribute | Specification |
|---|---|
| **Purpose / Responsibilities** | Per SAD §2.4 — executive + technical report, timeline, affected assets, citations. |
| **Workflow** | Consume all upstream findings → assemble timeline → synthesize technical + executive sections → compile citations → mark gaps → persist (via backend). |
| **Input schema (described)** | Outputs of Log/Threat/CVE agents, `investigation_meta`, `report_template`. |
| **Output schema (described)** | `executive_summary`, `timeline[]`, `findings[]`, `affected_assets[]`, `iocs[]`, `techniques[]`, `cves[]`, `caveats[]`, `citations[]`, `report_version`. |
| **Required tools** | Report/timeline assembler, template renderer, summarizer, citation compiler. |
| **Required memory** | Session (full context), investigation history (related incidents), knowledge (templates). |
| **Validation rules** | Only claims supported by upstream state; gaps/low-confidence explicitly marked; no new findings introduced. |
| **Retry / Fallback** | Missing upstream section → generate with "incomplete" markers, not omission. |
| **Confidence scoring** | Inherited from upstream + completeness of assembled report. |
| **Error recovery / Logging / Metrics** | Standard; metric on report-regeneration rate, citation completeness, Evaluator rejections. |
| **Testing strategy** | Fixtures asserting supported-claims-only; gap-marking; regenerate-from-state equivalence. |
| **Future improvements** | Audience-tailored variants; trend/related-incident linking. |

### 4.6 Patch Recommendation

| Attribute | Specification |
|---|---|
| **Purpose / Responsibilities** | Per SAD §2.5 — prioritized, justified remediation for human approval. |
| **Workflow** | Consume vuln dossier + threat + assets → retrieve remediation knowledge (RAG) + advisory lookups → prioritize by risk → justify + cite → flag requires-human-approval. |
| **Input schema (described)** | `vulnerability_dossier`, `threat_assessment`, `assets[]`, `retrieved_remediation[]`. |
| **Output schema (described)** | `recommendations[]` (action, type, priority, rationale, expected_impact, citations[]), `overall_risk`, `requires_human_approval: true`. |
| **Required tools** | Remediation RAG retriever, patch/advisory lookup (NVD/vendor/GitHub), risk prioritizer. |
| **Required memory** | Session, knowledge (runbooks, advisories). |
| **Validation rules** | Never recommend automated destructive actions; every recommendation justified + cited; always human-gated. |
| **Retry / Fallback** | Thin remediation knowledge → conservative general guidance flagged as such. |
| **Confidence scoring** | Evidence strength + advisory authority + applicability certainty. |
| **Error recovery / Logging / Metrics** | Standard; metric on recommendation acceptance rate (post-human), priority distribution. |
| **Testing strategy** | Fixtures asserting prioritization + citation + no-destructive-action; sparse-knowledge path. |
| **Future improvements** | Change-risk estimation; environment-aware sequencing; rollback guidance. |

### 4.7 Evaluator

| Attribute | Specification |
|---|---|
| **Purpose** | Quality/grounding gate: enforce schema validity, citation coverage, groundedness, and internal consistency before advancing. |
| **Responsibilities** | Adversarially check upstream agent outputs; reject un-sourced security claims and unsupported conclusions; return pass / needs-revision + reasons. |
| **Workflow** | Receive candidate output + its evidence/citations → run checks (schema, citation resolution, groundedness, consistency, injection-anomaly) → verdict. |
| **Input schema (described)** | `candidate_output`, `evidence_refs[]`, `citations[]`, `agent_source`. |
| **Output schema (described)** | `verdict` (pass/needs-revision/escalate), `violations[]` (type, detail), `revision_guidance`, `confidence`. |
| **Required tools** | Citation resolver, schema validator, consistency checker. |
| **Required memory** | Session (evidence), knowledge (validation rules). |
| **Validation rules** | Un-sourced security claim → fail; claim not entailed by evidence → fail; instruction-like content in data → flag injection. |
| **Retry / Fallback** | On its own failure, default to conservative escalate-to-human (never silently pass). |
| **Confidence scoring** | Strength/consistency of check results. |
| **Error recovery / Logging / Metrics** | Standard; metric on rejection rate by agent + violation-type distribution (calibration signal). |
| **Testing strategy** | Adversarial fixtures (hallucinations, missing citations, injected instructions) → must reject. |
| **Future improvements** | LLM-as-judge ensembles; learned violation detectors. |

### 4.8 Summarizer

| Attribute | Specification |
|---|---|
| **Purpose** | Compress long timelines/notes to fit context budgets without losing evidence. |
| **Responsibilities** | Produce lossless-by-reference summaries preserving IDs/provenance; introduce no new claims. |
| **Workflow** | Receive oversized context → summarize with source-ID retention → return compact context + references to raw evidence (retained in data layer). |
| **Input schema (described)** | `context_block` (events/notes), `token_budget`, `preserve_ids` (list). |
| **Output schema (described)** | `summary`, `preserved_ids[]`, `raw_refs[]`, `compression_ratio`. |
| **Required tools** | None external (LLM via AI Layer). |
| **Required memory** | Short-term; reads session. |
| **Validation rules** | No new facts; all referenced IDs retained; raw evidence still resolvable. |
| **Retry / Fallback** | On over-compression (ID loss detected) → retry with higher fidelity; fallback to reference-only. |
| **Confidence scoring** | Fidelity check (ID retention) + coverage. |
| **Error recovery / Logging / Metrics** | Standard; metric on compression ratio + ID-retention rate. |
| **Testing strategy** | Fixtures asserting ID/provenance retention + no-new-claim invariant. |
| **Future improvements** | Hierarchical/rolling summarization; salience-aware compression. |

### 4.9 Human Review (Human-in-the-Loop Node)

| Attribute | Specification |
|---|---|
| **Purpose** | Present findings to the analyst and structure their decision (the mandatory control gate). |
| **Responsibilities** | Neutrally present findings/confidence/gaps; capture approve/edit/reject/redirect + rationale; record to conversation + audit; resume the graph. |
| **Workflow** | Graph interrupt → package decision context → await authenticated human decision (via backend) → record → resume/redirect. |
| **Input schema (described)** | `decision_context` (report, recommendations, confidence, gaps), `pending_action` (notify/remediate/escalate). |
| **Output schema (described)** | `decision` (approve/edit/reject/redirect), `edits` (optional), `target`, `rationale`, `actor_id`, `timestamp`. |
| **Required tools** | None (backend-mediated human interaction). |
| **Required memory** | Conversation (dialogue/decisions), session. |
| **Validation rules** | Only authenticated, authorized actors may decide; every decision recorded in tamper-evident audit; no downstream action without an approval record. |
| **Retry / Fallback** | Not auto-retried; times out to a "pending human" state with reminders (never auto-approves unless explicit policy). |
| **Confidence scoring** | N/A (human authority); the *system* records the human's rationale. |
| **Error recovery / Logging / Metrics** | Standard; metric on approval latency, approve/reject/redirect distribution, gate SLA breaches. |
| **Testing strategy** | Tests: no action pre-approval; audit record created; redirect re-enters Planner; authz enforced. |
| **Future improvements** | Step-up auth for high-impact approvals; configurable auto-approval policies with guardrails. |

---

## 5. LangGraph Implementation Specification

The graph is the deterministic control plane. This section defines its *implementation-level* behavior. **No LangGraph code** — behavior is described.

| Aspect | Specification |
|---|---|
| **Nodes** | One node per agent (Planner, Log Analyzer, Threat Detector, CVE Research, Evaluator, Incident Reporter, Patch Recommendation, Summarizer, Human Review) plus system nodes (ingest-seed, enrichment, parallel-join, close/persist). Each node has a single owner (§ Node Ownership) and a validated I/O contract. |
| **Edges** | Directed edges encode data dependencies (Log→Threat→CVE→Evaluator→Reporter→Patch→Evaluator→Human→Notify→Close). Edges carry the shared state; no data passes outside state. |
| **Conditional routing** | Router functions branch on state: Threat verdict (benign→close; threat→fan-out), Evaluator verdict (pass→advance; needs-revision→bounded re-run; escalate→human), Human decision (approve→notify; reject→close; redirect→Planner). |
| **Interrupts** | `interrupt` points at mandatory human gates (pre-notification, remediation, escalation). The graph pauses, persists a resumable checkpoint, and surfaces "awaiting human" to the backend/UI. |
| **Checkpointing** | State is checkpointed after every node transition to durable storage (via backend/data layer). Checkpoints are the unit of resume and rollback and include the config snapshot for reproducibility. |
| **Shared state** | The single typed state object (SAD §4) with ownership-scoped sub-states (global/shared/agent/investigation/report/notification/conversation). Reducers use append-and-checkpoint semantics; agent sub-state is writer-isolated to avoid contention. |
| **Retry policies** | Per-node: exponential backoff + jitter, bounded attempts, idempotent re-run from checkpoint. External calls wrapped by circuit breakers (via Integrations). Distinct policy for model calls (AI-Layer failover) vs. tool calls (degradation). |
| **Error recovery** | Node failure → retry → (if unrecoverable) route to human gate with context; never silent-drop. Schema-invalid node output → bounded self-repair → Evaluator → human. Corrupt session memory → rebuild from durable tier/raw evidence. |
| **Human approval** | First-class interrupt gates; resume only on a recorded, authorized human decision; decisions are audited. No consequential action node (notify/remediate) is reachable without traversing an approval gate. |
| **Graph resume** | Resume from the last durable checkpoint using the pinned config snapshot; human-gate resume consumes the recorded decision. Resume is idempotent — re-running a completed node returns its checkpointed result. |
| **Rollback strategy** | Roll back to a prior valid checkpoint on validation failure or human "redirect"; superseded state retained (not destroyed) for audit; a redirect re-enters Planner with new instructions rather than mutating history. |
| **Parallel execution** | After a confirmed threat, CVE Research and enrichment run concurrently; a parallel-join node barriers and merges their sub-states before the Evaluator/Reporter. Join is deterministic (ordered merge by source). |
| **Sequential execution** | Data-dependent stages run strictly ordered (Log→Threat, Reporter→Patch). Sequencing is enforced by edges, not by agents. |
| **Node ownership** | Each node owns exactly one agent/system responsibility and writes only its designated sub-state fields; the graph runtime owns global state and routing. This ownership map is the contract for who-writes-what and drives conflict-free parallel merges. |

**Rationale.** Checkpoint-per-transition + config snapshot gives full replayability and forensic provenance (invariant #5). Interrupts as first-class gates make human control structural, not procedural (invariant #1). Writer-isolated sub-states make parallel fan-out safe without locks. Rollback-by-retain (never destroy) preserves the audit trail even when an investigation is redirected.

---

## 6. Database Implementation Specification

Implementation-level documentation per entity (from SAD §11 ER model). **No SQL/DDL.** Index/lifecycle/audit strategies are described. Postgres is the system of record; large raw evidence lives in object storage referenced by `raw_ref`.

**Global data policies.** All tables carry `created_at`/`updated_at`; security-relevant tables are append-friendly with revisions retained. **Soft delete** via `deleted_at` + status (records are never hard-deleted from the system of record while under retention). **Archival** moves closed/aged investigations and their children to cold storage by retention policy, leaving a tombstone + audit reference. **Versioning** applies to mutable-but-auditable artifacts (assessments, reports, recommendations) via monotonic `version` with prior versions retained. **Audit** entries are append-only and never soft-deleted, archived, or versioned (they *are* the history).

| Entity | Purpose | Relationships | Validation | Indexes (intent) | Lifecycle | Audit | Soft delete | Archival | Versioning |
|---|---|---|---|---|---|---|---|---|---|
| **users** | Analysts/managers/admins/auditors | 1..* investigations, human_decisions | Unique email/SSO subject; role ∈ RBAC set; status enum | PK; unique(email), unique(sso_subject); index(role,status) | Created on provisioning; deactivated not deleted | All role/status changes audited | Yes (deactivate) | Rare (retain for audit) | N/A (state, not versioned) |
| **investigations** | Central case record | owner→users; 1..* events/assessments/cves/recs/conversations/notifications; 1 report | Valid trigger/status/severity enums; owner exists; config_snapshot present | PK; index(status,severity), index(owner_id), index(created_at) | Open→(benign close | threat pipeline)→closed→archived | Create/close/redirect/reopen audited | Yes | Yes, by retention age | Config snapshot pins reproducibility |
| **assets** | Hosts/systems/software involved | *..* investigations (via events/cves) | Valid identifiers; software inventory schema | PK; index(hostname), index(ip); GIN on software_inventory | Long-lived reference; updated by inventory | Inventory changes audited | Yes | Cold-archive stale assets | Inventory revisions retained |
| **log_events** | Normalized evidence | investigation, asset | Provenance required (source,ts,actor,type); raw_ref resolvable | PK; index(investigation_id,event_time); index(asset_id); index(event_type) | Immutable once written | Not mutated; creation implicitly audited via investigation | No (evidence immutable) | Archived with parent investigation | N/A (immutable) |
| **threat_assessments** | Threat Detector output | investigation | Verdict/severity/confidence valid; enrichment_status set | PK; index(investigation_id); index(verdict,severity) | Revised as investigation evolves | Each revision audited | Soft (supersede) | With parent | Versioned; prior retained |
| **cve_findings** | CVE Research output | investigation, asset | CVE id format; cvss range; applicability enum; citations present | PK; index(investigation_id); index(cve_id); index(asset_id) | Created during research; may be re-run | Creation/update audited | Soft | With parent | Versioned on re-run |
| **reports** | Incident reports | investigation (1:1 current) | Only supported claims; citations compiled; status enum | PK; unique(investigation_id,version); index(status) | Draft→final→(regenerated new version) | Generation/regeneration/export audited | Soft | With parent | Versioned; regenerable from state |
| **recommendations** | Remediation guidance | investigation | Priority/type valid; rationale+citations present; approval_status | PK; index(investigation_id); index(approval_status,priority) | Proposed→(approved/rejected/edited by human) | Every status change audited | Soft | With parent | Versioned |
| **conversations** | Human↔system threads | investigation; 1..* messages/decisions | Belongs to investigation | PK; index(investigation_id) | Lives with investigation | Container; decisions audited | Soft | With parent | N/A |
| **messages** | Dialogue turns | conversation | author_type/content valid; untrusted content sanitized on display | PK; index(conversation_id,created_at) | Append-only within conversation | Part of audit context | No | With parent | N/A |
| **human_decisions** | Approvals/redirects | conversation→users | decision enum; rationale present; actor authorized | PK; index(conversation_id); index(user_id,created_at) | Append-only | **Core audit source** | No | With parent | N/A |
| **notifications** | Outbound alerts | investigation | channel/recipient valid; requires linked approval; status enum | PK; index(investigation_id); index(status,channel) | Pending→sent/failed/dead-letter | Dispatch + delivery audited | No | With parent | N/A |
| **audit_logs** | Immutable audit trail | actor→users; entity refs | Signature valid; append-only; before/after refs | PK; index(entity_type,entity_id); index(actor_id,timestamp) | Append-only, tamper-evident | Is the audit | **Never** | Long-retention cold storage only | Never (immutable) |

**Rationale.** Evidence (`log_events`) and audit (`audit_logs`) are immutable — the forensic backbone. Analytical artifacts (assessments/reports/recommendations) are versioned-with-retention so investigations can evolve without losing history. Soft delete + archival satisfy retention/compliance while keeping the system of record consistent. Indexes target the dominant access paths (by investigation, by time, by status/severity, by CVE/IoC) identified in the data-flow (SAD §8).

---

## 7. Memory Implementation Specification

Six memory tiers (SAD §5) specified for implementation. Managers sit behind the Memory module interface (§3.4); agents never touch stores directly.

| Tier | Storage | Lifetime | Eviction | Synchronization | Access rules | Recovery |
|---|---|---|---|---|---|---|
| **Working memory** | In-process + Redis (hot) | Single node/agent turn | Bounded by context token budget; oldest/least-salient summarized out via Summarizer | None (per-turn, ephemeral) | Only the executing node; not shared laterally | Rebuilt from session memory on retry |
| **Session memory** | Redis (hot) + Postgres (durable) two-tier | One investigation | Hot entries TTL'd; durable retained until investigation close | Write-through hot→durable; durable is source of truth on conflict | Scoped to the investigation's nodes; append semantics preserve provenance | Rebuild hot from durable; if durable gap, from raw evidence |
| **Conversation memory** | Postgres | Per session, retained | None during investigation; archived with parent | Written via backend on each human turn/decision | Authorized actors on that investigation; audited | Durable; part of audit context |
| **Long-term memory** | Postgres | Persistent, cross-investigation | Archival by retention policy | Written on investigation close (verdict/outcome/decisions) | Read across investigations for analytics/"seen before" | Durable; archival tombstones |
| **Knowledge memory** | pgvector (vectors) + Postgres (metadata) | Persistent, curated, versioned | Superseded chunks retired on refresh; version-pinned | Refresh pipeline updates index atomically per source/version | Read-only to agents (retrieval); write only via RAG ingestion | Re-ingest from source feeds; index rebuildable |
| **Investigation memory (history)** | Postgres (+ vector index) | Persistent, queryable | Archived with retention | Populated from closed investigations, indexed by asset/IoC/technique/CVE | Read by Threat/Reporter for related-incident context | Rebuildable index over durable investigations |

**Rationale.** The hot/durable split (session) buys sub-ms working access with crash survivability — an investigation must survive a worker restart (invariant #6). Knowledge memory is read-only to agents and separate from investigation data: this is a **prompt-injection safety boundary** (invariant #3) — untrusted investigation input can never mutate trusted reference knowledge. Summarization is the eviction mechanism for working memory, keeping token cost/latency bounded while raw evidence remains resolvable by reference.

---

## 8. RAG Implementation Specification

Implements SAD §6. Grounding + citations are mandatory (invariant #4).

| Aspect | Specification |
|---|---|
| **Knowledge sources** | NVD CVE feeds, MITRE ATT&CK/CWE, vendor + GitHub security advisories, curated internal runbooks/detection rules/policies. Each source has a trust tier and a refresh cadence. |
| **Document processing** | Fetch (scheduled + event-driven) → normalize/clean → deduplicate → structural + semantic chunking that preserves CVE/technique/runbook boundaries → metadata enrichment. |
| **Chunk strategy** | Boundary-aware chunks (one CVE/technique/section per chunk where possible) with overlap only where semantics require; size tuned to the embedding model's effective window; oversized entries split with parent linkage. |
| **Metadata strategy** | Per chunk: source, source-trust-tier, version, published/updated date, CVE id, CWE id, technique id, product/version applicability keys. Drives filtering, freshness weighting, and citation. |
| **Embedding strategy** | Pluggable embedding provider (AI-Layer port); one pinned model per index; embeddings versioned; re-embed on model/version change under a new index version. |
| **Retriever design** | Hybrid: dense vector similarity + keyword/BM25 + metadata filters (product/version, technique, date range). Query is expanded from agent context (assets, IoCs, techniques). |
| **Hybrid search** | Dense and sparse results fused, then metadata-filtered; exact identifiers (CVE ids/products) prioritized via keyword path; semantic path recovers related concepts. |
| **Ranking** | Relevance re-rank + dedupe + **freshness weighting** (newer advisories preferred) + trust-tier weighting; top-k within a token budget. |
| **Caching** | Retrieval results and third-party lookups cached with TTL keyed by query+filters+index-version; cache is the degradation fallback (with staleness flag). |
| **Versioning** | Index versioned by (embedding model, source snapshot); retrieval records the index version used, so investigations are reproducible. |
| **Knowledge refresh** | Scheduled per-source refresh + event-driven for high-severity advisories; atomic per-source index swap; superseded chunks retired, not mutated in place. |
| **Source trust** | Allow-listed sources only; trust tier influences ranking and whether a claim can stand on a single source; untrusted/unknown sources are excluded from grounding. |
| **Citation strategy** | Every retrieval-derived claim carries source IDs; Reporter compiles the reference list; Evaluator rejects security claims lacking resolvable citations. |
| **Hallucination prevention** | Grounded-generation discipline (answer must follow from retrieved context) + Evaluator groundedness checks + "candidate vs. confirmed" labeling + refusal-to-assert without evidence + citation enforcement. |

**Rationale.** Security knowledge is exact and time-sensitive; hybrid + freshness/trust weighting beats pure-semantic recall for precision and safety. Index versioning + recorded retrieval makes investigations reproducible (consistent with the config-snapshot principle). The Evaluator is the enforcement point that turns "citations preferred" into "citations required."

---

## 9. Prompt Implementation Specification

Per-prompt implementation contract. **The prompts themselves are not written here.** A shared preamble encodes the invariants (human-in-the-loop, evidence-vs-inference, untrusted-data separation, citation requirement); per-prompt entries specialize it. Prompts are versioned assets under change control with evaluation suites.

| Prompt | Purpose | Input (described) | Output (described) | Rules & Guardrails | Validation | Expected behaviour | Failure behaviour | Evaluation strategy | Versioning / change mgmt |
|---|---|---|---|---|---|---|---|---|---|
| **Planner** | Plan the investigation | Trigger, scope, available sources | Ordered plan + rationale | Plan from evidence; may request data; never skip human gate | Output schema-valid; steps reference real agents | Correct path selection (benign vs. full) | Low-confidence → conservative full plan | Fixtures: trigger→plan shape; gate-present check | Semver; change requires eval pass + review |
| **Log Agent** | Structure + correlate logs | Records, window, scope | Event set, timeline, gaps | "Structure only, no threat inference"; provenance required | Schema + provenance completeness | Accurate normalization/correlation | Parser uncertainty → low-confidence flag | Multi-format golden fixtures; correlation accuracy | Semver; regression suite gates changes |
| **Threat Agent** | Assess threat | Events, timeline, context, enrichment | Verdict, IoCs, ATT&CK, severity | Evidence/inference split; no fabricated reputation; escalate ambiguity | Schema; severity within tolerance | Calibrated verdict/severity | Enrichment down → degraded flag | Labeled verdict/severity sets; calibration | Semver; calibration gate |
| **Research Agent** | Identify CVEs | Threat + assets + IoCs | CVEs, candidates, CVSS, citations | Cite every claim; no CVE without version evidence | Schema; citation resolvable | Correct applicability + CVSS | Live API down → cache + staleness | Known-CVE fixtures; citation enforcement | Semver; citation-coverage gate |
| **Reporter** | Write report | All findings | Exec + technical report, citations | Only supported claims; mark gaps; no new findings | Schema; supported-claims check | Faithful, audience-appropriate report | Missing section → "incomplete" marker | Supported-claims-only fixtures | Semver; groundedness gate |
| **Patch Agent** | Recommend remediation | Vulns, threat, assets | Prioritized recommendations, citations | For human approval; no destructive automation; justify + cite | Schema; requires-approval flag present | Prioritized, justified, safe guidance | Sparse knowledge → conservative flagged | Prioritization + safety fixtures | Semver; safety gate |
| **Evaluator** | Grounding/quality gate | Candidate output + evidence | Verdict + violations | Reject un-sourced/unsupported; flag injection | Deterministic checks + schema | Correctly blocks bad output | Its own failure → escalate to human | Adversarial hallucination/injection corpus | Semver; adversarial suite gate |
| **Summarizer** | Compress context | Oversized context + budget | Summary + preserved IDs | No new claims; retain IDs/provenance | ID-retention check | Lossless-by-reference compression | ID loss → retry higher fidelity | ID-retention + no-new-claim fixtures | Semver; fidelity gate |
| **Human Review** | Structure human decision | Decision context | Structured decision + rationale | Neutral presentation; surface confidence/gaps | Authz + audit record required | Clear, unbiased decision capture | Timeout → pending state, no auto-approve | UX + authz + audit tests | Semver; policy review |

**Rationale.** Treating prompts as versioned, evaluated, change-controlled assets makes AI behavior a governed, regression-tested property — not tribal knowledge. The shared preamble guarantees the invariants are inherited uniformly, preventing per-prompt drift on safety-critical rules.

---

## 10. Folder Implementation Guide

Per-folder guidance mirroring the SAD monorepo (SAD §9). "Files (expected)" describes intended contents; no file contents are produced. "Ownership" refers to the responsible squad role. All folders inherit §11 standards and mirror their tests under `tests/`.

| Folder | Purpose | Files (expected) | Responsibilities | Ownership | Dependencies | Testing requirements | Future files |
|---|---|---|---|---|---|---|---|
| `backend/` | Sole write boundary; API + services + workers | api/, services/, middleware/, workers/, composition root | Validate, authorize, persist, orchestrate, dispatch | Backend | agents/graph, memory, integrations, models, config, db | Unit (services/middleware), integration (API↔db↔graph), security (authz) | New services/workers; tenant middleware |
| `frontend/` | Analyst SPA | pages/, components/, state/, realtime/ | Render screens, stream, capture approvals | Frontend | backend API, auth | Component + interaction + approval-flow tests | Voice UI; hunting/compliance dashboards |
| `agents/` | The 9 agents + shared contracts | per-agent modules, shared/ (schemas, guardrails) | Agent reasoning + I/O contracts + tool bindings | AI/Agents | graph, ai-layer, tools, memory, rag, models | Golden-fixture agent tests; guardrail tests | New specialist agents |
| `graph/` | LangGraph orchestration | nodes, edges/routing, checkpointer, interrupts, retry policy | Deterministic control flow | AI/Agents + Backend | memory, ai-layer, models, integrations | Graph tests (routing, resume, rollback, parallel join) | New nodes; distributed/A2A |
| `memory/` | Tiered memory managers | per-tier managers, sync, summarization hook | Store/evict/sync/recover memory | Backend + AI/Agents | redis, postgres, rag | Memory unit + recovery + sync tests | Tenant partitioning |
| `rag/` | RAG pipeline | ingestion, chunker, embeddings adapter, retriever, re-ranker, citation binder | Grounding + citations | AI/Agents | ai-layer, pgvector, integrations, config | RAG eval (retrieval/groundedness/citation) | Dedicated vector DB adapter |
| `tools/` | Deterministic agent tools | parsers, extractors, CVSS interpreter, correlators, lookup wrappers | Provide testable capabilities | AI/Agents + Backend | integrations, models, config | High-coverage unit tests | New/MCP tools |
| `prompts/` | Versioned prompt assets | shared preamble, per-prompt templates, version manifest, eval suites | Prompt contracts + change control | AI/Agents | models, ai-layer, testing | Prompt-eval suites gate changes | New prompts; A/B variants |
| `services/` | Cross-cutting domain logic | scoring, prioritization, correlation helpers | Shared domain rules | Backend + AI/Agents | models, knowledge (read) | Deterministic unit tests | Compliance mapping service |
| `models/` | Schemas & contracts | entity/state/agent-IO/DTO/event schemas, version manifest | Single source of truth for shapes | All (shared) | none (core) | Schema validation/compat tests | New/tenant schemas |
| `config/` | Config + flags + settings | schema/loader, env profiles, flag registry, secret-resolution client | Typed validated config; no secrets committed | Security/Platform | secret manager, models | Config-validation + fail-fast tests | Per-tenant/dynamic config |
| `integrations/` | External adapters | per-integration client + cache + breaker + normalizer + health | Isolated, read-only external access | Backend + Security/Platform | external services, config/secrets, models | Adapter tests vs. mocks/sandboxes; resilience tests | New/MCP sources |
| `logs/` | Runtime log/audit output | (runtime only; git-ignored) | Local/dev log sink | Security/Platform | — | N/A (destination) | — |
| `tests/` | All test/eval suites | per-module suites, fixtures, eval datasets, red-team corpus, load scenarios | Verify + gate quality/security | Shared QA + all | all modules | Is the test surface | New eval dimensions |
| `docs/` | Architecture + records | PROJECT_CONTEXT.md, TECHNICAL_ARCHITECTURE.md, this EDS, ADRs, runbooks | Governing docs + decisions | TPL/Leads | — | Doc-consistency review | New ADRs/runbooks |
| `scripts/` | Ops/dev scripts | KB seed, migrations, local bootstrap | Repeatable ops/dev tasks | Security/Platform | backend, db, rag | Script smoke tests | New ops automation |
| `deploy/` | Deployment artifacts | Dockerfiles, K8s manifests, CI/CD pipeline, rollout/rollback | Package + ship cloud-agnostically | Security/Platform | all (artifacts), secret manager | Deploy/rollback rehearsal in staging | Multi-region/on-prem packaging |

**Rationale.** The folder map is a 1:1 projection of the architecture layers (SAD §1/§9), so an engineer can navigate from any layer in the SAD to a folder here and to its tests under `tests/`. Ownership is assigned by role so accountability is unambiguous in a small squad.

---

## 11. Coding Standards

Project-wide standards, enforced in CI (§ Bootstrap). Rationale accompanies each rule cluster.

| Area | Standard | Rationale |
|---|---|---|
| **Naming** | Intent-revealing, consistent per-layer conventions; domain terms match the Models vocabulary; no abbreviations for security-critical concepts (e.g., spell out "investigation", "assessment"). | A shared, unambiguous vocabulary across a multi-year platform reduces defects and onboarding cost. |
| **Typing** | Strong, explicit types at every module boundary; all agent I/O, DTOs, and state are schema-typed; no untyped "any" across public interfaces. | Contract-first + type safety catch integration errors before runtime; essential for parallel workstreams. |
| **Error handling** | Typed error taxonomy (validation, auth, integration, model, internal); errors returned/propagated explicitly, never swallowed; boundaries fail-closed; external inputs validated before use. | Predictable failure is a security property; silent failure violates invariant #6. |
| **Logging** | Structured (key-value) logs with correlation + investigation IDs; log levels disciplined; **never** secrets/PII beyond policy; untrusted content escaped when logged. | Observability + audit require structured, safe logs; log injection is an attack vector. |
| **Comments** | Explain *why*, not *what*; document invariants, security assumptions, and non-obvious trade-offs; keep comment density matching the surrounding code. | Comments encode rationale that types can't; over-commenting the obvious adds noise. |
| **Documentation** | Every module has a README describing purpose, public interface, and dependencies; ADRs for decisions; this EDS is the index. | Docs-as-code keeps the system understandable as it grows. |
| **Folder organization** | Follow §10 exactly; one responsibility per module; tests mirror source; no cross-layer reach-around (respect the dependency direction). | Structural consistency enforces clean architecture. |
| **Imports** | Dependencies point inward (clean architecture); no upward/lateral imports that break layering; providers imported only at the edge/composition root. | Prevents the domain from depending on vendors; keeps SOLID-D intact. |
| **Dependency rules** | Depend on abstractions (ports) not concretions; third-party SDKs isolated behind adapters; new third-party deps require review + license/security check. | Preserves pluggability (Claude-primary-but-swappable) and supply-chain safety. |
| **Configuration rules** | All environment-specific behavior via typed config; fail-fast on invalid config; strict dev/staging/prod separation; no config drift into code. | Twelve-factor config enables safe promotion across environments. |
| **Secrets** | Never in code, config files, logs, or API payloads; resolved from the external secret manager at runtime; rotation-friendly; least-privilege scopes. | A security platform must be exemplary with its own secrets (invariant + §14). |

---

## 12. Testing Implementation Plan

Testing spans deterministic code and non-deterministic AI (from SAD §16, made implementation-level). All suites live under `tests/`, mirror the source tree, and gate CI.

| Test type | Scope | Method | Gate |
|---|---|---|---|
| **Unit** | Tools, parsers, services, adapters (mocked), data-access, middleware | Fast, deterministic, high coverage on logic + validation | Coverage threshold + all pass |
| **Integration** | Cross-layer: backend↔db↔graph, backend↔integrations (sandbox/mocks), notification dispatch | Verify contracts + persistence + **audit side-effects** | All pass; audit completeness asserted |
| **Agent** | Each of 9 agents vs. golden fixtures | I/O schema validity, guardrail adherence, evidence/inference separation, confidence calibration | Pass + calibration within tolerance |
| **Prompt evaluation** | Each prompt version | Correctness, format adherence, refusal, injection resistance; auto-scored (+ LLM-judge where apt) | Threshold met; regressions block merge |
| **Graph** | Orchestration behavior | Routing branches, resume, rollback, parallel join, human-gate pause/resume, retry/fallback | All pass; no path bypasses human gate |
| **Security** | AuthN/Z, RBAC boundaries, secret handling, **prompt-injection red-team**, dependency/vuln scans, audit completeness | Automated + red-team corpus | Injection fails to escalate; scans clean/accepted |
| **Performance** | Investigation latency (esp. parallel fan-out), surge throughput, LLM cost/latency budgets, degradation under outage, datastore load | Load/stress scenarios | SLOs + budgets met |
| **Regression** | Full behavioral surface incl. prompt/RAG evals | Run on every change; trend-tracked | No regression past thresholds |
| **Acceptance** | End-to-end investigation (benign + threat) against phase acceptance criteria | Scenario-based | Phase/DoD criteria satisfied |
| **CI** | The gating harness | Lint → unit → integration → agent → prompt-eval → RAG-eval → security scan → build | All gates green to merge/release |

**Rationale.** AI regresses silently; prompt/RAG evals as *first-class CI gates* make behavior a controlled property. Security tests treat the injection surface as continuously adversarial because the system deliberately ingests attacker-influenced data (invariant #3). Audit-completeness is asserted in integration tests because auditability is a correctness property, not a nicety.

---

## 13. Observability Plan

Investigations are multi-step, AI-driven, and cost-bearing; observability is built in from Phase 2, not bolted on.

| Aspect | Specification |
|---|---|
| **Logging** | Structured, correlated logs (request ID + investigation ID + node) across all layers; safe (no secrets/PII); untrusted content escaped. |
| **Tracing** | Distributed traces spanning API → graph → each node → tools/model/integrations, so a single investigation is one traceable story. |
| **Metrics** | RED (rate/errors/duration) per service + per node; agent success/validity/confidence; RAG retrieval quality/latency; queue depth; delivery metrics. |
| **Dashboards** | Per-investigation timeline; per-agent latency/cost; RAG health; integration/circuit health; human-gate wait times; error/failure analytics. |
| **Monitoring** | SLOs on investigation latency, availability, gate SLA, delivery success; synthetic canary investigations. |
| **Alerting** | Actionable alerts on SLO breach, circuit-open storms, eval-score drops, dead-letter notifications, cost-budget breach; tuned to avoid fatigue. |
| **Failure analytics** | Aggregated failure taxonomy (agent/API/model/network/memory/notification) with trends; feeds retros and risk register (§19). |
| **LLM usage** | Per-invocation token in/out, model/provider, prompt version, self-repair rate; usage by agent/investigation. |
| **Cost tracking** | Cost per investigation, per agent, per model; budget guardrails with backpressure; anomaly detection on cost spikes. |
| **Latency tracking** | End-to-end and per-node latency, parallel-join wall-clock, gate wait time, p50/p95/p99. |

**Rationale.** Cost and latency are per-agent, per-model properties; without per-node attribution they're unmanageable at scale. Canary investigations detect silent quality/latency regressions the moment a model/prompt/index changes.

---

## 14. Security Implementation Plan

The platform processes security data and acts on analyst trust; its own security is paramount and must cover AI-specific threats. Implements SAD §14 + invariants.

| Aspect | Specification |
|---|---|
| **Authentication** | Federated OIDC/SSO; MFA at IdP; short-lived signed JWTs with rotation; no local password store. |
| **Authorization** | RBAC (analyst/senior/manager/admin/auditor) enforced in backend middleware + object-level ownership checks; deny-by-default; least privilege. |
| **Audit** | Append-only, tamper-evident, signed audit of every consequential action + human decision; never deletable/editable; queryable by auditors. |
| **Prompt injection protection** | All ingested content untrusted; strict separation of instructions (system) from data; sanitize/quote untrusted data; Evaluator flags instruction-like content; per-agent tool allow-lists; **no agent can trigger irreversible actions** (invariant #2). |
| **Secrets** | External secret manager/KMS; runtime injection; rotation; never in code/config/logs/API; least-privilege scopes. |
| **Encryption** | TLS in transit everywhere; encryption at rest for DB/object store/backups; field-level encryption for the most sensitive data. |
| **Validation** | Schema validation at every boundary (API, tools, agent I/O, config); fail-closed on invalid input. |
| **Input sanitization** | Normalize/quote/escape untrusted log + external data before display, logging, or prompt assembly; reject malformed at the edge. |
| **Output validation** | All model output validated against schemas before any downstream action; Evaluator groundedness/citation checks; no action on unvalidated output. |
| **RBAC** | Roles mapped to capabilities (who can run/approve/configure/administer/audit); high-impact approvals may require step-up auth (future). |
| **Session management** | Server-side session lifecycle in Redis; idle/absolute timeouts; revocation; anomaly signals; session events audited. |
| **Compliance** | Retention/archival policies (§6), complete audit trail, data-residency via cloud-agnostic/on-prem + local-model option; supports audit/regulatory review. |

**Rationale.** The strongest control is architectural: the system has **no destructive capability**, so even a fully compromised agent can only produce recommendations for human approval. The untrusted-data boundary structurally prevents prompt injection from escalating to action — the single most important AI-security control here.

---

## 15. Deployment Implementation Plan

Cloud-agnostic, containerized, on-prem-capable (SAD §17).

| Aspect | Specification |
|---|---|
| **Development** | Contract-first local dev against schemas; mocked integrations + seeded knowledge base; fast inner loop. |
| **Local** | One-command compose stack (backend, frontend, Postgres+pgvector, Redis, object store, mocks); deterministic + offline. |
| **Docker** | Minimal, pinned, scanned, multi-stage images per service; signed at build. |
| **Staging** | Production-like K8s; real integration sandboxes; load tests + eval gates + rollback rehearsal before prod. |
| **Production** | K8s (any cloud or on-prem); HA data stores; autoscaling on backend + graph/RAG workers; ingress + TLS. |
| **CI/CD** | Pipeline gates: lint → tests → **prompt/RAG evals** → security scans → signed image → progressive rollout; automated rollback on failed gates. |
| **Scaling** | Horizontal autoscale of the compute-heavy agent/graph tier and RAG ingestion; stateless services; data stores scaled/HA independently. |
| **Environment variables** | All env-specific behavior via typed config/env; strict dev/staging/prod separation; no secrets in committed env files. |
| **Secrets** | External secret manager/KMS; runtime injection; rotation without rebuild; never in images/git. |
| **Monitoring** | Full observability stack (§13) wired at deploy; SLO dashboards + alerting live before go-live. |
| **Rollback** | Progressive/canary deploy with health + SLO gates; automated rollback; rehearsed in staging; runbooks maintained. |

**Rationale.** Autoscaling targets the *agent/graph* tier because that's the elastic, latency-variable bottleneck. AI evals as release gates prevent behavior regressions from reaching production. No proprietary-cloud dependency on the critical path keeps on-prem/multi-cloud viable for data-sovereign customers.

---

## 16. Implementation Order

The exact module build order, with rationale. (Aligns with the Roadmap §2 but stated as a strict dependency ordering of modules.) **No code.**

1. **Models (schemas/contracts)** — *why:* everything depends inward on these; contract-first enables parallel workstreams. Built first (even before backend) so all teams integrate against stable shapes.
2. **Configuration + Secrets wiring** — *why:* every other module needs typed config and secret resolution; fail-fast config prevents downstream ambiguity.
3. **Backend skeleton + middleware** — *why:* the sole write boundary and the composition root; nothing persists or orchestrates without it.
4. **Authentication/Authorization** — *why:* every request must be secured before real capabilities exist; retrofitting auth is dangerous.
5. **Database + audit + data-access** — *why:* the system of record and audit substrate that all state and human decisions require.
6. **AI Layer (model abstraction)** — *why:* agents and RAG depend on a stable model/embedding port with failover; built before any agent.
7. **Graph core (empty nodes) + checkpointing** — *why:* the deterministic control plane must exist before agents plug into it; checkpoint/resume proven early.
8. **Memory managers** — *why:* agents and RAG need working/session/knowledge memory before they can reason.
9. **RAG pipeline** — *why:* grounding + citations are prerequisites for the knowledge-dependent agents (Threat, CVE, Patch).
10. **Tools + Integrations adapters** — *why:* agents' capabilities (parsers, lookups, enrichment) must exist before the agents that call them.
11. **Agents in dependency order** — Log Analyzer → Threat Detector → CVE Research → Evaluator/Summarizer → Incident Reporter → Patch Recommendation. *why:* each consumes the prior's output; Evaluator/Summarizer support the later synthesis agents.
12. **Planner + full graph wiring** — *why:* planning and routing require the agents to exist; parallel fan-out + human gates wired last in the pipeline.
13. **Notifications** — *why:* depends on a working, human-gated pipeline; must never dispatch pre-approval.
14. **Frontend** — *why:* consumes the working backend + pipeline + streaming + approval surface.
15. **Observability + cost controls** — *why:* continuous from the start, but hardened once the full pipeline emits telemetry.
16. **Security hardening + red-team** — *why:* verify invariants under attack once the whole surface exists.
17. **Deployment to production** — *why:* the final gate after everything is built, tested, observable, and hardened.

**Rationale.** The ordering is a topological sort of the dependency graph with security foundations pulled as early as possible. Deterministic, auditable substrate precedes any AI so agents are always built on trustworthy ground (invariants #1, #5, #7).

---

## 17. Sprint Planning

Realistic 2-week sprints for a ~4–6 engineer cross-functional squad. Effort in story points (Fibonacci); **no calendar dates**. Sprints leave the system working + tested. Story points reflect effort+uncertainty; assumed sustainable velocity ≈ 20–26 pts/sprint. Cross-cutting work (observability, security, docs, tests) is embedded in each sprint, not deferred.

| Sprint | Objectives | Deliverables | Dependencies | Completion criteria (points) |
|---|---|---|---|---|
| **S1 — Foundation I** | Bootstrap + Models + Config | Monorepo, CI (lint+test skeleton), coding standards, schemas v1, config+secret resolution | — | Local stack runs; CI green; schemas validate; config fail-fast works. (~21) |
| **S2 — Foundation II** | Backend skeleton + Auth | Gateway + middleware, OIDC/SSO, JWT, RBAC, auth audit | S1 | RBAC boundary tests pass; authenticated no-op endpoints; auth events audited. (~24) |
| **S3 — Data + Graph core** | Database + audit + Graph skeleton | Entity schemas/migrations, data-access, append-only audit, graph checkpointer + stub pipeline + interrupt | S2 | CRUD+audit round-trip; graph runs stub end-to-end; checkpoint/resume + interrupt verified. (~24) |
| **S4 — AI Layer + Memory** | Model abstraction + memory tiers | LLM/embedding ports, streaming, cost/token metrics, secondary failover; working/session/knowledge managers | S3 | Provider swap via config; failover on induced fault; memory read/write/evict/recover + restart survival. (~24) |
| **S5 — RAG** | Grounding + citations | Ingestion, chunking, index, hybrid retriever, re-rank, citation binder, refresh | S4 | Retrieval eval ≥ baseline; citations resolve; freshness/trust weighting verified; cache fallback works. (~24) |
| **S6 — Tools + Log Analyzer + Threat Detector** | First two agents + their tools | Parsers/connectors/extractors, VirusTotal/MITRE adapters; Log Analyzer + Threat Detector nodes | S5 | Golden-fixture tests pass; timeline + verdict/severity produced; degraded-enrichment path flagged. (~26) |
| **S7 — CVE + Evaluator + Summarizer** | Research + quality gate + compression | NVD adapter, CVE agent; Evaluator (schema/citation/hallucination); Summarizer (lossless-by-reference) | S6 | CVE applicability + citations correct; Evaluator blocks adversarial fixtures; summaries retain IDs. (~24) |
| **S8 — Reporter + Patch + Planner + full wiring** | Complete the pipeline | Incident Reporter, Patch Recommendation, Planner, conditional routing, parallel join, human-gate interrupts | S7 | Full benign + threat investigation runs; human gate pauses/resumes; parallel join correct; no gate bypass. (~26) |
| **S9 — Notifications + Frontend I** | Human-gated alerts + core UI | Slack/SMTP channels, dedupe, failover, delivery tracking; Dashboard + Investigation + approval panel + streaming | S8 | No pre-approval dispatch; Slack→email failover; analyst can run + watch + approve an investigation. (~26) |
| **S10 — Frontend II + Observability** | Complete UI + telemetry | Timeline, Threat Details, Reports, Notifications, Settings; dashboards, alerting, per-agent cost/latency | S9 | All seven screens functional; dashboards live; alerts fire on induced faults; cost/latency per investigation visible. (~24) |
| **S11 — Security hardening + Red-team** | Verify invariants under attack | Injection red-team corpus, RBAC/secret audits, dependency/vuln scans, pen-test remediation | S10 | Injection corpus fails to escalate; scans clean/accepted; audit completeness proven. (~21) |
| **S12 — Production readiness** | Ship | K8s manifests, CI/CD eval+security gates, progressive rollout + rollback, staging load test, runbooks, on-call | S11 | Rollout+rollback rehearsed; SLOs met under staging load; runbooks validated; go/no-go passed. (~21) |

**Rationale.** Sprints follow the dependency order (§16); each ends demonstrable. Security and observability are embedded every sprint (not a late phase) so invariants hold continuously. XL roadmap items (RAG, Frontend) are split across sprints (S5; S9–S10) to fit squad velocity. A late hardening + readiness pair (S11–S12) verifies the whole surface before production.

---

## 18. Definition of Done

A module is **Done** only when all six criteria hold. The matrix records the module-specific bar for each. "✓" = the standard criterion applies as written; notes add module-specific requirements.

**Universal DoD (every module):** ✓ Implemented to contract · ✓ Tested (meets §12 bar for its category) · ✓ Documented (README + ADRs + this EDS updated) · ✓ Integrated (works in the assembled system, not just in isolation) · ✓ Monitored (emits logs/metrics/traces + has dashboards/alerts) · ✓ Reviewed (code + security review; standards §11 satisfied).

| Module | Module-specific "Done" additions |
|---|---|
| **Backend** | Sole-writer invariant verified; all endpoints authorized + audited; idempotency on mutations proven. |
| **Frontend** | All seven screens functional; approval UX surfaces confidence/gaps; untrusted content escaped; stream-loss recovery tested. |
| **Graph** | Routing/resume/rollback/parallel-join tested; **no path bypasses the human gate**; checkpoint reproducibility verified. |
| **Memory** | All tiers pass read/write/evict/sync/recover; session survives worker restart; knowledge tier read-only to agents. |
| **RAG** | Retrieval eval ≥ baseline; citations resolvable; freshness/trust weighting + version reproducibility verified. |
| **Prompts** | Every prompt versioned + eval-gated; shared preamble invariants present; change-control process exercised. |
| **Tools** | High-coverage unit tests; least-privilege allow-lists enforced; typed failures (no swallowed errors). |
| **Services** | Deterministic + side-effect-free where specified; score/priority calibration monitored. |
| **Database** | Migrations reversible; audit append-only + tamper-evident; soft-delete/archival/versioning policies enforced. |
| **Notifications** | No pre-approval dispatch; cross-channel failover + dead-letter proven; delivery recorded. |
| **Authentication** | RBAC boundary tests for all roles; fail-closed; MFA + rotation + session lifecycle verified; all auth events audited. |
| **Integrations** | Read-only enforced; circuit-breaker + cache-fallback + staleness-flag tested; per-integration rate limits enforced. |
| **Models** | Backward-compat or versioned migration; validators cover all boundaries; consumers updated. |
| **Configuration** | Fail-fast on invalid config; no secret leakage; env separation verified. |
| **Testing** | All CI gates active; eval thresholds set + tracked; no flaky tests in the merge lane. |
| **Deployment** | Signed images; eval+security release gates enforced; rollback rehearsed; SLOs met in staging. |

**Rationale.** "Done" explicitly includes *monitored* and *integrated* because a security platform component that isn't observable or isn't proven in the assembled system is not production-safe, regardless of unit-test status. Module-specific additions pin the invariant each module is most responsible for upholding.

---

## 19. Engineering Risks

Risks with cause, impact, likelihood, and mitigation. Likelihood/Impact are relative (Low/Med/High). Mitigations reference the mechanisms already designed above.

| # | Category | Risk | Cause | Impact | Likelihood | Mitigation |
|---|---|---|---|---|---|---|
| 1 | **Technical** | State-schema churn destabilizes agents/graph | Contracts evolve during agent build | High | Med | Contract-first (§1); versioned schemas (§3.13); build Models first (§16). |
| 2 | **Technical** | Parallel-join races/merge bugs | Concurrent CVE + enrichment sub-state writes | Med | Med | Writer-isolated sub-states + deterministic ordered merge (§5); graph tests. |
| 3 | **Architecture** | Hidden coupling erodes modularity | Cross-layer reach-arounds under deadline | High | Med | Dependency-direction rules (§11); import linting in CI; reviews. |
| 4 | **Architecture** | Agent scope creep (agents doing each other's jobs) | Ambiguous responsibilities | Med | Med | Single-responsibility agents; no lateral calls; Evaluator enforces contracts (§4). |
| 5 | **AI** | Hallucinated findings/recommendations | LLM ungrounded generation | High | Med | Mandatory RAG grounding + citations; Evaluator gate; candidate-vs-confirmed labeling (§8/§9). |
| 6 | **AI** | Confidence miscalibration → wrong triage | Poorly calibrated scoring | Med | Med | Calibration tests vs. ground truth; low-confidence routes to human (§4). |
| 7 | **AI** | Model/provider drift changes behavior | Provider/model/version updates | Med | High | Pinned versions; prompt/RAG eval gates in CI; canary investigations (§12/§13). |
| 8 | **Security** | Prompt injection via malicious log content | Untrusted data treated as instructions | High | High | Untrusted-data boundary; instruction/data separation; Evaluator injection flags; no destructive capability (§14, invariant #3). |
| 9 | **Security** | Privilege escalation / audit gaps | RBAC or audit defects | High | Low | Deny-by-default RBAC + object checks; append-only tamper-evident audit; security tests (§14). |
| 10 | **Security** | Secret leakage | Secrets in code/logs/config | High | Low | External secret store; no secrets in API/logs; scanning in CI (§11/§14). |
| 11 | **Performance** | Investigation latency under alert surge | Serial LLM/tool calls; hot bottleneck | Med | Med | Parallel fan-out; autoscale agent tier; caching; latency budgets + SLOs (§13/§15). |
| 12 | **Performance** | LLM cost overruns | Unbounded token usage | Med | Med | Per-investigation cost tracking + budget guardrails + backpressure; summarization (§13). |
| 13 | **Operational** | Missed critical alert | Notification channel failure | High | Low | Human-gated dispatch + cross-channel failover + dead-letter + ops alert (§3.10). |
| 14 | **Operational** | Third-party outage stalls investigations | NVD/VirusTotal/SIEM down | Med | Med | Circuit breakers + cache fallback + staleness flags; degrade-not-collapse (§7, invariant #6). |
| 15 | **Operational** | Bad release reaches production | Insufficient gates | High | Low | CI eval+security gates; progressive rollout + automated rollback; staging load test (§15). |
| 16 | **Maintenance** | Prompt/knowledge rot | Stale prompts/CVE corpus | Med | Med | Prompt versioning + change control; scheduled knowledge refresh; freshness weighting (§8/§9). |
| 17 | **Maintenance** | Onboarding/knowledge loss | Under-documented decisions | Med | Med | ADRs + module READMEs + this EDS as index; docs-as-code review (§11). |

**Rationale.** The two highest-likelihood/highest-impact risks (prompt injection #8, provider drift #7) are precisely the AI-specific ones, which is why the architecture makes their mitigations structural (untrusted-data boundary; eval gates) rather than procedural.

---

## 20. Implementation Checklist

Master engineering checklist — one checkbox per component/capability. Usable throughout development as the single source of "what's left." Grouped by area; a component is checked only when it meets its §18 Definition of Done.

### Foundations
- [ ] Monorepo structure (§10) + coding standards (§11) enforced in CI
- [ ] Models / schemas v1 (state, agent-IO, DTO, event, entity) + validators
- [ ] Configuration loader + feature flags + secret resolution (fail-fast)
- [ ] CI skeleton (lint → tests → build) green
- [ ] Local one-command dev stack (mocks + seeded KB)

### Backend & Auth
- [ ] API gateway + middleware pipeline (validation, logging, rate limit)
- [ ] Application services (investigation, report, notification, user, knowledge)
- [ ] Async worker runners (investigation, ingestion)
- [ ] OIDC/SSO integration + JWT issuance/rotation
- [ ] RBAC enforcement + object-level checks + auth audit
- [ ] Session management (lifecycle, timeout, revocation)

### Data
- [ ] Entity schemas + migrations (users, investigations, assets, log_events, threat_assessments, cve_findings, reports, recommendations, conversations, messages, human_decisions, notifications, audit_logs)
- [ ] Data-access layer (backend-only)
- [ ] Append-only tamper-evident audit path
- [ ] Object-store integration for raw evidence
- [ ] Soft-delete / archival / versioning policies

### Orchestration (Graph)
- [ ] Graph skeleton + node registry + shared-state reducers
- [ ] Checkpointer (persist + resume)
- [ ] Interrupt/human-gate mechanism
- [ ] Conditional routing (verdict / evaluator / human decision)
- [ ] Retry/backoff + circuit-breaker integration
- [ ] Parallel fan-out + deterministic join
- [ ] Rollback / redirect handling

### AI Layer & Memory
- [ ] Model-provider port (Claude primary) + streaming + cost/token accounting
- [ ] Secondary-model failover
- [ ] Embedding-provider port (versioned)
- [ ] Working / session (two-tier) / conversation memory managers
- [ ] Long-term / knowledge / investigation-history memory
- [ ] Summarization (lossless-by-reference)

### RAG
- [ ] Ingestion workers (NVD, MITRE, advisories, internal runbooks)
- [ ] Chunking + metadata enrichment
- [ ] pgvector index + version management
- [ ] Hybrid retriever + re-ranker (freshness/trust weighting)
- [ ] Citation binder + resolution
- [ ] Knowledge refresh scheduler + cache fallback

### Tools & Integrations
- [ ] Log connectors (files, SIEM query, Windows Event Log, syslog)
- [ ] Parsers/normalizers + entity/IoC extractor + correlator + CVSS interpreter
- [ ] NVD adapter · MITRE adapter · VirusTotal adapter · GitHub advisories adapter
- [ ] SIEM adapters (Splunk, Elastic)
- [ ] Per-adapter cache + rate limiter + circuit breaker + health probe

### Agents
- [ ] Planner
- [ ] Log Analyzer
- [ ] Threat Detector
- [ ] CVE Research
- [ ] Evaluator
- [ ] Summarizer
- [ ] Incident Reporter
- [ ] Patch Recommendation
- [ ] Human Review (human-in-the-loop node)

### Prompts
- [ ] Shared preamble (invariants) + version manifest
- [ ] Per-prompt templates (Planner, Log, Threat, Research, Reporter, Patch, Evaluator, Summarizer, Human Review)
- [ ] Prompt-eval suites wired as CI gates

### Notifications
- [ ] Slack channel + SMTP channel + templating
- [ ] Dedupe + delivery tracking
- [ ] Cross-channel failover + dead-letter + ops alert
- [ ] Post-approval-only dispatch enforced

### Frontend
- [ ] Dashboard · Investigation · Timeline · Threat Details · Reports · Notifications · Settings
- [ ] Live investigation streaming (WS/SSE)
- [ ] Human-approval panel (approve/edit/reject/redirect) with confidence/provenance
- [ ] Untrusted-content escaping + stream-loss recovery

### Observability
- [ ] Structured logging + distributed tracing across layers
- [ ] Metrics (RED per service/node; agent success/confidence; RAG; queues)
- [ ] Dashboards + SLO monitoring + alerting
- [ ] LLM usage + cost tracking + budget guardrails
- [ ] Failure analytics + canary investigations

### Security
- [ ] Prompt-injection protection (boundary + Evaluator flags + tool allow-lists)
- [ ] Encryption in transit + at rest + field-level for sensitive data
- [ ] Input sanitization + output validation at all boundaries
- [ ] Secret management (external store, rotation, no leakage)
- [ ] Red-team injection corpus + dependency/vuln scans + audit-completeness checks

### Testing & CI
- [ ] Unit / Integration / Agent / Graph suites
- [ ] Prompt-eval / RAG-eval harnesses + datasets
- [ ] Security / Performance / Regression / Acceptance suites
- [ ] CI gate chain enforced (all categories)

### Deployment
- [ ] Signed Docker images (per service)
- [ ] Kubernetes manifests (services, HPA, ingress/TLS)
- [ ] CI/CD pipeline with eval + security release gates
- [ ] Progressive rollout + automated rollback (rehearsed)
- [ ] Staging load test meeting SLOs
- [ ] Runbooks + on-call + secret injection in production

### Go-Live Gate
- [ ] All seven invariants (header) verified in the assembled system
- [ ] All modules meet §18 Definition of Done
- [ ] Security hardening pass complete (no unaccepted high risks)
- [ ] Go/no-go review passed

---

## Appendix — Consistency with Governing Documents

This EDS operationalizes `TECHNICAL_ARCHITECTURE.md` without altering it: the eight layers, five specialist agents (plus Planner/Evaluator/Summarizer/Human Review orchestration nodes), LangGraph control plane, Claude-primary pluggable model layer, Postgres+pgvector+Redis+object-store data tier, adapter-per-integration, endpoint-planning API surface, ER model, and cloud-agnostic Docker+K8s deployment are carried through unchanged. It upholds `PROJECT_CONTEXT.md`'s positioning — assistive, human-in-the-loop, assist-not-replace — as the seven inherited invariants that every module, agent, sprint, and Definition-of-Done criterion is measured against. Any proposed change that would weaken those invariants is out of scope for implementation and must be escalated as a change to the governing documents, not resolved as a local engineering trade-off.
