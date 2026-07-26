# AI Cybersecurity SOC Analyst — Sprint Implementation Roadmap

| Field | Detail |
|---|---|
| **Document Title** | Sprint Implementation Roadmap — AI Cybersecurity SOC Analyst |
| **Document Type** | Execution roadmap (sprint-by-sprint delivery plan; planning only, no code) |
| **Authored By** | Lead Software Engineer |
| **Audience** | Implementing squad (backend, AI/agents, frontend, security/platform, QA), tech lead, product |
| **Date** | 24 July 2026 |
| **Status** | Approved for execution planning |
| **Source of Truth (immutable)** | `PROJECT_CONTEXT.md` · `TECHNICAL_ARCHITECTURE.md` (SAD) · `ENGINEERING_DESIGN_SPEC.md` (EDS). This roadmap operationalizes them; it does not redesign, re-architect, or change technologies. |
| **Relationship** | Expands EDS §17 (Sprint Planning) into full per-sprint specifications, consistent with EDS §2 (Roadmap), §16 (Implementation Order), and §18 (Definition of Done). |

> **Scope & guardrails.** Planning artifact only — **no code, no SQL, no prompt text, no LangGraph code, no file contents, no new APIs.** "Database / Graph / Prompt Changes" describe *what* changes (entities, nodes, prompt assets) at the specification level. "Files/Folders Affected" references the EDS §10 monorepo folders, never file contents. Nothing here alters the architecture or stack.

### Execution Conventions (inherited from EDS — locked)

| Convention | Value |
|---|---|
| **Estimation** | Relative complexity tier (XS/S/M/L/XL) + story points (Fibonacci); **no calendar dates**. |
| **Team** | One cross-functional squad, ~4–6 engineers (Backend, AI/Agents, Frontend, Security/Platform, shared QA). |
| **Cadence** | 2-week sprints; assumed sustainable velocity ≈ 20–26 pts/sprint. |
| **Sprint contract** | Every sprint is independently buildable + testable, ends in a demonstrable working milestone, and embeds its own tests, security, observability, and docs (never deferred). |

### Inherited Invariants (must hold at every sprint's Definition of Done)

1. Human-in-the-loop for all consequential actions, recorded in tamper-evident audit. 2. Agents recommend; system never enforces. 3. All ingested content is untrusted. 4. Everything grounded and cited. 5. Deterministic control, non-deterministic reasoning. 6. Degrade, never collapse. 7. Backend is the single write boundary.

---

## Roadmap Overview

| Sprint | Name | Working Milestone | Complexity (pts) |
|---|---|---|---|
| **S1** | Foundation I — Bootstrap · Models · Config | Repo + CI + schemas + config; local stack runs | M–L (~21) |
| **S2** | Foundation II — Backend Skeleton · Auth | Secured backend; RBAC-guarded no-op endpoints | L (~24) |
| **S3** | Data + Graph Core | Persistence + audit + stub investigation runs end-to-end with checkpoint/resume | L (~24) |
| **S4** | AI Layer + Memory | Pluggable model layer with failover; tiered memory survives restart | L (~24) |
| **S5** | RAG | Grounded retrieval with citations, freshness, and cache fallback | XL (~24) |
| **S6** | Tools + Log Analyzer + Threat Detector | First two agents produce timeline + threat verdict on fixtures | L–XL (~26) |
| **S7** | CVE + Evaluator + Summarizer | Vulnerability research + grounding gate + context compression | L (~24) |
| **S8** | Reporter + Patch + Planner + Full Wiring | Full investigation runs end-to-end through the human gate | XL (~26) |
| **S9** | Notifications + Frontend I | Analyst can run, watch, and approve an investigation; human-gated alerts | XL (~26) |
| **S10** | Frontend II + Observability | All seven screens; dashboards, alerting, per-agent cost/latency live | L (~24) |
| **S11** | Security Hardening + Red-Team | Invariants verified under attack; scans clean/accepted | L (~21) |
| **S12** | Production Readiness | Cloud-agnostic deploy with eval+security gates, rollback rehearsed | L (~21) |

```mermaid
flowchart LR
    S1[S1 Foundation I] --> S2[S2 Backend+Auth]
    S2 --> S3[S3 Data+Graph core]
    S3 --> S4[S4 AI Layer+Memory]
    S4 --> S5[S5 RAG]
    S5 --> S6[S6 Log+Threat agents]
    S6 --> S7[S7 CVE+Evaluator+Summarizer]
    S7 --> S8[S8 Reporter+Patch+Planner+wiring]
    S8 --> S9[S9 Notifications+Frontend I]
    S9 --> S10[S10 Frontend II+Observability]
    S10 --> S11[S11 Security hardening]
    S11 --> S12[S12 Production readiness]
```

**Ordering rationale.** The sequence is a topological sort of the EDS §16 module dependency graph with security foundations pulled as early as possible: deterministic, auditable substrate (S1–S3) precedes any AI; grounding/memory (S4–S5) precede the knowledge-dependent agents; agents are built in data-dependency order (S6→S8); the human-facing surface (S9–S10) follows the working pipeline; hardening and production readiness (S11–S12) verify the whole surface last. Each sprint leaves the system working and demonstrable.

---

## Sprint Specifications

### Sprint 1 — Foundation I (Bootstrap · Models · Config)

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Stand up the monorepo, contracts, configuration, and CI so every downstream workstream can build against stable shapes and a running local stack. |
| **Business Objective** | De-risk the program: establish the engineering substrate and quality gates that protect a multi-million-dollar build from day one, enabling parallel, predictable delivery. |
| **Engineering Objective** | Contract-first foundation — canonical schemas, typed/validated config with secret resolution, enforced coding standards, and a green CI skeleton with a one-command local environment. |
| **Modules to Build** | Models (schemas/contracts), Configuration, Testing (skeleton), Deployment (local dev only). |
| **Files/Folders Affected** | `models/`, `config/`, `tests/`, `scripts/`, `deploy/` (local compose), `docs/` (READMEs/ADRs), repo root (CI, standards). |
| **Dependencies** | None (root sprint). |
| **Implementation Order** | 1) Repo + standards + CI skeleton → 2) Models v1 (state, agent-IO, DTO, event, entity schemas) → 3) Config loader + feature flags + secret-resolution client → 4) Local compose stack (backend/frontend placeholders, Postgres+pgvector, Redis, object store, mocks) → 5) Wire lint/test gates. |
| **Database Changes** | None yet (no persistence). Entity *schemas* defined as contracts in Models to inform S3. |
| **Graph Changes** | None. Graph-state schema shape defined in Models for S3 consumption. |
| **Prompt Changes** | None. (Prompt asset structure/version-manifest convention documented for later sprints.) |
| **Testing Required** | Schema validation/compatibility tests; config fail-fast tests; CI lint + empty-suite execution; local-stack smoke test. |
| **Acceptance Criteria** | One-command local stack runs; CI green on lint + tests; schemas validate sample payloads; invalid config fails fast at startup; secrets resolve from the store (never from files). |
| **Definition of Done** | EDS §18 universal DoD for **Models** and **Configuration** (implemented, tested, documented, integrated, monitored-where-applicable, reviewed): schemas versioned + backward-compat policy set; config validated + no secret leakage + env separation. |
| **Risks** | Under-investing in CI/standards early (EDS risk #17); schema churn later (#1) — mitigated by contract-first + versioning. |
| **Estimated Complexity** | **M–L (~21 pts).** Bootstrap M(8) + Models M(8) + Config S(5). |

### Sprint 2 — Foundation II (Backend Skeleton · Authentication)

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Establish the sole write boundary and secure every request path before any real capability exists. |
| **Business Objective** | Guarantee that the platform is secure-by-construction: no capability is ever added without identity, access control, and audit already in place — a non-negotiable for a security product. |
| **Engineering Objective** | Backend gateway + middleware pipeline and full AuthN/Z: OIDC/SSO, JWT issuance/rotation, RBAC with object-level checks, session lifecycle, and auth audit events. |
| **Modules to Build** | Backend (skeleton + middleware), Authentication. |
| **Files/Folders Affected** | `backend/` (api/, middleware/, services/ scaffolding, workers/ stub), `models/` (auth DTOs), `config/` (IdP/session settings), `tests/`. |
| **Dependencies** | S1 (Models, Config). |
| **Implementation Order** | 1) API gateway + middleware pipeline (validation, logging, rate-limit stub) → 2) OIDC/SSO integration → 3) JWT issuance/rotation + session store (Redis) → 4) RBAC policy enforcement + object-level checks → 5) Auth audit events. |
| **Database Changes** | Introduce `users` schema/handling (identity, role, sso_subject, status); session state in Redis. (Full persistence layer lands S3; users table finalized then.) |
| **Graph Changes** | None. |
| **Prompt Changes** | None. |
| **Testing Required** | RBAC boundary tests for all roles; token/session lifecycle tests (rotation, expiry, revocation); fail-closed auth tests; middleware-order tests; auth-event audit assertions. |
| **Acceptance Criteria** | Authenticated no-op endpoints pass; unauthorized/again-denied paths blocked by default; MFA enforced at IdP; all auth events audited. |
| **Definition of Done** | EDS §18 DoD for **Backend** (authorized + audited endpoints, idempotency scaffolding) and **Authentication** (RBAC all roles, fail-closed, rotation, session lifecycle, audited). |
| **Risks** | IdP integration friction; token/session edge cases (EDS risk #9); middleware security gaps — mitigated by boundary tests + deny-by-default. |
| **Estimated Complexity** | **L (~24 pts).** Backend skeleton M(8) + Auth L(8) + hardening/tests M(8). |

### Sprint 3 — Data + Graph Core

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Provide the system of record + audit substrate and a working deterministic control plane that runs a stub investigation end-to-end. |
| **Business Objective** | Establish auditability and reproducibility — the trust backbone that lets stakeholders rely on every future investigation and satisfies compliance from the outset. |
| **Engineering Objective** | Entity schemas + migrations + data-access (backend-only writer), append-only tamper-evident audit, object-store for raw evidence; LangGraph skeleton with checkpointer, interrupt, and a stub pipeline. |
| **Modules to Build** | Database, Graph (core, empty nodes). |
| **Files/Folders Affected** | `backend/` (data-access, services), `graph/` (nodes registry, routing, checkpointer, interrupts), `models/` (graph-state, entity finalization), `scripts/` (migrations), `tests/`. |
| **Dependencies** | S2 (Backend, Auth). |
| **Implementation Order** | 1) Entity schemas + reversible migrations → 2) Data-access layer (backend-only) → 3) Append-only signed audit path → 4) Object-store integration for raw evidence → 5) Graph skeleton + checkpointer → 6) Interrupt/human-gate mechanism + stub pipeline. |
| **Database Changes** | **Add all core entities** (SAD §11 / EDS §6): `investigations`, `assets`, `log_events`, `threat_assessments`, `cve_findings`, `reports`, `recommendations`, `conversations`, `messages`, `human_decisions`, `notifications`, `audit_logs`; finalize `users`. Indexes, soft-delete/archival/versioning policies applied per EDS §6. |
| **Graph Changes** | **Introduce the graph runtime**: node registry, shared-state reducers (append-and-checkpoint, writer-isolated sub-states), checkpoint-per-transition, one `interrupt` gate, a stub pipeline (ingest-seed → stub node → close). Resume + rollback scaffolding. |
| **Prompt Changes** | None. |
| **Testing Required** | CRUD + audit round-trip; migration reversibility; audit tamper-evidence; graph run of stub pipeline; checkpoint/resume; interrupt pause+resume; state-schema validation on transition. |
| **Acceptance Criteria** | Stub investigation runs end-to-end and persists; audit entries append-only + signed; graph checkpoints and resumes from last good state; interrupt pauses and resumes on a recorded decision. |
| **Definition of Done** | EDS §18 DoD for **Database** (reversible migrations, append-only tamper-evident audit, soft-delete/archival/versioning enforced) and **Graph** (routing/resume/rollback tested, no gate bypass, reproducibility). |
| **Risks** | Audit-completeness gaps; state-schema churn (EDS #1); checkpoint correctness — mitigated by round-trip tests + config-snapshot reproducibility. |
| **Estimated Complexity** | **L (~24 pts).** DB L(8) + Graph core L(13) split with tests. |

### Sprint 4 — AI Layer + Memory

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Deliver a provider-agnostic model/embedding layer with failover and the tiered memory managers agents will depend on. |
| **Business Objective** | Protect against vendor lock-in and outages (data-sovereignty + resilience) while enabling high-quality reasoning — a strategic guarantee for enterprise/regulated customers. |
| **Engineering Objective** | AI Layer: Claude-primary model port, streaming, token/cost accounting, output validation, secondary-model failover; Memory: working/session (two-tier)/conversation/long-term/knowledge/investigation managers with summarization. |
| **Modules to Build** | AI Layer (model abstraction), Memory. |
| **Files/Folders Affected** | `agents/shared/` (model/embedding ports), `memory/`, `services/` (summarization hook), `config/` (provider/model settings), `models/` (memory contracts), `tests/`. |
| **Dependencies** | S3 (Data, Graph) for durable memory + checkpoints; S1 config. |
| **Implementation Order** | 1) Model-provider port (Claude primary) + streaming + cost/token metrics → 2) Output validation + secondary-model failover → 3) Embedding-provider port (versioned) → 4) Working + two-tier session memory → 5) Conversation/long-term/knowledge/investigation managers → 6) Summarization (lossless-by-reference). |
| **Database Changes** | Memory durability uses existing tables (session→Postgres durable tier, conversation, long-term/history). No new entities; add history indexes (asset/IoC/technique/CVE) per EDS §7. |
| **Graph Changes** | Graph nodes gain access to memory + AI layer via interfaces (no new nodes yet). |
| **Prompt Changes** | None (summarization prompt asset *contract* stubbed; text authored in S7 with Summarizer). |
| **Testing Required** | Provider-swap-via-config test; induced-failure failover test; cost/token metric emission; memory read/write/evict/sync/recover; session survives worker restart; summary ID/provenance retention. |
| **Acceptance Criteria** | Model provider swaps by config with no caller change; failover triggers on induced fault; memory tiers pass lifecycle tests; session recovers after restart; knowledge tier is read-only to agents. |
| **Definition of Done** | EDS §18 DoD for **AI Layer/Models port** and **Memory** (all tiers pass read/write/evict/sync/recover; restart survival; knowledge read-only). |
| **Risks** | Provider quirks leaking through the abstraction (EDS #7); hot/durable sync bugs — mitigated by contract tests + durable-as-source-of-truth. |
| **Estimated Complexity** | **L (~24 pts).** AI Layer L(8) + Memory M(8) + failover/summarization M(8). |

### Sprint 5 — RAG

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Deliver grounded retrieval with citations, freshness/trust weighting, versioning, and cache fallback — the substrate that makes agent findings trustworthy. |
| **Business Objective** | Ensure every future finding is grounded and cited (analyst trust + defensibility), and that vulnerability knowledge is current — directly reducing risk of wrong or stale conclusions. |
| **Engineering Objective** | Full RAG pipeline: ingestion workers, boundary-aware chunking, metadata enrichment, pgvector index with versioning, hybrid retriever, re-ranker (freshness/trust), citation binder, refresh scheduler, cache fallback. |
| **Modules to Build** | RAG. |
| **Files/Folders Affected** | `rag/`, `integrations/` (NVD/MITRE/advisories ingest adapters — read paths), `backend/workers/` (ingestion runners), `config/` (sources/trust tiers), `tests/` (RAG eval + datasets). |
| **Dependencies** | S4 (AI Layer embeddings, Memory knowledge tier), S3 (pgvector via data layer). |
| **Implementation Order** | 1) Ingestion workers (NVD, MITRE, advisories, internal runbooks) → 2) Chunking + metadata enrichment → 3) pgvector index + version management → 4) Hybrid retriever (dense+keyword+filters) → 5) Re-ranker (freshness/trust) → 6) Citation binder + resolution → 7) Refresh scheduler + cache fallback. |
| **Database Changes** | Knowledge index (pgvector) + chunk metadata in Postgres; index-version tracking. No investigation entities changed. |
| **Graph Changes** | None (agents consume RAG via interface in later sprints). |
| **Prompt Changes** | None (grounded-generation discipline is enforced in agent prompts S6–S8; here the retrieval contract + citation binding are built). |
| **Testing Required** | Retrieval eval (precision/recall on labeled security-question set); citation-resolution tests; freshness/trust weighting tests; index-version reproducibility; cache-fallback + staleness-flag tests; ingestion isolation per source. |
| **Acceptance Criteria** | Retrieval eval meets baseline; citations resolve to sources; freshness/trust weighting verified; live→cache fallback flags staleness; retrieval records index version for reproducibility. |
| **Definition of Done** | EDS §18 DoD for **RAG** (retrieval eval ≥ baseline, citations resolvable, freshness/trust + version reproducibility). |
| **Risks** | Retrieval quality; embedding/version drift (EDS #7/#16) — mitigated by eval gates + pinned versions + refresh. |
| **Estimated Complexity** | **XL split to fit (~24 pts).** RAG XL(13) decomposed across ingestion/index/retriever/eval. |

### Sprint 6 — Tools + Log Analyzer + Threat Detector

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Build the deterministic agent tools and the first two agents, producing a correlated timeline and a threat verdict from real fixtures. |
| **Business Objective** | Deliver the first tangible SOC value — turning raw logs into an assessed threat — proving the core investigative capability the product exists to provide. |
| **Engineering Objective** | Tools (parsers/connectors/extractors/CVSS/correlator) + Log Analyzer and Threat Detector agent nodes with validated I/O, enrichment adapters, RAG use, retry/fallback, and confidence scoring. |
| **Modules to Build** | Tools, Integrations (log sources + VirusTotal/MITRE enrichment), Agents (Log Analyzer, Threat Detector). |
| **Files/Folders Affected** | `tools/`, `integrations/` (log connectors, VirusTotal, MITRE), `agents/log_analyzer/`, `agents/threat_detector/`, `agents/shared/` (schemas/guardrails), `prompts/`, `graph/` (two nodes), `tests/` (fixtures). |
| **Dependencies** | S5 (RAG), S4 (AI Layer, Memory), S3 (Graph). |
| **Implementation Order** | 1) Tools (log parsers/normalizers, entity/IoC extractor, correlator, CVSS interpreter) → 2) Integration adapters (log sources; VirusTotal, MITRE) with cache/breaker/rate-limit → 3) Log Analyzer node + prompt + schema → 4) Threat Detector node + prompt + schema → 5) Wire both into the graph (Log→Threat). |
| **Database Changes** | Populate `log_events` (normalized evidence, provenance, `raw_ref`) and `threat_assessments` (verdict/IoCs/techniques/severity/confidence); `assets` linkage. |
| **Graph Changes** | **Add Log Analyzer and Threat Detector nodes**; sequential edge Log→Threat; benign vs. threat routing stub after Threat verdict; enrichment tool calls with circuit breakers. |
| **Prompt Changes** | **Author Log Agent and Threat Agent prompts** (per EDS §9 contracts): Log = "structure only, no threat inference," provenance required; Threat = evidence/inference separation, no fabricated reputation, escalate ambiguity. Shared preamble applied. |
| **Testing Required** | Golden-fixture agent tests across log formats; correlation accuracy; verdict/severity calibration vs. ground truth; degraded-enrichment path; injection cases in log content; tool unit tests. |
| **Acceptance Criteria** | Fixtures produce provenance-tagged timeline + coverage gaps; verdict/severity within calibrated tolerance; enrichment-degraded path flagged with lowered confidence; malformed records quarantined not dropped. |
| **Definition of Done** | EDS §18 DoD for **Tools** (least-privilege allow-lists, typed failures), **Integrations** (read-only, breaker+cache+staleness), and the two **Agents** (fixture pass, guardrails, calibration). |
| **Risks** | Log-format diversity + correlation accuracy; enrichment variability; confidence miscalibration (EDS #6) — mitigated by golden fixtures + calibration tests. |
| **Estimated Complexity** | **L–XL (~26 pts).** Tools/Integrations M(8) + Log L(8) + Threat L(8). |

### Sprint 7 — CVE Research + Evaluator + Summarizer

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Add vulnerability research, the grounding/quality gate, and context compression — completing the evidence + control agents feeding synthesis. |
| **Business Objective** | Connect threats to known vulnerabilities with cited severity, and guarantee output quality (no hallucinations) before anything reaches an analyst — protecting decision integrity. |
| **Engineering Objective** | CVE Research agent (NVD + corpus, applicability, citations); Evaluator (schema/citation/hallucination/injection checks); Summarizer (lossless-by-reference). |
| **Modules to Build** | Agents (CVE Research, Evaluator, Summarizer), Integrations (NVD, GitHub advisories). |
| **Files/Folders Affected** | `agents/cve_research/`, `agents/shared/` (Evaluator, Summarizer), `integrations/` (NVD, GitHub advisories), `prompts/`, `graph/` (three nodes), `tests/`. |
| **Dependencies** | S6 (Threat Detector output, Tools), S5 (RAG), S4 (AI/Memory). |
| **Implementation Order** | 1) NVD + GitHub advisory adapters → 2) CVE Research node + prompt + applicability logic + citation enforcement → 3) Evaluator node + prompt (adversarial checks) → 4) Summarizer node + prompt (ID retention) → 5) Wire Evaluator as grounding gate post-research. |
| **Database Changes** | Populate `cve_findings` (CVE id, CVSS, applicability confirmed vs. candidate, exploit mapping, citations, source freshness); versioned on re-run. |
| **Graph Changes** | **Add CVE Research, Evaluator, Summarizer nodes.** Conditional routing on Evaluator verdict (pass→advance; needs-revision→bounded re-run; escalate→human). Summarizer invoked when context exceeds budget. |
| **Prompt Changes** | **Author Research, Evaluator, Summarizer prompts** (EDS §9): Research = cite every claim, no CVE without version evidence, confirmed vs. candidate; Evaluator = reject un-sourced/unsupported, flag injection, default-escalate on own failure; Summarizer = no new claims, retain IDs/provenance. |
| **Testing Required** | Known-CVE applicability fixtures; live→cache fallback; citation-enforcement; **adversarial Evaluator corpus** (hallucinations, missing citations, injected instructions) must be rejected; summarizer ID-retention + no-new-claim tests. |
| **Acceptance Criteria** | CVE applicability confirmed vs. candidate correct; all claims cited; Evaluator blocks adversarial fixtures and never silently passes; summaries preserve IDs and remain resolvable to raw evidence. |
| **Definition of Done** | EDS §18 DoD for the three **Agents** (fixture pass, guardrails, calibration) + **Integrations** (NVD/GitHub read-only + resilience). |
| **Risks** | CVE applicability false positives; Evaluator over/under-blocking (EDS #4/#5) — mitigated by labeled fixtures + adversarial corpus + calibration. |
| **Estimated Complexity** | **L (~24 pts).** CVE L(8) + Evaluator/Summarizer M(5) + integrations/tests. |

### Sprint 8 — Reporter + Patch + Planner + Full Wiring

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Complete the agent pipeline and wire the full investigation graph — benign and threat paths — through the mandatory human approval gate. |
| **Business Objective** | Deliver the end-to-end product promise: an incident investigated from log to human-reviewed report and prioritized remediation, with the analyst in control. |
| **Engineering Objective** | Incident Reporter + Patch Recommendation agents; Planner; conditional routing; parallel CVE/enrichment fan-out + deterministic join; human-approval interrupts wired to the backend. |
| **Modules to Build** | Agents (Incident Reporter, Patch Recommendation, Planner, Human Review node), Graph (full wiring). |
| **Files/Folders Affected** | `agents/incident_reporter/`, `agents/patch_recommender/`, `agents/` (Planner, Human Review), `services/` (severity/risk prioritization), `graph/` (routing, parallel join, interrupts), `backend/` (human-gate endpoints per SAD §12), `prompts/`, `tests/`. |
| **Dependencies** | S7 (CVE, Evaluator, Summarizer), S6 (Log, Threat), S3 (Graph), S2 (human-gate auth). |
| **Implementation Order** | 1) Incident Reporter node + prompt + report/timeline assembler + citation compiler → 2) Patch Recommendation node + prompt + risk prioritizer + advisory lookups → 3) Planner node + prompt (path selection) → 4) Conditional routing + parallel fan-out (CVE + enrichment) + deterministic join → 5) Human Review interrupt gates wired to backend approval endpoints → 6) Evaluator final quality gate before human. |
| **Database Changes** | Populate `reports` (exec+technical, citations, versioned, regenerable) and `recommendations` (action/type/priority/rationale/citations/approval_status); `conversations`/`messages`/`human_decisions` on the gate. |
| **Graph Changes** | **Complete the graph**: add Reporter, Patch, Planner, Human Review nodes; Planner→Log→Threat→(benign close | parallel CVE+enrichment→join→Evaluator→Reporter→Patch→Evaluator→Human gate→Notify stub→close). Rollback/redirect (human "redirect"→Planner). No path reaches a consequential action without traversing the gate. |
| **Prompt Changes** | **Author Reporter, Patch, Planner, Human Review prompts** (EDS §9): Reporter = only supported claims, mark gaps, no new findings; Patch = for human approval, no destructive automation, justify+cite; Planner = plan from evidence, never skip gate; Human Review = neutral presentation, capture decision+rationale. |
| **Testing Required** | Full benign + threat end-to-end runs; parallel-join determinism; human gate pause/resume/redirect; graph routing branches; report supported-claims-only + regenerate-from-state; patch prioritization + no-destructive-action; **no-gate-bypass** test. |
| **Acceptance Criteria** | A full investigation runs both paths; parallel join merges correctly; human gate pauses and resumes on a recorded, authorized decision; redirect re-enters Planner; recommendations flagged requires-human-approval; no consequential action reachable pre-approval. |
| **Definition of Done** | EDS §18 DoD for **Reporter/Patch/Planner/Human Review agents** and **Graph** (no gate bypass, resume/rollback/parallel-join tested). |
| **Risks** | Routing/branch bugs; join races (EDS #2); hallucinated findings (#5, mitigated by Evaluator); over-broad recommendations — mitigated by graph tests + Evaluator gate. |
| **Estimated Complexity** | **XL (~26 pts).** Reporter M(5) + Patch M(5) + Planner/wiring L(8) + gates/tests M(8). |

### Sprint 9 — Notifications + Frontend I

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Deliver human-gated outbound alerting and the core analyst UI so an analyst can run, watch, and approve an investigation. |
| **Business Objective** | Put the product in analysts' hands: the first usable workflow that reduces investigation time and keeps humans in control, with reliable high-priority alerting. |
| **Engineering Objective** | Notifications (Slack/SMTP, dedupe, delivery tracking, cross-channel failover, post-approval-only dispatch); Frontend core (Dashboard, Investigation screen, approval panel, live streaming). |
| **Modules to Build** | Notifications, Frontend (core screens + realtime + approval UX). |
| **Files/Folders Affected** | `backend/services/` (notification dispatch), `integrations/` (Slack, SMTP), `frontend/src/pages/` (Dashboard, Investigation), `frontend/src/realtime/`, `frontend/src/components/` (approval panel), `tests/`. |
| **Dependencies** | S8 (working human-gated pipeline), S2 (auth for UI + human-gate endpoints). |
| **Implementation Order** | 1) Slack + SMTP channel adapters + templating → 2) Dedupe + delivery tracking → 3) Cross-channel failover + dead-letter + ops alert → 4) Post-approval-only dispatch enforcement → 5) Frontend Dashboard + Investigation screen → 6) Live streaming (WS/SSE) + approval panel (approve/edit/reject/redirect). |
| **Database Changes** | Populate `notifications` (channel/recipient/status/attempts, linked approval). Enforce "requires linked approval" at write. |
| **Graph Changes** | Replace the S8 Notify stub with the real notification dispatch node — **reachable only after the human approval gate**. |
| **Prompt Changes** | None (notification templates are deterministic, not prompts). |
| **Testing Required** | No-pre-approval-dispatch test; Slack→email failover; delivery recording; dead-letter + ops alert; frontend interaction + approval-flow tests; stream-loss reconnect/reconcile; untrusted-content escaping in UI. |
| **Acceptance Criteria** | No notification sent before approval; failover verified; delivery recorded; an analyst can trigger, watch live, and approve/redirect an investigation with confidence/provenance visible. |
| **Definition of Done** | EDS §18 DoD for **Notifications** (post-approval dispatch, failover, dead-letter, delivery recorded) and **Frontend** (core screens, approval UX, escaping, stream recovery). |
| **Risks** | Missed critical alerts on channel failure (EDS #13); real-time UX complexity — mitigated by failover + dead-letter + reconnect logic. |
| **Estimated Complexity** | **XL (~26 pts).** Notifications M(5) + Frontend core XL(13) split + streaming/approval M(8). |

### Sprint 10 — Frontend II + Observability

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Complete the analyst workspace and stand up production-grade telemetry, including per-agent cost/latency. |
| **Business Objective** | Full analyst self-sufficiency plus operational and cost visibility — enabling SOC efficiency gains to be measured and LLM spend to be controlled. |
| **Engineering Objective** | Remaining screens (Timeline, Threat Details, Reports, Notifications, Settings) and the observability stack (dashboards, alerting, per-agent latency/cost, LLM usage, failure analytics, canaries). |
| **Modules to Build** | Frontend (remaining screens), Observability. |
| **Files/Folders Affected** | `frontend/src/pages/` (Timeline, Threat Details, Reports, Notifications, Settings), `frontend/src/components/`, cross-cutting observability in `backend/`, `graph/`, `agents/`, `rag/`, `integrations/`; `deploy/` (dashboards/alerts config), `tests/`. |
| **Dependencies** | S9 (Frontend core, working pipeline), S4 (cost/token metrics from AI Layer). |
| **Implementation Order** | 1) Timeline + Threat Details screens → 2) Reports (view/export/version) + Notifications screens → 3) Settings (integrations, channels/policies, model/provider, users/roles, auto-approval policy) → 4) Structured logging + tracing across layers → 5) Metrics (RED per service/node, agent success/confidence, RAG, queues) → 6) Dashboards + SLO monitoring + alerting → 7) LLM usage/cost tracking + budget guardrails + canary investigations. |
| **Database Changes** | None (reads existing data). Export/audit of report exports recorded. |
| **Graph Changes** | Instrument nodes with tracing spans + per-node latency/cost metrics (no structural change). |
| **Prompt Changes** | None. |
| **Testing Required** | Remaining-screen interaction tests; export tests; dashboard/alert wiring verified by induced faults; per-investigation cost/latency visibility; canary-investigation execution; budget-guardrail backpressure. |
| **Acceptance Criteria** | All seven screens functional; dashboards live; alerts fire on induced faults; cost/latency per investigation and per agent visible; canary investigations run; budget guardrails engage. |
| **Definition of Done** | EDS §18 DoD for **Frontend** (all screens) and **Observability** (logs/metrics/traces, dashboards/alerts, LLM cost, failure analytics, canaries). |
| **Risks** | Alert fatigue; metric/trace gaps; LLM cost overruns (EDS #12) — mitigated by tuned alerts + cost guardrails + canaries. |
| **Estimated Complexity** | **L (~24 pts).** Frontend remainder L(8) + Observability M(8) + cost/canary M(8). |

### Sprint 11 — Security Hardening + Red-Team

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Verify every security invariant under adversarial conditions before production. |
| **Business Objective** | Provide assurance that the security platform is itself secure — resistant to prompt injection and conventional attack — protecting customers and the organization's reputation. |
| **Engineering Objective** | Prompt-injection red-team suite; RBAC/secret audits; dependency/vuln scans; encryption + input-sanitization + output-validation verification; audit-completeness proof; remediation of findings. |
| **Modules to Build** | Security hardening across all modules (no new module); Testing (red-team corpus, scans). |
| **Files/Folders Affected** | `tests/` (injection corpus, security suites), `agents/shared/` (guardrail hardening), `backend/middleware/` (sanitization/validation), `integrations/` (egress controls), `config/`/secrets, `deploy/` (scan gates). |
| **Dependencies** | S1–S10 (whole surface must exist to attack). |
| **Implementation Order** | 1) Prompt-injection red-team corpus against log-borne payloads → 2) RBAC boundary + object-level audits → 3) Secret-handling audit (no leakage in code/logs/API) → 4) Encryption in-transit/at-rest/field-level verification → 5) Input-sanitization + output-validation verification at all boundaries → 6) Dependency/vuln scans → 7) Audit-completeness checks → 8) Remediate findings. |
| **Database Changes** | None structural; verify encryption-at-rest + audit immutability/tamper-evidence. |
| **Graph Changes** | None structural; verify no agent can trigger irreversible actions and Evaluator flags injected instructions. |
| **Prompt Changes** | Harden guardrails only (tighten instruction/data separation, injection resistance) — no new prompts; changes go through prompt-eval gates. |
| **Testing Required** | Injection corpus must fail to escalate to any action; RBAC boundary tests; secret-leakage tests; encryption tests; sanitization/validation tests; dependency/vuln scan; audit-completeness assertions; pen-test remediation verification. |
| **Acceptance Criteria** | Injection corpus cannot escalate to action; scans clean or risk-accepted; RBAC/secret/encryption verified; audit provably complete; all high findings remediated. |
| **Definition of Done** | EDS §18 DoD for **Security** posture across modules + **Testing** (red-team + scans active as gates); invariants #1–#7 verified under attack. |
| **Risks** | Undiscovered injection vectors (EDS #8, highest); privilege/audit gaps (#9) — mitigated by adversarial corpus + structural no-destructive-capability guarantee. |
| **Estimated Complexity** | **L (~21 pts).** Red-team L(8) + audits/scans M(8) + remediation S(5). |

### Sprint 12 — Production Readiness

| Attribute | Specification |
|---|---|
| **Sprint Goal** | Ship a cloud-agnostic, production-ready application with enforced release gates and rehearsed rollback. |
| **Business Objective** | Go live safely: deliver the platform to production with the operational guarantees (SLOs, rollback, runbooks) an enterprise security service requires. |
| **Engineering Objective** | Kubernetes manifests, CI/CD with eval+security release gates, progressive rollout + automated rollback, secret injection, staging load test meeting SLOs, runbooks, on-call. |
| **Modules to Build** | Deployment; production wiring of Observability + Security gates. |
| **Files/Folders Affected** | `deploy/` (Dockerfiles, K8s manifests, CI/CD pipeline, rollout/rollback), `config/` (prod profiles), `scripts/` (migrations/seed), `docs/` (runbooks), `tests/` (load scenarios). |
| **Dependencies** | S1–S11 (all modules built, tested, observable, hardened). |
| **Implementation Order** | 1) Signed multi-stage Docker images per service → 2) K8s manifests (services, HPA on backend + graph/RAG workers, ingress/TLS, HA data stores) → 3) CI/CD gates (lint→tests→prompt/RAG evals→security scans→signed image→progressive rollout) → 4) Automated rollback on failed health/SLO gates → 5) Secret injection + rotation in prod → 6) Staging load test to SLOs → 7) Runbooks + on-call → 8) Go/no-go review. |
| **Database Changes** | Production migration + seeding runbooks; HA + backup/restore + retention/archival verified in prod config. |
| **Graph Changes** | None structural; verify checkpoint durability + resume in the production topology. |
| **Prompt Changes** | Pin prompt versions for the release; prompt-eval gate enforced in CI/CD. |
| **Testing Required** | Rollout + rollback rehearsal in staging; load/throughput test vs. SLOs (incl. surge + degradation-under-outage); eval + security gates enforced in pipeline; backup/restore drill; runbook validation. |
| **Acceptance Criteria** | Progressive deploy + automated rollback rehearsed; SLOs met under staging load; eval/security gates block bad releases; backup/restore verified; runbooks validated; go/no-go passed. |
| **Definition of Done** | EDS §18 DoD for **Deployment** (signed images, eval+security gates, rehearsed rollback, SLOs in staging) + the Go-Live gate: all seven invariants verified in the assembled system, all modules at DoD, no unaccepted high risks. |
| **Risks** | Rollout/rollback correctness; capacity (EDS #15/#11) — mitigated by rehearsal + load test + automated rollback. |
| **Estimated Complexity** | **L (~21 pts).** K8s/CI-CD L(8) + rollout/rollback M(8) + load/runbooks S(5). |

---

## Recommended First Sprint

**Recommendation: begin with Sprint 1 — Foundation I (Bootstrap · Models · Config).**

**Why it must be built first:**

1. **It is the dependency root.** Every other sprint depends, directly or transitively, on the canonical **Models/contracts**, typed **Configuration**, and **CI**. Per EDS §16 Implementation Order, Models is built first — even before the backend — precisely because all layers depend inward on those shapes (clean architecture / dependency inversion). Starting anywhere else means building against shapes that don't yet exist and reworking them later.

2. **It unlocks parallelism for the whole squad.** Once the schemas and config exist, the squad's workstreams (backend, AI/agents, frontend, security/platform) can proceed against stable contracts without blocking each other. Contract-first is the mechanism that lets a small ~4–6 engineer squad work concurrently rather than serially — this sprint is what activates it.

3. **It establishes the trustworthy substrate before any AI.** The architecture's core principle is a deterministic, auditable control plane around non-deterministic reasoning. Foundation I lays the deterministic groundwork (validated contracts, fail-fast config, secret resolution, enforced standards, green CI, a runnable local stack) so that when agents arrive (S6+), they are built on ground that is already safe, reproducible, and testable — never the reverse.

4. **It is low-dependency and de-risks the program early.** With no upstream dependencies, it can start immediately and its deliverables (CI gates, coding standards, schema-versioning discipline) directly mitigate the two most corrosive slow risks — schema churn (EDS risk #1) and knowledge/quality erosion (#17) — from day one.

5. **It produces a real, demonstrable milestone.** At sprint end the team can run a one-command local stack, watch CI enforce standards, and validate payloads against versioned schemas — a working foundation, consistent with the "every sprint ends demonstrable" contract, not just scaffolding.

Building Foundation I first is therefore not merely conventional — it is the only ordering consistent with the architecture's dependency direction and its deterministic-substrate-before-AI principle. Every later sprint (S2→S12) becomes safe, parallelizable, and testable *because* this one comes first.

---

## Appendix — Consistency with the Governing Documents

This roadmap operationalizes the immutable trilogy without altering it. The 12 sprints map 1:1 to **EDS §17** (S1–S12) and follow **EDS §16** Implementation Order and **EDS §2** phases; each sprint's Definition of Done references **EDS §18** (universal + module-specific DoD); "Database / Graph / Prompt Changes" align with **EDS §6 / §5 / §9** and the **SAD §11 / §4 / §2** specifications; "Files/Folders Affected" reference the **EDS §10** monorepo map. The seven inherited invariants (from **PROJECT_CONTEXT.md** positioning and **SAD Appendix A**) are conditions on every sprint's completion — no sprint is Done if it weakens them. No architecture, technology, agent, or interface has been added, removed, or changed; this document is purely an execution sequencing of what the trilogy already specifies. Any proposed deviation must be escalated as a change to the governing documents, not resolved inside this roadmap.
