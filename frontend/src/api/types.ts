/**
 * The API contract, as the client sees it.
 *
 * Hand-written mirrors of `backend/api/schemas/`. They are deliberately narrow:
 * the client declares only the fields it renders, so a backend addition is not a
 * breaking change here, while a *removal* surfaces as a type error the moment
 * anything reads it.
 *
 * Note what is absent from `Recommendation` — there is no field a client could
 * read an executable out of, exactly as there is none on the stored row or in
 * the response model. The shape is the guarantee, and it is worth restating at
 * every layer that touches it (invariant #2).
 */

export type UserRole = 'analyst' | 'senior_analyst' | 'manager' | 'admin' | 'auditor'

export type Capability =
  | 'view_investigations'
  | 'run_investigations'
  | 'approve_actions'
  | 'view_audit'
  | 'manage_users'
  | 'configure'

export type InvestigationStatus =
  | 'open'
  | 'in_progress'
  | 'awaiting_approval'
  | 'closed'
  | 'archived'

export type Severity = 'info' | 'low' | 'medium' | 'high' | 'critical'
export type TriagePriority = 'low' | 'medium' | 'high' | 'urgent'
export type Verdict = 'benign' | 'suspicious' | 'malicious'
export type EnrichmentStatus = 'complete' | 'degraded' | 'unavailable'
export type CveApplicability = 'confirmed' | 'candidate' | 'not_applicable'
export type ReportStatus = 'draft' | 'final'
export type ApprovalStatus = 'pending' | 'approved' | 'rejected' | 'edited'
export type DecisionType = 'approve' | 'edit' | 'reject' | 'redirect'
export type TriggerSource = 'analyst' | 'alert' | 'scheduled'
export type NotificationChannel = 'slack' | 'email' | 'webhook'
export type NotificationStatus = 'pending' | 'sent' | 'failed' | 'dead_letter'

export interface Citation {
  source_id: string
  source: string
  url: string | null
  title: string | null
  trust_tier: string | null
  published_at: string | null
}

export interface Profile {
  id: string
  email: string
  name: string
  role: UserRole
}

export interface Capabilities {
  role: UserRole
  capabilities: Capability[]
}

export interface PipelineStage {
  name: string
  label: string
  complete: boolean
  skipped: boolean
  detail: string | null
}

export interface InvestigationSummary {
  id: string
  title: string | null
  status: InvestigationStatus
  severity: Severity | null
  trigger_source: TriggerSource
  verdict: Verdict | null
  triage_priority: TriagePriority | null
  confidence: number | null
  pending_approvals: number
  created_at: string
  updated_at: string
  closed_at: string | null
}

export interface InvestigationPage {
  items: InvestigationSummary[]
  total: number
  limit: number
  offset: number
}

export interface InvestigationSnapshot {
  id: string
  status: InvestigationStatus
  severity: Severity | null
  verdict: Verdict | null
  triage_priority: TriagePriority | null
  confidence: number | null
  awaiting_human: boolean
  pipeline: PipelineStage[]
  event_count: number
  cve_count: number
  recommendation_count: number
  pending_approvals: number
  report_version: number
  updated_at: string
}

export interface InvestigationDetail {
  id: string
  title: string | null
  summary: string | null
  status: InvestigationStatus
  severity: Severity | null
  trigger_source: TriggerSource
  owner_id: string | null
  snapshot: InvestigationSnapshot
  created_at: string
  updated_at: string
  closed_at: string | null
}

export interface TimelineEvent {
  id: string
  event_time: string
  source: string
  event_type: string
  actor: string | null
  notability: number
  raw_ref: string | null
  provenance: Record<string, unknown>
}

export interface TimelineResponse {
  investigation_id: string
  events: TimelineEvent[]
  truncated: boolean
}

export interface ThreatIndicator {
  type: string
  value: string
  defanged: string | null
  reputation: string | null
  source: string | null
  enriched: boolean
  internal: boolean
  observation_count: number
}

export interface ThreatTechnique {
  technique_id: string
  name: string | null
  tactics: string[]
  rationale: string | null
  confidence: number | null
  citations: Citation[]
}

export interface ThreatAssessment {
  id: string
  investigation_id: string
  verdict: Verdict
  severity: Severity
  triage_priority: TriagePriority
  enrichment_status: EnrichmentStatus
  confidence: number
  rationale: string | null
  indicators: ThreatIndicator[]
  techniques: ThreatTechnique[]
  version: number
  created_at: string
}

export interface CveFinding {
  id: string
  cve_id: string
  applicability: CveApplicability
  summary: string | null
  cvss: { score?: number; vector?: string; severity?: string; narrative?: string } | null
  exploit_mapping: Record<string, unknown>[]
  citations: Citation[]
  source_freshness: string | null
  version: number
}

export interface CveFindings {
  investigation_id: string
  /** Whether research ran at all — distinct from having found nothing. */
  researched: boolean
  findings: CveFinding[]
  version: number
}

export interface Report {
  id: string
  investigation_id: string
  executive_summary: string
  technical_body: string
  citations: Citation[]
  status: ReportStatus
  version: number
  created_at: string
}

export interface ReportVersionRef {
  id: string
  version: number
  status: ReportStatus
  created_at: string
}

export interface ReportHistory {
  investigation_id: string
  versions: ReportVersionRef[]
}

export interface Recommendation {
  id: string
  investigation_id: string
  action: string
  type: 'patch' | 'configuration' | 'mitigation' | 'other'
  priority: TriagePriority
  rationale: string
  expected_impact: string | null
  citations: Citation[]
  approval_status: ApprovalStatus
  requires_human_approval: boolean
  version: number
  created_at: string
}

export interface Recommendations {
  investigation_id: string
  recommendations: Recommendation[]
  version: number
}

export interface PendingApproval {
  kind: string
  id: string
  investigation_id: string
  title: string
  priority: TriagePriority | null
  confidence: number | null
  rationale: string | null
}

export interface PendingApprovals {
  investigation_id: string
  /** Separate from the item list: a paused gate with an empty plan is still work. */
  gate_open: boolean
  items: PendingApproval[]
}

export interface GateDecisionResult {
  investigation_id: string
  decision: DecisionType
  status: InvestigationStatus
  awaiting_human: boolean
  recorded_at: string
  /** Always false. Approval authorizes work; it does not perform it. */
  executed: boolean
  /** Queued, not delivered: dispatch runs behind the response. */
  notification_queued: boolean
}

export interface NotificationRecord {
  id: string
  investigation_id: string
  /** Non-optional: the column is NOT NULL, so an unapproved alert cannot exist. */
  approval_id: string
  channel: NotificationChannel
  recipient: string
  priority: TriagePriority
  status: NotificationStatus
  delivery_attempts: number
  /** Why the last attempt failed. A dead letter with no reason is unactionable. */
  failure_reason: string | null
  sent_at: string | null
  created_at: string
}

export interface NotificationPage {
  items: NotificationRecord[]
  total: number
  limit: number
  offset: number
  /** Counted across the whole table: an undelivered queue is a standing fact. */
  dead_lettered: number
}

export interface RetryResult {
  notification_id: string
  channel: NotificationChannel
  delivered: boolean
  attempts: number
  detail: string
  status: NotificationStatus
}

export interface TokenPair {
  access_token: string
  token_type: string
  expires_in: number
  refresh_token: string
}
