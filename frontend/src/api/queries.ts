/**
 * Server state, addressed by query key.
 *
 * The client caches; the server decides. Every mutation invalidates the reads it
 * could have changed rather than patching the cache optimistically, because on
 * this console an optimistic write would mean showing an approval that the
 * backend has not recorded — and the whole point of the human gate is that the
 * record is what happened (invariant #1).
 */

import { useMutation, useQuery, useQueryClient } from '@tanstack/react-query'
import type { UseMutationResult, UseQueryResult } from '@tanstack/react-query'

import type { ApiClient } from './client'
import type {
  ApprovalStatus,
  Capabilities,
  CveFindings,
  DecisionType,
  GateDecisionResult,
  InvestigationDetail,
  InvestigationPage,
  InvestigationStatus,
  NotificationPage,
  NotificationStatus,
  PendingApprovals,
  Profile,
  Recommendation,
  Recommendations,
  Report,
  ReportHistory,
  RetryResult,
  Severity,
  TimelineResponse,
} from './types'

export const keys = {
  profile: ['profile'] as const,
  capabilities: ['capabilities'] as const,
  investigations: (filters: InvestigationFilters) => ['investigations', filters] as const,
  investigation: (id: string) => ['investigation', id] as const,
  timeline: (id: string) => ['investigation', id, 'timeline'] as const,
  threat: (id: string) => ['investigation', id, 'threat'] as const,
  cves: (id: string) => ['investigation', id, 'cves'] as const,
  report: (id: string, version?: number) => ['investigation', id, 'report', version ?? 0] as const,
  reportHistory: (id: string) => ['investigation', id, 'report', 'history'] as const,
  recommendations: (id: string) => ['investigation', id, 'recommendations'] as const,
  approvals: (id: string) => ['investigation', id, 'approvals'] as const,
  notifications: (filters: NotificationFilters) => ['notifications', filters] as const,
}

export interface InvestigationFilters {
  status?: InvestigationStatus
  severity?: Severity
  mine?: boolean
}

function queryString(filters: InvestigationFilters): string {
  const params = new URLSearchParams()
  if (filters.status) params.set('status', filters.status)
  if (filters.severity) params.set('severity', filters.severity)
  if (filters.mine) params.set('mine', 'true')
  const encoded = params.toString()
  return encoded ? `?${encoded}` : ''
}

export function useProfile(client: ApiClient): UseQueryResult<Profile> {
  return useQuery({ queryKey: keys.profile, queryFn: () => client.get<Profile>('/auth/me') })
}

export function useCapabilities(client: ApiClient): UseQueryResult<Capabilities> {
  return useQuery({
    queryKey: keys.capabilities,
    queryFn: () => client.get<Capabilities>('/system/capabilities'),
  })
}

export function useInvestigations(
  client: ApiClient,
  filters: InvestigationFilters = {},
): UseQueryResult<InvestigationPage> {
  return useQuery({
    queryKey: keys.investigations(filters),
    queryFn: () => client.get<InvestigationPage>(`/investigations${queryString(filters)}`),
  })
}

export function useInvestigation(
  client: ApiClient,
  id: string,
): UseQueryResult<InvestigationDetail> {
  return useQuery({
    queryKey: keys.investigation(id),
    queryFn: () => client.get<InvestigationDetail>(`/investigations/${id}`),
  })
}

export function useTimeline(client: ApiClient, id: string): UseQueryResult<TimelineResponse> {
  return useQuery({
    queryKey: keys.timeline(id),
    queryFn: () => client.get<TimelineResponse>(`/investigations/${id}/timeline`),
  })
}

export function useThreat(client: ApiClient, id: string) {
  return useQuery({
    queryKey: keys.threat(id),
    queryFn: () => client.get(`/investigations/${id}/threat`),
    // A missing assessment means detection has not run, which is a state the
    // screen renders rather than an error worth retrying into.
    retry: false,
  })
}

export function useCves(client: ApiClient, id: string): UseQueryResult<CveFindings> {
  return useQuery({
    queryKey: keys.cves(id),
    queryFn: () => client.get<CveFindings>(`/investigations/${id}/cves`),
  })
}

export function useReport(client: ApiClient, id: string, version?: number) {
  return useQuery({
    queryKey: keys.report(id, version),
    queryFn: () =>
      client.get<Report>(
        `/investigations/${id}/report${version === undefined ? '' : `?version=${version}`}`,
      ),
    retry: false,
  })
}

export function useReportHistory(client: ApiClient, id: string): UseQueryResult<ReportHistory> {
  return useQuery({
    queryKey: keys.reportHistory(id),
    queryFn: () => client.get<ReportHistory>(`/investigations/${id}/report/history`),
  })
}

export function useRecommendations(client: ApiClient, id: string): UseQueryResult<Recommendations> {
  return useQuery({
    queryKey: keys.recommendations(id),
    queryFn: () => client.get<Recommendations>(`/investigations/${id}/recommendations`),
  })
}

export function usePendingApprovals(
  client: ApiClient,
  id: string,
): UseQueryResult<PendingApprovals> {
  return useQuery({
    queryKey: keys.approvals(id),
    queryFn: () => client.get<PendingApprovals>(`/investigations/${id}/pending-approvals`),
  })
}

export interface NotificationFilters {
  investigationId?: string
  status?: NotificationStatus
}

export function useNotifications(
  client: ApiClient,
  filters: NotificationFilters = {},
): UseQueryResult<NotificationPage> {
  const params = new URLSearchParams()
  if (filters.investigationId) params.set('investigation_id', filters.investigationId)
  if (filters.status) params.set('status', filters.status)
  const query = params.toString()

  return useQuery({
    queryKey: keys.notifications(filters),
    queryFn: () => client.get<NotificationPage>(`/notifications${query ? `?${query}` : ''}`),
  })
}

/**
 * Re-attempt one failed delivery.
 *
 * Not a send. This retries a delivery that failed, on the channel and the human
 * authority already recorded; re-sending an alert someone already received is a
 * new notification and needs a new decision. The backend enforces that — this
 * only has to avoid implying otherwise.
 */
export function useRetryNotification(
  client: ApiClient,
): UseMutationResult<RetryResult, Error, string> {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: (notificationId: string) =>
      client.post<RetryResult>(`/notifications/${notificationId}/retry`),
    onSuccess: () => {
      void cache.invalidateQueries({ queryKey: ['notifications'] })
    },
  })
}

export interface GateDecisionInput {
  decision: DecisionType
  rationale?: string
  target?: string
}

export function useGateDecision(
  client: ApiClient,
  id: string,
): UseMutationResult<GateDecisionResult, Error, GateDecisionInput> {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: (input: GateDecisionInput) =>
      client.post<GateDecisionResult>(`/investigations/${id}/decision`, input),
    onSuccess: () => {
      // Re-read rather than patch: what the record now says is the only thing
      // worth showing after a decision.
      void cache.invalidateQueries({ queryKey: ['investigation', id] })
      void cache.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}

export interface RecommendationDecisionInput {
  recommendationId: string
  decision: Exclude<ApprovalStatus, 'pending'>
  rationale?: string
}

export function useRecommendationDecision(
  client: ApiClient,
  id: string,
): UseMutationResult<Recommendation, Error, RecommendationDecisionInput> {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: (input: RecommendationDecisionInput) =>
      client.post<Recommendation>(
        `/investigations/${id}/recommendations/${input.recommendationId}/decision`,
        { decision: input.decision, rationale: input.rationale },
      ),
    onSuccess: () => {
      void cache.invalidateQueries({ queryKey: ['investigation', id] })
    },
  })
}

export interface CreateInvestigationInput {
  title?: string
  trigger_source?: 'analyst' | 'alert' | 'scheduled'
  evidence?: unknown
  assets?: unknown[]
  critical_assets?: string[]
  internal_networks?: string[]
}

export function useCreateInvestigation(client: ApiClient) {
  const cache = useQueryClient()
  return useMutation({
    mutationFn: (input: CreateInvestigationInput) =>
      client.post<{ id: string }>('/investigations', input),
    onSuccess: () => {
      void cache.invalidateQueries({ queryKey: ['investigations'] })
    },
  })
}
