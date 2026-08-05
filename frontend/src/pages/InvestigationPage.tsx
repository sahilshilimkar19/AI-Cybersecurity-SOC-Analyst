/**
 * The analyst workspace for one case (SAD §13).
 *
 * The header state comes from the live stream when one is connected and from the
 * fetched detail otherwise — never from both at once, and never from local
 * assumptions. If the stream drops, the last snapshot stays on screen labelled
 * stale rather than the panel emptying: an analyst mid-decision needs the data
 * they were reading more than they need a spinner.
 *
 * The gaps handed to the approval panel are the stages that neither completed
 * nor were skipped. That is what "we did not establish this" looks like in the
 * record, and it belongs next to the approve button rather than three screens
 * away.
 */

import type { ReactElement } from 'react'
import { Link, useParams } from 'react-router'

import type { ApiClient } from '../api/client'
import {
  useGateDecision,
  useInvestigation,
  usePendingApprovals,
  useRecommendationDecision,
  useRecommendations,
} from '../api/queries'
import type { InvestigationSnapshot, Recommendation } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { ApprovalPanel } from '../components/ApprovalPanel'
import { CitationList, ConfidenceMeter, PriorityBadge, SeverityBadge } from '../components/Indicators'
import { PipelineProgress } from '../components/PipelineProgress'
import { Empty, Failed, Loading, StreamStatusBanner } from '../components/States'
import { useInvestigationStream } from '../realtime/useInvestigationStream'

function gapsFrom(snapshot: InvestigationSnapshot): string[] {
  return snapshot.pipeline
    .filter((stage) => !stage.complete && !stage.skipped)
    .map((stage) => `${stage.label} did not complete.`)
}

function RecommendationCard({
  recommendation,
  canApprove,
  onDecide,
  submitting,
}: {
  recommendation: Recommendation
  canApprove: boolean
  onDecide: (decision: 'approved' | 'rejected') => void
  submitting: boolean
}): ReactElement {
  const decided = recommendation.approval_status !== 'pending'
  return (
    <li className={`recommendation priority-${recommendation.priority}`}>
      <h3>{recommendation.action}</h3>
      <div className="recommendation-meta">
        <PriorityBadge priority={recommendation.priority} />
        <span className={`badge approval-${recommendation.approval_status}`}>
          {recommendation.approval_status}
        </span>
        <span className="badge badge-unset">{recommendation.type}</span>
      </div>
      <p className="recommendation-rationale">{recommendation.rationale}</p>
      {recommendation.expected_impact !== null && (
        <p className="recommendation-impact">
          <strong>Expected impact:</strong> {recommendation.expected_impact}
        </p>
      )}
      <CitationList citations={recommendation.citations} />
      {canApprove && !decided && (
        <div className="recommendation-actions">
          <button type="button" disabled={submitting} onClick={() => onDecide('approved')}>
            Approve this item
          </button>
          <button type="button" disabled={submitting} onClick={() => onDecide('rejected')}>
            Reject this item
          </button>
        </div>
      )}
      {decided && (
        <p className="recommendation-decided">
          Recorded as {recommendation.approval_status}. Approval authorizes the work; it does not
          perform it.
        </p>
      )}
    </li>
  )
}

export function InvestigationPage({ client }: { client: ApiClient }): ReactElement {
  const { investigationId = '' } = useParams<{ investigationId: string }>()
  const auth = useAuth()
  const detail = useInvestigation(client, investigationId)
  const approvals = usePendingApprovals(client, investigationId)
  const recommendations = useRecommendations(client, investigationId)
  const gate = useGateDecision(client, investigationId)
  const itemDecision = useRecommendationDecision(client, investigationId)
  const stream = useInvestigationStream(client, investigationId)

  if (detail.isLoading) return <Loading what="this investigation" />
  if (detail.isError) return <Failed what="this investigation" error={detail.error} />
  if (detail.data === undefined) return <Empty>This investigation could not be found.</Empty>

  // The stream is authoritative while it is live; the fetched detail is the
  // fallback. Preferring the snapshot only when one has arrived avoids showing a
  // blank header for the first second of every visit.
  const snapshot = stream.snapshot ?? detail.data.snapshot
  const canApprove = auth.can('approve_actions')

  return (
    <div className="page page-investigation">
      <header className="investigation-header">
        <h1>{detail.data.title ?? 'Untitled investigation'}</h1>
        <div className="investigation-meta">
          <SeverityBadge severity={snapshot.severity} />
          <span className={`badge status-${snapshot.status}`}>
            {snapshot.status.replace(/_/g, ' ')}
          </span>
          <ConfidenceMeter confidence={snapshot.confidence} />
          <span className="trigger">triggered by {detail.data.trigger_source}</span>
        </div>
        <StreamStatusBanner status={stream.status} stale={stream.stale} />
      </header>

      {detail.data.summary !== null && (
        <section className="investigation-summary">
          <h2>Executive summary</h2>
          <p>{detail.data.summary}</p>
        </section>
      )}

      <section aria-labelledby="pipeline-heading">
        <h2 id="pipeline-heading">Agent pipeline</h2>
        <PipelineProgress stages={snapshot.pipeline} />
      </section>

      <nav className="investigation-links" aria-label="Investigation detail">
        <Link to={`/investigations/${investigationId}/timeline`}>
          Timeline ({snapshot.event_count})
        </Link>
        <Link to={`/investigations/${investigationId}/threat`}>Threat details</Link>
        <Link to={`/investigations/${investigationId}/report`}>
          Report {snapshot.report_version > 0 ? `(v${snapshot.report_version})` : '(none yet)'}
        </Link>
        <Link to={`/investigations/${investigationId}/notifications`}>Notifications</Link>
      </nav>

      <ApprovalPanel
        gateOpen={approvals.data?.gate_open ?? snapshot.awaiting_human}
        items={approvals.data?.items ?? []}
        verdict={snapshot.verdict}
        priority={snapshot.triage_priority}
        confidence={snapshot.confidence}
        gaps={gapsFrom(snapshot)}
        canApprove={canApprove}
        submitting={gate.isPending}
        error={gate.error === null ? null : gate.error.message}
        onDecide={(input) => gate.mutate(input)}
      />

      <section aria-labelledby="recommendations-heading">
        <h2 id="recommendations-heading">Recommended remediation</h2>
        <p className="section-note">
          Recommendations are proposals for a person to carry out. Nothing here runs by itself.
        </p>
        {recommendations.isLoading && <Loading what="recommendations" />}
        {recommendations.isError && (
          <Failed what="recommendations" error={recommendations.error} />
        )}
        {recommendations.data !== undefined &&
          (recommendations.data.recommendations.length === 0 ? (
            <Empty>No remediation was recommended for this investigation.</Empty>
          ) : (
            <ul className="recommendations">
              {recommendations.data.recommendations.map((recommendation) => (
                <RecommendationCard
                  key={recommendation.id}
                  recommendation={recommendation}
                  canApprove={canApprove}
                  submitting={itemDecision.isPending}
                  onDecide={(decision) =>
                    itemDecision.mutate({ recommendationId: recommendation.id, decision })
                  }
                />
              ))}
            </ul>
          ))}
      </section>
    </div>
  )
}
