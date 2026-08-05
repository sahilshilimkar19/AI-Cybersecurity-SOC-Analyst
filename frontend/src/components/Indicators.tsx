/**
 * The small components that make a claim's standing visible.
 *
 * SAD §13 asks for confidence and provenance everywhere, and the reason is
 * specific to this product: an analyst approving a finding needs to know how
 * strongly it is held and what it rests on, or the approval is a rubber stamp.
 * So confidence is never a bare number, an unenriched indicator says it was
 * never checked, and a citation list that is empty says so out loud rather than
 * rendering as nothing.
 */

import type { ReactElement } from 'react'

import type { Citation, Severity, TriagePriority, Verdict } from '../api/types'
import { SafeLink } from './SafeLink'

export function SeverityBadge({ severity }: { severity: Severity | null }): ReactElement {
  if (severity === null) return <span className="badge badge-unset">not assessed</span>
  return <span className={`badge severity-${severity}`}>{severity}</span>
}

export function PriorityBadge({ priority }: { priority: TriagePriority | null }): ReactElement {
  if (priority === null) return <span className="badge badge-unset">unset</span>
  return <span className={`badge priority-${priority}`}>{priority}</span>
}

export function VerdictBadge({ verdict }: { verdict: Verdict | null }): ReactElement {
  if (verdict === null) return <span className="badge badge-unset">not assessed</span>
  return <span className={`badge verdict-${verdict}`}>{verdict}</span>
}

/**
 * Confidence, shown as a proportion and named in words.
 *
 * The words matter more than the bar. "0.42" invites an analyst to read a
 * precision that is not there; "low confidence" is what the number actually
 * means, and it is harder to skim past.
 */
export function ConfidenceMeter({
  confidence,
  label = 'Confidence',
}: {
  confidence: number | null
  label?: string
}): ReactElement {
  if (confidence === null) {
    return (
      <span className="confidence confidence-unknown">
        {label}: not stated
      </span>
    )
  }
  const percent = Math.round(confidence * 100)
  const band = confidence >= 0.75 ? 'high' : confidence >= 0.45 ? 'moderate' : 'low'
  return (
    <span className={`confidence confidence-${band}`}>
      <span className="confidence-label">{label}:</span>{' '}
      <span className="confidence-word">{band}</span>{' '}
      <span className="confidence-value">({percent}%)</span>
      <span
        aria-hidden="true"
        className="confidence-bar"
        style={{ width: `${Math.max(2, percent)}%` }}
      />
    </span>
  )
}

/**
 * The sources behind a claim.
 *
 * An empty list renders as an explicit statement rather than as nothing at all:
 * "no source cited" is information an analyst needs when deciding how much
 * weight to give a finding (invariant #4).
 */
export function CitationList({
  citations,
  emptyMessage = 'No source cited.',
}: {
  citations: Citation[]
  emptyMessage?: string
}): ReactElement {
  if (citations.length === 0) {
    return <p className="citations citations-empty">{emptyMessage}</p>
  }
  return (
    <ul className="citations">
      {citations.map((citation, index) => (
        <li key={`${citation.source_id}-${index}`}>
          <SafeLink href={citation.url}>{citation.title ?? citation.source}</SafeLink>
          <span className="citation-source"> — {citation.source}</span>
          {citation.trust_tier !== null && (
            <span className={`badge trust-${citation.trust_tier}`}>{citation.trust_tier}</span>
          )}
        </li>
      ))}
    </ul>
  )
}

/**
 * Provenance for one timeline event.
 *
 * Rendered as key/value pairs without interpretation, because what a parser
 * established differs by source and inventing a common shape would mean either
 * hiding fields or fabricating them.
 */
export function ProvenanceList({
  provenance,
}: {
  provenance: Record<string, unknown>
}): ReactElement {
  const entries = Object.entries(provenance).filter(
    ([, value]) => value !== null && value !== undefined && value !== '',
  )
  if (entries.length === 0) {
    return <p className="provenance provenance-empty">No provenance recorded.</p>
  }
  return (
    <dl className="provenance">
      {entries.map(([key, value]) => (
        <div key={key} className="provenance-entry">
          <dt>{key.replace(/_/g, ' ')}</dt>
          <dd>{typeof value === 'string' ? value : JSON.stringify(value)}</dd>
        </div>
      ))}
    </dl>
  )
}

/**
 * An indicator's enrichment state.
 *
 * The distinction this draws is the whole point: an indicator nothing asserted a
 * reputation for is **unchecked**, not clean. Rendering the two the same way
 * would tell an analyst an external address was cleared when nobody looked.
 */
export function EnrichmentTag({
  enriched,
  reputation,
  source,
}: {
  enriched: boolean
  reputation: string | null
  source: string | null
}): ReactElement {
  if (!enriched) {
    return (
      <span className="badge enrichment-unchecked" title="No reputation source was consulted.">
        unchecked
      </span>
    )
  }
  return (
    <span className={`badge enrichment-${reputation ?? 'unknown'}`}>
      {reputation ?? 'unknown'}
      {source !== null && <span className="enrichment-source"> via {source}</span>}
    </span>
  )
}
