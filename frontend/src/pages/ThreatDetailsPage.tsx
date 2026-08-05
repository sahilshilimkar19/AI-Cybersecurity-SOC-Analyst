/**
 * The deep dive on the assessment (SAD §13).
 *
 * Two things this screen refuses to blur.
 *
 * **Indicators are shown defanged, with their enrichment state.** The defanged
 * form is what the backend stored, so nothing here has to remember to neutralize
 * an address before rendering it — and an indicator nobody checked is labelled
 * unchecked rather than shown the same way as one that came back clean.
 *
 * **A missing dossier is not an empty one.** "CVE research found nothing" and
 * "CVE research never ran" are different statements about an estate, and only
 * one of them means an analyst can stop looking.
 */

import type { ReactElement } from 'react'
import { useParams } from 'react-router'

import type { ApiClient } from '../api/client'
import { useCves, useThreat } from '../api/queries'
import type { ThreatAssessment } from '../api/types'
import {
  CitationList,
  ConfidenceMeter,
  EnrichmentTag,
  PriorityBadge,
  SeverityBadge,
  VerdictBadge,
} from '../components/Indicators'
import { Empty, Failed, Loading } from '../components/States'

const ENRICHMENT_NOTES: Record<string, string> = {
  complete: 'Indicator reputation was available and consulted.',
  degraded:
    'Reputation enrichment was partly unavailable. Indicators without a named source are unchecked, not clean.',
  unavailable:
    'Reputation enrichment was unavailable. No indicator on this page has been checked against external intelligence.',
}

function Assessment({ assessment }: { assessment: ThreatAssessment }): ReactElement {
  return (
    <>
      <section className="threat-headline">
        <VerdictBadge verdict={assessment.verdict} />
        <SeverityBadge severity={assessment.severity} />
        <PriorityBadge priority={assessment.triage_priority} />
        <ConfidenceMeter confidence={assessment.confidence} />
        <span className="version">assessment v{assessment.version}</span>
      </section>

      <p className={`state enrichment-${assessment.enrichment_status}`} role="note">
        {ENRICHMENT_NOTES[assessment.enrichment_status]}
      </p>

      {assessment.rationale !== null && (
        <section aria-labelledby="rationale-heading">
          <h2 id="rationale-heading">Why this verdict</h2>
          <p>{assessment.rationale}</p>
        </section>
      )}

      <section aria-labelledby="iocs-heading">
        <h2 id="iocs-heading">Indicators ({assessment.indicators.length})</h2>
        {assessment.indicators.length === 0 ? (
          <Empty>No indicators were extracted from this evidence.</Empty>
        ) : (
          <table className="iocs">
            <thead>
              <tr>
                <th scope="col">Type</th>
                <th scope="col">Indicator</th>
                <th scope="col">Reputation</th>
                <th scope="col">Seen</th>
                <th scope="col">Scope</th>
              </tr>
            </thead>
            <tbody>
              {assessment.indicators.map((indicator) => (
                <tr key={`${indicator.type}-${indicator.value}`}>
                  <td>{indicator.type}</td>
                  {/* The stored defanged form, so nothing on this page is clickable
                      or copy-pasteable straight into a terminal. */}
                  <td className="ioc-value">{indicator.defanged ?? indicator.value}</td>
                  <td>
                    <EnrichmentTag
                      enriched={indicator.enriched}
                      reputation={indicator.reputation}
                      source={indicator.source}
                    />
                  </td>
                  <td className="numeric">{indicator.observation_count}</td>
                  <td>{indicator.internal ? 'internal' : 'external'}</td>
                </tr>
              ))}
            </tbody>
          </table>
        )}
      </section>

      <section aria-labelledby="techniques-heading">
        <h2 id="techniques-heading">ATT&amp;CK techniques ({assessment.techniques.length})</h2>
        {assessment.techniques.length === 0 ? (
          <Empty>No adversary technique was mapped to this activity.</Empty>
        ) : (
          <ul className="techniques">
            {assessment.techniques.map((technique) => (
              <li key={technique.technique_id}>
                <h3>
                  {technique.technique_id} {technique.name ?? ''}
                </h3>
                <p className="technique-tactics">{technique.tactics.join(', ')}</p>
                {technique.rationale !== null && <p>{technique.rationale}</p>}
                <ConfidenceMeter confidence={technique.confidence} label="Mapping confidence" />
                <CitationList citations={technique.citations} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </>
  )
}

export function ThreatDetailsPage({ client }: { client: ApiClient }): ReactElement {
  const { investigationId = '' } = useParams<{ investigationId: string }>()
  const threat = useThreat(client, investigationId)
  const cves = useCves(client, investigationId)

  return (
    <div className="page page-threat">
      <h1>Threat details</h1>

      {threat.isLoading && <Loading what="the threat assessment" />}
      {threat.isError && (
        <Empty>
          Threat detection has not produced an assessment for this investigation yet.
        </Empty>
      )}
      {threat.data !== undefined && <Assessment assessment={threat.data as ThreatAssessment} />}

      <section aria-labelledby="cves-heading">
        <h2 id="cves-heading">Linked vulnerabilities</h2>
        {cves.isLoading && <Loading what="CVE findings" />}
        {cves.isError && <Failed what="CVE findings" error={cves.error} />}
        {cves.data !== undefined && !cves.data.researched && (
          <Empty>
            Vulnerability research was not performed for this investigation — the verdict did not
            call for it. This is not a statement that the estate is unaffected.
          </Empty>
        )}
        {cves.data !== undefined && cves.data.researched && cves.data.findings.length === 0 && (
          <Empty>Vulnerability research ran and found nothing applicable.</Empty>
        )}
        {cves.data !== undefined && cves.data.findings.length > 0 && (
          <ul className="cves">
            {cves.data.findings.map((finding) => (
              <li key={finding.id} className={`cve applicability-${finding.applicability}`}>
                <h3>
                  {finding.cve_id}{' '}
                  <span className={`badge applicability-${finding.applicability}`}>
                    {finding.applicability.replace(/_/g, ' ')}
                  </span>
                </h3>
                {finding.cvss !== null && (
                  <p className="cvss">
                    CVSS {finding.cvss.score ?? '—'} ({finding.cvss.severity ?? 'unrated'})
                    {finding.cvss.vector !== undefined && (
                      <span className="cvss-vector"> {finding.cvss.vector}</span>
                    )}
                  </p>
                )}
                {finding.summary !== null && <p>{finding.summary}</p>}
                <CitationList citations={finding.citations} />
              </li>
            ))}
          </ul>
        )}
      </section>
    </div>
  )
}
