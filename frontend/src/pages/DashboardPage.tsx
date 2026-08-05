/**
 * At-a-glance SOC posture (SAD §13).
 *
 * The queue leads with what is waiting on a person, because that is the only
 * part of the board where the platform has stopped and is holding: everything
 * else is either finished or still running, and neither needs an analyst right
 * now. Severity and confidence travel with every row so triage happens from the
 * list rather than by opening seven cases to find out which one matters.
 */

import { useState } from 'react'
import type { ReactElement } from 'react'
import { Link } from 'react-router'

import type { ApiClient } from '../api/client'
import { useInvestigations } from '../api/queries'
import type { InvestigationStatus, InvestigationSummary } from '../api/types'
import { ConfidenceMeter, SeverityBadge, VerdictBadge } from '../components/Indicators'
import { Empty, Failed, Loading } from '../components/States'

const STATUS_FILTERS: { value: InvestigationStatus | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'awaiting_approval', label: 'Awaiting approval' },
  { value: 'in_progress', label: 'Running' },
  { value: 'open', label: 'Open' },
  { value: 'closed', label: 'Closed' },
]

function QueueRow({ investigation }: { investigation: InvestigationSummary }): ReactElement {
  return (
    <tr className={`queue-row status-${investigation.status}`}>
      <td>
        <Link to={`/investigations/${investigation.id}`}>
          {investigation.title ?? 'Untitled investigation'}
        </Link>
      </td>
      <td>
        <SeverityBadge severity={investigation.severity} />
      </td>
      <td>
        <VerdictBadge verdict={investigation.verdict} />
      </td>
      <td>{investigation.status.replace(/_/g, ' ')}</td>
      <td>
        <ConfidenceMeter confidence={investigation.confidence} label="" />
      </td>
      <td className="numeric">{investigation.pending_approvals}</td>
      <td>{new Date(investigation.created_at).toLocaleString()}</td>
    </tr>
  )
}

export function DashboardPage({ client }: { client: ApiClient }): ReactElement {
  const [status, setStatus] = useState<InvestigationStatus | 'all'>('all')
  const [mine, setMine] = useState(false)

  const filters = {
    ...(status === 'all' ? {} : { status }),
    ...(mine ? { mine: true } : {}),
  }
  const investigations = useInvestigations(client, filters)
  const awaiting = useInvestigations(client, { status: 'awaiting_approval' })

  return (
    <div className="page page-dashboard">
      <h1>Dashboard</h1>

      <section className="posture" aria-label="Queue summary">
        <div className="posture-card posture-attention">
          <span className="posture-value">{awaiting.data?.total ?? '—'}</span>
          <span className="posture-label">awaiting a human decision</span>
        </div>
        <div className="posture-card">
          <span className="posture-value">{investigations.data?.total ?? '—'}</span>
          <span className="posture-label">investigations in this view</span>
        </div>
      </section>

      <section className="filters" aria-label="Filters">
        {STATUS_FILTERS.map((filter) => (
          <button
            key={filter.value}
            type="button"
            className={status === filter.value ? 'filter filter-active' : 'filter'}
            aria-pressed={status === filter.value}
            onClick={() => setStatus(filter.value)}
          >
            {filter.label}
          </button>
        ))}
        <label className="filter-mine">
          <input type="checkbox" checked={mine} onChange={() => setMine((value) => !value)} />
          Only mine
        </label>
      </section>

      {investigations.isLoading && <Loading what="investigations" />}
      {investigations.isError && <Failed what="investigations" error={investigations.error} />}
      {investigations.data !== undefined &&
        (investigations.data.items.length === 0 ? (
          <Empty>No investigations match this view.</Empty>
        ) : (
          <table className="queue">
            <caption>
              Investigation queue — {investigations.data.items.length} of{' '}
              {investigations.data.total}
            </caption>
            <thead>
              <tr>
                <th scope="col">Investigation</th>
                <th scope="col">Severity</th>
                <th scope="col">Verdict</th>
                <th scope="col">Status</th>
                <th scope="col">Confidence</th>
                <th scope="col">Pending</th>
                <th scope="col">Opened</th>
              </tr>
            </thead>
            <tbody>
              {investigations.data.items.map((investigation) => (
                <QueueRow key={investigation.id} investigation={investigation} />
              ))}
            </tbody>
          </table>
        ))}
    </div>
  )
}
