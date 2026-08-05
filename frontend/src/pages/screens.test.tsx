/**
 * Screen interaction tests.
 *
 * Each screen is rendered against a fake API — a route table, not mocked hooks,
 * so the real client and query layer run underneath. The assertions concentrate
 * on the distinctions this product cannot afford to blur: nothing-found versus
 * never-looked, unchecked versus clean, skipped versus pending, draft versus
 * final.
 */

import { screen, waitFor } from '@testing-library/react'
import userEvent from '@testing-library/user-event'
import { describe, expect, it } from 'vitest'

import type { CveFindings, ThreatAssessment, TimelineResponse } from '../api/types'
import { CAPABILITIES, PROFILE, fakeApi, renderScreen, snapshot, stages } from '../test/harness'
import { AuthProvider } from '../auth/AuthContext'
import { DashboardPage } from './DashboardPage'
import { InvestigationPage } from './InvestigationPage'
import { NotificationsPage } from './NotificationsPage'
import { ReportsPage } from './ReportsPage'
import { SettingsPage } from './SettingsPage'
import { ThreatDetailsPage } from './ThreatDetailsPage'
import { TimelinePage } from './TimelinePage'

const INVESTIGATION_PATH = '/investigations/inv-1'
const ROUTE = '/investigations/:investigationId'

const SUMMARY = {
  id: 'inv-1',
  title: 'SSH brute force against web-01',
  status: 'awaiting_approval' as const,
  severity: 'high' as const,
  trigger_source: 'alert' as const,
  verdict: 'malicious' as const,
  triage_priority: 'urgent' as const,
  confidence: 0.82,
  pending_approvals: 1,
  created_at: '2026-08-05T09:00:00Z',
  updated_at: '2026-08-05T10:00:00Z',
  closed_at: null,
}

const ASSESSMENT: ThreatAssessment = {
  id: 'a1',
  investigation_id: 'inv-1',
  verdict: 'malicious',
  severity: 'high',
  triage_priority: 'urgent',
  enrichment_status: 'unavailable',
  confidence: 0.8,
  rationale: 'Six failures then a success for the same principal.',
  indicators: [
    {
      type: 'ip',
      value: '203.0.113.9',
      defanged: '203[.]0[.]113[.]9',
      reputation: null,
      source: null,
      enriched: false,
      internal: false,
      observation_count: 7,
    },
  ],
  techniques: [
    {
      technique_id: 'T1110',
      name: 'Brute Force',
      tactics: ['credential-access'],
      rationale: 'Repeated authentication failures.',
      confidence: 0.7,
      citations: [],
    },
  ],
  version: 1,
  created_at: '2026-08-05T10:00:00Z',
}

// --- Dashboard --------------------------------------------------------------

describe('DashboardPage', () => {
  it('leads with what is waiting on a person', async () => {
    const api = fakeApi({
      '/investigations': { body: { items: [SUMMARY], total: 1, limit: 25, offset: 0 } },
      '/investigations?status=awaiting_approval': {
        body: { items: [SUMMARY], total: 1, limit: 25, offset: 0 },
      },
    })
    renderScreen(<DashboardPage client={api.client} />)

    await waitFor(() =>
      expect(screen.getByRole('link', { name: /SSH brute force/ })).toHaveAttribute(
        'href',
        '/investigations/inv-1',
      ),
    )
    expect(screen.getByText('awaiting a human decision')).toBeInTheDocument()
  })

  it('shows severity and confidence in the row so triage happens from the list', async () => {
    const api = fakeApi({
      '/investigations': { body: { items: [SUMMARY], total: 1, limit: 25, offset: 0 } },
      '/investigations?status=awaiting_approval': {
        body: { items: [], total: 0, limit: 25, offset: 0 },
      },
    })
    renderScreen(<DashboardPage client={api.client} />)

    await waitFor(() =>
      expect(screen.getByText('high', { selector: '.severity-high' })).toBeInTheDocument(),
    )
    expect(screen.getByText('malicious')).toBeInTheDocument()
    expect(screen.getByText(/82%/)).toBeInTheDocument()
  })

  it('says the view is empty rather than rendering a bare table', async () => {
    const api = fakeApi({
      '/investigations': { body: { items: [], total: 0, limit: 25, offset: 0 } },
      '/investigations?status=awaiting_approval': {
        body: { items: [], total: 0, limit: 25, offset: 0 },
      },
    })
    renderScreen(<DashboardPage client={api.client} />)

    await waitFor(() =>
      expect(screen.getByText('No investigations match this view.')).toBeInTheDocument(),
    )
  })

  it('filters by status without losing the count under that filter', async () => {
    const api = fakeApi({
      '/investigations': { body: { items: [SUMMARY], total: 1, limit: 25, offset: 0 } },
      '/investigations?status=closed': { body: { items: [], total: 0, limit: 25, offset: 0 } },
      '/investigations?status=awaiting_approval': {
        body: { items: [SUMMARY], total: 1, limit: 25, offset: 0 },
      },
    })
    renderScreen(<DashboardPage client={api.client} />)

    await waitFor(() => expect(screen.getByRole('table')).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: 'Closed' }))

    await waitFor(() =>
      expect(screen.getByText('No investigations match this view.')).toBeInTheDocument(),
    )
  })
})

// --- Investigation ----------------------------------------------------------

function investigationApi(overrides: Record<string, unknown> = {}) {
  return fakeApi({
    '/auth/me': { body: PROFILE },
    '/system/capabilities': { body: CAPABILITIES },
    '/investigations/inv-1': {
      body: {
        ...SUMMARY,
        summary: 'Credentials were guessed and used.',
        owner_id: 'u1',
        snapshot: snapshot(),
      },
    },
    '/investigations/inv-1/pending-approvals': {
      body: {
        investigation_id: 'inv-1',
        gate_open: true,
        items: [
          {
            kind: 'recommendation',
            id: 'r1',
            investigation_id: 'inv-1',
            title: 'Enforce account lockout',
            priority: 'high',
            confidence: null,
            rationale: 'Repeated failures preceded a success.',
          },
        ],
      },
    },
    '/investigations/inv-1/recommendations': {
      body: {
        investigation_id: 'inv-1',
        version: 1,
        recommendations: [
          {
            id: 'r1',
            investigation_id: 'inv-1',
            action: 'Enforce account lockout on web-01',
            type: 'configuration',
            priority: 'high',
            rationale: 'Repeated failures preceded a success.',
            expected_impact: 'Locks accounts after repeated failures.',
            citations: [],
            approval_status: 'pending',
            requires_human_approval: true,
            version: 1,
            created_at: '2026-08-05T10:00:00Z',
          },
        ],
      },
    },
    '/investigations/inv-1/stream': { stream: '' },
    '/investigations/inv-1/decision': {
      body: {
        investigation_id: 'inv-1',
        decision: 'approve',
        status: 'closed',
        awaiting_human: false,
        recorded_at: '2026-08-05T11:00:00Z',
        executed: false,
      },
    },
    ...(overrides as Record<string, { body?: unknown; status?: number; stream?: string }>),
  })
}

describe('InvestigationPage', () => {
  it('shows the pipeline, distinguishing pending from skipped', async () => {
    const api = investigationApi()
    renderScreen(
      <AuthProvider client={api.client}>
        <InvestigationPage client={api.client} />
      </AuthProvider>,
      { path: INVESTIGATION_PATH, route: ROUTE },
    )

    await waitFor(() => expect(screen.getByText('CVE research')).toBeInTheDocument())
    const pipeline = screen.getByLabelText('Investigation pipeline')
    expect(pipeline).toHaveTextContent('pending')
    expect(pipeline).not.toHaveTextContent('not required')
  })

  it('reports a deliberately skipped stage as not required', async () => {
    const api = investigationApi({
      '/investigations/inv-1': {
        body: {
          ...SUMMARY,
          summary: null,
          owner_id: 'u1',
          snapshot: snapshot({
            pipeline: stages({ cve_research: { skipped: true, complete: false } }),
          }),
        },
      },
    })
    renderScreen(
      <AuthProvider client={api.client}>
        <InvestigationPage client={api.client} />
      </AuthProvider>,
      { path: INVESTIGATION_PATH, route: ROUTE },
    )

    await waitFor(() =>
      expect(screen.getByLabelText('Investigation pipeline')).toHaveTextContent('not required'),
    )
  })

  it('offers the approval panel to a role that may approve', async () => {
    const api = investigationApi()
    renderScreen(
      <AuthProvider client={api.client}>
        <InvestigationPage client={api.client} />
      </AuthProvider>,
      { path: INVESTIGATION_PATH, route: ROUTE },
    )

    await waitFor(() =>
      expect(screen.getByRole('heading', { name: /human approval required/i })).toBeInTheDocument(),
    )
  })

  it('withholds the decision form from a role that may not approve', async () => {
    const api = investigationApi({
      '/system/capabilities': { body: { role: 'analyst', capabilities: ['view_investigations'] } },
    })
    renderScreen(
      <AuthProvider client={api.client}>
        <InvestigationPage client={api.client} />
      </AuthProvider>,
      { path: INVESTIGATION_PATH, route: ROUTE },
    )

    await waitFor(() => expect(screen.getByText(/Your role cannot record one/)).toBeInTheDocument())
    expect(screen.queryByRole('radio')).toBeNull()
  })

  it('sends the recorded decision to the server', async () => {
    const api = investigationApi()
    renderScreen(
      <AuthProvider client={api.client}>
        <InvestigationPage client={api.client} />
      </AuthProvider>,
      { path: INVESTIGATION_PATH, route: ROUTE },
    )

    await waitFor(() => expect(screen.getByRole('radio', { name: /approve/i })).toBeInTheDocument())
    await userEvent.click(screen.getByRole('radio', { name: /approve/i }))
    await userEvent.click(screen.getByRole('button', { name: /record decision/i }))

    await waitFor(() =>
      expect(
        api.calls.some(
          (call) => call.method === 'POST' && call.path === '/investigations/inv-1/decision',
        ),
      ).toBe(true),
    )
  })

  it('states that a recommendation is a proposal, not an action', async () => {
    const api = investigationApi()
    renderScreen(
      <AuthProvider client={api.client}>
        <InvestigationPage client={api.client} />
      </AuthProvider>,
      { path: INVESTIGATION_PATH, route: ROUTE },
    )

    await waitFor(() =>
      expect(screen.getByText(/Nothing here runs by itself/)).toBeInTheDocument(),
    )
  })

  it('surfaces a stage that failed as an unmet gap next to the decision', async () => {
    const api = investigationApi()
    renderScreen(
      <AuthProvider client={api.client}>
        <InvestigationPage client={api.client} />
      </AuthProvider>,
      { path: INVESTIGATION_PATH, route: ROUTE },
    )

    await waitFor(() =>
      expect(screen.getByText('CVE research did not complete.')).toBeInTheDocument(),
    )
  })
})

// --- Timeline ---------------------------------------------------------------

const TIMELINE: TimelineResponse = {
  investigation_id: 'inv-1',
  truncated: false,
  events: [
    {
      id: 'e1',
      event_time: '2026-08-05T09:34:00Z',
      source: 'hostlogs',
      event_type: 'auth_failure',
      actor: 'admin',
      notability: 0.8,
      raw_ref: 'auth.log#L1',
      provenance: { record_id: 'r1', parser: 'syslog', confidence: 0.9 },
    },
  ],
}

describe('TimelinePage', () => {
  it('shows provenance on request rather than losing the analyst the sequence', async () => {
    const api = fakeApi({ '/investigations/inv-1/timeline': { body: TIMELINE } })
    renderScreen(<TimelinePage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/timeline`,
      route: `${ROUTE}/timeline`,
    })

    await waitFor(() => expect(screen.getByText('auth_failure')).toBeInTheDocument())
    expect(screen.queryByText('record id')).toBeNull()

    await userEvent.click(screen.getByRole('button', { name: /show provenance/i }))
    expect(screen.getByText('record id')).toBeInTheDocument()
    expect(screen.getByText('auth.log#L1')).toBeInTheDocument()
  })

  it('says the view is truncated rather than reading as the whole incident', async () => {
    const api = fakeApi({
      '/investigations/inv-1/timeline': { body: { ...TIMELINE, truncated: true } },
    })
    renderScreen(<TimelinePage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/timeline`,
      route: `${ROUTE}/timeline`,
    })

    await waitFor(() => expect(screen.getByText(/This view is truncated/)).toBeInTheDocument())
  })

  it('explains an empty timeline instead of showing a blank page', async () => {
    const api = fakeApi({
      '/investigations/inv-1/timeline': { body: { ...TIMELINE, events: [] } },
    })
    renderScreen(<TimelinePage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/timeline`,
      route: `${ROUTE}/timeline`,
    })

    await waitFor(() =>
      expect(screen.getByText(/nothing collected could be parsed/)).toBeInTheDocument(),
    )
  })
})

// --- Threat details ---------------------------------------------------------

describe('ThreatDetailsPage', () => {
  const researched: CveFindings = {
    investigation_id: 'inv-1',
    researched: true,
    findings: [],
    version: 1,
  }

  it('labels an unenriched indicator unchecked, not clean', async () => {
    const api = fakeApi({
      '/investigations/inv-1/threat': { body: ASSESSMENT },
      '/investigations/inv-1/cves': { body: researched },
    })
    renderScreen(<ThreatDetailsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/threat`,
      route: `${ROUTE}/threat`,
    })

    await waitFor(() => expect(screen.getByText('unchecked')).toBeInTheDocument())
    expect(screen.getByText(/No indicator on this page has been checked/)).toBeInTheDocument()
  })

  it('shows the defanged form so nothing is copy-pasteable into a terminal', async () => {
    const api = fakeApi({
      '/investigations/inv-1/threat': { body: ASSESSMENT },
      '/investigations/inv-1/cves': { body: researched },
    })
    renderScreen(<ThreatDetailsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/threat`,
      route: `${ROUTE}/threat`,
    })

    await waitFor(() => expect(screen.getByText('203[.]0[.]113[.]9')).toBeInTheDocument())
    expect(screen.queryByText('203.0.113.9')).toBeNull()
  })

  it('distinguishes research that found nothing from research that never ran', async () => {
    const api = fakeApi({
      '/investigations/inv-1/threat': { body: ASSESSMENT },
      '/investigations/inv-1/cves': { body: { ...researched, researched: false } },
    })
    renderScreen(<ThreatDetailsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/threat`,
      route: `${ROUTE}/threat`,
    })

    await waitFor(() =>
      expect(screen.getByText(/not a statement that the estate is unaffected/)).toBeInTheDocument(),
    )
  })

  it('says so plainly when research ran and found nothing', async () => {
    const api = fakeApi({
      '/investigations/inv-1/threat': { body: ASSESSMENT },
      '/investigations/inv-1/cves': { body: researched },
    })
    renderScreen(<ThreatDetailsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/threat`,
      route: `${ROUTE}/threat`,
    })

    await waitFor(() =>
      expect(screen.getByText('Vulnerability research ran and found nothing applicable.')).toBeInTheDocument(),
    )
  })

  it('reports a missing assessment as detection not having run', async () => {
    const api = fakeApi({
      '/investigations/inv-1/threat': { status: 404, body: { error: 'not_found' } },
      '/investigations/inv-1/cves': { body: researched },
    })
    renderScreen(<ThreatDetailsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/threat`,
      route: `${ROUTE}/threat`,
    })

    await waitFor(() =>
      expect(screen.getByText(/has not produced an assessment/)).toBeInTheDocument(),
    )
  })
})

// --- Reports ----------------------------------------------------------------

const REPORT = {
  id: 'rep-1',
  investigation_id: 'inv-1',
  executive_summary: 'The account admin was brute-forced.',
  technical_body: '# Report\n\n<script>alert(1)</script>',
  citations: [],
  status: 'draft' as const,
  version: 1,
  created_at: '2026-08-05T10:00:00Z',
}

describe('ReportsPage', () => {
  it('renders the body as text, never as markup', async () => {
    const api = fakeApi({
      '/investigations/inv-1/report': { body: REPORT },
      '/investigations/inv-1/report/history': {
        body: { investigation_id: 'inv-1', versions: [] },
      },
    })
    const { container } = renderScreen(<ReportsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/report`,
      route: `${ROUTE}/report`,
    })

    await waitFor(() => expect(screen.getByText(/brute-forced/)).toBeInTheDocument())
    expect(container.querySelector('script')).toBeNull()
    expect(screen.getByText(/<script>alert\(1\)<\/script>/)).toBeInTheDocument()
  })

  it('marks a draft as a draft', async () => {
    const api = fakeApi({
      '/investigations/inv-1/report': { body: REPORT },
      '/investigations/inv-1/report/history': {
        body: { investigation_id: 'inv-1', versions: [] },
      },
    })
    renderScreen(<ReportsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/report`,
      route: `${ROUTE}/report`,
    })

    await waitFor(() => expect(screen.getByText(/This report is a draft/)).toBeInTheDocument())
  })

  it('offers earlier versions so a decided-on document stays readable', async () => {
    const api = fakeApi({
      '/investigations/inv-1/report': { body: { ...REPORT, version: 2 } },
      '/investigations/inv-1/report/history': {
        body: {
          investigation_id: 'inv-1',
          versions: [
            { id: 'rep-1', version: 1, status: 'final', created_at: '2026-08-05T09:00:00Z' },
            { id: 'rep-2', version: 2, status: 'draft', created_at: '2026-08-05T10:00:00Z' },
          ],
        },
      },
      '/investigations/inv-1/report?version=1': { body: REPORT },
    })
    renderScreen(<ReportsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/report`,
      route: `${ROUTE}/report`,
    })

    await waitFor(() => expect(screen.getByRole('button', { name: 'v1 (final)' })).toBeInTheDocument())
    await userEvent.click(screen.getByRole('button', { name: 'v1 (final)' }))

    await waitFor(() =>
      expect(
        api.calls.some((call) => call.path === '/investigations/inv-1/report?version=1'),
      ).toBe(true),
    )
  })

  it('explains an absent report rather than erroring', async () => {
    const api = fakeApi({
      '/investigations/inv-1/report': { status: 404, body: { error: 'not_found' } },
      '/investigations/inv-1/report/history': {
        body: { investigation_id: 'inv-1', versions: [] },
      },
    })
    renderScreen(<ReportsPage client={api.client} />, {
      path: `${INVESTIGATION_PATH}/report`,
      route: `${ROUTE}/report`,
    })

    await waitFor(() =>
      expect(screen.getByText(/No report has been generated/)).toBeInTheDocument(),
    )
  })
})

// --- Notifications ----------------------------------------------------------

describe('NotificationsPage', () => {
  it('flags a notification with no linked approval', async () => {
    const api = fakeApi({
      '/notifications': {
        body: {
          items: [
            {
              id: 'n1',
              investigation_id: 'inv-1',
              channel: 'slack',
              recipient: '#soc',
              status: 'sent',
              delivery_attempts: 1,
              approval_id: null,
              sent_at: '2026-08-05T10:00:00Z',
              created_at: '2026-08-05T10:00:00Z',
            },
          ],
          total: 1,
          limit: 25,
          offset: 0,
        },
      },
    })
    renderScreen(<NotificationsPage client={api.client} />)

    await waitFor(() => expect(screen.getByText('no linked approval')).toBeInTheDocument())
  })

  it('offers no way to send from this console', async () => {
    const api = fakeApi({
      '/notifications': { body: { items: [], total: 0, limit: 25, offset: 0 } },
    })
    renderScreen(<NotificationsPage client={api.client} />)

    await waitFor(() =>
      expect(screen.getByText(/sending is not available from this console/i)).toBeInTheDocument(),
    )
    expect(screen.queryByRole('button', { name: /resend|send/i })).toBeNull()
  })
})

// --- Settings ---------------------------------------------------------------

describe('SettingsPage', () => {
  it('shows what the role permits, from the server', async () => {
    const api = fakeApi({ '/auth/me': { body: PROFILE }, '/system/capabilities': { body: CAPABILITIES } })
    renderScreen(
      <AuthProvider client={api.client}>
        <SettingsPage />
      </AuthProvider>,
    )

    await waitFor(() => expect(screen.getByText('Record approval decisions')).toBeInTheDocument())
    const denied = screen.getByText('Manage users and roles').closest('li')
    expect(denied).toHaveClass('denied')
  })

  it('lists unbuilt settings so their absence is not read as a permission gap', async () => {
    const api = fakeApi({ '/auth/me': { body: PROFILE }, '/system/capabilities': { body: CAPABILITIES } })
    renderScreen(
      <AuthProvider client={api.client}>
        <SettingsPage />
      </AuthProvider>,
    )

    await waitFor(() =>
      expect(screen.getByText(/Notification channels and policies/)).toBeInTheDocument(),
    )
  })
})
