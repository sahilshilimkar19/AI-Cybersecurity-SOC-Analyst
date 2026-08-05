/**
 * Test harness: render a screen against a fake API.
 *
 * The fake is a route table rather than a mocked module, so a test states what
 * the *server* returns and the whole client stack — query cache, client,
 * components — runs for real underneath it. Mocking the hooks instead would test
 * the mocks.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { render } from '@testing-library/react'
import type { RenderResult } from '@testing-library/react'
import type { ReactElement } from 'react'
import { MemoryRouter, Route, Routes } from 'react-router'

import type { ApiClient } from '../api/client'
import { ApiError } from '../api/client'
import type { Capabilities, InvestigationSnapshot, PipelineStage, Profile } from '../api/types'

export interface FakeRoute {
  status?: number
  body?: unknown
  /** For the stream endpoint: the raw SSE text to deliver. */
  stream?: string
}

export interface FakeApi {
  client: ApiClient
  calls: { method: string; path: string; body?: unknown }[]
  routes: Map<string, FakeRoute>
}

export function fakeApi(routes: Record<string, FakeRoute>): FakeApi {
  const table = new Map(Object.entries(routes))
  const calls: { method: string; path: string; body?: unknown }[] = []

  function lookup(path: string): FakeRoute | undefined {
    return table.get(path) ?? table.get(path.split('?')[0] ?? path)
  }

  function request<T>(
    path: string,
    options: { method?: string; body?: unknown } = {},
  ): Promise<T> {
    const method = options.method ?? 'GET'
    calls.push({ method, path, body: options.body })
    const route = lookup(path)
    // Rejected, never thrown. The real client returns a rejected promise, and a
    // fake that throws synchronously would let a caller with a `.catch()` chain
    // pass here and fail in production.
    if (route === undefined) {
      return Promise.reject(new ApiError(404, 'not_found', `no fake route for ${path}`))
    }
    const status = route.status ?? 200
    if (status >= 400) {
      const payload = route.body as { error?: string; message?: string } | undefined
      return Promise.reject(
        new ApiError(status, payload?.error ?? 'error', payload?.message ?? 'failed'),
      )
    }
    return Promise.resolve(route.body as T)
  }

  const client: ApiClient = {
    request,
    send: (path: string) => {
      calls.push({ method: 'GET', path })
      const route = lookup(path)
      const status = route === undefined ? 404 : (route.status ?? 200)
      const body = route?.stream ?? ''
      return Promise.resolve(
        new Response(status >= 400 ? null : body, {
          status,
          headers: { 'Content-Type': 'text/event-stream' },
        }),
      )
    },
    get: <T,>(path: string) => request<T>(path),
    post: <T,>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  }

  return { client, calls, routes: table }
}

export function renderScreen(
  element: ReactElement,
  { path = '/', route = '/' }: { path?: string; route?: string } = {},
): RenderResult {
  const queries = new QueryClient({
    defaultOptions: { queries: { retry: false, gcTime: 0, staleTime: 0 } },
  })
  return render(
    <QueryClientProvider client={queries}>
      <MemoryRouter initialEntries={[path]}>
        <Routes>
          <Route path={route} element={element} />
        </Routes>
      </MemoryRouter>
    </QueryClientProvider>,
  )
}

// --- Fixtures ---------------------------------------------------------------

export const PROFILE: Profile = {
  id: 'u1',
  email: 'analyst@example.com',
  name: 'Test Analyst',
  role: 'senior_analyst',
}

export const CAPABILITIES: Capabilities = {
  role: 'senior_analyst',
  capabilities: ['view_investigations', 'run_investigations', 'approve_actions'],
}

export function stages(overrides: Partial<Record<string, Partial<PipelineStage>>> = {}) {
  const base: PipelineStage[] = [
    { name: 'log_analysis', label: 'Log analysis', complete: true, skipped: false, detail: null },
    {
      name: 'threat_detection',
      label: 'Threat detection',
      complete: true,
      skipped: false,
      detail: null,
    },
    { name: 'cve_research', label: 'CVE research', complete: false, skipped: false, detail: null },
    { name: 'report', label: 'Incident report', complete: true, skipped: false, detail: null },
    {
      name: 'remediation',
      label: 'Remediation plan',
      complete: true,
      skipped: false,
      detail: null,
    },
  ]
  return base.map((stage) => ({ ...stage, ...(overrides[stage.name] ?? {}) }))
}

export function snapshot(overrides: Partial<InvestigationSnapshot> = {}): InvestigationSnapshot {
  return {
    id: 'inv-1',
    status: 'awaiting_approval',
    severity: 'high',
    verdict: 'malicious',
    triage_priority: 'urgent',
    confidence: 0.82,
    awaiting_human: true,
    pipeline: stages(),
    event_count: 7,
    cve_count: 0,
    recommendation_count: 1,
    pending_approvals: 1,
    report_version: 1,
    updated_at: '2026-08-05T10:00:00Z',
    ...overrides,
  }
}
