/**
 * Stream-loss recovery.
 *
 * The recovery design is the snapshot protocol: every event is whole, so
 * reconnecting is a fresh read rather than a reconciliation. What these tests
 * pin is the honesty around it — that a dropped connection is reported rather
 * than hidden, that the last snapshot stays on screen labelled stale instead of
 * the panel blanking, and that a settled investigation stops retrying.
 */

import { act, renderHook, waitFor } from '@testing-library/react'
import { describe, expect, it, vi } from 'vitest'

import type { ApiClient } from '../api/client'
import { useInvestigationStream } from './useInvestigationStream'

function body(text: string): Response {
  const encoder = new TextEncoder()
  return new Response(
    new ReadableStream<Uint8Array>({
      start(controller) {
        controller.enqueue(encoder.encode(text))
        controller.close()
      },
    }),
    { status: 200 },
  )
}

const SNAPSHOT = (status: string, events: number) =>
  `event: snapshot\nid: 1\ndata: ${JSON.stringify({
    id: 'inv-1',
    status,
    severity: 'high',
    verdict: 'malicious',
    triage_priority: 'urgent',
    confidence: 0.8,
    awaiting_human: status === 'awaiting_approval',
    pipeline: [],
    event_count: events,
    cve_count: 0,
    recommendation_count: 0,
    pending_approvals: 0,
    report_version: 1,
    updated_at: '2026-08-05T10:00:00Z',
  })}\n\n`

function clientReturning(...responses: (() => Response | Promise<never>)[]): ApiClient {
  let call = 0
  const send = vi.fn(() => {
    const next = responses[Math.min(call, responses.length - 1)]
    call += 1
    return Promise.resolve(next?.() ?? new Response(null, { status: 500 }))
  })
  return { send } as unknown as ApiClient
}

const immediate = { delayFor: () => 0 }

describe('useInvestigationStream', () => {
  it('goes live and exposes the snapshot the server sent', async () => {
    const client = clientReturning(() => body(SNAPSHOT('in_progress', 3)))

    const { result } = renderHook(() => useInvestigationStream(client, 'inv-1', immediate))

    await waitFor(() => expect(result.current.snapshot?.event_count).toBe(3))
  })

  it('ends without retrying when the server says the case has settled', async () => {
    const client = clientReturning(
      () => body(`${SNAPSHOT('closed', 5)}event: end\ndata: {}\n\n`),
    )

    const { result } = renderHook(() => useInvestigationStream(client, 'inv-1', immediate))

    await waitFor(() => expect(result.current.status).toBe('ended'))
    expect(result.current.snapshot?.status).toBe('closed')
  })

  it('keeps the last snapshot and marks it stale when the connection drops', async () => {
    let resolveSecond: (() => void) | null = null
    const client = clientReturning(
      () => body(SNAPSHOT('in_progress', 4)),
      // A connection that never delivers, so the hook stays in its post-drop state.
      () =>
        new Promise<never>(() => {
          resolveSecond = () => undefined
        }),
    )

    const { result } = renderHook(() => useInvestigationStream(client, 'inv-1', immediate))

    await waitFor(() => expect(result.current.snapshot?.event_count).toBe(4))
    // The body ended without an `end` event: that is a drop, not a completion.
    await waitFor(() => expect(result.current.stale).toBe(true))
    // The data an analyst was reading is still there.
    expect(result.current.snapshot?.event_count).toBe(4)
    expect(result.current.status).toBe('reconnecting')
    void resolveSecond
  })

  it('recovers by taking the next whole snapshot, with nothing to replay', async () => {
    const client = clientReturning(
      () => body(SNAPSHOT('in_progress', 4)),
      () => body(`${SNAPSHOT('closed', 9)}event: end\ndata: {}\n\n`),
    )

    const { result } = renderHook(() => useInvestigationStream(client, 'inv-1', immediate))

    await waitFor(() => expect(result.current.status).toBe('ended'))
    expect(result.current.snapshot?.event_count).toBe(9)
    expect(result.current.stale).toBe(false)
  })

  it('gives up after a bounded number of attempts rather than retrying forever', async () => {
    const client = clientReturning(() => new Response(null, { status: 503 }))

    const { result } = renderHook(() =>
      useInvestigationStream(client, 'inv-1', { delayFor: () => 0, maxAttempts: 2 }),
    )

    await waitFor(() => expect(result.current.status).toBe('failed'))
    expect(result.current.snapshot).toBeNull()
  })

  it('drops an unreadable frame rather than rendering it as state', async () => {
    const client = clientReturning(
      () => body('event: snapshot\ndata: {not json\n\n'),
      () => body(`${SNAPSHOT('closed', 2)}event: end\ndata: {}\n\n`),
    )

    const { result } = renderHook(() => useInvestigationStream(client, 'inv-1', immediate))

    await waitFor(() => expect(result.current.status).toBe('ended'))
    expect(result.current.snapshot?.event_count).toBe(2)
  })

  it('does nothing without an investigation to watch', () => {
    const client = clientReturning(() => body(''))
    const { result } = renderHook(() => useInvestigationStream(client, null, immediate))

    expect(result.current.snapshot).toBeNull()
  })

  it('stops streaming when the screen goes away', async () => {
    const client = clientReturning(() => body(SNAPSHOT('in_progress', 1)))
    const { result, unmount } = renderHook(() =>
      useInvestigationStream(client, 'inv-1', immediate),
    )

    await waitFor(() => expect(result.current.snapshot).not.toBeNull())
    act(() => {
      unmount()
    })
    // No assertion beyond "this does not throw or keep fetching": an aborted
    // controller is the only teardown the hook has to get right.
  })
})
