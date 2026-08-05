/**
 * Subscribe to one investigation's live state.
 *
 * Stream loss is designed for rather than handled. Each event carries a whole
 * snapshot, so recovery is: reconnect, take the next snapshot, done — there is
 * no gap to replay and no local state that could have drifted. What the hook
 * adds is the honesty around it: `status` says whether the console is currently
 * live, and the last snapshot stays on screen labelled stale rather than being
 * blanked, because an analyst mid-decision needs the data they were reading more
 * than they need an empty panel.
 */

import { useCallback, useEffect, useRef, useState } from 'react'

import type { ApiClient } from '../api/client'
import type { InvestigationSnapshot } from '../api/types'
import { backoffDelay, consumeStream } from './stream'

export type StreamStatus = 'connecting' | 'live' | 'reconnecting' | 'ended' | 'failed'

export interface InvestigationStream {
  snapshot: InvestigationSnapshot | null
  status: StreamStatus
  /** Whether the displayed snapshot predates a connection loss. */
  stale: boolean
}

export interface StreamOptions {
  /** Injected in tests so reconnection can be exercised without real delays. */
  delayFor?: (attempt: number) => number
  maxAttempts?: number
}

export function useInvestigationStream(
  client: ApiClient,
  investigationId: string | null,
  options: StreamOptions = {},
): InvestigationStream {
  const [snapshot, setSnapshot] = useState<InvestigationSnapshot | null>(null)
  const [status, setStatus] = useState<StreamStatus>('connecting')
  const [stale, setStale] = useState(false)
  const { delayFor = backoffDelay, maxAttempts = 6 } = options
  const optionsRef = useRef({ delayFor, maxAttempts })
  optionsRef.current = { delayFor, maxAttempts }

  const sleep = useCallback((ms: number, signal: AbortSignal) => {
    return new Promise<void>((resolve) => {
      const timer = setTimeout(resolve, ms)
      signal.addEventListener('abort', () => {
        clearTimeout(timer)
        resolve()
      })
    })
  }, [])

  useEffect(() => {
    if (investigationId === null) return
    const controller = new AbortController()
    let attempt = 0
    let closed = false

    async function run(): Promise<void> {
      while (!controller.signal.aborted) {
        setStatus(attempt === 0 ? 'connecting' : 'reconnecting')
        let finished = false
        try {
          const response = await client.send(`/investigations/${investigationId}/stream`, {
            signal: controller.signal,
          })
          if (!response.ok) throw new Error(`stream refused with ${response.status}`)

          attempt = 0
          setStatus('live')
          setStale(false)

          await consumeStream(response, {
            onEvent: (event) => {
              if (event.event !== 'snapshot') return
              try {
                setSnapshot(JSON.parse(event.data) as InvestigationSnapshot)
                setStale(false)
              } catch {
                // A frame we cannot read is dropped rather than rendered; the
                // next whole snapshot supersedes it anyway.
              }
            },
            onClose: (final) => {
              finished = final
            },
            onError: () => {
              finished = false
            },
          })
        } catch {
          // Fall through to the backoff below; a failed connect is a retry.
        }

        if (controller.signal.aborted) return
        if (finished) {
          closed = true
          setStatus('ended')
          return
        }

        // The connection dropped without the server saying it was done, so what
        // is on screen may already be behind. Say so, then try again.
        setStale(true)
        attempt += 1
        if (attempt > optionsRef.current.maxAttempts) {
          setStatus('failed')
          return
        }
        setStatus('reconnecting')
        await sleep(optionsRef.current.delayFor(attempt), controller.signal)
      }
    }

    void run()
    return () => {
      if (!closed) controller.abort()
    }
  }, [client, investigationId, sleep])

  return { snapshot, status, stale }
}
