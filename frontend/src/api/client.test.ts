/**
 * HTTP client tests.
 *
 * The behavior worth pinning is the token refresh. A dashboard fires several
 * queries at once, so an expired token means several 401s arriving together —
 * and if each one rotates the refresh token independently, the backend sees the
 * old token replayed and (correctly) revokes the session. One refresh, awaited
 * by everyone, is what keeps a normal page load from looking like an attack.
 */

import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'

import { ApiError, createClient, resetRefreshState } from './client'
import type { TokenStore } from './client'
import type { TokenPair } from './types'

function store(initial: { access: string | null; refresh: string | null }): TokenStore & {
  state: { access: string | null; refresh: string | null }
  cleared: boolean
} {
  const state = { ...initial }
  const holder = {
    state,
    cleared: false,
    accessToken: () => state.access,
    refreshToken: () => state.refresh,
    set: (tokens: TokenPair) => {
      state.access = tokens.access_token
      state.refresh = tokens.refresh_token
    },
    clear: () => {
      state.access = null
      state.refresh = null
      holder.cleared = true
    },
  }
  return holder
}

function json(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { 'Content-Type': 'application/json' },
  })
}

/** The headers of the Nth fetch call, without indexing into a possibly-absent call. */
function headersOf(mock: { mock: { calls: unknown[][] } }, index: number): Record<string, string> {
  const call = mock.mock.calls.at(index)
  if (call === undefined) throw new Error(`no fetch call at index ${index}`)
  return (call[1] as { headers: Record<string, string> }).headers
}

const REFRESHED: TokenPair = {
  access_token: 'access-2',
  token_type: 'bearer',
  expires_in: 900,
  refresh_token: 'refresh-2',
}

beforeEach(() => {
  resetRefreshState()
})

afterEach(() => {
  vi.unstubAllGlobals()
})

describe('authorization', () => {
  it('sends the bearer token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)

    await createClient(store({ access: 'access-1', refresh: 'refresh-1' })).get('/investigations')

    expect(headersOf(fetchMock, 0).Authorization).toBe('Bearer access-1')
  })

  it('sends no authorization header when there is no session', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ ok: true }))
    vi.stubGlobal('fetch', fetchMock)

    await createClient(store({ access: null, refresh: null })).get('/health')

    expect(headersOf(fetchMock, 0).Authorization).toBeUndefined()
  })
})

describe('token refresh', () => {
  it('refreshes once and retries the original request', async () => {
    const tokens = store({ access: 'expired', refresh: 'refresh-1' })
    const fetchMock = vi
      .fn()
      .mockResolvedValueOnce(json({ error: 'token_expired' }, 401))
      .mockResolvedValueOnce(json(REFRESHED))
      .mockResolvedValueOnce(json({ items: [] }))
    vi.stubGlobal('fetch', fetchMock)

    const body = await createClient(tokens).get<{ items: unknown[] }>('/investigations')

    expect(body.items).toEqual([])
    expect(tokens.state.access).toBe('access-2')
    expect(headersOf(fetchMock, 2).Authorization).toBe('Bearer access-2')
  })

  it('rotates only once when several requests hit an expired token together', async () => {
    const tokens = store({ access: 'expired', refresh: 'refresh-1' })
    const fetchMock = vi.fn((input: string) => {
      const path = String(input)
      if (path.endsWith('/auth/refresh')) return Promise.resolve(json(REFRESHED))
      if (tokens.state.access === 'expired')
        return Promise.resolve(json({ error: 'token_expired' }, 401))
      return Promise.resolve(json({ ok: true }))
    })
    vi.stubGlobal('fetch', fetchMock)

    const client = createClient(tokens)
    await Promise.all([client.get('/a'), client.get('/b'), client.get('/c')])

    const refreshes = fetchMock.mock.calls.filter(([input]) =>
      String(input).endsWith('/auth/refresh'),
    )
    // More than one would be a replay of the rotated token, which the backend
    // treats as session compromise — and correctly.
    expect(refreshes).toHaveLength(1)
  })

  it('clears the session when the refresh itself is refused', async () => {
    const tokens = store({ access: 'expired', refresh: 'stale' })
    vi.stubGlobal(
      'fetch',
      vi
        .fn()
        .mockResolvedValueOnce(json({ error: 'token_expired' }, 401))
        .mockResolvedValueOnce(json({ error: 'refresh_token_reuse' }, 401)),
    )

    await expect(createClient(tokens).get('/investigations')).rejects.toThrow(ApiError)
    expect(tokens.cleared).toBe(true)
  })

  it('does not try to refresh without a refresh token', async () => {
    const fetchMock = vi.fn().mockResolvedValue(json({ error: 'invalid_token' }, 401))
    vi.stubGlobal('fetch', fetchMock)

    await expect(
      createClient(store({ access: 'x', refresh: null })).get('/investigations'),
    ).rejects.toThrow(ApiError)
    expect(fetchMock).toHaveBeenCalledTimes(1)
  })
})

describe('errors', () => {
  it('carries the server error code through so the UI can distinguish causes', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(json({ error: 'conflict', message: 'already approved' }, 409)),
    )

    const failure = await createClient(store({ access: 'a', refresh: 'r' }))
      .post('/investigations/1/decision', {})
      .catch((error: unknown) => error)

    expect(failure).toBeInstanceOf(ApiError)
    const apiError = failure as ApiError
    expect(apiError.isConflict).toBe(true)
    expect(apiError.code).toBe('conflict')
    expect(apiError.message).toBe('already approved')
  })

  it.each([
    [403, 'isForbidden'],
    [404, 'isMissing'],
  ] as const)('classifies %i', async (status, flag) => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(json({ error: 'x' }, status)))

    const failure = (await createClient(store({ access: 'a', refresh: 'r' }))
      .get('/x')
      .catch((error: unknown) => error)) as ApiError
    expect(failure[flag]).toBe(true)
  })

  it('survives an error body that is not JSON', async () => {
    vi.stubGlobal(
      'fetch',
      vi.fn().mockResolvedValue(new Response('<html>gateway timeout</html>', { status: 504 })),
    )

    const failure = (await createClient(store({ access: 'a', refresh: 'r' }))
      .get('/x')
      .catch((error: unknown) => error)) as ApiError
    expect(failure.status).toBe(504)
  })

  it('handles a no-content response without trying to parse a body', async () => {
    vi.stubGlobal('fetch', vi.fn().mockResolvedValue(new Response(null, { status: 204 })))

    await expect(
      createClient(store({ access: 'a', refresh: 'r' })).post('/auth/logout'),
    ).resolves.toBeUndefined()
  })
})
