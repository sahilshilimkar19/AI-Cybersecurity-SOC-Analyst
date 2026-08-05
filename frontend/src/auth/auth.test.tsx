/**
 * Session and sign-in tests.
 *
 * The one here that is genuinely a security test is the `state` check on the
 * callback. A code arriving for a login this tab never started is the CSRF case
 * the OIDC `state` parameter exists to catch, and the console has to refuse to
 * exchange it rather than trading it for a session that belongs to someone else.
 */

import { render, screen, waitFor } from '@testing-library/react'
import { afterEach, beforeEach, describe, expect, it, vi } from 'vitest'
import { MemoryRouter, Route, Routes } from 'react-router'

import type { TokenPair } from '../api/types'
import { fakeApi } from '../test/harness'
import { CallbackPage } from '../pages/SignInPage'
import { SignInPage } from '../pages/SignInPage'
import { loginState, sessionTokens } from './session'

const TOKENS: TokenPair = {
  access_token: 'access-1',
  token_type: 'bearer',
  expires_in: 900,
  refresh_token: 'refresh-1',
}

beforeEach(() => {
  window.sessionStorage.clear()
})

afterEach(() => {
  window.sessionStorage.clear()
})

// --- Session storage --------------------------------------------------------

describe('sessionTokens', () => {
  it('round-trips a token pair', () => {
    sessionTokens.set(TOKENS)

    expect(sessionTokens.accessToken()).toBe('access-1')
    expect(sessionTokens.refreshToken()).toBe('refresh-1')
  })

  it('reports no session before sign-in', () => {
    expect(sessionTokens.accessToken()).toBeNull()
    expect(sessionTokens.refreshToken()).toBeNull()
  })

  it('clears both tokens and the pending login state', () => {
    sessionTokens.set(TOKENS)
    loginState.remember('state-1')

    sessionTokens.clear()

    expect(sessionTokens.accessToken()).toBeNull()
    expect(sessionTokens.refreshToken()).toBeNull()
    expect(loginState.take()).toBeNull()
  })

  it('keeps working when storage is unavailable', () => {
    // Privacy mode and sandboxed frames both throw on access. The console should
    // degrade to a session that does not survive a reload, not to a blank page.
    const descriptor = Object.getOwnPropertyDescriptor(window, 'sessionStorage')
    Object.defineProperty(window, 'sessionStorage', {
      configurable: true,
      get() {
        throw new Error('storage disabled')
      },
    })

    expect(() => sessionTokens.set(TOKENS)).not.toThrow()
    expect(sessionTokens.accessToken()).toBeNull()
    expect(() => sessionTokens.clear()).not.toThrow()
    expect(loginState.take()).toBeNull()
    expect(() => loginState.remember('x')).not.toThrow()

    if (descriptor) Object.defineProperty(window, 'sessionStorage', descriptor)
  })
})

describe('loginState', () => {
  it('is consumed exactly once, so a replayed callback finds nothing', () => {
    loginState.remember('state-1')

    expect(loginState.take()).toBe('state-1')
    expect(loginState.take()).toBeNull()
  })
})

// --- Sign-in ----------------------------------------------------------------

function renderCallback(client: ReturnType<typeof fakeApi>['client'], search: string) {
  return render(
    <MemoryRouter initialEntries={[`/auth/callback${search}`]}>
      <Routes>
        <Route path="/auth/callback" element={<CallbackPage client={client} />} />
        <Route path="/" element={<p>Dashboard</p>} />
      </Routes>
    </MemoryRouter>,
  )
}

describe('SignInPage', () => {
  it('holds no credential field; identity is federated', async () => {
    const api = fakeApi({
      '/auth/login': { body: { authorization_url: 'https://idp.test/authorize', state: 's1' } },
    })
    render(<SignInPage client={api.client} />)

    expect(screen.queryByLabelText(/password/i)).toBeNull()
    expect(screen.getByRole('button', { name: /sign in with sso/i })).toBeInTheDocument()
    await Promise.resolve()
  })

  it('surfaces a failure to start sign-in rather than hanging', async () => {
    const api = fakeApi({
      '/auth/login': { status: 503, body: { error: 'oidc_error', message: 'IdP unreachable' } },
    })
    render(<SignInPage client={api.client} />)

    screen.getByRole('button', { name: /sign in with sso/i }).click()

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('IdP unreachable'))
  })
})

describe('CallbackPage', () => {
  it('exchanges the code and stores the session when the state matches', async () => {
    loginState.remember('state-1')
    const api = fakeApi({ '/auth/callback': { body: TOKENS } })

    renderCallback(api.client, '?code=abc&state=state-1')

    await waitFor(() => expect(sessionTokens.accessToken()).toBe('access-1'))
    expect(screen.getByText('Dashboard')).toBeInTheDocument()
  })

  it('refuses a code for a login this browser never started', async () => {
    // No remembered state: this callback did not originate here.
    const api = fakeApi({ '/auth/callback': { body: TOKENS } })

    renderCallback(api.client, '?code=abc&state=attacker-state')

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/did not originate from this browser/),
    )
    expect(sessionTokens.accessToken()).toBeNull()
    // The exchange must not even be attempted.
    expect(api.calls.some((call) => call.path.startsWith('/auth/callback'))).toBe(false)
  })

  it('refuses a mismatched state', async () => {
    loginState.remember('state-1')
    const api = fakeApi({ '/auth/callback': { body: TOKENS } })

    renderCallback(api.client, '?code=abc&state=state-2')

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/did not originate from this browser/),
    )
    expect(sessionTokens.accessToken()).toBeNull()
  })

  it('reports a provider that returned no result', async () => {
    const api = fakeApi({ '/auth/callback': { body: TOKENS } })

    renderCallback(api.client, '?error=access_denied')

    await waitFor(() =>
      expect(screen.getByRole('alert')).toHaveTextContent(/did not return a sign-in result/),
    )
  })

  it('reports a failed exchange rather than leaving a half session', async () => {
    loginState.remember('state-1')
    const api = fakeApi({
      '/auth/callback': { status: 401, body: { error: 'oidc_error', message: 'expired state' } },
    })

    renderCallback(api.client, '?code=abc&state=state-1')

    await waitFor(() => expect(screen.getByRole('alert')).toHaveTextContent('expired state'))
    expect(sessionTokens.accessToken()).toBeNull()
  })
})

// --- Sign-out ---------------------------------------------------------------

describe('signing out', () => {
  it('clears the local session even if the server call fails', async () => {
    sessionTokens.set(TOKENS)
    const api = fakeApi({})
    const assign = vi.fn()
    Object.defineProperty(window, 'location', {
      configurable: true,
      value: { assign, href: '/' },
    })

    const { useAuth, AuthProvider } = await import('./AuthContext')
    const { QueryClient, QueryClientProvider } = await import('@tanstack/react-query')
    // A holder rather than a bare `let`: TypeScript cannot see that React calls
    // the component, so it narrows a directly-assigned local to `never`.
    const captured: { signOut: (() => void) | null } = { signOut: null }
    function Probe() {
      captured.signOut = useAuth().signOut
      return null
    }
    render(
      <QueryClientProvider client={new QueryClient({ defaultOptions: { queries: { retry: false } } })}>
        <AuthProvider client={api.client}>
          <Probe />
        </AuthProvider>
      </QueryClientProvider>,
    )

    captured.signOut?.()

    expect(sessionTokens.accessToken()).toBeNull()
    expect(assign).toHaveBeenCalledWith('/')
  })
})
