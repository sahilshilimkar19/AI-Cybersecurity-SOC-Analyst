/**
 * Routing tests for the shell.
 *
 * The gate here is about *rendering*, not authorization: with no session the
 * console shows sign-in instead of the workspace. Every request the console then
 * makes is authorized independently by the backend, so a client-side bypass buys
 * an attacker an empty page rather than data.
 */

import { render, screen, waitFor } from '@testing-library/react'
import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { MemoryRouter } from 'react-router'
import { afterEach, beforeEach, describe, expect, it } from 'vitest'

import { App } from './App'
import { sessionTokens } from './auth/session'
import { CAPABILITIES, PROFILE, fakeApi } from './test/harness'

function renderApp(path: string) {
  const api = fakeApi({
    '/auth/me': { body: PROFILE },
    '/system/capabilities': { body: CAPABILITIES },
    '/auth/login': { body: { authorization_url: 'https://idp.test/a', state: 's1' } },
    '/investigations': { body: { items: [], total: 0, limit: 25, offset: 0 } },
    '/investigations?status=awaiting_approval': {
      body: { items: [], total: 0, limit: 25, offset: 0 },
    },
    '/notifications': { body: { items: [], total: 0, limit: 25, offset: 0 } },
  })
  const queries = new QueryClient({ defaultOptions: { queries: { retry: false, gcTime: 0 } } })
  render(
    <QueryClientProvider client={queries}>
      <MemoryRouter initialEntries={[path]}>
        <App client={api.client} />
      </MemoryRouter>
    </QueryClientProvider>,
  )
  return api
}

beforeEach(() => {
  window.sessionStorage.clear()
})

afterEach(() => {
  window.sessionStorage.clear()
})

describe('App', () => {
  it('shows sign-in rather than the workspace without a session', () => {
    renderApp('/')

    expect(screen.getByRole('button', { name: /sign in with sso/i })).toBeInTheDocument()
    expect(screen.queryByRole('navigation', { name: 'Main' })).toBeNull()
  })

  it('renders the console once a session exists', async () => {
    sessionTokens.set({
      access_token: 'a',
      token_type: 'bearer',
      expires_in: 900,
      refresh_token: 'r',
    })
    renderApp('/')

    await waitFor(() => expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument())
    expect(screen.getByRole('navigation', { name: 'Main' })).toBeInTheDocument()
  })

  it('states what the console is for, in the footer, on every screen', async () => {
    sessionTokens.set({
      access_token: 'a',
      token_type: 'bearer',
      expires_in: 900,
      refresh_token: 'r',
    })
    renderApp('/settings')

    await waitFor(() =>
      expect(screen.getByText(/It recommends; it never acts on its own/)).toBeInTheDocument(),
    )
  })

  it('sends an unknown path back to the dashboard', async () => {
    sessionTokens.set({
      access_token: 'a',
      token_type: 'bearer',
      expires_in: 900,
      refresh_token: 'r',
    })
    renderApp('/nowhere')

    await waitFor(() =>
      expect(screen.getByRole('heading', { name: 'Dashboard' })).toBeInTheDocument(),
    )
  })

  it('reaches the callback route without a session, so sign-in can complete', () => {
    renderApp('/auth/callback?code=x&state=y')

    // Not the sign-in page: the callback has to be able to run for an
    // unauthenticated browser, which is the entire point of it.
    expect(screen.queryByRole('button', { name: /sign in with sso/i })).toBeNull()
  })
})
