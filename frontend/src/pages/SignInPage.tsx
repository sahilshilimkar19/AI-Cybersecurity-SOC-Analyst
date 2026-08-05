/**
 * Sign-in and the OIDC callback.
 *
 * Identity is federated (SAD §14): this console holds no password field and
 * never sees a credential. It asks the backend for the provider's authorization
 * URL, sends the browser there, and exchanges the returned code through the
 * backend — which is the only party holding the client secret.
 *
 * The `state` value is kept in this tab across the redirect and checked before
 * the exchange. The backend validates it too; checking here is what stops the
 * console from exchanging a code it never asked for, which is the CSRF case
 * `state` exists to prevent.
 *
 * This flow requires `SOC_OIDC_REDIRECT_URI` to point at this app's
 * `/auth/callback` route rather than at the backend's, so the browser lands back
 * on the console instead of on a JSON document.
 */

import { useEffect, useState } from 'react'
import type { ReactElement } from 'react'
import { useNavigate, useSearchParams } from 'react-router'

import type { ApiClient } from '../api/client'
import type { TokenPair } from '../api/types'
import { loginState, sessionTokens } from '../auth/session'
import { Loading } from '../components/States'

export function SignInPage({ client }: { client: ApiClient }): ReactElement {
  const [error, setError] = useState<string | null>(null)
  const [starting, setStarting] = useState(false)

  async function beginLogin(): Promise<void> {
    setStarting(true)
    setError(null)
    try {
      const init = await client.get<{ authorization_url: string; state: string }>('/auth/login')
      loginState.remember(init.state)
      window.location.assign(init.authorization_url)
    } catch (cause) {
      setStarting(false)
      setError(cause instanceof Error ? cause.message : 'could not start sign-in')
    }
  }

  return (
    <div className="page page-signin">
      <h1>AI SOC Analyst</h1>
      <p>Sign in with your organization account to continue.</p>
      <button type="button" disabled={starting} onClick={() => void beginLogin()}>
        {starting ? 'Redirecting…' : 'Sign in with SSO'}
      </button>
      {error !== null && (
        <p role="alert" className="state state-error">
          {error}
        </p>
      )}
    </div>
  )
}

export function CallbackPage({ client }: { client: ApiClient }): ReactElement {
  const [params] = useSearchParams()
  const navigate = useNavigate()
  const [error, setError] = useState<string | null>(null)

  useEffect(() => {
    const code = params.get('code')
    const state = params.get('state')
    const expected = loginState.take()

    if (code === null || state === null) {
      setError('The identity provider did not return a sign-in result.')
      return
    }
    if (expected === null || expected !== state) {
      // A code arriving for a login this tab never started is exactly what the
      // state parameter exists to catch. Refuse it rather than exchange it.
      setError('This sign-in did not originate from this browser session.')
      return
    }

    client
      .get<TokenPair>(`/auth/callback?code=${encodeURIComponent(code)}&state=${encodeURIComponent(state)}`)
      .then((tokens) => {
        sessionTokens.set(tokens)
        void navigate('/', { replace: true })
      })
      .catch((cause: unknown) => {
        setError(cause instanceof Error ? cause.message : 'sign-in failed')
      })
  }, [client, navigate, params])

  if (error !== null) {
    return (
      <div className="page page-signin">
        <h1>Sign-in failed</h1>
        <p role="alert" className="state state-error">
          {error}
        </p>
        <a href="/">Start again</a>
      </div>
    )
  }
  return <Loading what="your session" />
}
