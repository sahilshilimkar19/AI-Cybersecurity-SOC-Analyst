/**
 * Where the session lives in the browser.
 *
 * `sessionStorage`, not `localStorage`: the token dies with the tab rather than
 * persisting on a shared workstation until something explicitly clears it, which
 * on a SOC floor is the difference between a session and a standing credential.
 *
 * Neither store survives cross-site scripting, and pretending otherwise would be
 * dishonest. The platform's actual defense against token theft is that this
 * client never renders untrusted content as markup (see `SafeText`/`SafeLink`
 * and the lint rule that forbids `dangerouslySetInnerHTML`). Moving the refresh
 * token into an httpOnly cookie is the next hardening step and belongs to the
 * Security sprint, because it changes the auth endpoints' contract.
 */

import type { TokenPair } from '../api/types'

const ACCESS_KEY = 'soc.access_token'
const REFRESH_KEY = 'soc.refresh_token'
const LOGIN_STATE_KEY = 'soc.login_state'

function storage(): Storage | null {
  try {
    return window.sessionStorage
  } catch {
    // Storage can be unavailable (privacy mode, a sandboxed frame). The console
    // still works for the life of the page; it just cannot survive a reload.
    return null
  }
}

export const sessionTokens = {
  accessToken(): string | null {
    return storage()?.getItem(ACCESS_KEY) ?? null
  },
  refreshToken(): string | null {
    return storage()?.getItem(REFRESH_KEY) ?? null
  },
  set(tokens: TokenPair): void {
    const store = storage()
    if (store === null) return
    store.setItem(ACCESS_KEY, tokens.access_token)
    store.setItem(REFRESH_KEY, tokens.refresh_token)
  },
  clear(): void {
    const store = storage()
    if (store === null) return
    store.removeItem(ACCESS_KEY)
    store.removeItem(REFRESH_KEY)
    store.removeItem(LOGIN_STATE_KEY)
  },
}

/**
 * The OIDC `state` value, held across the redirect to the identity provider.
 *
 * Stored so the callback can refuse a response that does not correspond to a
 * login this tab actually started — the CSRF property `state` exists for. The
 * backend validates it too; this check is what stops the client from bothering
 * to exchange a code it never asked for.
 */
export const loginState = {
  remember(state: string): void {
    storage()?.setItem(LOGIN_STATE_KEY, state)
  },
  take(): string | null {
    const store = storage()
    const value = store?.getItem(LOGIN_STATE_KEY) ?? null
    store?.removeItem(LOGIN_STATE_KEY)
    return value
  },
}
