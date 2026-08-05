/**
 * Who is signed in, and what the server says they may do.
 *
 * The capability list comes from `/system/capabilities` rather than from a role
 * table compiled into the bundle. Two reasons: a second copy of an access-control
 * rule is a copy that drifts, and the one in the browser would be the copy the
 * interface obeys. Hiding a control the caller cannot use is a courtesy — the
 * backend re-checks on every request regardless of what was rendered.
 */

import { createContext, useContext, useMemo } from 'react'
import type { ReactElement, ReactNode } from 'react'

import type { ApiClient } from '../api/client'
import { useCapabilities, useProfile } from '../api/queries'
import type { Capability, Profile } from '../api/types'
import { sessionTokens } from './session'

export interface AuthState {
  profile: Profile | null
  capabilities: Capability[]
  loading: boolean
  signedIn: boolean
  can: (capability: Capability) => boolean
  signOut: () => void
}

const AuthContext = createContext<AuthState | null>(null)

export function AuthProvider({
  client,
  children,
}: {
  client: ApiClient
  children: ReactNode
}): ReactElement {
  const signedIn = sessionTokens.accessToken() !== null
  const profile = useProfile(client)
  const capabilities = useCapabilities(client)

  const value = useMemo<AuthState>(() => {
    const granted = capabilities.data?.capabilities ?? []
    return {
      profile: profile.data ?? null,
      capabilities: granted,
      loading: signedIn && (profile.isLoading || capabilities.isLoading),
      signedIn,
      can: (capability: Capability) => granted.includes(capability),
      signOut: () => {
        // The session is revoked server-side too, but the local clear happens
        // first and unconditionally: a failed logout call must not leave a
        // usable token sitting in the tab.
        sessionTokens.clear()
        void client.post('/auth/logout').catch(() => undefined)
        window.location.assign('/')
      },
    }
  }, [client, capabilities.data, capabilities.isLoading, profile.data, profile.isLoading, signedIn])

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>
}

export function useAuth(): AuthState {
  const value = useContext(AuthContext)
  if (value === null) throw new Error('useAuth must be used inside an AuthProvider')
  return value
}
