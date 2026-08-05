/**
 * Loading, empty, and error states.
 *
 * Kept together and used everywhere so that "we are still fetching", "there is
 * nothing here", and "we could not tell" never render the same way. On a console
 * where an empty list can mean "no threats found", showing the three states
 * identically is how an analyst comes to believe something that is not true.
 */

import type { ReactElement, ReactNode } from 'react'

export function Loading({ what }: { what: string }): ReactElement {
  return (
    <p className="state state-loading" role="status">
      Loading {what}…
    </p>
  )
}

export function Empty({ children }: { children: ReactNode }): ReactElement {
  return <p className="state state-empty">{children}</p>
}

export function Failed({ what, error }: { what: string; error: unknown }): ReactElement {
  const detail = error instanceof Error ? error.message : 'an unexpected error occurred'
  return (
    <p className="state state-error" role="alert">
      Could not load {what}: {detail}
    </p>
  )
}

/**
 * The stream's connection state.
 *
 * `stale` is shown separately from `status` because they answer different
 * questions: whether the console is currently connected, and whether what is on
 * screen can still be trusted. During a reconnect the last snapshot is kept and
 * labelled rather than blanked — an analyst mid-decision needs the data they
 * were reading more than they need an empty panel.
 */
export function StreamStatusBanner({
  status,
  stale,
}: {
  status: 'connecting' | 'live' | 'reconnecting' | 'ended' | 'failed'
  stale: boolean
}): ReactElement | null {
  if (status === 'live' && !stale) return null

  const messages: Record<string, string> = {
    connecting: 'Connecting to live updates…',
    reconnecting: 'Live updates interrupted — reconnecting. Showing the last known state.',
    ended: 'This investigation has settled; live updates have ended.',
    failed: 'Live updates could not be restored. Reload to try again.',
    live: 'Showing the last known state while updates catch up.',
  }

  return (
    <p className={`stream-status stream-${status}`} role="status">
      {messages[status]}
    </p>
  )
}
