/**
 * Settings (SAD §13).
 *
 * What is here is the caller's identity and the capabilities their role grants —
 * read from `/system/capabilities`, so the screen shows what the backend will
 * actually permit rather than what a table compiled into this bundle believes.
 *
 * What is deliberately *not* here: integration configuration, notification
 * channels and policies, model and provider settings, and auto-approval policy.
 * Each of those configures a subsystem that arrives in a later sprint, and a
 * settings form that writes configuration for something not yet built is a form
 * that lies about what it controls. They are listed below as pending rather than
 * omitted, because an analyst should be able to tell the difference between "not
 * available to you" and "not built yet".
 */

import type { ReactElement } from 'react'

import type { Capability } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { Loading } from '../components/States'

const CAPABILITY_LABELS: Record<Capability, string> = {
  view_investigations: 'View investigations',
  run_investigations: 'Trigger investigations',
  approve_actions: 'Record approval decisions',
  view_audit: 'Read the audit trail',
  manage_users: 'Manage users and roles',
  configure: 'Change platform configuration',
}

const PENDING_SETTINGS: { name: string; sprint: string }[] = [
  { name: 'Notification channels and policies', sprint: 'Notifications' },
  { name: 'Integration configuration and health', sprint: 'Deployment' },
  { name: 'Model and provider selection', sprint: 'AI layer' },
  { name: 'Auto-approval policy', sprint: 'Security hardening' },
]

export function SettingsPage(): ReactElement {
  const auth = useAuth()

  if (auth.loading) return <Loading what="your profile" />

  return (
    <div className="page page-settings">
      <h1>Settings</h1>

      <section aria-labelledby="identity-heading">
        <h2 id="identity-heading">Signed in as</h2>
        {auth.profile === null ? (
          <p>Not signed in.</p>
        ) : (
          <dl className="profile">
            <div>
              <dt>Name</dt>
              <dd>{auth.profile.name}</dd>
            </div>
            <div>
              <dt>Email</dt>
              <dd>{auth.profile.email}</dd>
            </div>
            <div>
              <dt>Role</dt>
              <dd>{auth.profile.role.replace(/_/g, ' ')}</dd>
            </div>
          </dl>
        )}
        <button type="button" onClick={auth.signOut}>
          Sign out
        </button>
      </section>

      <section aria-labelledby="capabilities-heading">
        <h2 id="capabilities-heading">What your role permits</h2>
        <p className="section-note">
          Enforced by the backend on every request. Controls this console hides are hidden as a
          courtesy, not as a control.
        </p>
        <ul className="capabilities">
          {(Object.keys(CAPABILITY_LABELS) as Capability[]).map((capability) => (
            <li key={capability} className={auth.can(capability) ? 'granted' : 'denied'}>
              <span className="capability-state">{auth.can(capability) ? 'yes' : 'no'}</span>
              <span className="capability-label">{CAPABILITY_LABELS[capability]}</span>
            </li>
          ))}
        </ul>
      </section>

      <section aria-labelledby="pending-heading">
        <h2 id="pending-heading">Not yet configurable</h2>
        <p className="section-note">
          These configure subsystems that have not shipped. They are listed so the absence is
          visible rather than mistaken for a permission you lack.
        </p>
        <ul className="pending-settings">
          {PENDING_SETTINGS.map((setting) => (
            <li key={setting.name}>
              {setting.name} <span className="badge badge-unset">{setting.sprint} sprint</span>
            </li>
          ))}
        </ul>
      </section>
    </div>
  )
}
