/**
 * The application shell and its routes.
 *
 * Seven screens (SAD §13), plus the sign-in pair. The shell is thin on purpose:
 * navigation, the signed-in identity, and an outlet. Anything that reasons about
 * data belongs on a screen, and anything that reasons about permission belongs
 * on the server.
 */

import type { ReactElement } from 'react'
import { NavLink, Navigate, Outlet, Route, Routes } from 'react-router'

import type { ApiClient } from './api/client'
import { AuthProvider, useAuth } from './auth/AuthContext'
import { DashboardPage } from './pages/DashboardPage'
import { InvestigationPage } from './pages/InvestigationPage'
import { NotificationsPage } from './pages/NotificationsPage'
import { ReportsPage } from './pages/ReportsPage'
import { SettingsPage } from './pages/SettingsPage'
import { CallbackPage, SignInPage } from './pages/SignInPage'
import { ThreatDetailsPage } from './pages/ThreatDetailsPage'
import { TimelinePage } from './pages/TimelinePage'

function Shell(): ReactElement {
  const auth = useAuth()
  return (
    <div className="shell">
      <header className="shell-header">
        <span className="brand">AI SOC Analyst</span>
        <nav aria-label="Main">
          <NavLink to="/">Dashboard</NavLink>
          <NavLink to="/notifications">Notifications</NavLink>
          <NavLink to="/settings">Settings</NavLink>
        </nav>
        <span className="identity">
          {auth.profile === null ? '' : `${auth.profile.name} · ${auth.profile.role}`}
        </span>
      </header>
      <main className="shell-main">
        <Outlet />
      </main>
      <footer className="shell-footer">
        This console assists analysts. It recommends; it never acts on its own.
      </footer>
    </div>
  )
}

/**
 * Gate the shell on having a session at all.
 *
 * This is routing, not authorization: it decides whether to render a sign-in
 * page or the console. Every request the console then makes is authorized
 * independently by the backend.
 */
function RequireSession({ client }: { client: ApiClient }): ReactElement {
  const auth = useAuth()
  if (!auth.signedIn) return <SignInPage client={client} />
  return <Shell />
}

export function App({ client }: { client: ApiClient }): ReactElement {
  return (
    <AuthProvider client={client}>
      <Routes>
        <Route path="/auth/callback" element={<CallbackPage client={client} />} />
        <Route element={<RequireSession client={client} />}>
          <Route index element={<DashboardPage client={client} />} />
          <Route
            path="/investigations/:investigationId"
            element={<InvestigationPage client={client} />}
          />
          <Route
            path="/investigations/:investigationId/timeline"
            element={<TimelinePage client={client} />}
          />
          <Route
            path="/investigations/:investigationId/threat"
            element={<ThreatDetailsPage client={client} />}
          />
          <Route
            path="/investigations/:investigationId/report"
            element={<ReportsPage client={client} />}
          />
          <Route
            path="/investigations/:investigationId/notifications"
            element={<NotificationsPage client={client} />}
          />
          <Route path="/notifications" element={<NotificationsPage client={client} />} />
          <Route path="/settings" element={<SettingsPage />} />
          <Route path="*" element={<Navigate to="/" replace />} />
        </Route>
      </Routes>
    </AuthProvider>
  )
}
