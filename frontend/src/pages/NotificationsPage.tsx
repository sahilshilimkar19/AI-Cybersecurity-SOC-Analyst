/**
 * Alert history and delivery status (SAD §13).
 *
 * Read-only, because there is nothing to send yet: dispatch arrives with the
 * Notifications sprint, together with the post-approval enforcement, dedupe, and
 * cross-channel failover built to guard it. A resend button here ahead of those
 * controls would be a way to send an alert that no approval authorized.
 *
 * The column worth having is the last one. A notification with no linked human
 * approval is the thing an auditor is looking for, so its absence is rendered
 * explicitly rather than as a blank cell.
 */

import type { ReactElement } from 'react'
import { useParams } from 'react-router'

import type { ApiClient } from '../api/client'
import { useNotifications } from '../api/queries'
import { Empty, Failed, Loading } from '../components/States'

export function NotificationsPage({ client }: { client: ApiClient }): ReactElement {
  const { investigationId } = useParams<{ investigationId?: string }>()
  const notifications = useNotifications(client, investigationId)

  return (
    <div className="page page-notifications">
      <h1>Notifications</h1>
      <p className="section-note">
        Outbound alerting is dispatched only after a recorded human approval. This view is the
        record of what was sent; sending is not available from this console.
      </p>

      {notifications.isLoading && <Loading what="notification history" />}
      {notifications.isError && (
        <Failed what="notification history" error={notifications.error} />
      )}
      {notifications.data !== undefined &&
        (notifications.data.items.length === 0 ? (
          <Empty>
            No notifications have been recorded
            {investigationId === undefined ? '' : ' for this investigation'}.
          </Empty>
        ) : (
          <table className="notifications">
            <caption>
              {notifications.data.items.length} of {notifications.data.total}
            </caption>
            <thead>
              <tr>
                <th scope="col">Sent</th>
                <th scope="col">Channel</th>
                <th scope="col">Recipient</th>
                <th scope="col">Status</th>
                <th scope="col">Attempts</th>
                <th scope="col">Linked approval</th>
              </tr>
            </thead>
            <tbody>
              {notifications.data.items.map((notification) => (
                <tr key={notification.id} className={`notification-${notification.status}`}>
                  <td>
                    {notification.sent_at === null
                      ? 'not sent'
                      : new Date(notification.sent_at).toLocaleString()}
                  </td>
                  <td>{notification.channel}</td>
                  <td>{notification.recipient}</td>
                  <td>
                    <span className={`badge notification-${notification.status}`}>
                      {notification.status.replace(/_/g, ' ')}
                    </span>
                  </td>
                  <td className="numeric">{notification.delivery_attempts}</td>
                  <td>
                    {notification.approval_id === null ? (
                      <span className="badge badge-warning">no linked approval</span>
                    ) : (
                      <span className="approval-ref">{notification.approval_id}</span>
                    )}
                  </td>
                </tr>
              ))}
            </tbody>
          </table>
        ))}
    </div>
  )
}
