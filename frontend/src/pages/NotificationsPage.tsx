/**
 * Alert history and delivery status (SAD §13).
 *
 * There is no compose form here, and there is not going to be one. Alerting is
 * initiated by an approval at the human gate; a send button on this screen would
 * be a second entrance to the outbound path, one an analyst could drive without
 * a decision behind it.
 *
 * The screen leads with the dead-letter count. An alert nobody received is the
 * failure this whole subsystem exists to make impossible to miss, and a queue of
 * them discoverable only by scrolling is a queue that stays undiscovered.
 *
 * Retry is offered only on a delivery that failed, and its label says "retry"
 * rather than "resend" on purpose. Re-sending an alert someone already received
 * is a new notification and needs a new approval — the backend refuses it, and
 * the wording here should not suggest otherwise.
 */

import { useState } from 'react'
import type { ReactElement } from 'react'
import { useParams } from 'react-router'

import type { ApiClient } from '../api/client'
import { useNotifications, useRetryNotification } from '../api/queries'
import type { NotificationRecord, NotificationStatus } from '../api/types'
import { useAuth } from '../auth/AuthContext'
import { PriorityBadge } from '../components/Indicators'
import { Empty, Failed, Loading } from '../components/States'

const STATUS_FILTERS: { value: NotificationStatus | 'all'; label: string }[] = [
  { value: 'all', label: 'All' },
  { value: 'dead_letter', label: 'Undelivered' },
  { value: 'failed', label: 'Failed' },
  { value: 'sent', label: 'Sent' },
  { value: 'pending', label: 'Pending' },
]

/** Whether a delivery is in a state a retry could improve. */
function isRetryable(notification: NotificationRecord): boolean {
  return notification.status === 'failed' || notification.status === 'dead_letter'
}

function Row({
  notification,
  canRetry,
  retrying,
  onRetry,
}: {
  notification: NotificationRecord
  canRetry: boolean
  retrying: boolean
  onRetry: () => void
}): ReactElement {
  return (
    <tr className={`notification-${notification.status}`}>
      <td>
        {notification.sent_at === null
          ? 'not delivered'
          : new Date(notification.sent_at).toLocaleString()}
      </td>
      <td>{notification.channel}</td>
      <td>{notification.recipient}</td>
      <td>
        <PriorityBadge priority={notification.priority} />
      </td>
      <td>
        <span className={`badge notification-${notification.status}`}>
          {notification.status.replace(/_/g, ' ')}
        </span>
        {notification.failure_reason !== null && (
          <p className="failure-reason">{notification.failure_reason}</p>
        )}
      </td>
      <td className="numeric">{notification.delivery_attempts}</td>
      <td>
        {canRetry && isRetryable(notification) ? (
          <button type="button" disabled={retrying} onClick={onRetry}>
            {retrying ? 'Retrying…' : 'Retry delivery'}
          </button>
        ) : (
          <span className="no-action">—</span>
        )}
      </td>
    </tr>
  )
}

export function NotificationsPage({ client }: { client: ApiClient }): ReactElement {
  const { investigationId } = useParams<{ investigationId?: string }>()
  const [status, setStatus] = useState<NotificationStatus | 'all'>('all')
  const auth = useAuth()

  const notifications = useNotifications(client, {
    ...(investigationId ? { investigationId } : {}),
    ...(status === 'all' ? {} : { status }),
  })
  const retry = useRetryNotification(client)
  const canRetry = auth.can('approve_actions')

  const deadLettered = notifications.data?.dead_lettered ?? 0

  return (
    <div className="page page-notifications">
      <h1>Notifications</h1>
      <p className="section-note">
        Outbound alerting is dispatched only after a recorded human approval. This view is the
        record of what was sent; alerts are not composed here.
      </p>

      {deadLettered > 0 && (
        <p role="alert" className="state state-error">
          {deadLettered} alert{deadLettered === 1 ? '' : 's'} reached nobody on any channel. Each
          one had an approval behind it and still went undelivered.
        </p>
      )}

      <section className="filters" aria-label="Delivery status">
        {STATUS_FILTERS.map((filter) => (
          <button
            key={filter.value}
            type="button"
            className={status === filter.value ? 'filter filter-active' : 'filter'}
            aria-pressed={status === filter.value}
            onClick={() => setStatus(filter.value)}
          >
            {filter.label}
          </button>
        ))}
      </section>

      {retry.isError && (
        <p role="alert" className="state state-error">
          {retry.error.message}
        </p>
      )}
      {retry.isSuccess && (
        <p role="status" className="state">
          {retry.data.delivered
            ? 'Delivered on retry.'
            : `Still undelivered: ${retry.data.detail || 'the channel refused the message'}`}
        </p>
      )}

      {notifications.isLoading && <Loading what="notification history" />}
      {notifications.isError && <Failed what="notification history" error={notifications.error} />}
      {notifications.data !== undefined &&
        (notifications.data.items.length === 0 ? (
          <Empty>
            No notifications have been recorded
            {investigationId === undefined ? '' : ' for this investigation'}. Alerting sends
            nothing until a channel is configured and an analyst approves an investigation.
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
                <th scope="col">Priority</th>
                <th scope="col">Delivery</th>
                <th scope="col">Attempts</th>
                <th scope="col">Action</th>
              </tr>
            </thead>
            <tbody>
              {notifications.data.items.map((notification) => (
                <Row
                  key={notification.id}
                  notification={notification}
                  canRetry={canRetry}
                  retrying={retry.isPending && retry.variables === notification.id}
                  onRetry={() => retry.mutate(notification.id)}
                />
              ))}
            </tbody>
          </table>
        ))}
    </div>
  )
}
