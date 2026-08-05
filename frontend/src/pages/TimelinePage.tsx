/**
 * The chronological reconstruction (SAD §13).
 *
 * Every row can show where it came from, because an event that cannot say that
 * is not evidence — it is a claim. Provenance is collapsed by default and
 * expandable per row rather than hidden behind a separate screen: an analyst
 * checking one suspicious line should not lose their place in the sequence to do
 * it.
 *
 * Truncation is stated. A timeline silently cut at 500 events reads as a
 * complete account of the incident, which is exactly the mistake that gets a
 * later stage of an intrusion missed.
 */

import { useState } from 'react'
import type { ReactElement } from 'react'
import { useParams } from 'react-router'

import type { ApiClient } from '../api/client'
import { useTimeline } from '../api/queries'
import type { TimelineEvent } from '../api/types'
import { ProvenanceList } from '../components/Indicators'
import { Empty, Failed, Loading } from '../components/States'

function EventRow({ event }: { event: TimelineEvent }): ReactElement {
  const [open, setOpen] = useState(false)
  return (
    <li className="timeline-event">
      <div className="event-line">
        <time dateTime={event.event_time}>{new Date(event.event_time).toLocaleString()}</time>
        <span className="event-type">{event.event_type}</span>
        <span className="event-source">{event.source}</span>
        <span className="event-actor">{event.actor ?? 'no actor recorded'}</span>
        <span className="event-notability" title="How notable this event was judged">
          {event.notability.toFixed(2)}
        </span>
        <button type="button" onClick={() => setOpen((value) => !value)} aria-expanded={open}>
          {open ? 'Hide provenance' : 'Show provenance'}
        </button>
      </div>
      {open && (
        <div className="event-provenance">
          <ProvenanceList provenance={event.provenance} />
          {event.raw_ref !== null && (
            <p className="event-raw-ref">
              <strong>Original record:</strong> {event.raw_ref}
            </p>
          )}
        </div>
      )}
    </li>
  )
}

export function TimelinePage({ client }: { client: ApiClient }): ReactElement {
  const { investigationId = '' } = useParams<{ investigationId: string }>()
  const timeline = useTimeline(client, investigationId)

  if (timeline.isLoading) return <Loading what="the timeline" />
  if (timeline.isError) return <Failed what="the timeline" error={timeline.error} />
  if (timeline.data === undefined) return <Empty>No timeline is available.</Empty>

  return (
    <div className="page page-timeline">
      <h1>Timeline</h1>
      {timeline.data.truncated && (
        <p role="note" className="state state-warning">
          This view is truncated. More events were recorded than are shown here.
        </p>
      )}
      {timeline.data.events.length === 0 ? (
        <Empty>
          No events were normalized for this investigation. That may mean nothing was collected, or
          that nothing collected could be parsed — check the pipeline stages on the investigation.
        </Empty>
      ) : (
        <ol className="timeline">
          {timeline.data.events.map((event) => (
            <EventRow key={event.id} event={event} />
          ))}
        </ol>
      )}
    </div>
  )
}
