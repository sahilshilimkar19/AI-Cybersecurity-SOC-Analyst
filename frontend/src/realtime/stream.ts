/**
 * The investigation event stream.
 *
 * Built on `fetch` rather than `EventSource`, and that is not a preference.
 * `EventSource` cannot send an `Authorization` header, so using it would mean
 * putting a bearer token in a query string — where it lands in access logs,
 * proxy logs, and browser history. A streamed `fetch` body carries the header
 * like every other request, at the cost of parsing the wire format here.
 *
 * The format is small and the parser is exact about one thing: an event is only
 * dispatched when a blank line terminates it. A frame split across two network
 * chunks must not be delivered half-read, because half a snapshot is worse than
 * no snapshot — it looks like state.
 */

export interface StreamEvent {
  event: string
  data: string
  id: string | null
}

/** Parse a completed SSE frame. Returns null for comment-only frames (keep-alives). */
export function parseFrame(block: string): StreamEvent | null {
  let event = 'message'
  let id: string | null = null
  const data: string[] = []

  for (const line of block.split('\n')) {
    if (line === '' || line.startsWith(':')) continue
    const separator = line.indexOf(':')
    const field = separator === -1 ? line : line.slice(0, separator)
    // One optional space after the colon is part of the framing, not the value.
    const rawValue = separator === -1 ? '' : line.slice(separator + 1)
    const value = rawValue.startsWith(' ') ? rawValue.slice(1) : rawValue

    if (field === 'event') event = value
    else if (field === 'data') data.push(value)
    else if (field === 'id') id = value
  }

  if (data.length === 0) return null
  return { event, data: data.join('\n'), id }
}

/**
 * Split a buffer into completed frames plus whatever remains unterminated.
 *
 * The remainder is handed back rather than dispatched: it is the tail of a frame
 * whose rest has not arrived.
 */
export function drainFrames(buffer: string): { events: StreamEvent[]; rest: string } {
  const blocks = buffer.split('\n\n')
  const rest = blocks.pop() ?? ''
  const events: StreamEvent[] = []
  for (const block of blocks) {
    const parsed = parseFrame(block)
    if (parsed !== null) events.push(parsed)
  }
  return { events, rest }
}

export interface StreamHandlers {
  onEvent(event: StreamEvent): void
  /** Called when the connection ends, with whether the server said it was final. */
  onClose(final: boolean): void
  onError(error: unknown): void
}

/**
 * Consume an SSE response body, dispatching each completed frame.
 *
 * Returns when the body ends. A server-sent `end` event marks the close as
 * final: it means the investigation settled, and reconnecting would only
 * re-deliver a state that will not change again.
 */
export async function consumeStream(
  response: Response,
  handlers: StreamHandlers,
): Promise<void> {
  const body = response.body
  if (!body) {
    handlers.onClose(false)
    return
  }

  const reader = body.pipeThrough(new TextDecoderStream()).getReader()
  let buffer = ''
  let final = false

  try {
    for (;;) {
      const { done, value } = await reader.read()
      if (done) break
      buffer += value
      const drained = drainFrames(buffer)
      buffer = drained.rest
      for (const event of drained.events) {
        if (event.event === 'end') final = true
        handlers.onEvent(event)
      }
    }
  } catch (error) {
    handlers.onError(error)
  } finally {
    reader.releaseLock()
    handlers.onClose(final)
  }
}

/**
 * How long to wait before reconnecting after the Nth consecutive failure.
 *
 * Exponential with a ceiling, because a backend that just fell over should not
 * then be hit by every open console at once.
 */
export function backoffDelay(attempt: number, base = 1_000, ceiling = 30_000): number {
  return Math.min(ceiling, base * 2 ** Math.max(0, attempt - 1))
}
