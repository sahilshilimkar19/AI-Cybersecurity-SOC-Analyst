/**
 * Wire-format tests for the event stream.
 *
 * The parser exists because `EventSource` cannot send an `Authorization` header,
 * so the console reads the stream through `fetch`. Having written the parser, the
 * property worth pinning is that a frame is only dispatched once a blank line
 * terminates it: half a snapshot delivered as if it were whole is worse than no
 * snapshot, because it looks like state.
 */

import { describe, expect, it, vi } from 'vitest'

import { backoffDelay, consumeStream, drainFrames, parseFrame } from './stream'

function sse(...chunks: string[]): Response {
  const encoder = new TextEncoder()
  const body = new ReadableStream<Uint8Array>({
    start(controller) {
      for (const chunk of chunks) controller.enqueue(encoder.encode(chunk))
      controller.close()
    },
  })
  return new Response(body, { headers: { 'Content-Type': 'text/event-stream' } })
}

describe('parseFrame', () => {
  it('reads the event name, id, and data', () => {
    expect(parseFrame('event: snapshot\nid: 3\ndata: {"status":"open"}')).toEqual({
      event: 'snapshot',
      id: '3',
      data: '{"status":"open"}',
    })
  })

  it('joins multi-line data with newlines', () => {
    expect(parseFrame('event: x\ndata: one\ndata: two')?.data).toBe('one\ntwo')
  })

  it('treats a keep-alive comment as no event at all', () => {
    expect(parseFrame(': keep-alive')).toBeNull()
  })

  it('defaults the event name when the server omits it', () => {
    expect(parseFrame('data: {}')?.event).toBe('message')
  })

  it('strips exactly one leading space, which is framing rather than value', () => {
    expect(parseFrame('data:  padded')?.data).toBe(' padded')
  })
})

describe('drainFrames', () => {
  it('returns completed frames and keeps the unterminated tail', () => {
    const { events, rest } = drainFrames('event: a\ndata: 1\n\nevent: b\ndata: 2')

    expect(events).toHaveLength(1)
    expect(events[0]?.data).toBe('1')
    expect(rest).toBe('event: b\ndata: 2')
  })

  it('emits nothing from a buffer with no terminated frame', () => {
    expect(drainFrames('event: a\ndata: par').events).toEqual([])
  })
})

describe('consumeStream', () => {
  it('dispatches a frame split across two network chunks exactly once', async () => {
    const onEvent = vi.fn()
    await consumeStream(sse('event: snapshot\nda', 'ta: {"status":"open"}\n\n'), {
      onEvent,
      onClose: vi.fn(),
      onError: vi.fn(),
    })

    expect(onEvent).toHaveBeenCalledTimes(1)
    expect(onEvent.mock.calls[0]?.[0].data).toBe('{"status":"open"}')
  })

  it('reports a server-sent end as a final close', async () => {
    const onClose = vi.fn()
    await consumeStream(sse('event: snapshot\ndata: {}\n\nevent: end\ndata: {}\n\n'), {
      onEvent: vi.fn(),
      onClose,
      onError: vi.fn(),
    })

    expect(onClose).toHaveBeenCalledWith(true)
  })

  it('reports a body that just stops as a non-final close', async () => {
    const onClose = vi.fn()
    await consumeStream(sse('event: snapshot\ndata: {}\n\n'), {
      onEvent: vi.fn(),
      onClose,
      onError: vi.fn(),
    })

    expect(onClose).toHaveBeenCalledWith(false)
  })

  it('closes cleanly when there is no body to read', async () => {
    const onClose = vi.fn()
    await consumeStream(new Response(null, { status: 200 }), {
      onEvent: vi.fn(),
      onClose,
      onError: vi.fn(),
    })

    expect(onClose).toHaveBeenCalledWith(false)
  })
})

describe('backoffDelay', () => {
  it('grows exponentially so a fallen-over backend is not stampeded', () => {
    expect(backoffDelay(1)).toBe(1_000)
    expect(backoffDelay(2)).toBe(2_000)
    expect(backoffDelay(3)).toBe(4_000)
  })

  it('is capped', () => {
    expect(backoffDelay(20)).toBe(30_000)
  })
})
