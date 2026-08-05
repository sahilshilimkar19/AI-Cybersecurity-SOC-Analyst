/**
 * The HTTP client. One place that knows how to talk to the backend.
 *
 * Three things it does that matter.
 *
 * **It never guesses a base URL.** The API origin is injected at build time; a
 * bundle that silently defaults to some other host is one that can send an
 * analyst's bearer token somewhere nobody chose.
 *
 * **It refreshes exactly once per failed request, and serializes refreshes.** A
 * dashboard fires several queries at once; without a single in-flight refresh
 * promise, an expired token produces a burst of parallel rotations, and rotation
 * is precisely what the backend treats as replay when it sees the old token
 * again. One refresh, awaited by everyone.
 *
 * **It surfaces the server's error code.** The UI distinguishes "you cannot do
 * this" from "this no longer exists" from "someone already decided", and it can
 * only do that if the code survives the transport.
 */

import type { TokenPair } from './types'

export const API_BASE_URL: string = import.meta.env.VITE_API_BASE_URL ?? ''

export class ApiError extends Error {
  readonly status: number
  readonly code: string

  constructor(status: number, code: string, message: string) {
    super(message)
    this.name = 'ApiError'
    this.status = status
    this.code = code
  }

  /** Whether the caller is authenticated but not permitted (as opposed to unknown). */
  get isForbidden(): boolean {
    return this.status === 403
  }

  get isMissing(): boolean {
    return this.status === 404
  }

  /** Someone already decided, or the state moved underneath the request. */
  get isConflict(): boolean {
    return this.status === 409
  }
}

export interface TokenStore {
  accessToken(): string | null
  refreshToken(): string | null
  set(tokens: TokenPair): void
  clear(): void
}

export interface RequestOptions {
  method?: string
  body?: unknown
  signal?: AbortSignal
  /** Set when the request must not attempt a token refresh (the refresh itself). */
  skipRefresh?: boolean
}

let inFlightRefresh: Promise<boolean> | null = null

/** Reset the shared refresh state. Exists for tests; production never needs it. */
export function resetRefreshState(): void {
  inFlightRefresh = null
}

function url(path: string): string {
  return `${API_BASE_URL}${path}`
}

async function toError(response: Response): Promise<ApiError> {
  let code = 'error'
  let message = response.statusText || 'request failed'
  try {
    const body: unknown = await response.json()
    if (body !== null && typeof body === 'object') {
      const payload = body as { error?: unknown; message?: unknown; detail?: unknown }
      if (typeof payload.error === 'string') code = payload.error
      if (typeof payload.message === 'string') message = payload.message
      else if (typeof payload.detail === 'string') message = payload.detail
    }
  } catch {
    // A body that is not JSON tells us nothing more than the status already did.
  }
  return new ApiError(response.status, code, message)
}

export function createClient(tokens: TokenStore) {
  async function refresh(): Promise<boolean> {
    const token = tokens.refreshToken()
    if (token === null) return false

    inFlightRefresh ??= (async () => {
      const response = await fetch(url('/auth/refresh'), {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ refresh_token: token }),
      })
      if (!response.ok) {
        tokens.clear()
        return false
      }
      tokens.set((await response.json()) as TokenPair)
      return true
    })().finally(() => {
      inFlightRefresh = null
    })

    return inFlightRefresh
  }

  async function send(path: string, options: RequestOptions = {}): Promise<Response> {
    const headers: Record<string, string> = { Accept: 'application/json' }
    const access = tokens.accessToken()
    if (access !== null) headers.Authorization = `Bearer ${access}`
    if (options.body !== undefined) headers['Content-Type'] = 'application/json'

    const init: RequestInit = {
      method: options.method ?? 'GET',
      headers,
      ...(options.body !== undefined ? { body: JSON.stringify(options.body) } : {}),
      ...(options.signal ? { signal: options.signal } : {}),
    }

    let response = await fetch(url(path), init)
    if (response.status === 401 && options.skipRefresh !== true && (await refresh())) {
      const retryHeaders = { ...headers }
      const renewed = tokens.accessToken()
      if (renewed !== null) retryHeaders.Authorization = `Bearer ${renewed}`
      response = await fetch(url(path), { ...init, headers: retryHeaders })
    }
    return response
  }

  async function request<T>(path: string, options: RequestOptions = {}): Promise<T> {
    const response = await send(path, options)
    if (!response.ok) throw await toError(response)
    if (response.status === 204) return undefined as T
    return (await response.json()) as T
  }

  return {
    request,
    /** Raw response access, for the event stream which reads a body incrementally. */
    send,
    get: <T>(path: string, signal?: AbortSignal) =>
      request<T>(path, signal ? { signal } : {}),
    post: <T>(path: string, body?: unknown) => request<T>(path, { method: 'POST', body }),
  }
}

export type ApiClient = ReturnType<typeof createClient>
