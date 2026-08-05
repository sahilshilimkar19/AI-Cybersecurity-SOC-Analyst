/**
 * Composition root.
 *
 * The client and the query cache are built once here and handed down, so nothing
 * below this file reaches for a global. That is what lets every screen be
 * rendered in a test against a fake client without touching module state.
 */

import { QueryClient, QueryClientProvider } from '@tanstack/react-query'
import { StrictMode } from 'react'
import { createRoot } from 'react-dom/client'
import { BrowserRouter } from 'react-router'

import { App } from './App'
import { createClient } from './api/client'
import { sessionTokens } from './auth/session'
import './styles.css'

const client = createClient(sessionTokens)

const queries = new QueryClient({
  defaultOptions: {
    queries: {
      // Server-authoritative state: a stale read is refetched on focus rather
      // than trusted, because a security decision must reflect the record.
      staleTime: 10_000,
      refetchOnWindowFocus: true,
      retry: 1,
    },
  },
})

const container = document.getElementById('root')
if (container === null) throw new Error('missing #root')

createRoot(container).render(
  <StrictMode>
    <QueryClientProvider client={queries}>
      <BrowserRouter>
        <App client={client} />
      </BrowserRouter>
    </QueryClientProvider>
  </StrictMode>,
)
