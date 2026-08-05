# `frontend/`

The analyst-facing **React / TypeScript SPA** (SAD §13): Dashboard, Investigation
workspace, Timeline, Threat Details, Reports, Notifications, and Settings —
including the human-approval UI and live investigation streaming.

State is **server-authoritative** (the backend is the source of truth); the client
renders and streams. Every AI-derived claim shows its confidence and provenance,
reinforcing "assist, not replace".

## Running it

```bash
npm ci                  # install exactly the pinned tree
npm run dev             # dev server on :5173
npm run lint            # eslint, warnings are errors
npm run typecheck       # tsc --noEmit
npm test                # vitest
npm run build           # type-check then bundle
```

The API origin is injected at build time and has **no default** — a bundle that
silently falls back to some other host is one that can send an analyst's bearer
token somewhere nobody chose:

```bash
VITE_API_BASE_URL=http://localhost:8000 npm run dev
```

The backend must list this app's origin in `SOC_CORS_ALLOWED_ORIGINS`, and
`SOC_OIDC_REDIRECT_URI` must point at this app's `/auth/callback` route so the
browser lands back on the console rather than on a JSON document.

## Layout

| Path | Contents |
|---|---|
| `src/api/` | The typed API contract, the HTTP client, and the query layer. |
| `src/auth/` | Session storage, the OIDC login/callback flow, and the capability context. |
| `src/realtime/` | The fetch-based SSE client and the investigation stream hook. |
| `src/components/` | Approval panel, confidence/provenance indicators, safe rendering, pipeline. |
| `src/pages/` | The seven screens. |
| `src/test/` | The fake-API harness and fixtures. |

## The decisions worth knowing before changing anything

**Untrusted content is never rendered as markup.** Everything on screen came from
a log line, an advisory, or a model. React escapes text; `SafeLink` refuses any
URL scheme other than http(s), and report bodies render as preformatted text
rather than through a Markdown-to-HTML step. `dangerouslySetInnerHTML` is a lint
error — changing that needs an ADR, not a pull request.

**The stream is `fetch`, not `EventSource`.** `EventSource` cannot send an
`Authorization` header, and putting a bearer token in a query string writes a
credential into access logs, proxy logs, and browser history.

**Every stream event is a whole snapshot.** That is what makes stream loss a
non-event: reconnect, take the next snapshot, done. There is no replay log and no
local state that could have drifted. During a reconnect the last snapshot stays
on screen *labelled stale* rather than the panel blanking.

**Capabilities come from the server.** The client asks `/system/capabilities`
rather than keeping its own copy of the RBAC table. Hiding a control the caller
cannot use is a courtesy; the backend re-checks on every request.

**The approval panel is built to slow the analyst down.** No primary button, no
preselected decision, and a required rationale for anything other than a plain
approval. It states, next to the buttons, that approving authorizes work rather
than performing it.

## Ownership
Frontend squad.

## Testing
Component + interaction tests; approval-flow tests; untrusted-content escaping;
stream-loss recovery. Screens are rendered against a fake API route table so the
real client and query layers run underneath the assertions.
