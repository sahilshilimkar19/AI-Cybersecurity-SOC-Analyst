# `frontend/`

The analyst-facing **React / TypeScript SPA** (SAD §13): Dashboard, Investigation workspace,
Timeline, Threat Details, Reports, Notifications, and Settings — including the human-approval
UI and live investigation streaming.

State is **server-authoritative** (the backend is the source of truth); the client renders and
streams. Every AI-derived claim shows its confidence and provenance, reinforcing
"assist, not replace".

> The frontend application is scaffolded and built in the **Frontend Dashboard** sprint. Only
> this placeholder exists during Bootstrap so the monorepo structure is complete.

## Ownership
Frontend squad.

## Testing
Component + interaction tests; approval-flow tests; untrusted-content escaping; stream-loss
recovery.
