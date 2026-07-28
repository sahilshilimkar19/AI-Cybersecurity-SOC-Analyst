# ADR 0003 — Authentication and authorization

- **Status:** Accepted
- **Sprint:** Sprint 3 — Authentication
- **Deciders:** Lead Engineer

## Context

Sprint 3 introduces authentication, authorization, and the first HTTP surface (there is no
separate backend-skeleton sprint). The governing documents fix the security model: federated
**OIDC/SSO** with **no local password store**, **RBAC** (analyst → auditor), **short-lived
signed JWTs with refresh rotation**, deny-by-default authorization, and **audited** auth
events (SAD §14; EDS §3.11). Confirmed with the product owner: build a true OIDC Relying Party
(offline-testable) with server-side sessions + rotating refresh tokens.

## Decision

1. **FastAPI** is the web framework (typed, Pydantic-native, matches the SAD's "typed
   REST/streaming API"). The app is assembled by a factory with a lifespan that places runtime
   services on `app.state`. Endpoints are synchronous (run in a threadpool), consistent with
   the synchronous data layer (ADR 0002).
2. **OIDC Relying Party** using the authorization-code flow with **PKCE**. The platform
   validates the IdP's ID token (signature via **JWKS**, plus `iss`/`aud`/`exp`/`nonce`) and
   provisions the user from its claims. Signing-key resolution sits behind an interface so
   validation is unit-tested offline with a locally-generated key. There is no password store.
3. **The platform issues its own tokens:** a short-lived **access JWT** (HS256) plus an opaque
   **refresh token**. Refresh tokens are **single-use and rotated**; replay of a rotated token
   is treated as theft and **revokes the whole session** (reuse detection).
4. **Pluggable session store** — a `Protocol` with an in-memory implementation (tests/local)
   and a **Redis** implementation (real), mirroring the object-store pattern (ADR 0002). Short
   OIDC **login transactions** (state / nonce / PKCE verifier) are held server-side so the PKCE
   verifier never leaves the server.
5. **RBAC by capabilities:** roles map to capabilities; endpoint guards check capabilities
   (deny by default, least privilege). Object-level ownership checks build on this in later
   sprints.
6. **Middleware:** a request-context middleware assigns a correlation id and binds the
   structured-logging context; a simple per-process fixed-window **rate limiter** guards
   against bursts (distributed rate limiting is a later hardening concern).
7. **Auth audit:** login and logout are written to the append-only audit trail.
8. **Production safety:** configuration fails fast if the JWT secret is still the insecure dev
   default in the production environment.

## Consequences

- **Positive:** matches the architecture exactly (federated identity, no password store); fully
  testable **without a live IdP** (mock IdP via local keys / stub client); real logout and
  refresh-reuse revocation; clean separation of concerns behind interfaces.
- **Trade-offs:**
  - The access-token principal is derived from the token without a per-request session lookup,
    so an access token remains valid until it expires (short TTL) even after logout; refresh
    revocation is immediate. This is the standard access/refresh trade-off, documented here.
  - The rate limiter is per-process; a shared/distributed limiter is deferred.
  - OIDC provider discovery and the Redis store are exercised via integration paths and real
    deployments; unit tests use a stub OIDC client, locally-signed tokens, and (when
    `SOC_TEST_REDIS_URL` is set) a real Redis.
- **No schema change:** sessions live in Redis/memory, so Sprint 3 adds no database tables or
  migrations; it reuses `users` and `audit_logs`.
