"""Authentication & authorization layer.

The platform is an OIDC Relying Party: identity is federated to an external IdP,
and after login the platform issues its own short-lived access token plus a
rotating refresh token backed by a server-side session store. Access control is
role-based (RBAC). See docs/ENGINEERING_DESIGN_SPEC.md §3.11 and §14, and
docs/adr/0003-authentication.md.
"""
