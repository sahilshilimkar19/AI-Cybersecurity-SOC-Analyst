"""Memory layer — tiered memory managers behind clean interfaces.

Working, session (two-tier hot/durable), conversation, long-term, knowledge, and
investigation-history memory. Agents access memory only through these managers,
never the underlying stores.

Implemented in the Memory Layer sprint.
See docs/ENGINEERING_DESIGN_SPEC.md §7.
"""
