"""Models layer — canonical typed schemas and contracts shared across the system.

The single source of truth for shapes: domain entities, graph state, agent I/O,
DTOs, and events. Everything depends inward on these contracts (dependency
inversion / clean architecture).

Implemented in the Database + Models sprint.
See docs/ENGINEERING_DESIGN_SPEC.md §3.13 and §6.
"""
