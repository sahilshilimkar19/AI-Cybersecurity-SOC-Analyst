"""Services layer — cross-cutting domain logic reused beyond a single agent or the
HTTP layer (for example severity scoring and risk prioritization).

Deterministic and side-effect-free where possible, with no dependency on
transport or any specific agent. Populated as shared domain rules are introduced.
See docs/ENGINEERING_DESIGN_SPEC.md §3.8.
"""
