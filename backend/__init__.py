"""Backend application tier — the API gateway, services, middleware, and workers.

This layer is the **sole write boundary** to the system of record (governing
invariant #7): all persistence, audit writes, orchestration invocation, and
notification dispatch flow through it.

Implementation is built out from the Authentication sprint onward.
See docs/ENGINEERING_DESIGN_SPEC.md §3.1.
"""
