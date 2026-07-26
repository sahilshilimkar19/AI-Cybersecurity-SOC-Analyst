"""Tools layer — deterministic capabilities agents invoke.

Log parsers/normalizers, entity/IoC extractors, CVSS interpreter, correlators,
and integration-lookup wrappers. Kept separate from agent reasoning so they are
independently unit-testable, and bound to agents on a least-privilege allow-list.

Populated from the agent sprints onward.
See docs/ENGINEERING_DESIGN_SPEC.md §3.7.
"""
