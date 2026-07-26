"""Agent layer — the specialized AI agents and their shared contracts.

Each agent is a bounded specialist with a single responsibility and a strict,
schema-validated input/output contract. Agents never call one another directly;
the orchestration graph routes state between them (governing invariant #5).

Individual agents are implemented in their respective sprints (Log Analyzer,
Threat Detector, CVE Research, Incident Reporter, Patch Recommendation).
See docs/ENGINEERING_DESIGN_SPEC.md §4.
"""
