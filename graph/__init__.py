"""Orchestration layer — the LangGraph stateful multi-agent graph.

The deterministic control plane around the non-deterministic agents: nodes,
edges, conditional routing, checkpointing, retries, and human-approval
interrupts (governing invariants #1 and #5).

Implemented in the LangGraph Core sprint.
See docs/ENGINEERING_DESIGN_SPEC.md §5.
"""
