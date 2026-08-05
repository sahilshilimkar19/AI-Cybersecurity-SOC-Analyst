"""Patch Recommendation agent — prioritized, justified remediation guidance.

Proposes remediation for a human to review and execute; nothing here is ever
auto-applied, and the contracts it emits carry no field a machine could run
(governing invariants #1 and #2).
See docs/ENGINEERING_DESIGN_SPEC.md §4.6.
"""

from __future__ import annotations

from agents.patch_recommender.recommender import AGENT_NAME, ALLOWED_TOOLS, PatchRecommender

__all__ = ["AGENT_NAME", "ALLOWED_TOOLS", "PatchRecommender"]
