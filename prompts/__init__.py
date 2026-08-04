"""Prompts layer — versioned, change-controlled prompt assets (EDS §3.6, §9).

A shared preamble carries the invariants every agent inherits; per-agent assets
specialize it and bind to a validated output contract. Keeping prompts here
rather than inline in agent code is what makes their behavior reviewable and
lets evaluation suites gate changes to them.

Assembly enforces the untrusted-data boundary: caller content is wrapped in
delimited blocks with delimiter lookalikes neutralized, so log data cannot escape
its container and be read as instructions (invariant #3).

See docs/ENGINEERING_DESIGN_SPEC.md §9.
"""

from __future__ import annotations

from prompts.assembly import (
    LOG_ANALYZER_PROMPT,
    PROMPT_MANIFEST,
    PromptAsset,
    assemble_prompt,
    get_prompt,
    wrap_untrusted,
)
from prompts.preamble import PREAMBLE_VERSION, SHARED_PREAMBLE

__all__ = [
    "LOG_ANALYZER_PROMPT",
    "PREAMBLE_VERSION",
    "PROMPT_MANIFEST",
    "SHARED_PREAMBLE",
    "PromptAsset",
    "assemble_prompt",
    "get_prompt",
    "wrap_untrusted",
]
