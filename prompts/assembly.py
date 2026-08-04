"""Prompt assets, the version manifest, and prompt assembly (EDS §3.6, §9).

Prompts are **versioned, change-controlled assets**, not strings scattered through
agent code. That makes their behavior reviewable and lets the eval suites gate
changes to them.

Assembly is where the untrusted-data boundary is physically enforced: caller data
is wrapped in delimited blocks with any delimiter-lookalike neutralized, so log
content cannot break out of its container and be read as instructions
(invariant #3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import TYPE_CHECKING

from prompts.preamble import PREAMBLE_VERSION, SHARED_PREAMBLE

if TYPE_CHECKING:
    from collections.abc import Mapping

# The fence used to delimit untrusted data. Anything in the payload that could be
# mistaken for it is neutralized before insertion.
_BLOCK_OPEN = "<<<UNTRUSTED_DATA name={name}>>>"
_BLOCK_CLOSE = "<<<END_UNTRUSTED_DATA>>>"
_FENCE_LOOKALIKE = re.compile(r"<{2,}\s*/?\s*(?:END_)?UNTRUSTED_DATA[^>]*>{2,}", re.IGNORECASE)


@dataclass(frozen=True)
class PromptAsset:
    """One versioned prompt.

    ``output_contract`` names the schema the response must satisfy, binding the
    prompt to a validated shape rather than free text (EDS §3.6).
    """

    name: str
    version: str
    task: str
    output_contract: str

    def render(self, sections: Mapping[str, str] | None = None) -> str:
        """Render the full prompt: preamble, task, then delimited untrusted data."""
        parts = [SHARED_PREAMBLE, "", f"TASK ({self.name} v{self.version}):", self.task]
        if sections:
            parts.append("")
            parts.extend(
                wrap_untrusted(name, content) for name, content in sorted(sections.items())
            )
        parts.extend(["", f"OUTPUT: respond only with {self.output_contract}."])
        return "\n".join(parts)


def wrap_untrusted(name: str, content: str) -> str:
    """Wrap caller-supplied content in a delimited untrusted-data block.

    Delimiter lookalikes inside the content are neutralized first: without that,
    a crafted log line could close the block early and have its remainder read as
    trusted instructions.
    """
    safe = _FENCE_LOOKALIKE.sub("[redacted-delimiter]", content)
    return f"{_BLOCK_OPEN.format(name=name)}\n{safe}\n{_BLOCK_CLOSE}"


LOG_ANALYZER_PROMPT = PromptAsset(
    name="log_analyzer",
    version="1.0.0",
    task=(
        "Structure and correlate the supplied log records into a provenance-tagged "
        "timeline of security-relevant events.\n"
        "- Normalize each record: source, timestamp, host, actor, action, outcome.\n"
        "- Correlate related activity across sources into coherent sequences.\n"
        "- Report the coverage gaps: sources that were unavailable, records that "
        "could not be parsed, and periods with no evidence.\n"
        "- STRUCTURE ONLY. Do not infer whether activity is malicious, do not assign "
        "severity, and do not name threat actors or techniques. Assessing threats is "
        "another agent's responsibility; your output is evidence, not judgement.\n"
        "- Every event must carry its provenance. If a record cannot be attributed to "
        "a source and a time, quarantine it and report it rather than including it.\n"
        "- If parsing is uncertain, lower the confidence for that event and say why."
    ),
    output_contract="a LogAnalysisResult object",
)


# The version manifest. Every prompt shipped in a release is pinned here, so a
# release can state exactly which prompt versions produced its behavior.
PROMPT_MANIFEST: dict[str, str] = {
    "preamble": PREAMBLE_VERSION,
    LOG_ANALYZER_PROMPT.name: LOG_ANALYZER_PROMPT.version,
}

_ASSETS: dict[str, PromptAsset] = {LOG_ANALYZER_PROMPT.name: LOG_ANALYZER_PROMPT}


def get_prompt(name: str) -> PromptAsset:
    """Return a registered prompt asset, failing fast on an unknown name."""
    asset = _ASSETS.get(name)
    if asset is None:
        raise KeyError(f"unknown prompt asset: {name!r}")
    return asset


def assemble_prompt(name: str, sections: Mapping[str, str] | None = None) -> str:
    """Assemble the prompt for an agent with its untrusted context (EDS §3.6)."""
    return get_prompt(name).render(sections)
