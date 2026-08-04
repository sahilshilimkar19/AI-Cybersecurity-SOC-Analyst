"""CVE Research agent — relevant CVEs with CVSS, applicability, and citations.

Connects the assessed activity and the estate's inventory to publicly documented
vulnerabilities, confirming applicability only where a named host runs a named
product at a version inside a published vulnerable range.
See docs/ENGINEERING_DESIGN_SPEC.md §4.4.
"""

from __future__ import annotations

from agents.cve_research.researcher import (
    AGENT_NAME,
    ALLOWED_TOOLS,
    CveResearcher,
    find_cve_ids,
)

__all__ = ["AGENT_NAME", "ALLOWED_TOOLS", "CveResearcher", "find_cve_ids"]
