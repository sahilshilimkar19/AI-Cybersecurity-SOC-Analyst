"""Declarative node registry — the who-writes-what contract for the graph.

Each :class:`NodeSpec` names a node, its single owner (SAD §5 node ownership), the
callable that runs it, and whether it participates in the retry policy. The builder
consumes this registry so node ownership and retry behavior have exactly one source
of truth. Agent nodes are added to this registry in their respective sprints.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from graph.nodes import (
    CLOSE,
    CVE_RESEARCH,
    HUMAN_GATE,
    INGEST_SEED,
    LOG_ANALYSIS,
    NOTIFY,
    REMEDIATION,
    REPORT,
    THREAT_DETECTION,
    TRIAGE,
    close,
    cve_research,
    human_gate,
    ingest_seed,
    log_analysis,
    notify,
    remediation,
    report,
    threat_detection,
    triage,
)
from graph.state import GraphState

NodeAction = Callable[[GraphState], dict[str, Any]]


@dataclass(frozen=True)
class NodeSpec:
    """The registration contract for a single graph node."""

    name: str
    owner: str
    action: NodeAction
    retriable: bool = True


# The interrupt gate is not retriable: an interrupt is control flow, not a fault,
# and an invalid resume must fail fast rather than re-run.
_REGISTRY: tuple[NodeSpec, ...] = (
    NodeSpec(INGEST_SEED, owner="graph-runtime", action=ingest_seed),
    NodeSpec(LOG_ANALYSIS, owner="log-analyzer", action=log_analysis),
    NodeSpec(THREAT_DETECTION, owner="threat-detector", action=threat_detection),
    NodeSpec(CVE_RESEARCH, owner="cve-research", action=cve_research),
    NodeSpec(REPORT, owner="incident-reporter", action=report),
    NodeSpec(REMEDIATION, owner="patch-recommender", action=remediation),
    NodeSpec(TRIAGE, owner="graph-runtime", action=triage),
    NodeSpec(HUMAN_GATE, owner="human-review", action=human_gate, retriable=False),
    NodeSpec(NOTIFY, owner="graph-runtime", action=notify),
    NodeSpec(CLOSE, owner="graph-runtime", action=close),
)


def node_registry() -> tuple[NodeSpec, ...]:
    """Return the registered graph nodes in build order."""
    return _REGISTRY
