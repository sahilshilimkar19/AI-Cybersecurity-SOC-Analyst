"""Tests for the node registry — the who-writes-what contract."""

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
)
from graph.registry import node_registry


def test_registry_has_the_expected_nodes_in_build_order() -> None:
    names = [spec.name for spec in node_registry()]
    assert names == [
        INGEST_SEED,
        LOG_ANALYSIS,
        THREAT_DETECTION,
        CVE_RESEARCH,
        REPORT,
        REMEDIATION,
        TRIAGE,
        HUMAN_GATE,
        NOTIFY,
        CLOSE,
    ]


def test_agent_nodes_are_owned_by_their_agent() -> None:
    by_name = {spec.name: spec for spec in node_registry()}
    assert by_name[LOG_ANALYSIS].owner == "log-analyzer"
    assert by_name[THREAT_DETECTION].owner == "threat-detector"
    assert by_name[CVE_RESEARCH].owner == "cve-research"
    assert by_name[REPORT].owner == "incident-reporter"
    assert by_name[REMEDIATION].owner == "patch-recommender"


def test_every_node_has_an_owner_and_callable_action() -> None:
    for spec in node_registry():
        assert spec.owner, f"{spec.name} is missing an owner"
        assert callable(spec.action)


def test_node_names_are_unique() -> None:
    names = [spec.name for spec in node_registry()]
    assert len(names) == len(set(names))


def test_human_gate_is_not_retriable() -> None:
    by_name = {spec.name: spec for spec in node_registry()}
    assert by_name[HUMAN_GATE].retriable is False
    assert by_name[INGEST_SEED].retriable is True


def test_human_gate_is_owned_by_human_review() -> None:
    by_name = {spec.name: spec for spec in node_registry()}
    assert by_name[HUMAN_GATE].owner == "human-review"
