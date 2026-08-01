"""Tests for the summarization hook and token estimation."""

from memory.summarization import (
    ReferenceSummarizer,
    estimate_entry_tokens,
    estimate_tokens,
)
from models.memory import MemoryEntry


def test_estimate_tokens_is_zero_for_empty_text() -> None:
    assert estimate_tokens("") == 0


def test_estimate_tokens_grows_with_length() -> None:
    assert estimate_tokens("a") >= 1
    assert estimate_tokens("a" * 400) > estimate_tokens("a" * 40)


def test_estimate_entry_tokens_includes_key_and_value() -> None:
    small = MemoryEntry(key="k", value={"a": 1}, source="node")
    large = MemoryEntry(key="k", value={"a": "x" * 500}, source="node")
    assert estimate_entry_tokens(large) > estimate_entry_tokens(small)


def test_summary_of_nothing_is_empty() -> None:
    assert ReferenceSummarizer().summarize([]) == ""


def test_summary_retains_every_key_and_source() -> None:
    entries = [
        MemoryEntry(key="alpha", value={"n": 1}, source="log_analyzer"),
        MemoryEntry(key="beta", value={"n": 2}, source="threat_detector"),
    ]
    summary = ReferenceSummarizer().summarize(entries)
    # Lossless by reference: no identifier is dropped.
    assert "alpha" in summary
    assert "beta" in summary
    assert "log_analyzer" in summary
    assert "threat_detector" in summary


def test_summary_states_where_full_values_live() -> None:
    entry = MemoryEntry(key="alpha", value={"n": 1}, source="log_analyzer")
    summary = ReferenceSummarizer().summarize([entry])
    assert "durable session memory" in summary


def test_summary_is_deterministic() -> None:
    entries = [MemoryEntry(key="a", value={"v": 1}, source="s")]
    summarizer = ReferenceSummarizer()
    assert summarizer.summarize(entries) == summarizer.summarize(entries)
