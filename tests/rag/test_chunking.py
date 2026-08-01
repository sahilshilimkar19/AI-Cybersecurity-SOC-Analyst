"""Tests for boundary-aware chunking."""

from models.enums import KnowledgeSourceKind, SourceTrustTier
from models.knowledge import ChunkMetadata, SourceDocument
from rag.chunking import Chunker, clean_text, split_sections


def _document(content: str, *, document_id: str = "doc-1") -> SourceDocument:
    return SourceDocument(
        document_id=document_id,
        title="Test document",
        content=content,
        metadata=ChunkMetadata(
            source_kind=KnowledgeSourceKind.INTERNAL_RUNBOOK,
            source_id="internal_runbooks",
            source_name="Internal Runbooks",
            trust_tier=SourceTrustTier.INTERNAL,
        ),
    )


def test_clean_text_collapses_whitespace_but_keeps_structure() -> None:
    cleaned = clean_text("# Title\r\n\r\n\r\n\r\nSome    spaced   text  \n")
    assert cleaned == "# Title\n\nSome spaced text"


def test_clean_text_of_blank_input_is_empty() -> None:
    assert clean_text("   \n\n  ") == ""


def test_split_sections_prefers_headings() -> None:
    sections = split_sections("# One\nalpha\n\n# Two\nbeta")
    assert len(sections) == 2
    assert sections[0].startswith("# One")
    assert sections[1].startswith("# Two")


def test_split_sections_keeps_preamble_before_first_heading() -> None:
    sections = split_sections("intro text\n\n# One\nalpha")
    assert sections[0] == "intro text"
    assert sections[1].startswith("# One")


def test_split_sections_falls_back_to_blank_lines() -> None:
    assert split_sections("alpha\n\nbeta\n\ngamma") == ["alpha", "beta", "gamma"]


def test_empty_document_produces_no_chunks() -> None:
    chunker = Chunker(max_characters=500, overlap_characters=50)
    assert chunker.chunk(_document("   ")) == []


def test_small_sections_are_packed_together() -> None:
    chunker = Chunker(max_characters=500, overlap_characters=50)
    chunks = chunker.chunk(_document("alpha\n\nbeta\n\ngamma"))
    # All three fit comfortably, so they become one chunk rather than three tiny ones.
    assert len(chunks) == 1
    assert "alpha" in chunks[0].content
    assert "gamma" in chunks[0].content


def test_sections_are_not_merged_past_the_size_limit() -> None:
    chunker = Chunker(max_characters=60, overlap_characters=10)
    chunks = chunker.chunk(_document("a" * 50 + "\n\n" + "b" * 50))
    assert len(chunks) == 2


def test_oversized_section_is_split_with_parent_linkage() -> None:
    chunker = Chunker(max_characters=100, overlap_characters=20)
    chunks = chunker.chunk(_document(" ".join(["word"] * 200)))

    assert len(chunks) > 1
    # Every part points at one shared parent, so the whole remains resolvable.
    parents = {chunk.parent_chunk_id for chunk in chunks}
    assert parents == {"doc-1#s0"}


def test_chunks_carry_ordinals_ids_and_metadata() -> None:
    chunker = Chunker(max_characters=60, overlap_characters=10)
    chunks = chunker.chunk(_document("a" * 50 + "\n\n" + "b" * 50))

    assert [chunk.ordinal for chunk in chunks] == [0, 1]
    assert [chunk.chunk_id for chunk in chunks] == ["doc-1#0", "doc-1#1"]
    assert all(chunk.document_id == "doc-1" for chunk in chunks)
    assert all(chunk.metadata.source_id == "internal_runbooks" for chunk in chunks)
    assert all(chunk.title == "Test document" for chunk in chunks)


def test_chunking_is_deterministic() -> None:
    chunker = Chunker(max_characters=120, overlap_characters=20)
    document = _document(" ".join(["token"] * 100))
    assert [c.content for c in chunker.chunk(document)] == [
        c.content for c in chunker.chunk(document)
    ]


def test_overlap_must_be_smaller_than_the_chunk_size() -> None:
    import pytest

    with pytest.raises(ValueError, match="overlap"):
        Chunker(max_characters=100, overlap_characters=100)
