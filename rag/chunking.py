"""Boundary-aware chunking (EDS §8 chunk strategy).

Security knowledge is already structured — one CVE record, one ATT&CK technique,
one runbook section — and those boundaries carry meaning. Splitting mid-record
would produce a chunk that cites a CVE it only half describes, so chunks follow
the document's own structure first and only fall back to size-based splitting
when a single section is genuinely too large.

When a section must be split, the parts are linked to a parent id so the whole
remains resolvable: the corpus is compressed for retrieval, never truncated.
"""

from __future__ import annotations

import re
from typing import TYPE_CHECKING

from models.knowledge import KnowledgeChunkRecord

if TYPE_CHECKING:
    from models.knowledge import SourceDocument

# A markdown-style heading or a blank-line-separated block starts a new section.
_HEADING = re.compile(r"^\s{0,3}#{1,6}\s+\S", re.MULTILINE)
_WHITESPACE = re.compile(r"[ \t]+")
_BLANK_LINES = re.compile(r"\n{3,}")


def clean_text(text: str) -> str:
    """Normalize whitespace without destroying structure.

    Collapses runs of spaces and excess blank lines but preserves single blank
    lines and headings, because those are the boundaries chunking relies on.
    """
    normalized = text.replace("\r\n", "\n").replace("\r", "\n")
    normalized = _WHITESPACE.sub(" ", normalized)
    normalized = _BLANK_LINES.sub("\n\n", normalized)
    return "\n".join(line.rstrip() for line in normalized.split("\n")).strip()


def split_sections(text: str) -> list[str]:
    """Split a document into structural sections, preferring headings."""
    heading_positions = [match.start() for match in _HEADING.finditer(text)]
    if heading_positions:
        # Keep any preamble before the first heading as its own section.
        boundaries = ([0] if heading_positions[0] > 0 else []) + heading_positions
        sections = [
            text[start:end].strip()
            for start, end in zip(boundaries, [*boundaries[1:], len(text)], strict=True)
        ]
    else:
        sections = [block.strip() for block in text.split("\n\n")]
    return [section for section in sections if section]


class Chunker:
    """Turns a source document into indexable chunks."""

    def __init__(self, *, max_characters: int, overlap_characters: int) -> None:
        if overlap_characters >= max_characters:
            raise ValueError("chunk overlap must be smaller than the maximum chunk size")
        self._max = max_characters
        self._overlap = overlap_characters

    def chunk(self, document: SourceDocument) -> list[KnowledgeChunkRecord]:
        """Chunk a document, preserving its structural boundaries."""
        content = clean_text(document.content)
        if not content:
            return []

        records: list[KnowledgeChunkRecord] = []
        for section in self._pack(split_sections(content)):
            if len(section) <= self._max:
                records.append(self._record(document, section, ordinal=len(records)))
                continue
            # Oversized section: split it, linking every part to a shared parent.
            parent_id = f"{document.document_id}#s{len(records)}"
            for part in self._split_oversized(section):
                records.append(
                    self._record(document, part, ordinal=len(records), parent_chunk_id=parent_id)
                )
        return records

    def _pack(self, sections: list[str]) -> list[str]:
        """Merge consecutive small sections so chunks are not uselessly tiny."""
        packed: list[str] = []
        buffer = ""
        for section in sections:
            if not buffer:
                buffer = section
            elif len(buffer) + len(section) + 2 <= self._max:
                buffer = f"{buffer}\n\n{section}"
            else:
                packed.append(buffer)
                buffer = section
        if buffer:
            packed.append(buffer)
        return packed

    def _split_oversized(self, section: str) -> list[str]:
        """Split an oversized section on whitespace, with overlap for continuity."""
        parts: list[str] = []
        start = 0
        stride = self._max - self._overlap
        while start < len(section):
            end = min(start + self._max, len(section))
            if end < len(section):
                # Prefer a whitespace boundary so words are not cut in half.
                boundary = section.rfind(" ", start + stride, end)
                if boundary > start:
                    end = boundary
            parts.append(section[start:end].strip())
            if end >= len(section):
                break
            start = max(end - self._overlap, start + 1)
        return [part for part in parts if part]

    @staticmethod
    def _record(
        document: SourceDocument,
        content: str,
        *,
        ordinal: int,
        parent_chunk_id: str | None = None,
    ) -> KnowledgeChunkRecord:
        return KnowledgeChunkRecord(
            chunk_id=f"{document.document_id}#{ordinal}",
            document_id=document.document_id,
            title=document.title,
            content=content,
            metadata=document.metadata,
            ordinal=ordinal,
            parent_chunk_id=parent_chunk_id,
        )
