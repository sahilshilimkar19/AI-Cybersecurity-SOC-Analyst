"""Entity and indicator extraction (EDS §4.2 required tools).

Pulls the identifiers that let events from different sources be recognized as
the same activity: hosts, users, addresses, domains, URLs, hashes, paths, and
processes.

This is extraction, not judgement. Finding an IP address says nothing about
whether it is hostile — reputation belongs to the Threat Detector and its
enrichment adapters. Keeping that line sharp is what stops the Log Analyzer from
quietly becoming a detector (EDS §4.2 validation rules).
"""

from __future__ import annotations

import ipaddress
import re
from typing import TYPE_CHECKING

from models.logs import Entity, EntityType

if TYPE_CHECKING:
    from collections.abc import Iterable

# Ordered so that longer, more specific matches are extracted before the
# fragments they contain (a URL before its domain, a path before its filename).
_URL = re.compile(r"\bhttps?://[^\s\"'<>\\]+", re.IGNORECASE)
_IPV4 = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
_IPV6 = re.compile(r"\b(?:[A-F0-9]{1,4}:){2,7}[A-F0-9]{1,4}\b", re.IGNORECASE)
_HASH = re.compile(r"\b[A-F0-9]{32}\b|\b[A-F0-9]{40}\b|\b[A-F0-9]{64}\b", re.IGNORECASE)
_WINDOWS_PATH = re.compile(r"\b[A-Z]:\\\\?(?:[^\\\s\"'<>|]+\\\\?)*[^\\\s\"'<>|]+", re.IGNORECASE)
_UNIX_PATH = re.compile(r"(?:^|\s)(/(?:[\w.\-]+/)*[\w.\-]+)")
_DOMAIN = re.compile(
    r"\b(?!\d+\.\d+)(?:[a-z0-9](?:[a-z0-9\-]{0,61}[a-z0-9])?\.)+[a-z]{2,24}\b", re.IGNORECASE
)
_PROCESS = re.compile(r"\b[\w.\-]+\.(?:exe|dll|ps1|sh|bat|cmd|py|jar)\b", re.IGNORECASE)

# Domains that appear in log prose without being indicators of anything.
_DOMAIN_NOISE = frozenset({"localhost.localdomain"})


def _is_routable_ip(value: str) -> bool:
    try:
        ipaddress.ip_address(value)
    except ValueError:
        return False
    return True


def extract_entities(
    text: str, *, extra: Iterable[tuple[EntityType, str | None]] = ()
) -> list[Entity]:
    """Extract entities from log text, plus any already-known structured values.

    Results are deduplicated and returned in a deterministic order so downstream
    correlation and tests are reproducible.
    """
    found: list[Entity] = []

    def add(entity_type: EntityType, value: str | None) -> None:
        if not value:
            return
        cleaned = value.strip().strip(".,;:)]}\"'")
        if cleaned:
            found.append(Entity(type=entity_type, value=cleaned))

    for entity_type, value in extra:
        add(entity_type, value)

    urls = _URL.findall(text)
    for url in urls:
        add(EntityType.URL, url)

    # Remove URLs before scanning for domains so a URL's host is not also
    # reported as a bare domain.
    remainder = _URL.sub(" ", text)

    for match in _IPV4.findall(remainder):
        if _is_routable_ip(match):
            add(EntityType.IP_ADDRESS, match)
    for match in _IPV6.findall(remainder):
        if _is_routable_ip(match):
            add(EntityType.IP_ADDRESS, match)

    for match in _HASH.findall(remainder):
        add(EntityType.FILE_HASH, match)

    for match in _PROCESS.findall(remainder):
        add(EntityType.PROCESS, match)

    for match in _WINDOWS_PATH.findall(remainder):
        add(EntityType.FILE_PATH, match)
    for match in _UNIX_PATH.findall(remainder):
        add(EntityType.FILE_PATH, match)

    for match in _DOMAIN.findall(remainder):
        lowered = match.lower()
        if lowered in _DOMAIN_NOISE or _is_routable_ip(match):
            continue
        # A domain that is really a filename (foo.exe) is already a process.
        if _PROCESS.fullmatch(match):
            continue
        add(EntityType.DOMAIN, lowered)

    return _deduplicate(found)


def _deduplicate(entities: list[Entity]) -> list[Entity]:
    """Drop repeats, keeping first-seen order."""
    seen: set[tuple[str, str]] = set()
    unique: list[Entity] = []
    for entity in entities:
        key = (entity.type.value, entity.value.lower())
        if key in seen:
            continue
        seen.add(key)
        unique.append(entity)
    return unique
