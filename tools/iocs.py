"""Indicator-of-compromise extraction and classification (EDS §4.3 required tools).

The Log Analyzer's entity extractor answers *"what identifiers appear in this
record?"*. This tool answers the narrower question *"which of those are things an
analyst would pivot on or submit to threat intelligence?"* — and stops there.

Three lines are drawn deliberately:

* **Hosts and accounts are context, not indicators.** They are how events are
  correlated, but "the account ``deploy`` exists" is not an indicator of
  compromise. Treating every username as an IoC floods an assessment with noise
  and, worse, makes internal identities look like findings.
* **Nothing here assigns reputation.** Extraction is observation. Whether an
  address is hostile is asserted only by an intel source, through
  ``integrations.threat_intel``, and is recorded with that source attached.
* **Internal indicators are marked and never submitted.** Estate-internal
  addresses are kept as pivots but are excluded from third-party lookups, so an
  investigation does not leak the internal topology to an external API.

Every indicator is also stored **defanged** — ``hxxp://evil[.]com`` — so a value
that reaches a report, a Slack message, or a browser cannot be clicked into a
live connection by accident.
"""

from __future__ import annotations

import ipaddress
from typing import TYPE_CHECKING

from models.logs import EntityType
from models.threat import IocIndicator, IocType

if TYPE_CHECKING:
    from collections.abc import Iterable, Sequence
    from datetime import datetime

    from models.logs import NormalizedEvent

# Entity kinds that become indicators. Hosts and users are deliberately absent:
# they are correlation keys, not indicators (see the module docstring).
_ENTITY_TO_IOC: dict[EntityType, IocType] = {
    EntityType.IP_ADDRESS: IocType.IP_ADDRESS,
    EntityType.DOMAIN: IocType.DOMAIN,
    EntityType.URL: IocType.URL,
    EntityType.FILE_HASH: IocType.FILE_HASH,
    EntityType.FILE_PATH: IocType.FILE_PATH,
    EntityType.PROCESS: IocType.PROCESS,
}

# Indicator kinds that may be sent to a third-party reputation service. File
# paths and process names are excluded: they routinely embed usernames and
# directory structure, and submitting them would leak more than it learns.
ENRICHABLE_TYPES: frozenset[IocType] = frozenset(
    {IocType.IP_ADDRESS, IocType.DOMAIN, IocType.URL, IocType.FILE_HASH}
)

# Suffixes conventionally reserved for private naming, treated as estate-internal.
_INTERNAL_SUFFIXES: tuple[str, ...] = (".local", ".internal", ".lan", ".corp", ".home.arpa")

# The address space an estate actually occupies: RFC 1918, RFC 4193 unique-local,
# and carrier-grade NAT.
#
# Deliberately NOT ``ipaddress.is_private``. That property follows IANA's
# special-purpose registry, which also covers the documentation ranges
# (192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24) and several other reserved
# blocks. Treating those as "ours" would mark an external address internal, and
# an indicator marked internal is never enriched and never scrutinized — the
# failure would be silent and would run in exactly the wrong direction.
_PRIVATE_NETWORKS: tuple[ipaddress.IPv4Network | ipaddress.IPv6Network, ...] = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
    ipaddress.ip_network("100.64.0.0/10"),
    ipaddress.ip_network("fc00::/7"),
)


def defang(value: str) -> str:
    """Render an indicator inert for display.

    Neutralizes the scheme and the dots so the value can be shown to a human, or
    pasted into a chat client, without becoming a live link.
    """
    return (
        value.replace("http://", "hxxp://")
        .replace("https://", "hxxps://")
        .replace("ftp://", "fxp://")
        .replace(".", "[.]")
        .replace("@", "[at]")
    )


def is_internal_address(value: str, internal_networks: Sequence[str] = ()) -> bool:
    """Whether an address or hostname belongs to the estate.

    RFC 1918 / unique-local / loopback / link-local addresses are internal by
    definition; ``internal_networks`` adds the CIDR blocks a deployment considers
    its own. A malformed CIDR is ignored rather than raised — a misconfigured
    range must not abort an investigation, and the address then simply stays
    external, which is the conservative direction: it gets scrutinized rather
    than trusted.
    """
    lowered = value.lower()
    if lowered.endswith(_INTERNAL_SUFFIXES):
        return True

    try:
        address = ipaddress.ip_address(value)
    except ValueError:
        return False

    if address.is_loopback or address.is_link_local:
        return True

    return any(
        _contains(network, address)
        for network in (*_PRIVATE_NETWORKS, *_parse_networks(internal_networks))
    )


def _parse_networks(
    cidrs: Sequence[str],
) -> list[ipaddress.IPv4Network | ipaddress.IPv6Network]:
    """Parse configured CIDRs, skipping any that are malformed."""
    networks: list[ipaddress.IPv4Network | ipaddress.IPv6Network] = []
    for cidr in cidrs:
        try:
            networks.append(ipaddress.ip_network(cidr, strict=False))
        except ValueError:
            continue
    return networks


def _contains(
    network: ipaddress.IPv4Network | ipaddress.IPv6Network,
    address: ipaddress.IPv4Address | ipaddress.IPv6Address,
) -> bool:
    """Membership test that tolerates a version mismatch instead of raising."""
    return address.version == network.version and address in network


def extract_iocs(
    events: Sequence[NormalizedEvent], *, internal_networks: Sequence[str] = ()
) -> list[IocIndicator]:
    """Collect the indicators observed across a set of normalized events.

    Indicators are deduplicated by (type, value), and each one accumulates the
    events it was seen in plus the span over which it appeared — so an analyst can
    tell a single sighting from sustained activity without re-reading the log.
    Ordering is deterministic (most-observed first, then type, then value) so
    fixtures pin behavior rather than dictionary iteration order.
    """
    collected: dict[tuple[IocType, str], IocIndicator] = {}

    for event in events:
        for entity in event.entities:
            ioc_type = _ENTITY_TO_IOC.get(entity.type)
            if ioc_type is None:
                continue

            key = (ioc_type, entity.value.lower())
            existing = collected.get(key)
            if existing is None:
                collected[key] = IocIndicator(
                    type=ioc_type,
                    value=entity.value,
                    defanged=defang(entity.value),
                    event_ids=[event.event_id],
                    first_seen=event.event_time,
                    last_seen=event.event_time,
                    observation_count=1,
                    internal=_is_internal(ioc_type, entity.value, internal_networks),
                )
                continue

            collected[key] = existing.model_copy(
                update={
                    "event_ids": _append_unique(existing.event_ids, event.event_id),
                    "first_seen": _earliest(existing.first_seen, event.event_time),
                    "last_seen": _latest(existing.last_seen, event.event_time),
                    "observation_count": existing.observation_count + 1,
                }
            )

    return sorted(
        collected.values(),
        key=lambda ioc: (-ioc.observation_count, ioc.type.value, ioc.value.lower()),
    )


def enrichable(iocs: Iterable[IocIndicator]) -> list[IocIndicator]:
    """The indicators eligible for third-party reputation lookup."""
    return [ioc for ioc in iocs if ioc.type in ENRICHABLE_TYPES and not ioc.internal]


def _is_internal(ioc_type: IocType, value: str, internal_networks: Sequence[str]) -> bool:
    """Only addresses and hostnames have an inside/outside; artifacts do not."""
    if ioc_type not in {IocType.IP_ADDRESS, IocType.DOMAIN}:
        return False
    return is_internal_address(value, internal_networks)


def _append_unique(values: list[str], value: str) -> list[str]:
    return values if value in values else [*values, value]


def _earliest(current: datetime | None, candidate: datetime | None) -> datetime | None:
    if current is None or candidate is None:
        return current or candidate
    return min(current, candidate)


def _latest(current: datetime | None, candidate: datetime | None) -> datetime | None:
    if current is None or candidate is None:
        return current or candidate
    return max(current, candidate)
