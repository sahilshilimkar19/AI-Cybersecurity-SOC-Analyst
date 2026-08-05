"""Version reasoning and what it implies for CVE applicability (EDS §4.4).

This is where the sprint's defining rule is actually executed: *a CVE is not
applicable until a specific host is shown to run a specific version inside a
published vulnerable range*. Everything softer than that is a candidate, and a
candidate says which piece of evidence was missing.

The bar is set here because this is the decision that gets a remediation
programme wrong in both directions. Assert applicability too eagerly and analysts
chase patches for software that is already fixed; assert it too reluctantly and a
genuinely exposed host is filed as "unknown" and never revisited. Naming the
missing evidence — *version unknown*, *version unparseable*, *no range published*
— turns the uncertain cases into a work list instead of a shrug.

Version comparison is tolerant by design, because real inventories are messy:
``v2.14.1``, ``2.14.1-rc2``, ``8.5.0.1``, ``1.2.3.RELEASE`` all appear. Pre-release
suffixes sort *below* the release they precede (``2.0-rc1 < 2.0``), which is the
behavior that matters for "fixed in 2.0": a release candidate is not the fix.
Anything that cannot be read as a version returns ``None`` rather than a guess.
"""

from __future__ import annotations

import operator
import re
from dataclasses import dataclass, field
from typing import TYPE_CHECKING

from models.enums import CveApplicability
from models.vulnerability import ApplicabilityEvidence, ApplicabilityReason

if TYPE_CHECKING:
    from collections.abc import Sequence

    from models.vulnerability import AffectedRange, AssetContext, CveRecord

# Trailing qualifiers that name a release rather than modify it.
_RELEASE_WORDS = frozenset({"release", "final", "ga", "stable"})

# Words that mark a build as pre-release, ordered by increasing maturity.
_PRERELEASE_RANK: dict[str, int] = {
    "dev": 0,
    "alpha": 1,
    "a": 1,
    "beta": 2,
    "b": 2,
    "milestone": 3,
    "m": 3,
    "rc": 4,
    "cr": 4,
    "preview": 4,
    "pre": 4,
}

_SEPARATOR = re.compile(r"[.\-_+~]")
_LEADING_V = re.compile(r"^[vV](?=\d)")
_NUMERIC = re.compile(r"^\d+$")
_ALPHANUM = re.compile(r"^([a-z]+)(\d*)$")

# Punctuation and vendor noise stripped before comparing product names.
_PRODUCT_NOISE = re.compile(r"[^a-z0-9]+")

# Tokens that appear in product names without distinguishing anything. Without
# this list "Apache HTTP Server" and "Apache Tomcat" would match on "apache".
_GENERIC_TOKENS = frozenset(
    {
        "apache",
        "client",
        "community",
        "corp",
        "corporation",
        "edition",
        "enterprise",
        "foundation",
        "framework",
        "free",
        "gnu",
        "google",
        "hat",
        "inc",
        "library",
        "microsoft",
        "open",
        "oracle",
        "project",
        "red",
        "redhat",
        "server",
        "software",
        "source",
        "standard",
        "the",
    }
)

# A shared token shorter than this is too generic to carry a match on its own.
_MIN_TOKEN_LENGTH = 3

# Score for an exact name match, above any achievable token-overlap count.
_EXACT_MATCH_SCORE = 100


@dataclass(frozen=True, order=True)
class Version:
    """A comparable version.

    ``release`` is the numeric backbone. ``prerelease`` is empty for a final
    release and is compared only when the release parts tie — with an empty tuple
    deliberately sorting *above* a populated one, so ``2.0`` beats ``2.0-rc1``.

    ``text`` is the string as the inventory spelled it, kept for provenance and
    excluded from comparison: ``1.2.3.RELEASE`` and ``1.2.3`` name the same
    release, and a comparison that disagreed would rule a vulnerable host out on
    a spelling difference.
    """

    sort_key: tuple[tuple[int, ...], int, tuple[int, ...]]
    text: str = field(compare=False)

    @property
    def release(self) -> tuple[int, ...]:
        return self.sort_key[0]

    @property
    def is_prerelease(self) -> bool:
        return self.sort_key[1] == 0


def parse_version(text: str | None) -> Version | None:
    """Parse a version string, or return ``None`` if it cannot be read.

    Refusing is the point: an unreadable version becomes a *candidate* with a
    named reason, never a silently-assumed match.
    """
    if not text:
        return None
    cleaned = _LEADING_V.sub("", str(text).strip())
    if not cleaned:
        return None

    release: list[int] = []
    prerelease: list[int] = []
    seen_prerelease = False

    for token in _SEPARATOR.split(cleaned.lower()):
        if not token:
            continue
        if _NUMERIC.match(token):
            (prerelease if seen_prerelease else release).append(int(token))
            continue
        if token in _RELEASE_WORDS:
            continue

        match = _ALPHANUM.match(token)
        if match is None:
            return None
        word, digits = match.group(1), match.group(2)
        rank = _PRERELEASE_RANK.get(word)
        if rank is None:
            return None
        seen_prerelease = True
        prerelease.append(rank)
        if digits:
            prerelease.append(int(digits))

    if not release:
        return None
    # 1 for a final release, 0 for a pre-release: a plain tuple comparison then
    # puts 2.0 above 2.0-rc1 without special-casing at every call site.
    return Version(
        sort_key=(tuple(release), 0 if seen_prerelease else 1, tuple(prerelease)),
        text=str(text),
    )


def normalize_product(name: str) -> str:
    """Reduce a product name to a comparable form.

    ``Apache Log4j``, ``apache_log4j``, and ``log4j`` should all match the same
    advisory, so punctuation and casing are dropped.
    """
    return _PRODUCT_NOISE.sub("", name.lower())


def products_match(installed: str, affected: str) -> bool:
    """Whether an inventory entry names the product an advisory affects.

    Matching is deliberately **generous** and version matching is deliberately
    **strict**, and that asymmetry is the design: advisories and inventories
    disagree constantly about how much of the vendor name to include
    (``log4j-core`` versus ``Apache Log4j``), so a narrow product match would drop
    real findings. A generous match still cannot confirm applicability on its own
    — the version has to land inside a published range — so the cost of a loose
    match here is an extra candidate to review, not a false confirmation.

    Generic tokens are excluded so "Apache HTTP Server" and "Apache Tomcat" do
    not match on the vendor they share.
    """
    return product_match_score(installed, affected) > 0


def product_match_score(installed: str, affected: str) -> int:
    """How *well* two product names match, not merely whether they do.

    Generosity is right when deciding whether to look at a candidate at all, and
    wrong when choosing between several candidates from the same family:
    ``log4j-api`` matches both ``log4j-core`` and ``log4j-api``, and picking the
    first would attach the wrong fixed version to the finding. Callers with a
    choice should rank by this score; callers with a yes/no question can use
    :func:`products_match`.

    Higher is better. Exact equality outranks everything; otherwise the score is
    the number of distinctive tokens the two names share.
    """
    left, right = normalize_product(installed), normalize_product(affected)
    if not left or not right:
        return 0
    if left == right:
        return _EXACT_MATCH_SCORE

    shared = {
        token
        for token in (_distinctive_tokens(installed) & _distinctive_tokens(affected))
        if len(token) >= _MIN_TOKEN_LENGTH
    }
    if shared:
        return len(shared)

    # Fall back to containment for names that carry no separators at all.
    if min(len(left), len(right)) < 4:
        return 0
    return 1 if (left in right or right in left) else 0


def _distinctive_tokens(name: str) -> set[str]:
    """The words in a product name that actually identify the product."""
    return {token for token in _PRODUCT_NOISE.split(name.lower()) if token} - _GENERIC_TOKENS


def in_vulnerable_range(version: Version, affected: AffectedRange) -> bool | None:
    """Whether a version falls inside a published vulnerable range.

    Returns ``None`` when a bound exists but cannot be parsed — undecidable is a
    third answer, and collapsing it into ``False`` would quietly clear a host
    that nobody actually checked.
    """
    if affected.is_unbounded:
        return True

    # Each published bound pairs with the comparison the version must satisfy to
    # stay inside the range.
    bounds = (
        (affected.version_start_including, operator.ge),
        (affected.version_start_excluding, operator.gt),
        (affected.version_end_including, operator.le),
        (affected.version_end_excluding, operator.lt),
    )
    for raw, satisfies in bounds:
        if raw is None:
            continue
        bound = parse_version(raw)
        if bound is None:
            return None
        if not satisfies(version, bound):
            return False
    return True


def assess_applicability(
    record: CveRecord, assets: Sequence[AssetContext]
) -> tuple[CveApplicability, list[ApplicabilityEvidence]]:
    """Decide whether a CVE applies to this estate, and say why.

    Confirmation requires the full chain — host, product, installed version,
    matched range — because that is the only combination that supports the claim
    "this machine is exposed". Everything else is returned with the specific
    reason it fell short, so the gap is actionable rather than merely recorded.
    """
    evidence: list[ApplicabilityEvidence] = []

    if not record.affected:
        return CveApplicability.CANDIDATE, [
            ApplicabilityEvidence(
                reason=ApplicabilityReason.NO_AFFECTED_RANGE_PUBLISHED,
                detail=(
                    f"{record.cve_id} publishes no affected version range, so applicability "
                    "cannot be confirmed against the inventory"
                ),
            )
        ]

    for asset in assets:
        for installed in asset.software:
            for affected in record.affected:
                if not products_match(installed.product, affected.product):
                    continue
                evidence.append(_assess_one(asset, installed.product, installed.version, affected))

    if not evidence:
        return CveApplicability.CANDIDATE, [
            ApplicabilityEvidence(
                reason=ApplicabilityReason.PRODUCT_NOT_IN_INVENTORY,
                detail=(
                    f"no asset inventory entry matches the products {record.cve_id} affects"
                    if assets
                    else "no asset inventory was supplied, so applicability cannot be assessed"
                ),
            )
        ]

    reasons = {item.reason for item in evidence}
    if ApplicabilityReason.VERSION_IN_VULNERABLE_RANGE in reasons:
        return CveApplicability.CONFIRMED, evidence
    if reasons - {ApplicabilityReason.VERSION_NOT_IN_VULNERABLE_RANGE}:
        return CveApplicability.CANDIDATE, evidence
    return CveApplicability.NOT_APPLICABLE, evidence


def _assess_one(
    asset: AssetContext, product: str, installed_version: str | None, affected: AffectedRange
) -> ApplicabilityEvidence:
    """Assess one installed product against one published range."""
    if not installed_version:
        return ApplicabilityEvidence(
            reason=ApplicabilityReason.VERSION_UNKNOWN,
            hostname=asset.hostname,
            product=product,
            matched_range=affected,
            detail=f"{asset.hostname} runs {product} but the inventory records no version",
        )

    parsed = parse_version(installed_version)
    if parsed is None:
        return ApplicabilityEvidence(
            reason=ApplicabilityReason.VERSION_UNPARSEABLE,
            hostname=asset.hostname,
            product=product,
            installed_version=installed_version,
            matched_range=affected,
            detail=f"version {installed_version!r} on {asset.hostname} could not be parsed",
        )

    verdict = in_vulnerable_range(parsed, affected)
    if verdict is None:
        return ApplicabilityEvidence(
            reason=ApplicabilityReason.VERSION_UNPARSEABLE,
            hostname=asset.hostname,
            product=product,
            installed_version=installed_version,
            matched_range=affected,
            detail="the published range contains a bound that could not be parsed",
        )
    if verdict:
        return ApplicabilityEvidence(
            reason=ApplicabilityReason.VERSION_IN_VULNERABLE_RANGE,
            hostname=asset.hostname,
            product=product,
            installed_version=installed_version,
            matched_range=affected,
            detail=(
                f"{asset.hostname} runs {product} {installed_version}, "
                f"which falls inside the published vulnerable range"
            ),
        )
    return ApplicabilityEvidence(
        reason=ApplicabilityReason.VERSION_NOT_IN_VULNERABLE_RANGE,
        hostname=asset.hostname,
        product=product,
        installed_version=installed_version,
        matched_range=affected,
        detail=(
            f"{asset.hostname} runs {product} {installed_version}, "
            f"which is outside the published vulnerable range"
        ),
    )
