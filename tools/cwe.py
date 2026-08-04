"""The CWE weakness catalogue (SAD §2.3 required tools).

A CVE says *this product has a flaw*; a CWE says *what kind of flaw it is*. That
second answer is what lets an analyst reason about a vulnerability they have
never seen before — "deserialization of untrusted data" tells you the shape of
the exploit and the shape of the mitigation, where "CVE-2021-44228" tells you
only a number.

Like the ATT&CK catalogue, the vocabulary is **pinned rather than generated**: an
identifier absent from this table comes back with no name and no explanation
instead of an invented one. NVD also emits the sentinels ``NVD-CWE-noinfo`` and
``NVD-CWE-Other`` for records it has not classified; those are recognized
explicitly so "not categorized" reads as itself rather than as an unknown code.

Each entry carries a one-sentence plain explanation, which is what the dossier
puts in front of a reader who is not a vulnerability researcher (SAD §2.3).
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from models.enums import SourceTrustTier
from models.values import Citation

CWE_SOURCE_ID = "mitre_cwe"
CWE_SOURCE_NAME = "MITRE CWE"
_CWE_BASE_URL = "https://cwe.mitre.org/data/definitions"

_CWE_ID = re.compile(r"^CWE-(\d+)$", re.IGNORECASE)

# NVD's placeholders for records it has not assigned a weakness class to.
_UNCLASSIFIED = {
    "NVD-CWE-NOINFO": "The vulnerability record carries no weakness classification.",
    "NVD-CWE-OTHER": "The weakness does not fit an existing CWE category.",
}


@dataclass(frozen=True)
class WeaknessDefinition:
    """One catalogued weakness class."""

    cwe_id: str
    name: str
    explanation: str

    @property
    def url(self) -> str:
        number = self.cwe_id.removeprefix("CWE-")
        return f"{_CWE_BASE_URL}/{number}.html"

    def citation(self) -> Citation:
        """A resolvable reference for the weakness class."""
        return Citation(
            source_id=CWE_SOURCE_ID,
            source=CWE_SOURCE_NAME,
            url=self.url,
            title=f"{self.cwe_id} — {self.name}",
            trust_tier=SourceTrustTier.AUTHORITATIVE,
        )


_CATALOGUE: tuple[WeaknessDefinition, ...] = (
    WeaknessDefinition(
        "CWE-20",
        "Improper Input Validation",
        "The product accepts input without checking it is well-formed, so malformed "
        "input reaches logic that assumed it was valid.",
    ),
    WeaknessDefinition(
        "CWE-22",
        "Path Traversal",
        "A filename supplied by the caller is used without restriction, letting an "
        "attacker read or write files outside the intended directory.",
    ),
    WeaknessDefinition(
        "CWE-77",
        "Command Injection",
        "Caller-supplied text is embedded in a command the product then executes, so "
        "an attacker can append commands of their own.",
    ),
    WeaknessDefinition(
        "CWE-78",
        "OS Command Injection",
        "Caller-supplied text reaches an operating-system shell, letting an attacker "
        "run arbitrary commands on the host.",
    ),
    WeaknessDefinition(
        "CWE-79",
        "Cross-site Scripting",
        "Untrusted input is rendered into a web page without escaping, so an attacker "
        "can run script in another user's browser session.",
    ),
    WeaknessDefinition(
        "CWE-89",
        "SQL Injection",
        "Untrusted input is concatenated into a database query, letting an attacker "
        "read, alter, or destroy data the query was never meant to touch.",
    ),
    WeaknessDefinition(
        "CWE-94",
        "Code Injection",
        "Untrusted input is evaluated as program code, giving an attacker execution "
        "inside the product's own process.",
    ),
    WeaknessDefinition(
        "CWE-119",
        "Improper Restriction of Operations within the Bounds of a Memory Buffer",
        "The product reads or writes outside a buffer's bounds, which can crash it or "
        "let an attacker control execution.",
    ),
    WeaknessDefinition(
        "CWE-125",
        "Out-of-bounds Read",
        "The product reads past the end of a buffer, leaking adjacent memory that may "
        "contain secrets.",
    ),
    WeaknessDefinition(
        "CWE-190",
        "Integer Overflow or Wraparound",
        "An arithmetic result exceeds its type and wraps around, producing a size or "
        "index the surrounding code treats as valid.",
    ),
    WeaknessDefinition(
        "CWE-200",
        "Exposure of Sensitive Information to an Unauthorized Actor",
        "The product discloses information to someone who should not be able to see it.",
    ),
    WeaknessDefinition(
        "CWE-269",
        "Improper Privilege Management",
        "Privileges are assigned, dropped, or checked incorrectly, so an actor ends up "
        "with more authority than intended.",
    ),
    WeaknessDefinition(
        "CWE-287",
        "Improper Authentication",
        "The product does not correctly prove who a caller is, so an attacker can act "
        "as someone else.",
    ),
    WeaknessDefinition(
        "CWE-306",
        "Missing Authentication for Critical Function",
        "A sensitive operation can be invoked without authenticating at all.",
    ),
    WeaknessDefinition(
        "CWE-352",
        "Cross-Site Request Forgery",
        "The product accepts a state-changing request without confirming the user "
        "intended it, so another site can act on their behalf.",
    ),
    WeaknessDefinition(
        "CWE-362",
        "Race Condition",
        "Two operations that assume exclusive access can interleave, leaving the "
        "product in a state neither expected.",
    ),
    WeaknessDefinition(
        "CWE-400",
        "Uncontrolled Resource Consumption",
        "An attacker can make the product consume unbounded memory, CPU, or disk, "
        "denying service to everyone else.",
    ),
    WeaknessDefinition(
        "CWE-416",
        "Use After Free",
        "Memory is used after it has been released, which can crash the product or let "
        "an attacker control what runs.",
    ),
    WeaknessDefinition(
        "CWE-434",
        "Unrestricted Upload of File with Dangerous Type",
        "The product accepts uploaded files without restricting their type, so an "
        "attacker can upload something the server will execute.",
    ),
    WeaknessDefinition(
        "CWE-502",
        "Deserialization of Untrusted Data",
        "The product reconstructs objects from attacker-controlled data, which can "
        "trigger code execution during deserialization itself.",
    ),
    WeaknessDefinition(
        "CWE-522",
        "Insufficiently Protected Credentials",
        "Credentials are stored or transmitted in a way that lets an attacker recover them.",
    ),
    WeaknessDefinition(
        "CWE-611",
        "Improper Restriction of XML External Entity Reference",
        "The XML parser resolves external references, letting an attacker read local "
        "files or reach internal services.",
    ),
    WeaknessDefinition(
        "CWE-732",
        "Incorrect Permission Assignment for Critical Resource",
        "A sensitive file or object is left readable or writable by actors who should "
        "not have access.",
    ),
    WeaknessDefinition(
        "CWE-787",
        "Out-of-bounds Write",
        "The product writes past the end of a buffer, corrupting adjacent memory and "
        "often enabling code execution.",
    ),
    WeaknessDefinition(
        "CWE-798",
        "Use of Hard-coded Credentials",
        "A password or key is embedded in the product, so it is the same everywhere it "
        "is installed and cannot be rotated.",
    ),
    WeaknessDefinition(
        "CWE-862",
        "Missing Authorization",
        "The product authenticates the caller but never checks whether they are allowed "
        "to perform the action.",
    ),
    WeaknessDefinition(
        "CWE-863",
        "Incorrect Authorization",
        "An authorization check exists but reaches the wrong answer, granting access it "
        "should refuse.",
    ),
    WeaknessDefinition(
        "CWE-918",
        "Server-Side Request Forgery",
        "The product fetches a URL the caller controls, letting an attacker reach "
        "internal services from the server's own network position.",
    ),
    WeaknessDefinition(
        "CWE-1321",
        "Prototype Pollution",
        "Attacker-controlled keys modify a shared object prototype, changing behavior "
        "across unrelated parts of the application.",
    ),
)

WEAKNESSES: dict[str, WeaknessDefinition] = {item.cwe_id: item for item in _CATALOGUE}


def known_weakness(cwe_id: str) -> WeaknessDefinition | None:
    """Look a weakness up, returning ``None`` for anything not catalogued."""
    normalized = normalize_cwe_id(cwe_id)
    return WEAKNESSES.get(normalized) if normalized else None


def normalize_cwe_id(cwe_id: str) -> str | None:
    """Canonicalize a CWE identifier, or return ``None`` if it is not one."""
    text = cwe_id.strip()
    match = _CWE_ID.match(text)
    return f"CWE-{match.group(1)}" if match else None


def explain(cwe_id: str) -> str | None:
    """A plain-language explanation, or ``None`` when the class is unrecognized.

    NVD's "no info" and "other" sentinels get their own honest text, because
    "not categorized" is a fact worth reporting and is not the same as a lookup
    miss.
    """
    sentinel = _UNCLASSIFIED.get(cwe_id.strip().upper())
    if sentinel is not None:
        return sentinel
    definition = known_weakness(cwe_id)
    return definition.explanation if definition is not None else None
