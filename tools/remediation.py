"""The remediation guidance catalogue (EDS §4.6 required tools).

Turning a finding into advice is where a security tool either earns its place or
becomes noise. "Patch it" is not guidance. Guidance says what to change, in what
order, how to tell it worked, and on whose authority — and the last of those is
why this catalogue is **pinned rather than generated**, exactly like the ATT&CK
and CWE vocabularies before it. Invented remediation steps are worse than absent
ones: they are plausible, specific, and wrong, and someone will run them on a
production host at 2am.

Three tiers of grounding, and the difference between them is stated on every
recommendation rather than left to the reader's judgement:

* **Vendor-specific** — a named fixed version from an advisory. The strongest
  advice available: upgrade *this* to *that*.
* **Class-specific** — mitigations mapped from the observed ATT&CK technique or
  the CVE's weakness class, each citing the MITRE mitigation it comes from.
* **Generic** — conservative hardening for when nothing better is known. Sound,
  and explicitly labelled so it is never mistaken for a fix (SAD §2.5's "thin
  remediation knowledge" path).

Nothing here is executable, and nothing here should become executable. The
templates carry ``steps`` written for a person; a catalogue of runnable payloads
one wiring change away from an automation runner is precisely the artifact this
platform must not build.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import TYPE_CHECKING

from models.enums import RecommendationType, SourceTrustTier
from models.remediation import RemediationConfidence
from models.values import Citation

if TYPE_CHECKING:
    from collections.abc import Sequence

_ATTACK_MITIGATIONS_URL = "https://attack.mitre.org/mitigations"
_CWE_URL = "https://cwe.mitre.org/data/definitions"

INTERNAL_BASELINE_SOURCE_ID = "internal_baseline"
INTERNAL_BASELINE_SOURCE = "Internal remediation baseline"


@dataclass(frozen=True)
class Mitigation:
    """One catalogued MITRE ATT&CK mitigation."""

    mitigation_id: str
    name: str

    @property
    def url(self) -> str:
        return f"{_ATTACK_MITIGATIONS_URL}/{self.mitigation_id}/"

    def citation(self) -> Citation:
        return Citation(
            source_id="mitre_attack",
            source="MITRE ATT&CK",
            url=self.url,
            title=f"{self.mitigation_id} — {self.name}",
            trust_tier=SourceTrustTier.AUTHORITATIVE,
        )


MITIGATIONS: dict[str, Mitigation] = {
    item.mitigation_id: item
    for item in (
        Mitigation("M1013", "Application Developer Guidance"),
        Mitigation("M1018", "User Account Management"),
        Mitigation("M1022", "Restrict File and Directory Permissions"),
        Mitigation("M1026", "Privileged Account Management"),
        Mitigation("M1027", "Password Policies"),
        Mitigation("M1029", "Remote Data Storage"),
        Mitigation("M1030", "Network Segmentation"),
        Mitigation("M1032", "Multi-factor Authentication"),
        Mitigation("M1037", "Filter Network Traffic"),
        Mitigation("M1038", "Execution Prevention"),
        Mitigation("M1042", "Disable or Remove Feature or Program"),
        Mitigation("M1047", "Audit"),
        Mitigation("M1049", "Antivirus/Antimalware"),
        Mitigation("M1051", "Update Software"),
        Mitigation("M1054", "Software Configuration"),
    )
}


@dataclass(frozen=True)
class RemediationTemplate:
    """One catalogued piece of remediation guidance."""

    template_id: str
    action: str
    type: RecommendationType
    rationale: str
    expected_impact: str
    steps: tuple[str, ...]
    verification: str
    grounding: RemediationConfidence
    mitigation_ids: tuple[str, ...] = ()
    extra_citations: tuple[Citation, ...] = ()

    def citations(self) -> list[Citation]:
        """Every source this guidance rests on, deduplicated by URL."""
        found: list[Citation] = [
            MITIGATIONS[item].citation() for item in self.mitigation_ids if item in MITIGATIONS
        ]
        found.extend(self.extra_citations)
        if not found:
            found.append(baseline_citation())
        seen: set[str] = set()
        unique: list[Citation] = []
        for citation in found:
            key = citation.url or citation.title or citation.source_id
            if key in seen:
                continue
            seen.add(key)
            unique.append(citation)
        return unique


def baseline_citation() -> Citation:
    """The source for generic hardening advice.

    Naming the internal baseline is not a formality: it tells a reader the advice
    is *ours*, not a vendor's, which is exactly the distinction that decides
    whether they can treat it as a fix.
    """
    return Citation(
        source_id=INTERNAL_BASELINE_SOURCE_ID,
        source=INTERNAL_BASELINE_SOURCE,
        title="Conservative hardening guidance (no product-specific advisory available)",
        trust_tier=SourceTrustTier.INTERNAL,
    )


# --- Technique-driven guidance ----------------------------------------------

_TEMPLATES: tuple[RemediationTemplate, ...] = (
    RemediationTemplate(
        template_id="credential_attack_controls",
        action="Harden authentication on the affected accounts and hosts",
        type=RecommendationType.CONFIGURATION,
        rationale=(
            "Repeated authentication attempts against a single principal indicate "
            "credential guessing; rate limiting and a second factor remove the "
            "attacker's ability to keep trying."
        ),
        expected_impact=(
            "Guessing attacks fail before they succeed. Users without an enrolled "
            "second factor will be interrupted at next sign-in."
        ),
        steps=(
            "Reset the credentials of every account named in the timeline.",
            "Require multi-factor authentication for those accounts.",
            "Enable account lockout or progressive delay on repeated failures.",
            "Review whether the source addresses should reach this service at all.",
        ),
        verification=(
            "Confirm authentication failures for the named principals stop, and that "
            "a test sign-in is challenged for a second factor."
        ),
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1032", "M1027", "M1018"),
    ),
    RemediationTemplate(
        template_id="account_privilege_review",
        action="Review the account and privilege changes observed",
        type=RecommendationType.MITIGATION,
        rationale=(
            "Accounts created or elevated during an incident are a common persistence "
            "route, and one that survives the original entry point being closed."
        ),
        expected_impact=(
            "Attacker-created access is removed. Legitimate changes made in the same "
            "window will need re-approving."
        ),
        steps=(
            "List accounts created or modified in the incident window and confirm "
            "each with its owner.",
            "Remove group memberships that were not requested through change control.",
            "Rotate credentials for any privileged account involved.",
        ),
        verification="Confirm the privileged group membership matches the approved baseline.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1026", "M1018"),
    ),
    RemediationTemplate(
        template_id="script_execution_controls",
        action="Constrain script and interpreter execution on the affected hosts",
        type=RecommendationType.CONFIGURATION,
        rationale=(
            "Obfuscated or hidden interpreter invocations are deliberate concealment; "
            "execution policy and script logging remove both the capability and the "
            "attacker's ability to work unobserved."
        ),
        expected_impact=(
            "Unsigned and encoded scripts stop running. Administrative automation that "
            "relies on unsigned scripts will need signing or an explicit exemption."
        ),
        steps=(
            "Enable script block and module logging so future invocations are recorded in full.",
            "Apply an execution policy or allow-list that blocks unsigned scripts.",
            "Review scheduled tasks and services for the same command line.",
        ),
        verification="Confirm a test encoded invocation is blocked and appears in the script log.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1038", "M1042", "M1047"),
    ),
    RemediationTemplate(
        template_id="persistence_review",
        action="Review services, scheduled tasks, and startup entries on the affected hosts",
        type=RecommendationType.MITIGATION,
        rationale=(
            "Services and scheduled jobs created during an incident survive reboots and "
            "credential resets, so closing the entry point alone does not end the access."
        ),
        expected_impact=(
            "Attacker persistence is removed. Legitimate jobs created in the same window "
            "will need confirming with their owners."
        ),
        steps=(
            "Compare installed services and scheduled tasks against a known-good baseline.",
            "Remove entries that cannot be attributed to an approved change.",
            "Re-check after reboot, since some persistence re-creates itself.",
        ),
        verification="Confirm the service and task inventory matches the baseline after a reboot.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1047", "M1022"),
    ),
    RemediationTemplate(
        template_id="log_integrity",
        action="Restore and protect the audit trail",
        type=RecommendationType.CONFIGURATION,
        rationale=(
            "Cleared logs destroy the record this and every future investigation depends "
            "on. Forwarding logs off-host puts them beyond the reach of whoever holds the host."
        ),
        expected_impact=(
            "Future activity remains reconstructable even if a host is fully compromised. "
            "Log storage and forwarding volume will increase."
        ),
        steps=(
            "Forward security logs to a remote collector the host cannot modify.",
            "Restrict log-clearing rights to a small, audited set of accounts.",
            "Alert on log-clearing events themselves.",
        ),
        verification=(
            "Confirm a test log-clearing event is alerted on and the remote copy survives."
        ),
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1029", "M1047", "M1022"),
    ),
    RemediationTemplate(
        template_id="restore_security_tooling",
        action="Restore the disabled security tooling and alert on future changes",
        type=RecommendationType.CONFIGURATION,
        rationale=(
            "Endpoint protection and auditing were turned off. Until they are restored the "
            "host is both undefended and unobserved."
        ),
        expected_impact="Detection coverage returns on the affected host.",
        steps=(
            "Re-enable endpoint protection, auditing, and the host firewall.",
            "Confirm the tooling reports healthy to its management console.",
            "Alert on future attempts to disable it.",
        ),
        verification="Confirm the management console shows the agent healthy and reporting.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1049", "M1047"),
    ),
    RemediationTemplate(
        template_id="egress_controls",
        action="Review and restrict outbound access from the affected hosts",
        type=RecommendationType.CONFIGURATION,
        rationale=(
            "Repeated contact with an external destination is the shape of command and "
            "control as well as of ordinary polling; egress filtering makes the difference "
            "visible and cuts the channel if it is the former."
        ),
        expected_impact=(
            "Unapproved outbound destinations become unreachable. Legitimate integrations "
            "must be allow-listed first, so this needs a change window."
        ),
        steps=(
            "Confirm with the service owner whether the destination is expected.",
            "If it is not, block it at the egress point and hunt for the same "
            "destination elsewhere.",
            "Move toward a default-deny egress policy for this network segment.",
        ),
        verification=(
            "Confirm the destination is unreachable from the segment and no service broke."
        ),
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1037", "M1030"),
    ),
    RemediationTemplate(
        template_id="remote_access_review",
        action="Review remote administration access to the affected hosts",
        type=RecommendationType.CONFIGURATION,
        rationale=(
            "Remote execution and remote desktop are how lateral movement happens once a "
            "single host is held; limiting who may reach them limits how far an intrusion travels."
        ),
        expected_impact=(
            "Remote administration is reachable only from approved sources. Ad-hoc "
            "administrative access from arbitrary hosts will stop working."
        ),
        steps=(
            "Restrict remote administration ports to a jump host or management network.",
            "Require multi-factor authentication for remote administrative sessions.",
            "Review which accounts hold remote logon rights.",
        ),
        verification="Confirm remote administration is refused from a non-management address.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1030", "M1032", "M1026"),
    ),
    RemediationTemplate(
        template_id="untrusted_input_handling",
        action="Fix the unsafe handling of untrusted input in the affected component",
        type=RecommendationType.PATCH,
        rationale=(
            "The weakness class behind this vulnerability is untrusted input reaching an "
            "interpreter, a parser, or a deserializer. Until that path is closed, the same "
            "class of bug recurs with each new payload."
        ),
        expected_impact=(
            "The vulnerable input path is closed. Application changes require testing "
            "before release."
        ),
        steps=(
            "Apply the vendor fix if one exists; otherwise disable the affected feature.",
            "Validate and constrain the input at the boundary rather than deep in the call stack.",
            "Add a regression test reproducing the original payload.",
        ),
        verification="Confirm the original payload no longer reaches the vulnerable code path.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1051", "M1013"),
    ),
    RemediationTemplate(
        template_id="access_control_fix",
        action="Correct the access control on the affected component",
        type=RecommendationType.CONFIGURATION,
        rationale=(
            "The weakness class behind this vulnerability is a missing or incorrect "
            "authorization check, so the exposure is not limited to the path that was found."
        ),
        expected_impact=(
            "Unauthorized access is refused. Callers relying on the gap will start failing, "
            "which is the intended outcome but needs communicating."
        ),
        steps=(
            "Apply the vendor fix if one exists.",
            "Audit the surrounding endpoints or objects for the same missing check.",
            "Restrict permissions on the affected resource to the roles that need it.",
        ),
        verification="Confirm an unauthorized caller is refused on the affected path.",
        grounding=RemediationConfidence.CLASS_SPECIFIC,
        mitigation_ids=("M1022", "M1026", "M1051"),
    ),
    RemediationTemplate(
        template_id="generic_hardening",
        action="Apply conservative hardening to the affected assets",
        type=RecommendationType.MITIGATION,
        rationale=(
            "No product-specific remediation was available for this finding, so this is "
            "general hardening rather than a fix. It reduces exposure while the specific "
            "remediation is identified."
        ),
        expected_impact=(
            "Reduced exposure without addressing the underlying cause. The specific fix is "
            "still required."
        ),
        steps=(
            "Confirm the affected software is on a supported, fully patched release.",
            "Restrict network reachability of the affected service to what it needs.",
            "Increase logging on the affected hosts until the specific remediation is applied.",
            "Track this item until product-specific guidance is available.",
        ),
        verification="Confirm patch level and reachability match the intended baseline.",
        grounding=RemediationConfidence.GENERIC,
    ),
)

TEMPLATES: dict[str, RemediationTemplate] = {item.template_id: item for item in _TEMPLATES}

# Observed technique to the guidance that addresses it. Techniques absent here
# fall through to generic hardening, which is a labelled answer rather than a
# missing one.
_TECHNIQUE_TEMPLATES: dict[str, str] = {
    "T1021": "remote_access_review",
    "T1027": "script_execution_controls",
    "T1041": "egress_controls",
    "T1053": "persistence_review",
    "T1059": "script_execution_controls",
    "T1059.001": "script_execution_controls",
    "T1068": "account_privilege_review",
    "T1070": "log_integrity",
    "T1070.001": "log_integrity",
    "T1071": "egress_controls",
    "T1078": "credential_attack_controls",
    "T1098": "account_privilege_review",
    "T1105": "egress_controls",
    "T1110": "credential_attack_controls",
    "T1136": "account_privilege_review",
    "T1218": "script_execution_controls",
    "T1543": "persistence_review",
    "T1548": "account_privilege_review",
    "T1562": "restore_security_tooling",
    "T1569": "persistence_review",
}

# Weakness class to the guidance that addresses it.
_WEAKNESS_TEMPLATES: dict[str, str] = {
    "CWE-20": "untrusted_input_handling",
    "CWE-22": "untrusted_input_handling",
    "CWE-77": "untrusted_input_handling",
    "CWE-78": "untrusted_input_handling",
    "CWE-79": "untrusted_input_handling",
    "CWE-89": "untrusted_input_handling",
    "CWE-94": "untrusted_input_handling",
    "CWE-502": "untrusted_input_handling",
    "CWE-611": "untrusted_input_handling",
    "CWE-918": "untrusted_input_handling",
    "CWE-1321": "untrusted_input_handling",
    "CWE-269": "access_control_fix",
    "CWE-287": "access_control_fix",
    "CWE-306": "access_control_fix",
    "CWE-732": "access_control_fix",
    "CWE-798": "access_control_fix",
    "CWE-862": "access_control_fix",
    "CWE-863": "access_control_fix",
}


def for_technique(technique_id: str) -> RemediationTemplate | None:
    """Guidance addressing an observed ATT&CK technique, if any is catalogued."""
    template_id = _TECHNIQUE_TEMPLATES.get(technique_id.upper())
    return TEMPLATES.get(template_id) if template_id else None


def for_weakness(cwe_id: str) -> RemediationTemplate | None:
    """Guidance addressing a CVE's weakness class, if any is catalogued."""
    template_id = _WEAKNESS_TEMPLATES.get(cwe_id.upper())
    return TEMPLATES.get(template_id) if template_id else None


def generic_guidance() -> RemediationTemplate:
    """The conservative fallback, always labelled as generic."""
    return TEMPLATES["generic_hardening"]


def patch_guidance(
    cve_id: str,
    *,
    product: str | None = None,
    fixed_version: str | None = None,
    references: Sequence[str] = (),
    advisory_citation: Citation | None = None,
) -> RemediationTemplate:
    """Build upgrade guidance for a confirmed CVE.

    A named fixed version is the strongest advice this system can give — upgrade
    *this* to *that* — so it is stated in the action itself rather than buried in
    the steps. Without one the guidance stays honest about what it does not know:
    it names the CVE and points at the advisory rather than inventing a version.
    """
    subject = product or "the affected component"
    target = f" to {fixed_version} or later" if fixed_version else ""
    grounding = (
        RemediationConfidence.VENDOR_SPECIFIC
        if fixed_version
        else RemediationConfidence.CLASS_SPECIFIC
    )

    steps = [
        f"Identify every host running {subject} and record its current version.",
        (
            f"Upgrade {subject}{target} in a change window, starting with internet-facing hosts."
            if fixed_version
            else f"Consult the referenced advisory for the fixed release of {subject}."
        ),
        "Restart the affected services so the new version is actually loaded.",
    ]
    if not fixed_version:
        steps.append(
            "If no fixed release exists yet, apply the vendor's interim mitigation and "
            "track the advisory for updates."
        )

    citations = [advisory_citation] if advisory_citation else []
    citations.extend(
        Citation(source_id="vendor_advisories", source="Vendor advisory", url=url)
        for url in references[:3]
    )

    return RemediationTemplate(
        template_id=f"patch:{cve_id}",
        action=f"Patch {cve_id} on {subject}{target}",
        type=RecommendationType.PATCH,
        rationale=(
            f"{cve_id} was confirmed applicable to assets in this investigation. "
            + (
                f"The vendor has published a fixed release ({fixed_version}), so the "
                "exposure can be removed rather than only reduced."
                if fixed_version
                else "No fixed release was identified, so the advisory must be consulted "
                "for the current remediation."
            )
        ),
        expected_impact=(
            "The vulnerability is removed from the upgraded hosts. Upgrading requires a "
            "service restart and a change window."
        ),
        steps=tuple(steps),
        verification=(
            f"Confirm the deployed version of {subject} is{target or ' the fixed release'} "
            "on every affected host."
        ),
        grounding=grounding,
        mitigation_ids=("M1051",),
        extra_citations=tuple(citation for citation in citations if citation is not None),
    )
