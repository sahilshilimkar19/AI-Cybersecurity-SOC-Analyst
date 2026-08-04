"""Detection heuristics over normalized evidence (EDS §4.3 responsibilities).

This is where "abnormal behavior" stops being a vague phrase and becomes a set of
named, individually testable rules. Each rule states what it looks for, what it
weighs, and which ATT&CK techniques it supports — and each match points back at
the exact events that triggered it, so an analyst can disagree with a specific
rule on specific evidence rather than with an opaque score.

Three properties are deliberate:

* **Rules are data, not control flow.** A rule is a record with a callable, so
  the catalogue can be inspected, documented, weighted, and extended without
  touching the engine. Adding a detection is adding an entry.
* **Weights are a calibrated prior, not a verdict.** They feed the severity
  scorer; nothing here decides whether an investigation is malicious.
* **Common behavior scores low, not zero.** A PowerShell launch is normal
  administration and an *encoded* PowerShell launch is not, so they are separate
  rules with an order of magnitude between their weights. Collapsing them would
  either flood analysts with noise or hide the real thing inside it.

Rules read only the fields the Log Analyzer normalized. Message text is untrusted
attacker-influenceable content (invariant #3): it is matched as data, never
interpreted as instruction, and a rule firing on crafted text is reported as an
observation about the text rather than as a fact about the world.
"""

from __future__ import annotations

import re
from collections import defaultdict
from collections.abc import Callable
from dataclasses import dataclass
from typing import TYPE_CHECKING

from models.logs import EntityType, EventType
from models.threat import DetectionSignal, IocReputation

if TYPE_CHECKING:
    from collections.abc import Sequence
    from datetime import timedelta

    from models.logs import NormalizedEvent
    from models.threat import IocIndicator

# --- Thresholds -------------------------------------------------------------
# Calibrated triage priors, pinned by fixtures. They are intentionally visible
# constants rather than magic numbers buried in the rules.

# Failed authentications by one principal before the pattern reads as guessing
# rather than as a mistyped password.
BRUTE_FORCE_THRESHOLD = 5
# Failures preceding a success before the success reads as the guess landing.
BREAKTHROUGH_THRESHOLD = 3
# Connections to one external destination before the pattern reads as repeated
# contact rather than as a one-off request.
BEACONING_THRESHOLD = 3


# --- Pattern vocabulary -----------------------------------------------------

_ENCODED_COMMAND = re.compile(
    r"(?:-enc(?:odedcommand)?\b|frombase64string|-nop\b|-noprofile\b|-w\s+hidden\b"
    r"|-windowstyle\s+hidden\b|invoke-expression|\biex\s*\(|downloadstring)",
    re.IGNORECASE,
)
_INTERPRETER = re.compile(
    r"\b(?:powershell(?:\.exe)?|pwsh|cmd\.exe|wscript\.exe|cscript\.exe|bash|sh|python[\d.]*)\b",
    re.IGNORECASE,
)
_PROXY_BINARY = re.compile(
    r"\b(?:certutil|mshta|rundll32|regsvr32|msiexec|bitsadmin|wmic|installutil)(?:\.exe)?\b",
    re.IGNORECASE,
)
_TOOL_TRANSFER = re.compile(
    r"(?:\bcurl\b|\bwget\b|invoke-webrequest|downloadfile|-urlcache|\bscp\b|bitsadmin\s+/transfer)",
    re.IGNORECASE,
)
_SERVICE_CREATE = re.compile(
    r"(?:\bsc(?:\.exe)?\s+create\b|service was installed|new-service|systemctl\s+enable"
    r"|installed\s+a\s+service)",
    re.IGNORECASE,
)
_SCHEDULED_TASK = re.compile(
    r"(?:schtasks(?:\.exe)?\s*/create|register-scheduledtask|\bcrontab\s+-e\b|\bat\.exe\b"
    r"|scheduled task (?:was )?created)",
    re.IGNORECASE,
)
_LOG_CLEARED = re.compile(
    r"(?:audit log was cleared|event log was cleared|clear-eventlog|wevtutil\s+cl\b"
    r"|\blogs?\s+cleared\b|rm\s+-rf?\s+/var/log)",
    re.IGNORECASE,
)
_DEFENSE_DISABLED = re.compile(
    r"(?:disablerealtimemonitoring|set-mppreference\s+-disable|defender\s+(?:was\s+)?disabled"
    r"|systemctl\s+stop\s+(?:auditd|falcon-sensor|osqueryd)|firewall\s+(?:was\s+)?disabled"
    r"|setenforce\s+0)",
    re.IGNORECASE,
)
_ACCOUNT_CREATED = re.compile(
    r"(?:user account was created|useradd\b|new-localuser|adduser\b|account\s+created)",
    re.IGNORECASE,
)
_ACCOUNT_ELEVATED = re.compile(
    # Windows 4728/4732 read "A member was added to a security-enabled local
    # group", so the article and the qualifiers are all optional.
    r"(?:added to (?:a |an |the )?(?:security-enabled )?(?:local |global |universal )?group"
    r"|usermod\s+-a?G\b|add-localgroupmember|\bsudoers\b|granted\s+admin)",
    re.IGNORECASE,
)
_REMOTE_SERVICE = re.compile(
    r"(?:\bpsexec\b|\bwinrm\b|\brdp\b|remote desktop|\bport\s*(?:3389|5985|5986)\b)",
    re.IGNORECASE,
)


# --- Engine -----------------------------------------------------------------


@dataclass(frozen=True)
class DetectionContext:
    """Everything the rules are allowed to see."""

    events: Sequence[NormalizedEvent]
    window: timedelta
    internal_networks: tuple[str, ...] = ()


@dataclass(frozen=True)
class RuleMatch:
    """One firing of a rule: the events responsible, and why."""

    event_ids: list[str]
    detail: str


# What every rule is: a pure function from the evidence to zero or more matches.
RuleEvaluator = Callable[[DetectionContext], list[RuleMatch]]


@dataclass(frozen=True)
class DetectionRule:
    """A named heuristic with its weight and the techniques it supports."""

    rule_id: str
    name: str
    description: str
    weight: float
    technique_ids: tuple[str, ...]
    evaluate: RuleEvaluator


def evaluate_rules(
    context: DetectionContext, *, rules: Sequence[DetectionRule] | None = None
) -> list[DetectionSignal]:
    """Run every rule, returning one signal per match, strongest first."""
    signals: list[DetectionSignal] = []
    for rule in rules if rules is not None else DEFAULT_RULES:
        for match in rule.evaluate(context):
            signals.append(
                DetectionSignal(
                    rule_id=rule.rule_id,
                    name=rule.name,
                    description=rule.description,
                    weight=rule.weight,
                    event_ids=match.event_ids,
                    technique_ids=list(rule.technique_ids),
                    detail=match.detail,
                )
            )
    return sorted(signals, key=lambda signal: (-signal.weight, signal.rule_id, signal.detail))


def signal_from_hostile_indicators(iocs: Sequence[IocIndicator]) -> DetectionSignal | None:
    """Turn *confirmed* hostile indicators into a signal.

    Kept out of the rule catalogue on purpose: every rule above reads only
    observed evidence, while this one rests on an external assertion. An
    indicator counts here **only** when an intel source actually said so —
    ``enriched`` is required, so "not checked" can never become "confirmed bad".
    """
    hostile = [ioc for ioc in iocs if ioc.is_hostile]
    if not hostile:
        return None

    malicious = [ioc for ioc in hostile if ioc.reputation is IocReputation.MALICIOUS]
    graded = malicious or hostile
    sources = sorted({ioc.reputation_source for ioc in graded if ioc.reputation_source})
    return DetectionSignal(
        rule_id="hostile_indicator_confirmed",
        name="Indicator flagged by threat intelligence",
        description=(
            "One or more observed indicators were reported as malicious or suspicious "
            "by an external threat-intelligence source."
        ),
        weight=8.5 if malicious else 6.0,
        event_ids=_unique([event_id for ioc in graded for event_id in ioc.event_ids]),
        technique_ids=[],
        detail=(
            f"{len(graded)} indicator(s) flagged by {', '.join(sources) or 'threat intelligence'}: "
            + ", ".join(ioc.defanged for ioc in graded[:5])
        ),
    )


# --- Rule implementations ---------------------------------------------------


def _searchable(event: NormalizedEvent) -> str:
    """The untrusted text a pattern rule matches against, lowercased."""
    parts = [event.message, event.action or "", event.outcome or ""]
    parts.extend(str(value) for value in event.fields.values())
    return " ".join(parts).lower()


def _pattern_rule(
    pattern: re.Pattern[str], *, types: frozenset[EventType] | None = None
) -> RuleEvaluator:
    """Build an evaluator matching a regex against each event's untrusted text."""

    def evaluate(context: DetectionContext) -> list[RuleMatch]:
        matched = [
            event
            for event in context.events
            if (types is None or event.event_type in types) and pattern.search(_searchable(event))
        ]
        return _single_match(matched)

    return evaluate


def _type_rule(types: frozenset[EventType]) -> RuleEvaluator:
    """Build an evaluator that fires on the presence of an event *category*.

    Some behaviors are already a finding once the Log Analyzer has classified
    them — a privilege change is a privilege change regardless of how the vendor
    worded it — so matching the normalized type is both sufficient and more
    robust than matching prose.
    """

    def evaluate(context: DetectionContext) -> list[RuleMatch]:
        return _single_match([event for event in context.events if event.event_type in types])

    return evaluate


def _single_match(events: Sequence[NormalizedEvent]) -> list[RuleMatch]:
    """Collapse the matched events into one match, or none if nothing matched."""
    if not events:
        return []
    return [RuleMatch(event_ids=[event.event_id for event in events], detail=_describe(events))]


def _describe(events: Sequence[NormalizedEvent]) -> str:
    hosts = sorted({event.host for event in events if event.host})
    actors = sorted({event.actor for event in events if event.actor})
    where = f" on {', '.join(hosts)}" if hosts else ""
    who = f" by {', '.join(actors)}" if actors else ""
    return f"{len(events)} event(s){where}{who}"


def _principal(event: NormalizedEvent) -> str | None:
    """The identity a rule groups by: the actor, or the host when unattributed."""
    return (event.actor or event.host or "").lower() or None


def _group_by_principal(
    events: Sequence[NormalizedEvent], *, types: frozenset[EventType]
) -> dict[str, list[NormalizedEvent]]:
    grouped: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in events:
        if event.event_type not in types:
            continue
        principal = _principal(event)
        if principal is not None:
            grouped[principal].append(event)
    return {
        key: sorted(value, key=lambda event: (event.event_time, event.event_id))
        for key, value in sorted(grouped.items())
    }


def _detect_brute_force(context: DetectionContext) -> list[RuleMatch]:
    """Repeated authentication failures by one principal inside the window."""
    matches: list[RuleMatch] = []
    for principal, events in _group_by_principal(
        context.events, types=frozenset({EventType.AUTH_FAILURE})
    ).items():
        for burst in _bursts(events, context.window):
            if len(burst) < BRUTE_FORCE_THRESHOLD:
                continue
            matches.append(
                RuleMatch(
                    event_ids=[event.event_id for event in burst],
                    detail=(
                        f"{len(burst)} failed authentications for {principal!r} "
                        f"between {burst[0].event_time.isoformat()} and "
                        f"{burst[-1].event_time.isoformat()}"
                    ),
                )
            )
    return matches


def _detect_breakthrough(context: DetectionContext) -> list[RuleMatch]:
    """A successful authentication immediately following a run of failures."""
    matches: list[RuleMatch] = []
    relevant = frozenset({EventType.AUTH_FAILURE, EventType.AUTH_SUCCESS})
    for principal, events in _group_by_principal(context.events, types=relevant).items():
        run: list[NormalizedEvent] = []
        for event in events:
            if event.event_type is EventType.AUTH_FAILURE:
                if run and event.event_time - run[-1].event_time > context.window:
                    run = []
                run.append(event)
                continue
            # A success: it only matters if enough failures preceded it in window.
            if len(run) >= BREAKTHROUGH_THRESHOLD and (
                event.event_time - run[-1].event_time <= context.window
            ):
                matches.append(
                    RuleMatch(
                        event_ids=[item.event_id for item in [*run, event]],
                        detail=(
                            f"{len(run)} failed authentications for {principal!r} followed by a "
                            f"success at {event.event_time.isoformat()}"
                        ),
                    )
                )
            run = []
    return matches


def _detect_beaconing(context: DetectionContext) -> list[RuleMatch]:
    """Repeated network contact with one external destination."""
    from tools.iocs import is_internal_address

    destinations: dict[str, list[NormalizedEvent]] = defaultdict(list)
    for event in context.events:
        if event.event_type is not EventType.NETWORK_CONNECTION:
            continue
        for entity in event.entities:
            if entity.type not in {EntityType.IP_ADDRESS, EntityType.DOMAIN}:
                continue
            if is_internal_address(entity.value, context.internal_networks):
                continue
            destinations[entity.value.lower()].append(event)

    matches: list[RuleMatch] = []
    for destination, events in sorted(destinations.items()):
        ordered = sorted(events, key=lambda event: (event.event_time, event.event_id))
        unique = _unique([event.event_id for event in ordered])
        if len(unique) < BEACONING_THRESHOLD:
            continue
        matches.append(
            RuleMatch(
                event_ids=unique,
                detail=f"{len(unique)} connections to external destination {destination!r}",
            )
        )
    return matches


def _bursts(events: Sequence[NormalizedEvent], window: timedelta) -> list[list[NormalizedEvent]]:
    """Split time-ordered events wherever the gap exceeds the window."""
    bursts: list[list[NormalizedEvent]] = []
    current: list[NormalizedEvent] = []
    for event in events:
        if current and event.event_time - current[-1].event_time > window:
            bursts.append(current)
            current = []
        current.append(event)
    if current:
        bursts.append(current)
    return bursts


def _unique(values: Sequence[str]) -> list[str]:
    seen: set[str] = set()
    ordered: list[str] = []
    for value in values:
        if value in seen:
            continue
        seen.add(value)
        ordered.append(value)
    return ordered


# --- The catalogue ----------------------------------------------------------

DEFAULT_RULES: tuple[DetectionRule, ...] = (
    DetectionRule(
        rule_id="brute_force_authentication",
        name="Repeated authentication failures",
        description=(
            f"At least {BRUTE_FORCE_THRESHOLD} failed authentications for one principal "
            "within the correlation window."
        ),
        weight=5.5,
        technique_ids=("T1110",),
        evaluate=_detect_brute_force,
    ),
    DetectionRule(
        rule_id="authentication_breakthrough",
        name="Successful authentication after repeated failures",
        description=(
            f"A successful authentication preceded by at least {BREAKTHROUGH_THRESHOLD} "
            "failures for the same principal — the pattern of a guess landing."
        ),
        weight=7.5,
        technique_ids=("T1110", "T1078"),
        evaluate=_detect_breakthrough,
    ),
    DetectionRule(
        rule_id="privilege_change_observed",
        name="Privilege change",
        description="A privilege level was altered.",
        weight=6.0,
        technique_ids=("T1068", "T1548"),
        evaluate=_type_rule(frozenset({EventType.PRIVILEGE_CHANGE})),
    ),
    DetectionRule(
        rule_id="account_created",
        name="Account creation",
        description="A new account was created.",
        weight=5.0,
        technique_ids=("T1136",),
        evaluate=_pattern_rule(_ACCOUNT_CREATED),
    ),
    DetectionRule(
        rule_id="account_elevated",
        name="Account granted elevated group membership",
        description="An account was added to a privileged group or granted administrative rights.",
        weight=6.5,
        technique_ids=("T1098", "T1078"),
        evaluate=_pattern_rule(_ACCOUNT_ELEVATED),
    ),
    DetectionRule(
        rule_id="script_interpreter_execution",
        name="Script interpreter execution",
        description=(
            "A command or scripting interpreter was launched. Routine on its own — "
            "weighted low so it contributes context rather than alarm."
        ),
        weight=2.5,
        technique_ids=("T1059",),
        evaluate=_pattern_rule(_INTERPRETER, types=frozenset({EventType.PROCESS_START})),
    ),
    DetectionRule(
        rule_id="encoded_command_execution",
        name="Obfuscated or hidden command execution",
        description=(
            "An interpreter was invoked with encoding, hidden-window, or in-memory "
            "execution flags — deliberate concealment, not ordinary administration."
        ),
        weight=7.5,
        technique_ids=("T1027", "T1059.001"),
        evaluate=_pattern_rule(_ENCODED_COMMAND),
    ),
    DetectionRule(
        rule_id="proxy_binary_execution",
        name="Signed binary proxy execution",
        description="A trusted system binary commonly abused to run other code was invoked.",
        weight=6.0,
        technique_ids=("T1218",),
        evaluate=_pattern_rule(_PROXY_BINARY),
    ),
    DetectionRule(
        rule_id="ingress_tool_transfer",
        name="File transferred into the environment",
        description="A download or file-transfer utility was used to pull content onto a host.",
        weight=6.0,
        technique_ids=("T1105",),
        evaluate=_pattern_rule(_TOOL_TRANSFER),
    ),
    DetectionRule(
        rule_id="service_installed",
        name="Service installed",
        description="A new system service was created or installed — a common persistence route.",
        weight=5.5,
        technique_ids=("T1543", "T1569"),
        evaluate=_pattern_rule(_SERVICE_CREATE),
    ),
    DetectionRule(
        rule_id="scheduled_task_created",
        name="Scheduled task created",
        description="A scheduled task or cron entry was created — persistence or timed execution.",
        weight=5.5,
        technique_ids=("T1053",),
        evaluate=_pattern_rule(_SCHEDULED_TASK),
    ),
    DetectionRule(
        rule_id="audit_log_cleared",
        name="Audit log cleared",
        description=(
            "Event or audit logs were cleared. Destroying the record of activity is "
            "rarely accidental and directly attacks the evidence this platform rests on."
        ),
        weight=8.0,
        technique_ids=("T1070", "T1070.001"),
        evaluate=_pattern_rule(_LOG_CLEARED),
    ),
    DetectionRule(
        rule_id="security_tooling_disabled",
        name="Security tooling disabled",
        description="Endpoint protection, auditing, or the host firewall was turned off.",
        weight=7.5,
        technique_ids=("T1562",),
        evaluate=_pattern_rule(_DEFENSE_DISABLED),
    ),
    DetectionRule(
        rule_id="remote_service_activity",
        name="Remote administration service used",
        description="Remote execution or remote desktop tooling appears in the evidence.",
        weight=3.5,
        technique_ids=("T1021",),
        evaluate=_pattern_rule(_REMOTE_SERVICE),
    ),
    DetectionRule(
        rule_id="external_beaconing",
        name="Repeated contact with an external destination",
        description=(
            f"At least {BEACONING_THRESHOLD} connections to the same external address "
            "or domain — the shape of command-and-control, though also of ordinary polling."
        ),
        weight=4.5,
        technique_ids=("T1071",),
        evaluate=_detect_beaconing,
    ),
)

RULES_BY_ID: dict[str, DetectionRule] = {rule.rule_id: rule for rule in DEFAULT_RULES}
