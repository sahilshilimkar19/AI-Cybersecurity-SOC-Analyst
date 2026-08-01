"""Enumerations shared across domain contracts and persistence.

Values are stable wire/storage representations; renaming a value is a breaking
change requiring a migration (EDS §3.13).
"""

from __future__ import annotations

from enum import StrEnum


class UserRole(StrEnum):
    """RBAC roles (SAD §14)."""

    ANALYST = "analyst"
    SENIOR_ANALYST = "senior_analyst"
    MANAGER = "manager"
    ADMIN = "admin"
    AUDITOR = "auditor"


class UserStatus(StrEnum):
    """Account lifecycle state. Users are deactivated, never hard-deleted."""

    ACTIVE = "active"
    DISABLED = "disabled"


class TriggerSource(StrEnum):
    """What initiated an investigation (EDS §3 orchestration triggers)."""

    ANALYST = "analyst"
    ALERT = "alert"
    SCHEDULED = "scheduled"


class InvestigationStatus(StrEnum):
    """Investigation lifecycle."""

    OPEN = "open"
    IN_PROGRESS = "in_progress"
    AWAITING_APPROVAL = "awaiting_approval"
    CLOSED = "closed"
    ARCHIVED = "archived"


class Severity(StrEnum):
    """Severity scale, shared by assessments and investigations."""

    INFO = "info"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    CRITICAL = "critical"


class TriagePriority(StrEnum):
    """Triage / remediation priority."""

    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"
    URGENT = "urgent"


class Verdict(StrEnum):
    """Threat Detector verdict."""

    BENIGN = "benign"
    SUSPICIOUS = "suspicious"
    MALICIOUS = "malicious"


class EnrichmentStatus(StrEnum):
    """Whether external enrichment (threat intel) was available."""

    COMPLETE = "complete"
    DEGRADED = "degraded"
    UNAVAILABLE = "unavailable"


class CveApplicability(StrEnum):
    """Whether a CVE is confirmed to apply to the affected assets."""

    CONFIRMED = "confirmed"
    CANDIDATE = "candidate"
    NOT_APPLICABLE = "not_applicable"


class ReportStatus(StrEnum):
    """Incident report lifecycle."""

    DRAFT = "draft"
    FINAL = "final"


class RecommendationType(StrEnum):
    """Kind of remediation recommendation."""

    PATCH = "patch"
    CONFIGURATION = "configuration"
    MITIGATION = "mitigation"
    OTHER = "other"


class ApprovalStatus(StrEnum):
    """Human-approval state of a remediation recommendation."""

    PENDING = "pending"
    APPROVED = "approved"
    REJECTED = "rejected"
    EDITED = "edited"


class DecisionType(StrEnum):
    """Human-in-the-loop decision at an approval gate."""

    APPROVE = "approve"
    EDIT = "edit"
    REJECT = "reject"
    REDIRECT = "redirect"


class MessageAuthorType(StrEnum):
    """Author of a conversation message."""

    HUMAN = "human"
    SYSTEM = "system"
    AGENT = "agent"


class NotificationChannel(StrEnum):
    """Outbound notification channel."""

    SLACK = "slack"
    EMAIL = "email"
    WEBHOOK = "webhook"


class NotificationStatus(StrEnum):
    """Delivery state of a notification."""

    PENDING = "pending"
    SENT = "sent"
    FAILED = "failed"
    DEAD_LETTER = "dead_letter"


class AssetEnvironment(StrEnum):
    """Environment an asset belongs to."""

    PRODUCTION = "production"
    STAGING = "staging"
    DEVELOPMENT = "development"
    UNKNOWN = "unknown"


class SourceTrustTier(StrEnum):
    """How far a knowledge source can be trusted, in descending authority.

    Ranking prefers higher tiers, and a claim resting only on a low tier is
    treated as weaker evidence (EDS §8 source trust).
    """

    AUTHORITATIVE = "authoritative"
    VENDOR = "vendor"
    COMMUNITY = "community"
    INTERNAL = "internal"


class KnowledgeSourceKind(StrEnum):
    """The knowledge sources the RAG pipeline ingests (SAD §6)."""

    NVD = "nvd"
    MITRE_ATTACK = "mitre_attack"
    ADVISORY = "advisory"
    INTERNAL_RUNBOOK = "internal_runbook"


class IndexStatus(StrEnum):
    """Lifecycle of a knowledge index version; swaps are atomic per source."""

    BUILDING = "building"
    ACTIVE = "active"
    RETIRED = "retired"


class MemoryIndexKind(StrEnum):
    """Dimension a closed investigation is indexed by for recall (EDS §7)."""

    ASSET = "asset"
    IOC = "ioc"
    TECHNIQUE = "technique"
    CVE = "cve"
