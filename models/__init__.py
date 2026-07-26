"""Models layer — canonical typed schemas and contracts shared across the system.

The single source of truth for shapes: domain entities and value objects (this
sprint), and later the graph-state, agent I/O, and event schemas. Everything
depends inward on these contracts (dependency inversion / clean architecture).

See docs/ENGINEERING_DESIGN_SPEC.md §3.13 and §6.
"""

from models.analysis import CveFinding, ThreatAssessment
from models.audit import AuditLog
from models.base import DomainModel, IdentifiedModel
from models.conversation import Conversation, HumanDecision, Message
from models.enums import (
    ApprovalStatus,
    AssetEnvironment,
    CveApplicability,
    DecisionType,
    EnrichmentStatus,
    InvestigationStatus,
    MessageAuthorType,
    NotificationChannel,
    NotificationStatus,
    RecommendationType,
    ReportStatus,
    Severity,
    TriagePriority,
    TriggerSource,
    UserRole,
    UserStatus,
    Verdict,
)
from models.evidence import LogEvent
from models.investigation import Asset, Investigation
from models.notification import Notification
from models.reporting import Recommendation, Report
from models.user import User
from models.values import AttackTechnique, Citation, Cvss, Ioc

__all__ = [
    # enums
    "ApprovalStatus",
    # entities
    "Asset",
    "AssetEnvironment",
    # value objects
    "AttackTechnique",
    "AuditLog",
    "Citation",
    "Conversation",
    "CveApplicability",
    "CveFinding",
    "Cvss",
    "DecisionType",
    # base
    "DomainModel",
    "EnrichmentStatus",
    "HumanDecision",
    "IdentifiedModel",
    "Investigation",
    "InvestigationStatus",
    "Ioc",
    "LogEvent",
    "Message",
    "MessageAuthorType",
    "Notification",
    "NotificationChannel",
    "NotificationStatus",
    "Recommendation",
    "RecommendationType",
    "Report",
    "ReportStatus",
    "Severity",
    "ThreatAssessment",
    "TriagePriority",
    "TriggerSource",
    "User",
    "UserRole",
    "UserStatus",
    "Verdict",
]
