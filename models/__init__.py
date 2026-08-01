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
    IndexStatus,
    InvestigationStatus,
    KnowledgeSourceKind,
    MemoryIndexKind,
    MessageAuthorType,
    NotificationChannel,
    NotificationStatus,
    RecommendationType,
    ReportStatus,
    Severity,
    SourceTrustTier,
    TriagePriority,
    TriggerSource,
    UserRole,
    UserStatus,
    Verdict,
)
from models.evidence import LogEvent
from models.investigation import Asset, Investigation
from models.knowledge import (
    ChunkMetadata,
    IngestionReport,
    KnowledgeChunkRecord,
    RetrievalFilters,
    RetrievalResult,
    RetrievedChunk,
    SourceDocument,
)
from models.memory import (
    ContextBundle,
    ConversationTurn,
    KnowledgeChunk,
    MemoryEntry,
    MemoryStats,
    MemoryTier,
    RelatedInvestigation,
)
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
    "ChunkMetadata",
    "Citation",
    "ContextBundle",
    "Conversation",
    "ConversationTurn",
    "CveApplicability",
    "CveFinding",
    "Cvss",
    "DecisionType",
    # base
    "DomainModel",
    "EnrichmentStatus",
    "HumanDecision",
    "IdentifiedModel",
    "IndexStatus",
    "IngestionReport",
    "Investigation",
    "InvestigationStatus",
    "Ioc",
    "KnowledgeChunk",
    "KnowledgeChunkRecord",
    "KnowledgeSourceKind",
    "LogEvent",
    "MemoryEntry",
    "MemoryIndexKind",
    "MemoryStats",
    "MemoryTier",
    "Message",
    "MessageAuthorType",
    "Notification",
    "NotificationChannel",
    "NotificationStatus",
    "Recommendation",
    "RecommendationType",
    "RelatedInvestigation",
    "Report",
    "ReportStatus",
    "RetrievalFilters",
    "RetrievalResult",
    "RetrievedChunk",
    "Severity",
    "SourceDocument",
    "SourceTrustTier",
    "ThreatAssessment",
    "TriagePriority",
    "TriggerSource",
    "User",
    "UserRole",
    "UserStatus",
    "Verdict",
]
