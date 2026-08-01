"""ORM models package.

Importing this package registers every table on ``Base.metadata`` (needed by
Alembic autogeneration and ``create_all``).
"""

from backend.db.base import Base
from backend.db.orm.analysis import CveFinding, ThreatAssessment
from backend.db.orm.audit import AuditLog
from backend.db.orm.conversation import Conversation, HumanDecision, Message
from backend.db.orm.evidence import LogEvent
from backend.db.orm.investigation import Asset, Investigation
from backend.db.orm.knowledge import KnowledgeChunk, KnowledgeIndexVersion
from backend.db.orm.memory import InvestigationMemoryIndexEntry, SessionMemoryEntry
from backend.db.orm.notification import Notification
from backend.db.orm.reporting import Recommendation, Report
from backend.db.orm.user import User

__all__ = [
    "Asset",
    "AuditLog",
    "Base",
    "Conversation",
    "CveFinding",
    "HumanDecision",
    "Investigation",
    "InvestigationMemoryIndexEntry",
    "KnowledgeChunk",
    "KnowledgeIndexVersion",
    "LogEvent",
    "Message",
    "Notification",
    "Recommendation",
    "Report",
    "SessionMemoryEntry",
    "ThreatAssessment",
    "User",
]
