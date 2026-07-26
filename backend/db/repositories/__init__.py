"""Data-access repositories.

Repositories are the persistence interface consumed by backend services. Keeping
writes behind repositories preserves the "backend is the sole write boundary"
invariant (#7) and centralizes validation and audit.
"""

from backend.db.repositories.audit import AuditLogRepository
from backend.db.repositories.base import Repository

__all__ = ["AuditLogRepository", "Repository"]
