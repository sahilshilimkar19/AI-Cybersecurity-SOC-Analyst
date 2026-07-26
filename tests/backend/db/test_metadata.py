"""ORM metadata tests (no database required)."""

from sqlalchemy import Enum as SAEnum

import backend.db  # noqa: F401 - registers all ORM tables on Base.metadata
from backend.db.base import Base

EXPECTED_TABLES = {
    "users",
    "assets",
    "investigations",
    "log_events",
    "threat_assessments",
    "cve_findings",
    "reports",
    "recommendations",
    "conversations",
    "messages",
    "human_decisions",
    "notifications",
    "audit_logs",
}


def test_all_core_tables_are_registered() -> None:
    assert set(Base.metadata.tables) >= EXPECTED_TABLES


def test_audit_log_is_append_only_shape() -> None:
    columns = set(Base.metadata.tables["audit_logs"].columns.keys())

    # Audit rows are immutable: created but never updated.
    assert "updated_at" not in columns
    assert "created_at" in columns
    assert "signature" in columns


def test_soft_delete_present_where_expected_and_absent_on_evidence() -> None:
    assert "deleted_at" in Base.metadata.tables["investigations"].columns
    # Evidence and audit are immutable — no soft delete.
    assert "deleted_at" not in Base.metadata.tables["log_events"].columns
    assert "deleted_at" not in Base.metadata.tables["audit_logs"].columns


def test_user_email_is_unique() -> None:
    assert Base.metadata.tables["users"].c.email.unique is True


def test_enum_columns_are_non_native() -> None:
    role_type = Base.metadata.tables["users"].c.role.type
    # Stored as VARCHAR + CHECK so migrations up/downgrade cleanly.
    assert isinstance(role_type, SAEnum)
    assert role_type.native_enum is False
