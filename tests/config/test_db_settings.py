"""Tests for the database and object-store settings added in Sprint 2."""

import pytest

from config.settings import Settings


def test_database_defaults() -> None:
    settings = Settings()

    assert settings.database_url.startswith("postgresql+psycopg://")
    assert settings.database_echo is False
    assert settings.database_pool_size == 5


def test_object_store_defaults() -> None:
    settings = Settings()

    assert settings.object_store_endpoint == "localhost:9000"
    assert settings.object_store_bucket == "soc-evidence"
    assert settings.object_store_secure is False


def test_secret_is_not_leaked_in_repr() -> None:
    settings = Settings()

    # SecretStr masks its value in repr/str; the raw secret must not appear.
    assert "soc_minio_local_pw" not in repr(settings)
    assert settings.object_store_secret_key.get_secret_value() == "soc_minio_local_pw"


def test_database_url_override(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("SOC_DATABASE_URL", "postgresql+psycopg://u:p@db:5432/x")

    assert Settings().database_url == "postgresql+psycopg://u:p@db:5432/x"
