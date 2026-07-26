"""Object storage abstraction for immutable raw evidence.

Large raw log records are stored in S3-compatible object storage and referenced
from the database by ``raw_ref`` (EDS §6). This module defines the storage
interface plus an in-memory implementation (for tests) and a MinIO/S3-backed
implementation (for real deployments).
"""

from __future__ import annotations

import io
from typing import Protocol, runtime_checkable

from minio import Minio
from minio.error import S3Error

from config.settings import Settings

_DEFAULT_CONTENT_TYPE = "application/octet-stream"


@runtime_checkable
class ObjectStore(Protocol):
    """Interface for storing and retrieving immutable evidence blobs."""

    def put(self, key: str, data: bytes, content_type: str = _DEFAULT_CONTENT_TYPE) -> str:
        """Store ``data`` under ``key`` and return the key (the ``raw_ref``)."""
        ...

    def get(self, key: str) -> bytes:
        """Return the bytes stored under ``key``."""
        ...

    def exists(self, key: str) -> bool:
        """Whether an object exists under ``key``."""
        ...


class InMemoryObjectStore:
    """In-memory object store for tests and local development."""

    def __init__(self) -> None:
        self._store: dict[str, bytes] = {}

    def put(self, key: str, data: bytes, content_type: str = _DEFAULT_CONTENT_TYPE) -> str:
        self._store[key] = data
        return key

    def get(self, key: str) -> bytes:
        return self._store[key]

    def exists(self, key: str) -> bool:
        return key in self._store


class MinioObjectStore:
    """MinIO / S3-compatible object store."""

    def __init__(self, client: Minio, bucket: str) -> None:
        self._client = client
        self._bucket = bucket

    def ensure_bucket(self) -> None:
        """Create the backing bucket if it does not already exist."""
        if not self._client.bucket_exists(self._bucket):
            self._client.make_bucket(self._bucket)

    def put(self, key: str, data: bytes, content_type: str = _DEFAULT_CONTENT_TYPE) -> str:
        self._client.put_object(
            self._bucket, key, io.BytesIO(data), length=len(data), content_type=content_type
        )
        return key

    def get(self, key: str) -> bytes:
        response = self._client.get_object(self._bucket, key)
        try:
            payload: bytes = response.read()
            return payload
        finally:
            response.close()
            response.release_conn()

    def exists(self, key: str) -> bool:
        try:
            self._client.stat_object(self._bucket, key)
        except S3Error:
            return False
        return True


def minio_object_store_from_settings(settings: Settings) -> MinioObjectStore:
    """Build a :class:`MinioObjectStore` from application settings."""
    client = Minio(
        settings.object_store_endpoint,
        access_key=settings.object_store_access_key,
        secret_key=settings.object_store_secret_key.get_secret_value(),
        secure=settings.object_store_secure,
    )
    return MinioObjectStore(client, settings.object_store_bucket)
