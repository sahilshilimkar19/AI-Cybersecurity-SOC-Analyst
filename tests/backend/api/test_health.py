"""Tests for the health endpoints (no database required)."""

from fastapi.testclient import TestClient


def test_health(app_client: TestClient) -> None:
    response = app_client.get("/health")
    assert response.status_code == 200
    assert response.json() == {"status": "ok"}


def test_ready(app_client: TestClient) -> None:
    response = app_client.get("/ready")
    assert response.status_code == 200
    assert response.json() == {"status": "ready"}


def test_request_id_header_is_returned(app_client: TestClient) -> None:
    response = app_client.get("/health")
    assert response.headers.get("X-Request-ID")
