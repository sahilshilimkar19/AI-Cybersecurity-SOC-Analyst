"""End-to-end auth flow tests (login -> callback -> refresh/logout) with stub OIDC."""

from typing import Any, cast

from fastapi.testclient import TestClient
from sqlalchemy import Engine, select
from sqlalchemy.orm import Session

from backend.db.orm.audit import AuditLog


def _login(client: TestClient) -> dict[str, Any]:
    state = client.get("/auth/login").json()["state"]
    response = client.get(f"/auth/callback?code=abc&state={state}")
    assert response.status_code == 200
    return cast("dict[str, Any]", response.json())


def test_login_returns_authorization_url(client: TestClient) -> None:
    response = client.get("/auth/login")
    assert response.status_code == 200
    body = response.json()
    assert body["state"]
    assert body["authorization_url"].startswith("https://idp.test/authorize")


def test_callback_issues_tokens_and_me_works(client: TestClient) -> None:
    tokens = _login(client)
    assert tokens["access_token"]
    assert tokens["refresh_token"]
    assert tokens["token_type"] == "bearer"

    me = client.get("/auth/me", headers={"Authorization": f"Bearer {tokens['access_token']}"})
    assert me.status_code == 200
    body = me.json()
    assert body["email"] == "analyst@example.com"
    assert body["role"] == "analyst"


def test_callback_with_invalid_state_is_rejected(client: TestClient) -> None:
    response = client.get("/auth/callback?code=abc&state=does-not-exist")
    assert response.status_code == 401
    assert response.json()["error"] == "oidc_error"


def test_refresh_rotates_and_detects_reuse(client: TestClient) -> None:
    tokens = _login(client)

    rotated = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert rotated.status_code == 200
    assert rotated.json()["refresh_token"] != tokens["refresh_token"]

    # Replaying the original (now rotated) refresh token is detected as reuse.
    reuse = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert reuse.status_code == 401
    assert reuse.json()["error"] == "refresh_token_reuse"

    # Reuse revoked the whole session, so the rotated token no longer works either.
    after = client.post("/auth/refresh", json={"refresh_token": rotated.json()["refresh_token"]})
    assert after.status_code == 401


def test_logout_revokes_session(client: TestClient) -> None:
    tokens = _login(client)

    logout = client.post(
        "/auth/logout", headers={"Authorization": f"Bearer {tokens['access_token']}"}
    )
    assert logout.status_code == 204

    refresh = client.post("/auth/refresh", json={"refresh_token": tokens["refresh_token"]})
    assert refresh.status_code == 401


def test_login_writes_audit_event(client: TestClient, db_engine: Engine) -> None:
    _login(client)

    with Session(db_engine) as session:
        actions = [row.action for row in session.execute(select(AuditLog)).scalars().all()]

    assert "auth.login" in actions


def test_me_requires_bearer_token(client: TestClient) -> None:
    assert client.get("/auth/me").status_code == 401
