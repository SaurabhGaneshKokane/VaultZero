"""Supabase session validation and authorization tests."""

from types import SimpleNamespace

import pytest
from fastapi import HTTPException
from httpx import ASGITransport, AsyncClient

from backend.app.main import app
from backend.app.services import database
from backend.app.services import auth_service


class FakeAuth:
    def __init__(self, user=None, error=None):
        self.user = user
        self.error = error

    def get_user(self, token):
        if self.error:
            raise self.error
        return SimpleNamespace(user=self.user)


class FakeSupabaseClient:
    def __init__(self, auth):
        self.auth = auth


def test_valid_supabase_session_resolves_auth_user_id(monkeypatch):
    auth_user = SimpleNamespace(id="auth-user-123", email="verified@example.com", email_confirmed_at="2026-10-29T00:00:00Z")
    monkeypatch.setattr(database, "_supabase_client", FakeSupabaseClient(FakeAuth(user=auth_user)))
    profile = {"id": "profile-1", "auth_user_id": "auth-user-123", "email": "verified@example.com"}
    monkeypatch.setattr(database, "get_or_create_user", lambda email, auth_user_id: profile)

    assert auth_service.authenticate_supabase_token("valid-access-token") == profile


def test_invalid_session_is_rejected(monkeypatch):
    monkeypatch.setattr(database, "_supabase_client", FakeSupabaseClient(FakeAuth(error=ValueError("invalid"))))
    with pytest.raises(HTTPException) as caught:
        auth_service.authenticate_supabase_token("invalid-token")
    assert caught.value.status_code == 401


def test_unverified_email_is_rejected(monkeypatch):
    auth_user = SimpleNamespace(id="auth-user-456", email="pending@example.com", email_confirmed_at=None)
    monkeypatch.setattr(database, "_supabase_client", FakeSupabaseClient(FakeAuth(user=auth_user)))
    with pytest.raises(HTTPException) as caught:
        auth_service.authenticate_supabase_token("valid-but-unverified-token")
    assert caught.value.status_code == 403


@pytest.mark.anyio
async def test_protected_directory_requires_bearer_session(monkeypatch):
    monkeypatch.setattr(database, "_supabase_client", FakeSupabaseClient(FakeAuth(error=ValueError("invalid"))))
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/keys/lookup", params={"query": "alice@example.com"})
        assert response.status_code == 401
        response = await client.get("/api/keys/mine", headers={"Authorization": "Bearer invalid"})
        assert response.status_code == 401


@pytest.mark.anyio
async def test_legacy_custom_passwordless_auth_endpoints_are_removed():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        assert (await client.post("/api/auth/register", json={"email": "x@example.com"})).status_code == 404
        assert (await client.post("/api/auth/login", json={"email": "x@example.com"})).status_code == 404
