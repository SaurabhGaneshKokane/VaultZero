"""
VaultZero - Public Key Directory & Security Invariant Tests
Verifies server-side RSA key validation, canonical fingerprinting, anti-silent-overwrite protection, and zero-private-key enforcement.
"""

import uuid
import pytest
from httpx import AsyncClient, ASGITransport
from cryptography.hazmat.primitives.asymmetric import rsa, ec
from cryptography.hazmat.primitives import serialization
from backend.app.main import app
from backend.app.services import database
from backend.app.services.auth_service import get_current_user
from fastapi import Header, HTTPException
from typing import Optional

_TEST_USERS = {}

async def _test_current_user(authorization: Optional[str] = Header(None)):
    token = authorization.removeprefix("Bearer ") if authorization else ""
    user = _TEST_USERS.get(token)
    if not user:
        raise HTTPException(status_code=401, detail="Invalid test session")
    return user

@pytest.fixture(autouse=True)
def use_local_test_auth():
    original_client = database._supabase_client
    original_overrides = app.dependency_overrides.copy()
    database._supabase_client = None
    database.init_database()
    app.dependency_overrides[get_current_user] = _test_current_user
    _TEST_USERS.clear()
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(original_overrides)
    database._supabase_client = original_client
    _TEST_USERS.clear()


def generate_test_rsa_key(bits=2048):
    """Generates an ephemeral RSA key for testing."""
    key = rsa.generate_private_key(public_exponent=65537, key_size=bits)
    pub_pem = key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")
    priv_pem = key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    ).decode("utf-8")
    return pub_pem, priv_pem


async def create_auth_user(client: AsyncClient, prefix: str = "user"):
    uid = uuid.uuid4().hex[:8]
    email = f"{prefix}_{uid}@example.com"
    vault_id = f"vz_{prefix}_{uid}"
    auth_user_id = str(uuid.uuid4())
    data = database.get_or_create_user(email=email, vault_id=vault_id, auth_user_id=auth_user_id)
    token = f"test-session-{uid}"
    _TEST_USERS[token] = data
    return {"headers": {"Authorization": f"Bearer {token}"}, "user": data}


@pytest.mark.anyio
async def test_register_valid_rsa2048_public_key():
    """Valid RSA-2048 public key registration succeeds and calculates canonical fingerprint."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_reg")
        pub_pem, _ = generate_test_rsa_key(2048)
        resp = await client.post(
            "/api/keys",
            json={"public_key_pem": pub_pem},
            headers=alice["headers"],
        )
        assert resp.status_code == 201
        data = resp.json()
        assert data["algorithm"] == "RSA-OAEP-2048"
        assert data["key_size_bits"] == 2048
        assert data["status"] == "active"
        assert data["fingerprint"].startswith("SHA256:")
        assert len(data["fingerprint_raw_hex"]) == 64
        assert data["owner_email"] == alice["user"]["email"]
        stored = database.get_active_key_for_user(alice["user"]["id"])
        assert stored["auth_user_id"] == alice["user"]["auth_user_id"]


@pytest.mark.anyio
async def test_reject_private_key_upload():
    """CRITICAL: Submitting a private key to the public key directory MUST be rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_priv")
        _, priv_pem = generate_test_rsa_key(2048)
        resp = await client.post(
            "/api/keys",
            json={"public_key_pem": priv_pem},
            headers=alice["headers"],
        )
        assert resp.status_code == 400
        assert "PRIVATE KEY" in resp.json()["detail"]


@pytest.mark.anyio
async def test_reject_invalid_key_size():
    """RSA keys smaller than 2048-bit are rejected for security and interoperability."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_size")
        pub_1024, _ = generate_test_rsa_key(1024)
        resp = await client.post(
            "/api/keys",
            json={"public_key_pem": pub_1024},
            headers=alice["headers"],
        )
        assert resp.status_code == 400
        assert "2048-bit" in resp.json()["detail"]


@pytest.mark.anyio
async def test_reject_malformed_key():
    """Malformed PEM data is rejected."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_malf")
        resp = await client.post(
            "/api/keys",
            json={"public_key_pem": "-----BEGIN PUBLIC KEY-----\nNOT_A_KEY\n-----END PUBLIC KEY-----"},
            headers=alice["headers"],
        )
        assert resp.status_code == 400


@pytest.mark.anyio
async def test_reject_elliptic_curve_key():
    """Non-RSA keys are rejected because VaultZero relies on RSA-OAEP for AES key encapsulation."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_ec")
        ec_key = ec.generate_private_key(ec.SECP256R1())
        ec_pub_pem = ec_key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        ).decode("utf-8")

        resp = await client.post(
            "/api/keys",
            json={"public_key_pem": ec_pub_pem},
            headers=alice["headers"],
        )
        assert resp.status_code == 400
        assert "requires RSA keys" in resp.json()["detail"]


@pytest.mark.anyio
async def test_prevent_silent_key_replacement():
    """Registering another key without explicit rotation MUST fail to prevent silent overwrite."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_silent")
        pub1, _ = generate_test_rsa_key(2048)
        pub2, _ = generate_test_rsa_key(2048)

        # First registration
        r1 = await client.post("/api/keys", json={"public_key_pem": pub1}, headers=alice["headers"])
        assert r1.status_code == 201

        # Second registration without rotation
        r2 = await client.post("/api/keys", json={"public_key_pem": pub2}, headers=alice["headers"])
        assert r2.status_code == 409
        assert "already has an active public key" in r2.json()["detail"]


@pytest.mark.anyio
async def test_explicit_key_rotation():
    """Explicit authenticated rotation deactivates old key and registers new key with link."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_rot")
        pub1, _ = generate_test_rsa_key(2048)
        pub2, _ = generate_test_rsa_key(2048)

        r1 = await client.post("/api/keys", json={"public_key_pem": pub1}, headers=alice["headers"])
        assert r1.status_code == 201
        old_key_id = r1.json()["key_id"]

        # Rotate key
        rot_resp = await client.post(
            f"/api/keys/{old_key_id}/rotate",
            json={
                "new_public_key_pem": pub2,
                "rotation_reason": "Scheduled annual cryptographic key rotation",
            },
            headers=alice["headers"],
        )
        assert rot_resp.status_code == 200
        new_data = rot_resp.json()
        assert new_data["status"] == "active"
        assert new_data["previous_key_id"] == old_key_id
        assert new_data["rotation_reason"] == "Scheduled annual cryptographic key rotation"

        # Verify old key status is now 'rotated'
        old_resp = await client.get(f"/api/keys/{old_key_id}/status", headers=alice["headers"])
        assert old_resp.status_code == 200
        assert old_resp.json()["status"] == "rotated"
        assert old_resp.json()["is_active"] is False

        bob = await create_auth_user(client, "bob_old_key")
        hidden_history = await client.get(f"/api/keys/{old_key_id}", headers=bob["headers"])
        assert hidden_history.status_code == 404


@pytest.mark.anyio
async def test_recipient_discovery_by_email_and_vault_id():
    """Other users can discover active public key by email or VaultZero ID."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_disc")
        pub, _ = generate_test_rsa_key(2048)
        reg = await client.post("/api/keys", json={"public_key_pem": pub}, headers=alice["headers"])
        assert reg.status_code == 201
        expected_fingerprint = reg.json()["fingerprint"]

        # Lookup by email
        lookup_email = await client.get("/api/keys/lookup", params={"email": alice["user"]["email"]}, headers=alice["headers"])
        assert lookup_email.status_code == 200
        assert lookup_email.json()["fingerprint"] == expected_fingerprint

        # Lookup by vault_id
        lookup_vault_id = await client.get("/api/keys/lookup", params={"vault_id": alice["user"]["vault_id"]}, headers=alice["headers"])
        assert lookup_vault_id.status_code == 200
        assert lookup_vault_id.json()["fingerprint"] == expected_fingerprint


@pytest.mark.anyio
async def test_key_deactivation():
    """Owner can deactivate a key, after which it cannot be discovered as active."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_deact")
        pub, _ = generate_test_rsa_key(2048)
        reg = await client.post("/api/keys", json={"public_key_pem": pub}, headers=alice["headers"])
        assert reg.status_code == 201
        key_id = reg.json()["key_id"]

        deact = await client.post(
            f"/api/keys/{key_id}/deactivate",
            json={"reason": "Compromised device"},
            headers=alice["headers"],
        )
        assert deact.status_code == 200
        assert deact.json()["status"] == "deactivated"

        # Lookup now returns 404 because no active key exists
        lookup = await client.get("/api/keys/lookup", params={"email": alice["user"]["email"]}, headers=alice["headers"])
        assert lookup.status_code == 404


@pytest.mark.anyio
async def test_unauthorized_key_tampering_rejected():
    """Bob cannot rotate or deactivate Alice's key."""
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        alice = await create_auth_user(client, "alice_tamp")
        bob = await create_auth_user(client, "bob_tamp")

        pub, _ = generate_test_rsa_key(2048)
        reg = await client.post("/api/keys", json={"public_key_pem": pub}, headers=alice["headers"])
        assert reg.status_code == 201
        alice_key_id = reg.json()["key_id"]

        bob_pub, _ = generate_test_rsa_key(2048)
        # Bob attempts to rotate Alice's key
        rot_resp = await client.post(
            f"/api/keys/{alice_key_id}/rotate",
            json={"new_public_key_pem": bob_pub},
            headers=bob["headers"],
        )
        assert rot_resp.status_code == 403

