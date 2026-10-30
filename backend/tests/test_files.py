"""
Backend Tests for File Storage, Retrieval, and Security Isolation
"""

import json
import pytest
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.services import database
from backend.app.services.auth_service import get_current_user
from fastapi import Header, HTTPException
from typing import Optional

async def _test_current_user(authorization: Optional[str] = Header(None)):
    if authorization != "Bearer test-file-session":
        raise HTTPException(status_code=401, detail="Invalid test session")
    return {"id": "file-test-profile", "auth_user_id": "file-test-auth-user", "email": "files@example.com", "vault_id": "vz_file_test"}

@pytest.fixture(autouse=True)
def use_local_test_auth():
    original_client = database._supabase_client
    original_overrides = app.dependency_overrides.copy()
    database._supabase_client = None
    database.init_database()
    app.dependency_overrides[get_current_user] = _test_current_user
    yield
    app.dependency_overrides.clear()
    app.dependency_overrides.update(original_overrides)
    database._supabase_client = original_client
from backend.app.services.file_service import (
    MIN_PACKAGE_SIZE_BYTES,
    MAX_FILE_SIZE_BYTES,
)


def create_mock_vault_package(
    filename: str = "secret.txt",
    filetype: str = "text/plain",
    content_len: int = 64,
) -> bytes:
    """
    Constructs a structurally valid .vault binary package:
    - 256 bytes: Encrypted AES Key (RSA-OAEP 2048-bit)
    - 12 bytes: IV
    - 4 bytes: Metadata Length (uint32 big-endian)
    - N bytes: JSON Metadata
    - Remainder: Ciphertext + 16-byte Auth Tag
    """
    encrypted_key = b"\x01" * 256
    iv = b"\x02" * 12
    metadata = {
        "fileName": filename,
        "fileType": filetype,
        "hash": "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
    }
    meta_bytes = json.dumps(metadata).encode("utf-8")
    meta_len = len(meta_bytes).to_bytes(4, byteorder="big", signed=False)
    ciphertext = b"\xaa" * content_len
    tag = b"\xff" * 16

    return encrypted_key + iv + meta_len + meta_bytes + ciphertext + tag


@pytest.mark.anyio
async def test_successful_multipart_upload_and_retrieval():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        valid_pkg = create_mock_vault_package("confidential.pdf", "application/pdf", 128)
        
        # 1. Upload via multipart/form-data
        files = {
            "file": ("confidential.pdf.vault", valid_pkg, "application/octet-stream")
        }
        res_upload = await client.post("/api/files", files=files)
        assert res_upload.status_code == 201
        data = res_upload.json()
        assert "file_id" in data
        assert data["filename"] == "confidential.pdf.vault"
        assert data["size_bytes"] == len(valid_pkg)
        file_id = data["file_id"]

        # 2. Retrieve via GET /api/files/{file_id}
        res_get = await client.get(f"/api/files/{file_id}")
        assert res_get.status_code == 200
        assert res_get.headers["content-type"] == "application/octet-stream"
        assert res_get.headers["x-vault-file-id"] == file_id
        assert res_get.content == valid_pkg


@pytest.mark.anyio
async def test_successful_raw_body_upload():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        valid_pkg = create_mock_vault_package("notes.txt", "text/plain", 32)
        headers = {
            "Content-Type": "application/octet-stream",
            "X-Filename": "notes.txt.vault",
        }
        res_upload = await client.post("/api/files", content=valid_pkg, headers=headers)
        assert res_upload.status_code == 201
        data = res_upload.json()
        assert "file_id" in data
        assert data["filename"] == "notes.txt.vault"

        # Download and verify
        res_get = await client.get(f"/api/files/{data['file_id']}")
        assert res_get.status_code == 200
        assert res_get.content == valid_pkg


@pytest.mark.anyio
async def test_unknown_file_id_returns_404():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        # 16-char urlsafe token that does not exist
        res = await client.get("/api/files/non_existent_token_12345")
        assert res.status_code == 404
        assert "not found" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_invalid_file_id_pattern_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        # Directory traversal attempt
        res = await client.get("/api/files/../../etc/passwd")
        # FastAPI router will return 400 or 404
        assert res.status_code in (400, 404)


@pytest.mark.anyio
async def test_empty_upload_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        res = await client.post("/api/files", content=b"")
        assert res.status_code == 400


@pytest.mark.anyio
async def test_truncated_package_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        # Less than 288 bytes minimum
        small_garbage = b"\x00" * 100
        headers = {"Content-Type": "application/octet-stream"}
        res = await client.post("/api/files", content=small_garbage, headers=headers)
        assert res.status_code == 400
        assert "below minimum required header size" in res.json()["detail"]


@pytest.mark.anyio
async def test_corrupted_metadata_length_rejected():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        # Claim metadata is 500,000 bytes when package is only 300 bytes
        corrupted = (
            b"\x01" * 256
            + b"\x02" * 12
            + (500000).to_bytes(4, byteorder="big")
            + b"\xaa" * 32
        )
        headers = {"Content-Type": "application/octet-stream"}
        res = await client.post("/api/files", content=corrupted, headers=headers)
        assert res.status_code == 400
        assert "truncated" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_oversized_upload_rejected(monkeypatch):
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        # Temporarily mock MAX_FILE_SIZE_BYTES to 500 bytes for test
        from backend.app.routes import files as routes_files
        from backend.app.services import file_service

        monkeypatch.setattr(routes_files, "MAX_FILE_SIZE_BYTES", 500)
        monkeypatch.setattr(file_service, "MAX_FILE_SIZE_BYTES", 500)

        oversized_pkg = create_mock_vault_package("large.iso", "application/octet-stream", 600)
        headers = {"Content-Type": "application/octet-stream"}
        res = await client.post("/api/files", content=oversized_pkg, headers=headers)
        assert res.status_code == 413
        assert "exceeds" in res.json()["detail"].lower()


@pytest.mark.anyio
async def test_file_id_isolation():
    """
    Verifies that distinct uploads produce unique, isolated file IDs
    and cannot collide or access each other.
    """
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test", headers={"Authorization": "Bearer test-file-session"}) as client:
        pkg1 = create_mock_vault_package("doc1.pdf", "application/pdf", 64)
        pkg2 = create_mock_vault_package("doc2.pdf", "application/pdf", 128)

        res1 = await client.post("/api/files", content=pkg1, headers={"X-Filename": "doc1.pdf.vault"})
        res2 = await client.post("/api/files", content=pkg2, headers={"X-Filename": "doc2.pdf.vault"})

        id1 = res1.json()["file_id"]
        id2 = res2.json()["file_id"]

        assert id1 != id2

        get1 = await client.get(f"/api/files/{id1}")
        get2 = await client.get(f"/api/files/{id2}")

        assert get1.content == pkg1
        assert get2.content == pkg2
        assert get1.content != get2.content
