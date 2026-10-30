"""
VaultZero Lite - File Routes
Endpoints for uploading and downloading client-encrypted .vault packages.
"""

from fastapi import APIRouter, HTTPException, UploadFile, File, Request, status, Depends
from fastapi.responses import FileResponse, JSONResponse
from pydantic import BaseModel
from typing import Optional

from ..services.auth_service import get_current_user
from typing import Dict, Any

from ..services.file_service import (
    store_vault_package,
    get_vault_package,
    validate_file_id,
    MAX_FILE_SIZE_BYTES,
)

router = APIRouter(prefix="/api/files", tags=["files"])


class FileUploadResponse(BaseModel):
    file_id: str
    filename: str
    size_bytes: int
    download_url: str
    message: str


@router.post(
    "",
    response_model=FileUploadResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Upload an encrypted .vault package",
    description="Stores a client-side encrypted package without decrypting it. The server never sees the plaintext or private keys.",
)
async def upload_encrypted_file(
    request: Request,
    file: Optional[UploadFile] = File(None),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    """
    Accepts an encrypted .vault package via either:
    1. multipart/form-data upload (standard form input)
    2. application/octet-stream raw binary body
    """
    package_bytes: bytes
    filename: Optional[str] = None

    if file is not None:
        filename = file.filename
        content = await file.read()
        package_bytes = content
    else:
        # Check raw body stream
        body = await request.body()
        if not body:
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No file payload provided. Please upload a .vault package.",
            )
        package_bytes = body
        # Attempt to extract filename from custom header or query
        filename = request.headers.get("X-Filename", "encrypted_payload.vault")

    # Check maximum file size limit
    if len(package_bytes) > MAX_FILE_SIZE_BYTES:
        raise HTTPException(
            status_code=status.HTTP_413_CONTENT_TOO_LARGE if hasattr(status, "HTTP_413_CONTENT_TOO_LARGE") else 413,
            detail=f"Uploaded package ({len(package_bytes)} bytes) exceeds the maximum allowed size of {MAX_FILE_SIZE_BYTES} bytes.",
        )

    try:
        result = store_vault_package(package_bytes, original_filename=filename)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=f"Package validation error: {str(e)}",
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Failed to securely store encrypted package: {str(e)}",
        )

    file_id = result["file_id"]
    return FileUploadResponse(
        file_id=file_id,
        filename=result["filename"],
        size_bytes=result["size_bytes"],
        download_url=f"/api/files/{file_id}",
        message="Encrypted package received and stored. Plaintext and private keys were never transmitted to or processed by the server.",
    )


@router.get(
    "/{file_id}",
    summary="Retrieve an encrypted .vault package",
    description="Retrieves the stored encrypted package by its unique file ID. Requires the recipient's private key to decrypt locally in browser.",
)
async def download_encrypted_file(file_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    """
    Returns the encrypted .vault package as an octet-stream attachment.
    """
    if not validate_file_id(file_id):
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="Invalid file ID format.",
        )

    retrieval = get_vault_package(file_id)
    if retrieval is None:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"File with ID '{file_id}' was not found or has expired.",
        )

    package_path, meta = retrieval
    safe_filename = meta.get("filename", f"{file_id}.vault")

    return FileResponse(
        path=str(package_path),
        filename=safe_filename,
        media_type="application/octet-stream",
        headers={
            "X-Vault-File-Id": file_id,
            "X-Vault-Size": str(meta.get("size_bytes", package_path.stat().st_size)),
            "Cache-Control": "no-store, no-cache, must-revalidate",
        },
    )
