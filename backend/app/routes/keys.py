"""
VaultZero - Public Key Directory Routes
Endpoints for registering, discovering, verifying, rotating, and managing recipient RSA public keys.
"""

from fastapi import APIRouter, HTTPException, Depends, Query, status
from pydantic import BaseModel, Field
from typing import Optional, List, Dict, Any

from ..services.key_validator import (
    validate_and_canonicalize_rsa_public_key,
    generate_stable_key_id,
    KeyValidationError,
)
from ..services.database import (
    register_public_key,
    get_public_key_by_id,
    lookup_recipient,
    list_user_keys,
    rotate_public_key,
    deactivate_public_key,
    get_active_key_for_user,
)
from ..services.auth_service import get_current_user

router = APIRouter(prefix="/api/keys", tags=["public-keys"])


# ============================================================================
# Schemas
# ============================================================================

class KeyRegistrationRequest(BaseModel):
    public_key_pem: str = Field(..., description="SubjectPublicKeyInfo (SPKI) RSA-2048 public key in PEM format")


class KeyRotationRequest(BaseModel):
    new_public_key_pem: str = Field(..., description="New SubjectPublicKeyInfo (SPKI) RSA-2048 public key in PEM format")
    rotation_reason: Optional[str] = Field(None, description="Optional explanation for the key rotation")


class KeyDeactivationRequest(BaseModel):
    reason: Optional[str] = Field(None, description="Optional explanation for key deactivation")


class PublicKeyResponse(BaseModel):
    key_id: str
    owner_vault_id: str
    owner_email: str
    algorithm: str
    key_size_bits: int
    public_key_pem: str
    fingerprint: str
    fingerprint_raw_hex: str
    status: str
    previous_key_id: Optional[str] = None
    rotation_reason: Optional[str] = None
    registered_at: str
    revoked_at: Optional[str] = None
    is_active: bool


class RecipientKeyResponse(BaseModel):
    key_id: str
    owner_vault_id: str
    owner_email: str
    algorithm: str
    key_size_bits: int
    public_key_pem: str
    fingerprint: str
    status: str
    registered_at: str
    is_active: bool


class KeyFingerprintResponse(BaseModel):
    key_id: str
    algorithm: str
    fingerprint: str
    fingerprint_raw_hex: str
    status: str
    is_active: bool


class KeyStatusResponse(BaseModel):
    key_id: str
    status: str
    is_active: bool
    registered_at: str
    revoked_at: Optional[str] = None


# ============================================================================
# Endpoints
# ============================================================================

@router.post(
    "",
    response_model=PublicKeyResponse,
    status_code=status.HTTP_201_CREATED,
    summary="Register a new RSA-2048 public key",
    description="Registers an authenticated user's public key in the cloud directory. Rejects private keys and invalid algorithms.",
)
async def register_key(
    req: KeyRegistrationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    # 1. Cryptographically validate the public key
    try:
        validation = validate_and_canonicalize_rsa_public_key(req.public_key_pem)
    except KeyValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    # 2. Derive stable key ID
    key_id = generate_stable_key_id(validation["fingerprint_hex"])

    # 3. Register under authenticated user
    try:
        record = register_public_key(current_user, validation, key_id)
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_409_CONFLICT,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error registering public key: {str(e)}",
        )

    return PublicKeyResponse(
        key_id=record["key_id"],
        owner_vault_id=record["owner_vault_id"],
        owner_email=record["owner_email"],
        algorithm=record["algorithm"],
        key_size_bits=record["key_size_bits"],
        public_key_pem=record["public_key_pem"],
        fingerprint=record["fingerprint"],
        fingerprint_raw_hex=record["fingerprint_raw_hex"],
        status=record["status"],
        previous_key_id=record.get("previous_key_id"),
        rotation_reason=record.get("rotation_reason"),
        registered_at=record["registered_at"],
        revoked_at=record.get("revoked_at"),
        is_active=record["status"] == "active",
    )


@router.get(
    "/lookup",
    response_model=RecipientKeyResponse,
    summary="Search for recipient public key by email or VaultZero ID",
    description="Looks up an active public key in the directory for an intended recipient.",
)
async def lookup_key(
    query: Optional[str] = Query(None, description="Search term: verified email address or VaultZero ID"),
    email: Optional[str] = Query(None, description="Specific recipient email address"),
    vault_id: Optional[str] = Query(None, description="Specific recipient VaultZero ID"),
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    search_term = query or email or vault_id
    if not search_term:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail="A search query parameter ('query', 'email', or 'vault_id') must be provided.",
        )

    record = lookup_recipient(search_term)
    if not record:
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail=f"No active public key found for recipient matching '{search_term}'.",
        )

    return RecipientKeyResponse(
        key_id=record["key_id"],
        owner_vault_id=record["owner_vault_id"],
        owner_email=record["owner_email"],
        algorithm=record["algorithm"],
        key_size_bits=record["key_size_bits"],
        public_key_pem=record["public_key_pem"],
        fingerprint=record["fingerprint"],
        status=record["status"],
        registered_at=record["registered_at"],
        is_active=True,
    )


@router.get(
    "/mine",
    response_model=List[PublicKeyResponse],
    summary="List all public keys registered by the authenticated user",
)
async def get_my_keys(current_user: Dict[str, Any] = Depends(get_current_user)):
    """Returns the full key history (active, rotated, and deactivated) for the current user."""
    records = list_user_keys(current_user["id"])
    return [
        PublicKeyResponse(
            key_id=r["key_id"],
            owner_vault_id=r["owner_vault_id"],
            owner_email=r["owner_email"],
            algorithm=r["algorithm"],
            key_size_bits=r["key_size_bits"],
            public_key_pem=r["public_key_pem"],
            fingerprint=r["fingerprint"],
            fingerprint_raw_hex=r["fingerprint_raw_hex"],
            status=r["status"],
            previous_key_id=r.get("previous_key_id"),
            rotation_reason=r.get("rotation_reason"),
            registered_at=r["registered_at"],
            revoked_at=r.get("revoked_at"),
            is_active=r["status"] == "active",
        )
        for r in records
    ]


@router.get(
    "/{key_id}",
    response_model=PublicKeyResponse,
    summary="Retrieve public key details by key ID",
)
async def get_key_by_id(key_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = get_public_key_by_id(key_id)
    if not record or (record.get("status") != "active" and record.get("auth_user_id") != current_user.get("auth_user_id")):
        raise HTTPException(
            status_code=status.HTTP_404_NOT_FOUND,
            detail="Public key was not found or is unavailable.",
        )

    return PublicKeyResponse(
        key_id=record["key_id"],
        owner_vault_id=record["owner_vault_id"],
        owner_email=record["owner_email"],
        algorithm=record["algorithm"],
        key_size_bits=record["key_size_bits"],
        public_key_pem=record["public_key_pem"],
        fingerprint=record["fingerprint"],
        fingerprint_raw_hex=record["fingerprint_raw_hex"],
        status=record["status"],
        previous_key_id=record.get("previous_key_id"),
        rotation_reason=record.get("rotation_reason"),
        registered_at=record["registered_at"],
        revoked_at=record.get("revoked_at"),
        is_active=record["status"] == "active",
    )


@router.get(
    "/{key_id}/fingerprint",
    response_model=KeyFingerprintResponse,
    summary="Retrieve canonical fingerprint for a public key",
)
async def get_key_fingerprint(key_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = get_public_key_by_id(key_id)
    if not record or (record.get("status") != "active" and record.get("auth_user_id") != current_user.get("auth_user_id")):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Public key was not found or is unavailable.")

    return KeyFingerprintResponse(
        key_id=record["key_id"],
        algorithm=record["algorithm"],
        fingerprint=record["fingerprint"],
        fingerprint_raw_hex=record["fingerprint_raw_hex"],
        status=record["status"],
        is_active=record["status"] == "active",
    )


@router.get(
    "/{key_id}/status",
    response_model=KeyStatusResponse,
    summary="Check whether a public key is currently active",
)
async def get_key_status(key_id: str, current_user: Dict[str, Any] = Depends(get_current_user)):
    record = get_public_key_by_id(key_id)
    if not record or (record.get("status") != "active" and record.get("auth_user_id") != current_user.get("auth_user_id")):
        raise HTTPException(status_code=status.HTTP_404_NOT_FOUND, detail="Public key was not found or is unavailable.")

    return KeyStatusResponse(
        key_id=record["key_id"],
        status=record["status"],
        is_active=record["status"] == "active",
        registered_at=record["registered_at"],
        revoked_at=record.get("revoked_at"),
    )


@router.post(
    "/{key_id}/rotate",
    response_model=PublicKeyResponse,
    summary="Explicitly rotate an active public key (Authenticated)",
    description="Deactivates the existing key with status 'rotated' and links the new key to prevent silent key replacement.",
)
async def rotate_key(
    key_id: str,
    req: KeyRotationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    # 1. Validate new key
    try:
        validation = validate_and_canonicalize_rsa_public_key(req.new_public_key_pem)
    except KeyValidationError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )

    new_key_id = generate_stable_key_id(validation["fingerprint_hex"])

    # 2. Perform authenticated rotation
    try:
        new_record = rotate_public_key(
            user=current_user,
            old_key_id=key_id,
            new_key_validation=validation,
            new_key_id=new_key_id,
            rotation_reason=req.rotation_reason,
        )
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except ValueError as e:
        raise HTTPException(
            status_code=status.HTTP_400_BAD_REQUEST,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error during key rotation: {str(e)}",
        )

    return PublicKeyResponse(
        key_id=new_record["key_id"],
        owner_vault_id=new_record["owner_vault_id"],
        owner_email=new_record["owner_email"],
        algorithm=new_record["algorithm"],
        key_size_bits=new_record["key_size_bits"],
        public_key_pem=new_record["public_key_pem"],
        fingerprint=new_record["fingerprint"],
        fingerprint_raw_hex=new_record["fingerprint_raw_hex"],
        status=new_record["status"],
        previous_key_id=new_record.get("previous_key_id"),
        rotation_reason=new_record.get("rotation_reason"),
        registered_at=new_record["registered_at"],
        revoked_at=new_record.get("revoked_at"),
        is_active=new_record["status"] == "active",
    )


@router.post(
    "/{key_id}/deactivate",
    response_model=PublicKeyResponse,
    summary="Deactivate a public key (Authenticated)",
)
async def deactivate_key(
    key_id: str,
    req: KeyDeactivationRequest,
    current_user: Dict[str, Any] = Depends(get_current_user),
):
    try:
        updated = deactivate_public_key(current_user, key_id, req.reason)
    except PermissionError as e:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail=str(e),
        )
    except Exception as e:
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"Database error during key deactivation: {str(e)}",
        )

    return PublicKeyResponse(
        key_id=updated["key_id"],
        owner_vault_id=updated["owner_vault_id"],
        owner_email=updated["owner_email"],
        algorithm=updated["algorithm"],
        key_size_bits=updated["key_size_bits"],
        public_key_pem=updated["public_key_pem"],
        fingerprint=updated["fingerprint"],
        fingerprint_raw_hex=updated["fingerprint_raw_hex"],
        status=updated["status"],
        previous_key_id=updated.get("previous_key_id"),
        rotation_reason=updated.get("rotation_reason"),
        registered_at=updated["registered_at"],
        revoked_at=updated.get("revoked_at"),
        is_active=False,
    )
