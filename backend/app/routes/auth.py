"""Authenticated VaultZero profile endpoints; credentials are managed by Supabase Auth."""

from typing import Any, Dict, Optional

from fastapi import APIRouter, Depends
from pydantic import BaseModel

from ..services.auth_service import get_current_user
from ..services.database import get_active_key_for_user

router = APIRouter(prefix="/api/auth", tags=["auth"])


class UserProfileResponse(BaseModel):
    email: str
    vault_id: str
    active_key: Optional[Dict[str, Any]] = None


@router.get("/me", response_model=UserProfileResponse, summary="Resolve the authenticated Supabase profile")
async def get_me(current_user: Dict[str, Any] = Depends(get_current_user)):
    active_key = get_active_key_for_user(current_user["id"])
    key_summary = None
    if active_key:
        key_summary = {
            "key_id": active_key["key_id"],
            "algorithm": active_key["algorithm"],
            "key_size_bits": active_key["key_size_bits"],
            "fingerprint": active_key["fingerprint"],
            "registered_at": active_key["registered_at"],
            "status": active_key["status"],
        }
    return UserProfileResponse(
        email=current_user["email"],
        vault_id=current_user["vault_id"],
        active_key=key_summary,
    )
