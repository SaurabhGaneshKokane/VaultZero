"""Supabase Auth access-token validation and VaultZero user resolution."""

from typing import Any, Dict, Optional

from fastapi import Header, HTTPException, status

from . import database


def _unauthorized(detail: str = "Invalid or expired Supabase session.") -> HTTPException:
    return HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail=detail,
        headers={"WWW-Authenticate": "Bearer"},
    )


def authenticate_supabase_token(token: str) -> Dict[str, Any]:
    """Ask Supabase Auth to validate the token, then resolve its stable user ID."""
    if database._supabase_client is None:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Supabase Auth is not configured on this backend.",
        )

    try:
        response = database._supabase_client.auth.get_user(token)
        auth_user = response.user if response else None
    except Exception:
        raise _unauthorized()

    if not auth_user or not getattr(auth_user, "id", None):
        raise _unauthorized()

    email = getattr(auth_user, "email", None)
    confirmed_at = getattr(auth_user, "email_confirmed_at", None)
    if not email or not confirmed_at:
        raise HTTPException(
            status_code=status.HTTP_403_FORBIDDEN,
            detail="Verify your email address before using the VaultZero directory.",
        )

    try:
        return database.get_or_create_user(email=email, auth_user_id=str(auth_user.id))
    except Exception:
        raise HTTPException(
            status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
            detail="Unable to resolve the authenticated VaultZero profile. Apply the pending database migration.",
        )


async def get_current_user(authorization: Optional[str] = Header(None)) -> Dict[str, Any]:
    if not authorization or not authorization.startswith("Bearer "):
        raise _unauthorized("Missing or malformed Authorization header. Expected 'Bearer <token>'.")

    token = authorization.split("Bearer ", 1)[1].strip()
    if not token:
        raise _unauthorized()
    return authenticate_supabase_token(token)
