"""
VaultZero Lite - File Storage Service
Manages storage and retrieval of client-encrypted .vault packages.

SECURITY NOTICE:
- The backend stores ONLY pre-encrypted .vault binary envelopes.
- The backend never receives, processes, or stores plaintext data, AES session keys,
  or RSA private keys.
- File IDs are generated with cryptographically secure randomness (secrets.token_urlsafe).
- Strict path sanitization prevents directory traversal attacks.
"""

import os
import json
import re
import secrets
from pathlib import Path
from typing import Optional, Tuple, Dict, Any

# Configurable storage directory and limits
STORAGE_DIR = Path(os.getenv("VAULT_STORAGE_DIR", Path(__file__).resolve().parent.parent.parent / "storage"))
MAX_FILE_SIZE_BYTES = int(os.getenv("MAX_FILE_SIZE_BYTES", 50 * 1024 * 1024))  # 50 MB default limit
MIN_PACKAGE_SIZE_BYTES = 256 + 12 + 4 + 16  # 288 bytes (RSA key + IV + meta len uint32 + min tag)

# Safe pattern for unpredictable file IDs: alphanumeric, hyphens, underscores
FILE_ID_PATTERN = re.compile(r"^[a-zA-Z0-9_-]{16,64}$")


def ensure_storage_dir() -> Path:
    """Ensures the storage directory exists and returns its Path."""
    STORAGE_DIR.mkdir(parents=True, exist_ok=True)
    return STORAGE_DIR


def validate_file_id(file_id: str) -> bool:
    """Validates that a file_id matches the safe regex pattern."""
    return bool(FILE_ID_PATTERN.match(file_id))


def validate_vault_package_bytes(package_bytes: bytes) -> Tuple[bool, Optional[str], Optional[int]]:
    """
    Validates structural properties of a .vault package binary:
    - Minimum length check (288 bytes: 256B RSA key + 12B IV + 4B meta length + 16B AEAD tag)
    - Metadata length sanity check
    Returns: (is_valid, error_message, metadata_length)
    """
    if len(package_bytes) < MIN_PACKAGE_SIZE_BYTES:
        return False, f"Package size ({len(package_bytes)} bytes) is below minimum required header size ({MIN_PACKAGE_SIZE_BYTES} bytes)", None

    if len(package_bytes) > MAX_FILE_SIZE_BYTES:
        return False, f"Package size exceeds maximum allowed threshold of {MAX_FILE_SIZE_BYTES} bytes", None

    # Read uint32 big-endian metadata length at byte offset 268
    meta_len = int.from_bytes(package_bytes[268:272], byteorder="big", signed=False)
    
    # Metadata length sanity check (prevent absurd sizes)
    if meta_len > 1_000_000:
        return False, f"Package metadata length ({meta_len} bytes) exceeds safety limit of 1MB", None

    min_required_with_meta = 272 + meta_len + 16
    if len(package_bytes) < min_required_with_meta:
        return False, f"Package is truncated: expected at least {min_required_with_meta} bytes for metadata and auth tag, got {len(package_bytes)}", None

    return True, None, meta_len


def store_vault_package(
    package_bytes: bytes,
    original_filename: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Stores an encrypted .vault package and writes an isolation metadata sidecar.
    """
    is_valid, error_msg, meta_len = validate_vault_package_bytes(package_bytes)
    if not is_valid:
        raise ValueError(error_msg)

    storage_path = ensure_storage_dir()

    # Generate unpredictable 128-bit urlsafe token
    file_id = secrets.token_urlsafe(16)

    # Sanitize provided filename or default to file_id.vault
    safe_name = "protected_payload.vault"
    if original_filename:
        # Keep base name only, remove paths and dangerous characters
        cleaned = Path(original_filename).name
        cleaned = re.sub(r"[^\w\.\-]", "_", cleaned)
        if not cleaned.endswith(".vault"):
            cleaned = f"{cleaned}.vault"
        safe_name = cleaned

    package_path = storage_path / f"{file_id}.vault"
    meta_path = storage_path / f"{file_id}.meta.json"

    # Write binary package
    with open(package_path, "wb") as f:
        f.write(package_bytes)

    # Write non-sensitive storage metadata
    meta_data = {
        "file_id": file_id,
        "filename": safe_name,
        "size_bytes": len(package_bytes),
        "metadata_header_bytes": meta_len,
    }
    with open(meta_path, "w", encoding="utf-8") as f:
        json.dump(meta_data, f)

    return {
        "file_id": file_id,
        "filename": safe_name,
        "size_bytes": len(package_bytes),
    }


def get_vault_package(file_id: str) -> Optional[Tuple[Path, Dict[str, Any]]]:
    """
    Retrieves the Path and metadata for a stored .vault package by file_id.
    Strictly prevents path traversal. Returns None if not found.
    """
    if not validate_file_id(file_id):
        return None

    storage_path = ensure_storage_dir()
    package_path = storage_path / f"{file_id}.vault"
    meta_path = storage_path / f"{file_id}.meta.json"

    if not package_path.is_file():
        return None

    meta = {
        "file_id": file_id,
        "filename": f"{file_id}.vault",
        "size_bytes": package_path.stat().st_size,
    }

    if meta_path.is_file():
        try:
            with open(meta_path, "r", encoding="utf-8") as f:
                meta = json.load(f)
        except Exception:
            pass

    return package_path, meta
