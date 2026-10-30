"""
VaultZero - Database Service Layer
Supports Supabase PostgreSQL in production and local SQLite fallback for standalone development/testing.
Ensures zero SQL injection with parameterized queries and strict schema enforcement.
"""

import os
import sqlite3
import uuid
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional, Dict, Any, List

# Check environment for Supabase credentials
SUPABASE_URL = os.getenv("SUPABASE_URL", "").strip()
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY", "").strip()

# Local storage fallback directory
STORAGE_DIR = Path(os.getenv("VAULT_STORAGE_DIR", "backend/storage"))
STORAGE_DIR.mkdir(parents=True, exist_ok=True)
SQLITE_DB_PATH = STORAGE_DIR / "vaultzero.db"

_supabase_client = None

if SUPABASE_URL and SUPABASE_SERVICE_ROLE_KEY:
    try:
        from supabase import create_client
        _supabase_client = create_client(SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)
    except Exception as e:
        print(f"[VaultZero DB] Failed to initialize Supabase client: {e}. Falling back to SQLite.")
        _supabase_client = None


def get_db_connection() -> sqlite3.Connection:
    """Returns a SQLite connection configured with Row factory."""
    conn = sqlite3.connect(str(SQLITE_DB_PATH), check_same_thread=False)
    conn.row_factory = sqlite3.Row
    return conn


def init_database():
    """Initializes SQLite schema if not using Supabase."""
    if _supabase_client is not None:
        return

    conn = get_db_connection()
    try:
        with conn:
            conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_users (
                id TEXT PRIMARY KEY,
                auth_user_id TEXT UNIQUE,
                vault_id TEXT UNIQUE NOT NULL,
                email TEXT UNIQUE NOT NULL,
                email_verified INTEGER NOT NULL DEFAULT 1,
                created_at TEXT NOT NULL,
                updated_at TEXT NOT NULL
            );
            """)

            conn.execute("""
            CREATE TABLE IF NOT EXISTS vault_public_keys (
                id TEXT PRIMARY KEY,
                key_id TEXT UNIQUE NOT NULL,
                user_id TEXT NOT NULL,
                auth_user_id TEXT,
                owner_vault_id TEXT NOT NULL,
                owner_email TEXT NOT NULL,
                algorithm TEXT NOT NULL,
                key_size_bits INTEGER NOT NULL,
                public_key_pem TEXT NOT NULL,
                fingerprint TEXT NOT NULL,
                fingerprint_raw_hex TEXT NOT NULL,
                status TEXT NOT NULL DEFAULT 'active',
                previous_key_id TEXT,
                rotation_reason TEXT,
                created_at TEXT NOT NULL,
                registered_at TEXT NOT NULL,
                expires_at TEXT,
                revoked_at TEXT,
                FOREIGN KEY (user_id) REFERENCES vault_users(id) ON DELETE CASCADE
            );
            """)

            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_email ON vault_users(email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_users_vault_id ON vault_users(vault_id);")
            # Upgrade existing local SQLite databases without dropping key history.
            user_columns = {row[1] for row in conn.execute("PRAGMA table_info(vault_users)").fetchall()}
            if "auth_user_id" not in user_columns:
                conn.execute("ALTER TABLE vault_users ADD COLUMN auth_user_id TEXT")
            key_columns = {row[1] for row in conn.execute("PRAGMA table_info(vault_public_keys)").fetchall()}
            if "auth_user_id" not in key_columns:
                conn.execute("ALTER TABLE vault_public_keys ADD COLUMN auth_user_id TEXT")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_auth_user_id ON vault_users(auth_user_id)")
            conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_keys_one_active_auth_user ON vault_public_keys(auth_user_id) WHERE status = 'active' AND auth_user_id IS NOT NULL")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_key_id ON vault_public_keys(key_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_owner_email ON vault_public_keys(owner_email);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_owner_vault_id ON vault_public_keys(owner_vault_id);")
            conn.execute("CREATE INDEX IF NOT EXISTS idx_keys_status ON vault_public_keys(status);")
    finally:
        conn.close()


# Auto-initialize on import
init_database()


def get_or_create_user(email: str, vault_id: Optional[str] = None, auth_user_id: Optional[str] = None) -> Dict[str, Any]:
    """Resolve an email-verified Supabase identity to its existing VaultZero profile."""
    clean_email = email.strip().lower()
    if not clean_email or not auth_user_id:
        raise ValueError("A verified Supabase user ID and email are required.")
    clean_vault_id = (vault_id or f"vz_{clean_email.split('@')[0]}_{uuid.uuid4().hex[:6]}").strip().lower()

    if _supabase_client is not None:
        by_auth_id = _supabase_client.table("vault_users").select("*").eq("auth_user_id", auth_user_id).execute()
        if by_auth_id.data:
            user = by_auth_id.data[0]
            if user.get("email", "").lower() != clean_email:
                changed = _supabase_client.table("vault_users").update({
                    "email": clean_email, "email_verified": True,
                    "updated_at": datetime.now(timezone.utc).isoformat(),
                }).eq("id", user["id"]).execute()
                user = changed.data[0] if changed.data else {**user, "email": clean_email}
            return user

        by_email = _supabase_client.table("vault_users").select("*").eq("email", clean_email).execute()
        if by_email.data:
            user = by_email.data[0]
            linked_id = user.get("auth_user_id")
            if linked_id and linked_id != auth_user_id:
                raise ValueError("This email is already linked to a different authenticated account.")
            updated = _supabase_client.table("vault_users").update({
                "auth_user_id": auth_user_id, "email_verified": True,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }).eq("id", user["id"]).execute()
            return updated.data[0] if updated.data else {**user, "auth_user_id": auth_user_id}

        now = datetime.now(timezone.utc).isoformat()
        new_user = {
            "id": str(uuid.uuid4()), "auth_user_id": auth_user_id,
            "email": clean_email, "vault_id": clean_vault_id,
            "email_verified": True, "created_at": now, "updated_at": now,
        }
        inserted = _supabase_client.table("vault_users").insert(new_user).execute()
        return inserted.data[0]

    conn = get_db_connection()
    try:
        row = conn.execute("SELECT * FROM vault_users WHERE auth_user_id = ?", (auth_user_id,)).fetchone()
        if row:
            user = dict(row)
            if user["email"].lower() != clean_email:
                conn.execute("UPDATE vault_users SET email = ?, email_verified = 1, updated_at = ? WHERE id = ?", (clean_email, datetime.now(timezone.utc).isoformat(), user["id"]))
                conn.execute("UPDATE vault_public_keys SET owner_email = ? WHERE user_id = ?", (clean_email, user["id"]))
                conn.commit()
                user["email"] = clean_email
            return user

        row = conn.execute("SELECT * FROM vault_users WHERE LOWER(email) = ?", (clean_email,)).fetchone()
        if row:
            user = dict(row)
            if user.get("auth_user_id") and user["auth_user_id"] != auth_user_id:
                raise ValueError("This email is already linked to a different authenticated account.")
            conn.execute("UPDATE vault_users SET auth_user_id = ?, email_verified = 1, updated_at = ? WHERE id = ?", (auth_user_id, datetime.now(timezone.utc).isoformat(), user["id"]))
            conn.commit()
            user["auth_user_id"] = auth_user_id
            return user

        now = datetime.now(timezone.utc).isoformat()
        user_id = str(uuid.uuid4())
        user = {"id": user_id, "auth_user_id": auth_user_id, "vault_id": clean_vault_id, "email": clean_email, "email_verified": True, "created_at": now, "updated_at": now}
        conn.execute("INSERT INTO vault_users (id, auth_user_id, vault_id, email, email_verified, created_at, updated_at) VALUES (?, ?, ?, ?, 1, ?, ?)", (user_id, auth_user_id, clean_vault_id, clean_email, now, now))
        conn.commit()
        return user
    finally:
        conn.close()


def get_user_by_id(user_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a user by ID."""
    if _supabase_client is not None:
        res = _supabase_client.table("vault_users").select("*").eq("id", user_id).execute()
        return res.data[0] if res.data else None

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM vault_users WHERE id = ?", (user_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def get_active_key_for_user(user_id: str) -> Optional[Dict[str, Any]]:
    """Returns the currently active public key record for a user."""
    if _supabase_client is not None:
        res = (
            _supabase_client.table("vault_public_keys")
            .select("*")
            .eq("user_id", user_id)
            .eq("status", "active")
            .execute()
        )
        return res.data[0] if res.data else None

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM vault_public_keys WHERE user_id = ? AND status = 'active'",
            (user_id,),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def register_public_key(user: Dict[str, Any], key_validation: Dict[str, Any], key_id: str) -> Dict[str, Any]:
    """
    Registers a new public key for a user.
    Fails if the user already has an active key (requires explicit rotation to prevent silent replacement).
    """
    active_key = get_active_key_for_user(user["id"])
    if active_key is not None:
        raise ValueError(
            f"User '{user['email']}' already has an active public key ({active_key['key_id']}). "
            "To prevent silent key replacement, you must explicitly rotate your key using the key rotation workflow."
        )

    now = datetime.now(timezone.utc).isoformat()
    record_id = str(uuid.uuid4())

    record = {
        "id": record_id,
        "key_id": key_id,
        "user_id": user["id"],
        "auth_user_id": user["auth_user_id"],
        "owner_vault_id": user["vault_id"],
        "owner_email": user["email"],
        "algorithm": key_validation["algorithm"],
        "key_size_bits": key_validation["key_size_bits"],
        "public_key_pem": key_validation["canonical_pem"],
        "fingerprint": key_validation["fingerprint_formatted"],
        "fingerprint_raw_hex": key_validation["fingerprint_hex"],
        "status": "active",
        "previous_key_id": None,
        "rotation_reason": None,
        "created_at": now,
        "registered_at": now,
        "expires_at": None,
        "revoked_at": None,
    }

    if _supabase_client is not None:
        try:
            ins_res = _supabase_client.table("vault_public_keys").insert(record).execute()
            return ins_res.data[0]
        except Exception as exc:
            if getattr(exc, "code", None) == "23505":
                raise ValueError("A key is already registered or your account already has an active key. Restore it or use explicit key rotation.") from exc
            raise

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            INSERT INTO vault_public_keys (
                id, key_id, user_id, auth_user_id, owner_vault_id, owner_email, algorithm,
                key_size_bits, public_key_pem, fingerprint, fingerprint_raw_hex,
                status, previous_key_id, rotation_reason, created_at, registered_at,
                expires_at, revoked_at
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                record["id"],
                record["key_id"],
                record["user_id"],
                record["auth_user_id"],
                record["owner_vault_id"],
                record["owner_email"],
                record["algorithm"],
                record["key_size_bits"],
                record["public_key_pem"],
                record["fingerprint"],
                record["fingerprint_raw_hex"],
                record["status"],
                record["previous_key_id"],
                record["rotation_reason"],
                record["created_at"],
                record["registered_at"],
                record["expires_at"],
                record["revoked_at"],
            ),
        )
        conn.commit()
        return record
    except sqlite3.IntegrityError as exc:
        raise ValueError("A key is already registered or your account already has an active key. Restore it or use explicit key rotation.") from exc
    finally:
        conn.close()


def get_public_key_by_id(key_id: str) -> Optional[Dict[str, Any]]:
    """Retrieves a public key record by its stable key_id."""
    if _supabase_client is not None:
        res = _supabase_client.table("vault_public_keys").select("*").eq("key_id", key_id).execute()
        return res.data[0] if res.data else None

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute("SELECT * FROM vault_public_keys WHERE key_id = ?", (key_id,))
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def lookup_recipient(query: str) -> Optional[Dict[str, Any]]:
    """
    Looks up a recipient's active public key by either verified email or VaultZero ID.
    Returns key data, owner metadata, and previous key history for change warning.
    """
    clean_query = query.strip().lower()
    if not clean_query:
        return None

    if _supabase_client is not None:
        # Try by email or vault_id
        for column in ("owner_email", "owner_vault_id"):
            res = (
                _supabase_client.table("vault_public_keys")
                .select("*")
                .eq(column, clean_query)
                .eq("status", "active")
                .limit(1)
                .execute()
            )
            if res.data:
                return res.data[0]
        return None

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            """
            SELECT * FROM vault_public_keys 
            WHERE (LOWER(owner_email) = ? OR LOWER(owner_vault_id) = ?) 
              AND status = 'active'
            LIMIT 1
            """,
            (clean_query, clean_query),
        )
        row = cur.fetchone()
        return dict(row) if row else None
    finally:
        conn.close()


def list_user_keys(user_id: str) -> List[Dict[str, Any]]:
    """Returns all public keys (active, rotated, deactivated) belonging to a user."""
    if _supabase_client is not None:
        res = (
            _supabase_client.table("vault_public_keys")
            .select("*")
            .eq("user_id", user_id)
            .order("registered_at", desc=True)
            .execute()
        )
        return res.data or []

    conn = get_db_connection()
    try:
        cur = conn.cursor()
        cur.execute(
            "SELECT * FROM vault_public_keys WHERE user_id = ? ORDER BY registered_at DESC",
            (user_id,),
        )
        return [dict(r) for r in cur.fetchall()]
    finally:
        conn.close()


def rotate_public_key(
    user: Dict[str, Any],
    old_key_id: str,
    new_key_validation: Dict[str, Any],
    new_key_id: str,
    rotation_reason: Optional[str] = None,
) -> Dict[str, Any]:
    """
    Explicitly rotates a user's active public key:
    1. Validates that old_key_id belongs to the authenticated user and is currently active.
    2. Marks old key as 'rotated' with revoked_at timestamp and rotation reason.
    3. Inserts new key with status 'active' and links previous_key_id.
    """
    old_key = get_public_key_by_id(old_key_id)
    if not old_key or old_key["user_id"] != user["id"]:
        raise PermissionError("You can only rotate public keys that belong to your authenticated account.")

    if old_key["status"] != "active":
        raise ValueError(f"Cannot rotate key {old_key_id}: current status is '{old_key['status']}', expected 'active'.")

    now = datetime.now(timezone.utc).isoformat()
    new_record_id = str(uuid.uuid4())

    new_record = {
        "id": new_record_id,
        "key_id": new_key_id,
        "user_id": user["id"],
        "auth_user_id": user["auth_user_id"],
        "owner_vault_id": user["vault_id"],
        "owner_email": user["email"],
        "algorithm": new_key_validation["algorithm"],
        "key_size_bits": new_key_validation["key_size_bits"],
        "public_key_pem": new_key_validation["canonical_pem"],
        "fingerprint": new_key_validation["fingerprint_formatted"],
        "fingerprint_raw_hex": new_key_validation["fingerprint_hex"],
        "status": "active",
        "previous_key_id": old_key_id,
        "rotation_reason": rotation_reason or "User-initiated cryptographic key rotation",
        "created_at": now,
        "registered_at": now,
        "expires_at": None,
        "revoked_at": None,
    }

    if _supabase_client is not None:
        try:
            result = _supabase_client.rpc("vaultzero_rotate_public_key", {
                "p_owner_profile_id": user["id"],
                "p_auth_user_id": user["auth_user_id"],
                "p_old_key_id": old_key_id,
                "p_new_record": new_record,
                "p_rotation_reason": rotation_reason,
            }).execute()
        except Exception as exc:
            if getattr(exc, "code", None) == "42501":
                raise PermissionError("This active key does not belong to your authenticated account.") from exc
            if getattr(exc, "code", None) == "23505":
                raise ValueError("The new key is already registered; no key rotation was applied.") from exc
            raise
        if not result.data:
            raise ValueError("Key rotation did not return an active key record.")
        return result.data[0]

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                UPDATE vault_public_keys 
                SET status = 'rotated', revoked_at = ?, rotation_reason = ? 
                WHERE key_id = ?
                """,
                (now, rotation_reason, old_key_id),
            )
            conn.execute(
                """
                INSERT INTO vault_public_keys (
                    id, key_id, user_id, auth_user_id, owner_vault_id, owner_email, algorithm,
                    key_size_bits, public_key_pem, fingerprint, fingerprint_raw_hex,
                    status, previous_key_id, rotation_reason, created_at, registered_at,
                    expires_at, revoked_at
                ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_record["id"],
                    new_record["key_id"],
                    new_record["user_id"],
                    new_record["auth_user_id"],
                    new_record["owner_vault_id"],
                    new_record["owner_email"],
                    new_record["algorithm"],
                    new_record["key_size_bits"],
                    new_record["public_key_pem"],
                    new_record["fingerprint"],
                    new_record["fingerprint_raw_hex"],
                    new_record["status"],
                    new_record["previous_key_id"],
                    new_record["rotation_reason"],
                    new_record["created_at"],
                    new_record["registered_at"],
                    new_record["expires_at"],
                    new_record["revoked_at"],
                ),
            )
        return new_record
    finally:
        conn.close()


def deactivate_public_key(user: Dict[str, Any], key_id: str, reason: Optional[str] = None) -> Dict[str, Any]:
    """Deactivates a public key so it can no longer be used for new encryptions."""
    key = get_public_key_by_id(key_id)
    if not key or key["user_id"] != user["id"]:
        raise PermissionError("You can only deactivate public keys that belong to your account.")

    now = datetime.now(timezone.utc).isoformat()
    update_data = {
        "status": "deactivated",
        "revoked_at": now,
        "rotation_reason": reason or "User-initiated deactivation",
    }

    if _supabase_client is not None:
        res = _supabase_client.table("vault_public_keys").update(update_data).eq("key_id", key_id).execute()
        return res.data[0] if res.data else update_data

    conn = get_db_connection()
    try:
        with conn:
            conn.execute(
                """
                UPDATE vault_public_keys 
                SET status = 'deactivated', revoked_at = ?, rotation_reason = ? 
                WHERE key_id = ?
                """,
                (now, reason or "User-initiated deactivation", key_id),
            )
        updated = dict(key)
        updated.update(update_data)
        return updated
    finally:
        conn.close()
