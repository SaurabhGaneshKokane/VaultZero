-- ============================================================================
-- VaultZero: Public Key Directory & Recipient Verification Schema
-- Target Database: Supabase PostgreSQL
-- ============================================================================

-- 1. Users Table (VaultZero Identities)
CREATE TABLE IF NOT EXISTS vault_users (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    vault_id TEXT UNIQUE NOT NULL,            -- e.g. "vz_alice_4a1f" or unique username
    email TEXT UNIQUE NOT NULL,               -- User verified email address
    email_verified BOOLEAN NOT NULL DEFAULT true,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

-- Index for fast recipient lookup by email or VaultZero ID
CREATE INDEX IF NOT EXISTS idx_vault_users_email ON vault_users(LOWER(email));
CREATE INDEX IF NOT EXISTS idx_vault_users_vault_id ON vault_users(LOWER(vault_id));

-- 2. Public Keys Directory Table
-- Invariant: NEVER store private keys. Stores ONLY validated SPKI public keys.
CREATE TABLE IF NOT EXISTS vault_public_keys (
    id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
    key_id TEXT UNIQUE NOT NULL,              -- e.g. "key_rsa2048_9f2bc4e1"
    user_id UUID NOT NULL REFERENCES vault_users(id) ON DELETE CASCADE,
    owner_vault_id TEXT NOT NULL,
    owner_email TEXT NOT NULL,
    algorithm TEXT NOT NULL DEFAULT 'RSA-OAEP-2048',
    key_size_bits INTEGER NOT NULL DEFAULT 2048,
    public_key_pem TEXT NOT NULL,             -- Validated SubjectPublicKeyInfo PEM
    fingerprint TEXT NOT NULL,                -- Canonical formatted fingerprint (SHA256:xx:xx...)
    fingerprint_raw_hex TEXT NOT NULL,        -- 64-character lowercase SHA-256 hex
    status TEXT NOT NULL DEFAULT 'active',    -- 'active', 'rotated', 'deactivated', 'revoked'
    previous_key_id TEXT,                     -- Links to previous key on rotation (audit trail)
    rotation_reason TEXT,
    created_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    registered_at TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    expires_at TIMESTAMPTZ,
    revoked_at TIMESTAMPTZ,
    CONSTRAINT chk_status_valid CHECK (status IN ('active', 'rotated', 'deactivated', 'revoked'))
);

-- Indexing for fast search and integrity verification
CREATE INDEX IF NOT EXISTS idx_public_keys_owner_email ON vault_public_keys(LOWER(owner_email));
CREATE INDEX IF NOT EXISTS idx_public_keys_owner_vault_id ON vault_public_keys(LOWER(owner_vault_id));
CREATE INDEX IF NOT EXISTS idx_public_keys_key_id ON vault_public_keys(key_id);
CREATE INDEX IF NOT EXISTS idx_public_keys_fingerprint ON vault_public_keys(fingerprint);
CREATE INDEX IF NOT EXISTS idx_public_keys_status ON vault_public_keys(status);

-- Ensure only ONE key can be 'active' for a given user at any time (prevents silent replacement)
CREATE UNIQUE INDEX IF NOT EXISTS idx_single_active_key_per_user 
ON vault_public_keys (user_id) 
WHERE status = 'active';

-- 3. Row-Level Security (RLS) Policies
ALTER TABLE vault_users ENABLE ROW LEVEL SECURITY;
ALTER TABLE vault_public_keys ENABLE ROW LEVEL SECURITY;

-- Anonymous and authenticated users can view active public keys for encryption
CREATE POLICY "Public keys are discoverable" 
ON vault_public_keys FOR SELECT 
USING (true);

-- Users can only insert/manage their own public keys
CREATE POLICY "Users can only insert own public keys" 
ON vault_public_keys FOR INSERT 
WITH CHECK (auth.uid() = user_id);

CREATE POLICY "Users can only update own public keys" 
ON vault_public_keys FOR UPDATE 
USING (auth.uid() = user_id);
