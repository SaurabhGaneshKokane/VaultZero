# VaultZero Backend: Storage Relay & Public Key Directory

The **VaultZero Backend** is an independent, lightweight, zero-knowledge microservice providing:
1. **Cloud Public Key Directory & Recipient Verification** (Supabase PostgreSQL / SQLite fallback)
2. **Encrypted Package Relay** for hybrid-encrypted `.vault` packages (AES-256-GCM + RSA-OAEP-2048)

---

## Non-Negotiable Cryptographic Rules & Invariants

1. **Private Keys Stay in Browser**: The backend **never** receives, generates, stores, or logs RSA private keys. Any attempt to upload a private key (`BEGIN PRIVATE KEY`) is rejected with HTTP 400.
2. **Zero-Plaintext Knowledge**: The backend never sees unencrypted documents or raw symmetric AES keys.
3. **Canonical Fingerprints**: Public key fingerprints are deterministically calculated as SHA-256 digests over the SubjectPublicKeyInfo (SPKI) DER binary representation, formatted identically on client and server (`SHA256:xx:xx:xx...`).
4. **Anti-Silent Replacement**: A user cannot silently overwrite an existing active public key. Key replacement requires explicit, authenticated rotation (`POST /api/keys/{key_id}/rotate`), creating an auditable transition history.
5. **No Automatic Trust**: The frontend warns that a key from a directory cannot be blindly trusted; fingerprints must be verified through an out-of-band channel (e.g. Signal, phone call, in-person).
6. **Supabase Secrets**: The Supabase service-role secret key must NEVER be exposed to the frontend.

---

## Database Schema (Supabase PostgreSQL)

The schema migration is located in `backend/migrations/001_create_public_keys_schema.sql`.

To set up Supabase PostgreSQL:
1. Create a project in [Supabase](https://supabase.com).
2. Open the **SQL Editor** in your Supabase dashboard and execute `backend/migrations/001_create_public_keys_schema.sql`.
3. Copy your project URL and `service_role` key into your backend `.env`:
   ```bash
   SUPABASE_URL=https://your-project.supabase.co
   SUPABASE_SERVICE_ROLE_KEY=your-supabase-service-role-secret
   ```
*(If Supabase database credentials are omitted, SQLite is used for local storage. Supabase Auth itself is still required for authenticated API access.)*

---

## API Endpoints

### System & Health
- `GET /api/health`: Confirms service health, storage mode, and directory status.

### Authentication & Identities
- Supabase Auth handles email/password sign-up, email confirmation, login, refresh, and logout in the browser.
- `GET /api/auth/me`: Requires a verified Supabase bearer session and returns the VaultZero profile plus its active public-key summary. Passwordless custom register/login endpoints are removed.

### Public Key Directory
- `POST /api/keys`: Authenticated endpoint to register an RSA-2048 public key. Rejects private keys, non-RSA keys, and key sizes other than 2048 bits.
- `GET /api/keys/lookup?email=...&vault_id=...`: Authenticated discovery of an active recipient public key by email or VaultZero ID; returns only required public metadata.
- `GET /api/keys/{key_id}`: Authenticated access to an active public key or the caller's own history.
- `GET /api/keys/{key_id}/fingerprint`: Authenticated canonical public-key fingerprint.
- `GET /api/keys/{key_id}/status`: Authenticated status; inactive history is visible only to its owner.
- `GET /api/keys/mine`: Authenticated endpoint listing all public keys registered by the caller.
- `POST /api/keys/{key_id}/rotate`: Explicit authenticated key rotation (marks old key `rotated` and registers new key).
- `POST /api/keys/{key_id}/deactivate`: Deactivates a public key so it can no longer be used for new encryptions.

### Encrypted Package Relay
- `POST /api/files`: Upload opaque `.vault` binary package with a verified Supabase bearer session.
- `GET /api/files/{file_id}`: Download opaque `.vault` binary package with a verified Supabase bearer session.

---

## Running and Testing

```bash
# Install dependencies
pip install -r backend/requirements.txt

# Run automated test suite (25 unit and integration tests)
python3 -m pytest backend/tests -v

# Start development server
uvicorn backend.app.main:app --host 0.0.0.0 --port 8000 --reload
```


## Supabase Email Authentication

The browser uses Supabase Auth for email/password sign-up, confirmation, login, refresh, and logout. FastAPI validates each access token with Supabase Auth; passwords are never sent to this backend or stored in VaultZero tables. Enable email confirmation in the Supabase Auth settings.

Before using the Auth-linked directory, review and manually apply `backend/migrations/002_supabase_auth_bridge.sql` in the Supabase SQL Editor. It adds Auth ID mappings to the existing tables, preserves public-key IDs and history, and tightens RLS. The application does not run SQL migrations automatically.

For local development, place `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` only in `backend/.env`. Put `VITE_SUPABASE_URL` and `VITE_SUPABASE_ANON_KEY` in the frontend `.env.local`; the browser key is public and must never be the service-role secret.

