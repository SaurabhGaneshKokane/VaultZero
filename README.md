# VaultZero: End-to-End Hybrid Cryptographic Vault

A modern, enterprise-grade, client-side zero-knowledge cryptographic web application built with **React**, **TypeScript**, **Tailwind CSS**, and the browser's native **Web Crypto API (`window.crypto.subtle`)**.

Developed for the **Cryptography & Network Security (CNS) Micro-Project — Stage 2** at **Shah & Anchor Kutchhi Engineering College**.

---

## 🛡️ Key Features

### 1. Core Vault (`VaultTab.tsx`)
- **Hybrid Cryptography**: Combines the raw speed of symmetric **AES-256-GCM** (authenticated encryption) with the security of asymmetric **RSA-OAEP-2048** key wrapping.
- **Zero External Dependencies**: Implemented entirely via native browser `window.crypto.subtle` (BoringSSL/NSS) with hardware-accelerated **AES-NI** CPU instructions.
- **Client-Side Processing**: Plaintext files never leave the browser unencrypted.
- **Streamlined User Experience**:
  - Segmented control toggling between **Send Protected File** and **Unlock Received File**.
  - Expandable **My Security Keys** identity drawer with 1-click public address copying.
  - Automatic `sessionStorage` master key persistence for zero-friction unlocking.
  - **Dual Terminology Modes**: Toggle between **Simple Mode** (approachable, human-friendly terms) and **Cryptographic Audit Mode** (deep telemetry, byte offsets, and hex digests).

### 2. Adversarial Lab (`AdversarialLab.tsx`)
*Implements Stage 1 Objective 5 (Tamper, Misuse, and Malicious Server Detection)*:
- **Scenario A (In-Transit 1-Bit Mutation Attack)**:
  - Injects a single-bit XOR flip (`tamperedBytes[offset] ^= 0x01`) inside the ciphertext body.
  - Demonstrates how the 128-bit **AES-GCM GMAC** authentication tag detects tampering and throws `OperationError`, rejecting corrupted files before any plaintext is released.
  - Features an interactive **Hex Diff Card** showing the mutated byte, binary bit-flips, and memory context window.
- **Scenario B (Key Mismatch / Unauthorized Identity)**:
  - Attempts to unwrap the 256-byte session key header using an unauthorized rogue RSA-2048 private key.
  - Demonstrates **RSA-OAEP** plaintext-aware padding rejection (MGF1 with SHA-256).
- **Scenario C (Honest-but-Curious / Malicious Server Demonstration)**:
  - Evaluates zero-plaintext exposure on the storage relay server.
  - Verifies that the server holds only opaque `.vault` ciphertext, has 0 bytes of unencrypted plaintext, and is mathematically blocked from unwrapping the AES key without the recipient's private key.
  - Confirms non-malleability against server-side tampering and rejects rogue keys.
  - Transparent academic disclosure distinguishing zero-plaintext exposure from formal zero-knowledge proofs.
- **Security Audit Telemetry Console**: Embedded live terminal logging cryptographic engine decisions.

### 3. FastAPI Storage Relay Backend (`backend/`)
- **Zero-Plaintext Architecture**: Stores only client-encrypted `.vault` packages; never receives plaintext or private keys.
- **Endpoints**:
  - `GET /api/health`: System health and zero-knowledge posture confirmation.
  - `POST /api/files`: Uploads encrypted `.vault` package, enforces size and binary header integrity checks, and returns a unique 128-bit URL-safe `file_id`.
  - `GET /api/files/{file_id}`: Securely retrieves the encrypted package by ID.
- **Automated Pytest Suite**: 11 unit & integration tests covering health, uploads, downloads, 404s, malformed headers, 413 size limits, and path traversal isolation.

### 4. Performance Benchmark Suite (`BenchmarkTab.tsx`)
*Implements Stage 1 Objective 7 (Performance Measurement)*:
- Automated micro-benchmark suite measuring encryption and decryption across 4 tiers:
  - **12 KB**: Text / Configuration payload
  - **50 KB**: Document payload
  - **2 MB**: Media / Image payload
  - **10 MB**: Stress test payload
- **Byte-for-Byte Plaintext Verification**: Validates decrypted output against input buffers.
- **Literature Comparison**: Real-time comparison against baseline metrics from *Elumalaivasan et al. (2025)* (legacy CFB mode).
- **Throughput & Speedup Visualizer**: Real-time MB/s calculations and dual-bar latency charts demonstrating up to **170× speedup** via hardware-level vector instructions.

---

## 📦 Binary Package Layout (`.vault`)

Each protected file is packed into a unified binary buffer:
```
+-------------------------------------------------------------------------------------------------+
| Offset    | Size (Bytes) | Description                                                          |
+-------------------------------------------------------------------------------------------------+
| 0         | 256          | Encrypted AES Session Key (RSA-OAEP 2048-bit with SHA-256)         |
| 256       | 12           | AES-GCM Initialization Vector (IV)                                   |
| 268       | 4            | Metadata Length (uint32 big-endian)                                  |
| 272       | N            | Metadata JSON (UTF-8 encoded: fileName, fileType, plaintext hash)   |
| 272 + N   | Remainder    | AES-256-GCM Ciphertext + 16-byte Authentication Tag (GMAC)           |
+-------------------------------------------------------------------------------------------------+
```

---

## 🚀 Running Locally

### 1. Frontend (React + Vite)
```bash
npm install
npm run dev
```
The frontend starts on `http://localhost:3000` (or `http://localhost:5173`).

### 2. Backend (FastAPI Python)
```bash
pip install -r backend/requirements.txt
python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8001 --reload
```
Interactive API docs: `http://localhost:8001/docs`

### 3. Running Backend Tests
```bash
python3 -m pytest backend/tests -v
```

---

## 🌐 Deployment Configuration

### Frontend (Vercel)
The React SPA builds with `npm run build` into `dist/`.
In production on Vercel:
- Set environment variable `VITE_API_BASE_URL` to your deployed FastAPI backend URL (e.g. `https://vaultzero-api.onrender.com`).
- If `VITE_API_BASE_URL` is unset, the app operates in standalone local mode where users can directly download and upload `.vault` files.

### Backend (Render, Railway, Fly.io, or VPS)
- Deploy using `python3 -m uvicorn backend.app.main:app --host 0.0.0.0 --port $PORT`.
- Set `CORS_ORIGINS` to your Vercel frontend URL (e.g. `https://vault-zero.vercel.app`).
- Set `VAULT_STORAGE_DIR` for storing packages.
- *Ephemeral Storage Note*: Serverless platforms spin down containers and wipe local disk; for permanent storage, attach a persistent volume or configure cloud bucket relay.

---

## 🏛️ Academic Citation
**Shah & Anchor Kutchhi Engineering College**  
*Cryptography & Network Security (CNS) Micro-Project — Stage 2*  
Topic: Client-Side Zero-Knowledge Hybrid Encryption Vault



## Supabase Auth setup

1. Enable email confirmation in Supabase Auth settings and configure the confirmation redirect URL for `http://localhost:3000` during local development.
2. Copy `.env.example` to `.env.local` and set `VITE_SUPABASE_URL` plus `VITE_SUPABASE_ANON_KEY` (the public anon/publishable key). Never use the service-role secret in a `VITE_` variable.
3. Keep `SUPABASE_URL` and `SUPABASE_SERVICE_ROLE_KEY` in `backend/.env`. FastAPI loads that file at startup.
4. Review `backend/migrations/002_supabase_auth_bridge.sql`; apply it manually in the Supabase SQL Editor. No migration runs automatically.
5. Start the API with `python -m uvicorn backend.app.main:app --host 0.0.0.0 --port 8001 --reload` and the frontend with `npm run dev`.
6. Sign up and verify the email. On a new account, VaultZero asks for a backup passphrase, downloads an encrypted `.vaultkey`, and only then registers the public key. On another device, restore the matching backup; a different key is never registered over an active one.

Backend tests: `python -m pytest -q backend/tests`. Frontend type-check: `npm run lint`.
