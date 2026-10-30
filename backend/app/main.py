"""
VaultZero Lite - Backend Application
FastAPI Server for Zero-Knowledge Encrypted Package Relay & Public Key Directory
"""

import os
from pathlib import Path
from dotenv import load_dotenv

# Load backend-only credentials before importing modules that initialize Supabase.
load_dotenv(Path(__file__).resolve().parents[1] / ".env")

from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from .routes.files import router as files_router
from .routes.keys import router as keys_router
from .routes.auth import router as auth_router

app = FastAPI(
    title="VaultZero Cryptographic Directory & Storage Relay",
    description=(
        "A secure, zero-knowledge backend providing: "
        "1. Cloud Public Key Directory & Recipient Verification (RSA-OAEP-2048) "
        "2. Zero-plaintext relay for hybrid-encrypted .vault packages. "
        "The server NEVER receives unencrypted files, AES session keys, or private keys."
    ),
    version="1.1.0",
)

# CORS Configuration
cors_origins_raw = os.getenv("CORS_ORIGINS", "*")
origins = [origin.strip() for origin in cors_origins_raw.split(",") if origin.strip()]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins if origins != ["*"] else ["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
    expose_headers=["X-Vault-File-Id", "X-Vault-Size", "Content-Disposition"],
)

# Register routes
app.include_router(files_router)
app.include_router(keys_router)
app.include_router(auth_router)


@app.get(
    "/api/health",
    tags=["system"],
    summary="Health check endpoint",
    description="Returns backend system health, storage, and directory status.",
)
async def health_check():
    supabase_configured = bool(os.getenv("SUPABASE_URL") and os.getenv("SUPABASE_SERVICE_ROLE_KEY"))
    return {
        "status": "healthy",
        "service": "VaultZero Lite Cryptographic Directory & Storage Relay",
        "version": "1.1.0",
        "storage": "local_ephemeral",
        "directory": "supabase_postgresql" if supabase_configured else "sqlite_local",
        "encryption_model": "client-side-hybrid (AES-256-GCM + RSA-OAEP)",
        "server_knowledge": "zero-plaintext (stores only opaque .vault ciphertext)",
        "private_keys_stored": False,
    }


@app.get("/", tags=["system"])
async def root():
    return {
        "message": "VaultZero Backend Relay and Public Key Directory is running.",
        "health": "/api/health",
        "docs": "/docs",
    }
