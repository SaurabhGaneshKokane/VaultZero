"""
VaultZero - Server-Side Public Key Validation & Canonical Fingerprinting

Enforces strict cryptographic invariants on all registered public keys:
1. MUST be standard SubjectPublicKeyInfo (SPKI) RSA public key.
2. MUST NOT be a private key (immediate rejection).
3. MUST be exactly 2048-bit RSA with public exponent 65537 (OAEP compatible).
4. Computes deterministic, canonical SHA-256 fingerprint over DER bytes matching WebCrypto.
"""

import hashlib
import re
from typing import Dict, Any, Tuple
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


class KeyValidationError(ValueError):
    """Raised when a public key fails format, size, or cryptographic validation."""
    pass


def validate_and_canonicalize_rsa_public_key(pem_string: str) -> Dict[str, Any]:
    """
    Validates that a PEM string contains a valid, secure RSA-2048 public key.
    
    Returns a dictionary with:
    - 'canonical_pem': standard normalized PEM representation
    - 'der_bytes': canonical DER bytes
    - 'fingerprint_formatted': 'SHA256:xx:xx:xx:xx:xx:xx:xx:xx'
    - 'fingerprint_hex': 64-char lowercase SHA-256 hex
    - 'key_size_bits': 2048
    - 'algorithm': 'RSA-OAEP-2048'
    """
    if not pem_string or not isinstance(pem_string, str):
        raise KeyValidationError("Public key PEM string is required.")

    trimmed = pem_string.strip()

    # Rule 1: Immediate rejection of private keys
    if "PRIVATE KEY" in trimmed.upper():
        raise KeyValidationError(
            "CRITICAL SECURITY REJECTION: You have submitted a PRIVATE KEY. "
            "VaultZero is zero-knowledge: private keys must NEVER leave the browser "
            "or be transmitted to the server."
        )

    # Rule 2: Must have standard public key headers
    if "-----BEGIN PUBLIC KEY-----" not in trimmed or "-----END PUBLIC KEY-----" not in trimmed:
        raise KeyValidationError(
            "Invalid public key format: Key must be in X.509 SubjectPublicKeyInfo (SPKI) PEM format "
            "beginning with '-----BEGIN PUBLIC KEY-----' and ending with '-----END PUBLIC KEY-----'."
        )

    # Rule 3: Parse key using cryptography library
    try:
        public_key = serialization.load_pem_public_key(trimmed.encode("utf-8"))
    except Exception as e:
        raise KeyValidationError(f"Malformed public key PEM: {str(e)}")

    # Rule 4: Must be RSA
    if not isinstance(public_key, rsa.RSAPublicKey):
        raise KeyValidationError(
            f"Unsupported public key algorithm: VaultZero requires RSA keys for RSA-OAEP hybrid encryption. "
            f"Received: {type(public_key).__name__}"
        )

    # Rule 5: Key size must be exactly 2048 bits
    key_size = public_key.key_size
    if key_size != 2048:
        raise KeyValidationError(
            f"Invalid RSA key size ({key_size} bits). VaultZero requires exactly 2048-bit RSA keys "
            f"for hybrid RSA-OAEP interoperability."
        )

    # Rule 6: Public exponent should be 65537 (standard F4)
    public_numbers = public_key.public_numbers()
    if public_numbers.e != 65537:
        raise KeyValidationError(
            f"Unsupported RSA public exponent (e={public_numbers.e}). Expected standard 65537."
        )

    # Canonicalize DER bytes & PEM format
    der_bytes = public_key.public_bytes(
        encoding=serialization.Encoding.DER,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )

    canonical_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    ).decode("utf-8")

    # Canonical SHA-256 fingerprint over DER bytes
    sha256_digest = hashlib.sha256(der_bytes).hexdigest().lower()
    
    # Format matches frontend computeKeyFingerprint: SHA256:xx:xx:xx:xx:xx:xx:xx:xx
    pairs = [sha256_digest[i : i + 2] for i in range(0, 16, 2)]
    fingerprint_formatted = f"SHA256:{':'.join(pairs)}"

    return {
        "canonical_pem": canonical_pem,
        "der_bytes": der_bytes,
        "fingerprint_formatted": fingerprint_formatted,
        "fingerprint_hex": sha256_digest,
        "key_size_bits": key_size,
        "algorithm": "RSA-OAEP-2048",
    }


def generate_stable_key_id(fingerprint_hex: str) -> str:
    """
    Generates a human-scannable stable key identifier based on the public key fingerprint.
    e.g. 'key_rsa2048_9f2bc4e1'
    """
    short_hash = fingerprint_hex[:12]
    return f"key_rsa2048_{short_hash}"
