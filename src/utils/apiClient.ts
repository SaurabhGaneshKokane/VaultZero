/**
 * VaultZero - Frontend API Client
 *
 * Lightweight HTTP client for communicating with the FastAPI backend relay
 * and Public Key Directory (Supabase PostgreSQL / SQLite).
 * Configurable via VITE_API_BASE_URL.
 *
 * IMPORTANT SECURITY INVARIANT:
 * This client ONLY transmits pre-encrypted .vault binary payloads and public keys.
 * Unencrypted files, AES symmetric keys, and RSA private keys are NEVER
 * sent across the network.
 */

export interface BackendHealthResponse {
  status: string;
  service: string;
  version: string;
  storage: string;
  directory?: string;
  encryption_model: string;
  server_knowledge: string;
  private_keys_stored?: boolean;
}

export interface UploadPackageResponse {
  file_id: string;
  filename: string;
  size_bytes: number;
  download_url: string;
  message: string;
}

export interface DownloadPackageResponse {
  packageBuffer: ArrayBuffer;
  filename: string;
  sizeBytes: number;
}

export interface PublicKeyDirectoryRecord {
  key_id: string;
  owner_vault_id: string;
  owner_email: string;
  algorithm: string;
  key_size_bits: number;
  public_key_pem: string;
  fingerprint: string;
  fingerprint_raw_hex?: string;
  status: "active" | "rotated" | "deactivated" | "revoked";
  previous_key_id?: string | null;
  rotation_reason?: string | null;
  registered_at: string;
  revoked_at?: string | null;
  is_active: boolean;
}

export interface UserProfileResponse {
  email: string;
  vault_id: string;
  active_key?: {
    key_id: string;
    algorithm: string;
    key_size_bits: number;
    fingerprint: string;
    registered_at: string;
    status: string;
  } | null;
}

// Configurable base URL: if unset or empty, uses relative paths (routed via Vite proxy in dev)
const rawBaseUrl = import.meta.env.VITE_API_BASE_URL || "";
export const API_BASE_URL = rawBaseUrl.endsWith("/")
  ? rawBaseUrl.slice(0, -1)
  : rawBaseUrl;

/**
 * Checks backend health, storage status, and directory configuration.
 */
export async function checkBackendHealth(): Promise<{
  isAvailable: boolean;
  data?: BackendHealthResponse;
  error?: string;
}> {
  try {
    const endpoint = `${API_BASE_URL}/api/health`;
    const res = await fetch(endpoint, {
      method: "GET",
      headers: { Accept: "application/json" },
      signal: AbortSignal.timeout(4000),
    });

    if (!res.ok) {
      return {
        isAvailable: false,
        error: `Server responded with status HTTP ${res.status}`,
      };
    }

    const data: BackendHealthResponse = await res.json();
    return { isAvailable: true, data };
  } catch (err: unknown) {
    const errorMsg =
      err instanceof Error ? err.message : "Unable to reach backend service";
    return { isAvailable: false, error: errorMsg };
  }
}

/**
 * Uploads a client-encrypted .vault package to the FastAPI backend relay.
 * Plaintext files and private keys are never transmitted.
 */
export async function uploadVaultPackage(
  token: string,
  packageBuffer: ArrayBuffer,
  filename: string
): Promise<UploadPackageResponse> {
  const endpoint = `${API_BASE_URL}/api/files`;

  const blob = new Blob([packageBuffer], {
    type: "application/octet-stream",
  });
  const formData = new FormData();
  formData.append("file", blob, filename);

  const res = await fetch(endpoint, {
    method: "POST",
    headers: { Authorization: `Bearer ${token}` },
    body: formData,
  });

  if (!res.ok) {
    let errorDetail = `Upload failed with status HTTP ${res.status}`;
    try {
      const errJson = await res.json();
      if (errJson.detail) {
        errorDetail = errJson.detail;
      }
    } catch {
      // Use fallback error message
    }
    throw new Error(errorDetail);
  }

  const result: UploadPackageResponse = await res.json();
  return result;
}

/**
 * Downloads a stored encrypted .vault package from the backend by file ID.
 * Returns the raw binary ArrayBuffer for local browser decryption.
 */
export async function downloadVaultPackage(
  token: string,
  fileId: string
): Promise<DownloadPackageResponse> {
  const sanitizedId = fileId.trim();
  if (!sanitizedId) {
    throw new Error("Please enter a valid File ID.");
  }

  const endpoint = `${API_BASE_URL}/api/files/${encodeURIComponent(sanitizedId)}`;
  const res = await fetch(endpoint, {
    method: "GET",
    headers: { Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    if (res.status === 404) {
      throw new Error(`File ID "${sanitizedId}" was not found or has expired on the relay server.`);
    }
    let errorDetail = `Failed to fetch file (HTTP ${res.status})`;
    try {
      const errJson = await res.json();
      if (errJson.detail) errorDetail = errJson.detail;
    } catch {
      // Fallback error
    }
    throw new Error(errorDetail);
  }

  let filename = `${sanitizedId}.vault`;
  const disposition = res.headers.get("Content-Disposition");
  if (disposition && disposition.includes("filename=")) {
    const match = disposition.match(/filename="?([^"]+)"?/);
    if (match && match[1]) {
      filename = match[1];
    }
  }

  const packageBuffer = await res.arrayBuffer();
  const sizeBytes = packageBuffer.byteLength;

  return {
    packageBuffer,
    filename,
    sizeBytes,
  };
}

// ============================================================================
// Public Key Directory & Authentication API
// ============================================================================

/**
 * Fetches caller profile and currently active public key.
 */
export async function fetchUserProfile(token: string): Promise<UserProfileResponse> {
  const endpoint = `${API_BASE_URL}/api/auth/me`;
  const res = await fetch(endpoint, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    let msg = `Failed to fetch profile (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

/**
 * Publishes an authenticated user's RSA-2048 public key to the cloud directory.
 * Never transmits private keys.
 */
export async function publishPublicKey(
  token: string,
  publicKeyPem: string
): Promise<PublicKeyDirectoryRecord> {
  const endpoint = `${API_BASE_URL}/api/keys`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ public_key_pem: publicKeyPem }),
  });

  if (!res.ok) {
    let msg = `Key publication failed (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

/**
 * Discovers an intended recipient's active public key by email or VaultZero ID.
 * Returns null if no active key is registered.
 */
export async function lookupRecipientPublicKey(
  token: string,
  searchTerm: string
): Promise<PublicKeyDirectoryRecord | null> {
  const cleanTerm = searchTerm.trim();
  if (!cleanTerm) return null;

  const endpoint = `${API_BASE_URL}/api/keys/lookup?query=${encodeURIComponent(cleanTerm)}`;
  const res = await fetch(endpoint, {
    method: "GET",
    headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    if (res.status === 404) return null;
    let msg = `Lookup failed (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

/**
 * Fetches a public key record by its stable key ID.
 */
export async function fetchKeyById(token: string, keyId: string): Promise<PublicKeyDirectoryRecord> {
  const endpoint = `${API_BASE_URL}/api/keys/${encodeURIComponent(keyId)}`;
  const res = await fetch(endpoint, {
    method: "GET",
    headers: { Accept: "application/json", Authorization: `Bearer ${token}` },
  });

  if (!res.ok) {
    throw new Error(`Public key '${keyId}' not found in directory.`);
  }

  return await res.json();
}

/**
 * Lists all public keys (active, rotated, deactivated) owned by the authenticated caller.
 */
export async function listMyPublicKeys(token: string): Promise<PublicKeyDirectoryRecord[]> {
  const endpoint = `${API_BASE_URL}/api/keys/mine`;
  const res = await fetch(endpoint, {
    method: "GET",
    headers: {
      Authorization: `Bearer ${token}`,
      Accept: "application/json",
    },
  });

  if (!res.ok) {
    throw new Error(`Failed to list keys (HTTP ${res.status})`);
  }

  return await res.json();
}

/**
 * Explicitly rotates the caller's active public key with transition history.
 */
export async function rotateMyPublicKey(
  token: string,
  oldKeyId: string,
  newPublicKeyPem: string,
  rotationReason?: string
): Promise<PublicKeyDirectoryRecord> {
  const endpoint = `${API_BASE_URL}/api/keys/${encodeURIComponent(oldKeyId)}/rotate`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({
      new_public_key_pem: newPublicKeyPem,
      rotation_reason: rotationReason || undefined,
    }),
  });

  if (!res.ok) {
    let msg = `Key rotation failed (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}

/**
 * Deactivates a public key so it can no longer be used for new encryptions.
 */
export async function deactivateMyPublicKey(
  token: string,
  keyId: string,
  reason?: string
): Promise<PublicKeyDirectoryRecord> {
  const endpoint = `${API_BASE_URL}/api/keys/${encodeURIComponent(keyId)}/deactivate`;
  const res = await fetch(endpoint, {
    method: "POST",
    headers: {
      "Content-Type": "application/json",
      Authorization: `Bearer ${token}`,
    },
    body: JSON.stringify({ reason: reason || undefined }),
  });

  if (!res.ok) {
    let msg = `Key deactivation failed (HTTP ${res.status})`;
    try {
      const err = await res.json();
      if (err.detail) msg = err.detail;
    } catch {}
    throw new Error(msg);
  }

  return await res.json();
}
