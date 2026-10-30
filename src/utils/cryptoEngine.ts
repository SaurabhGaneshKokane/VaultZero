/**
 * VaultZero Cryptographic Engine
 *
 * Implements client-side hybrid encryption using the browser's native
 * Web Crypto API (window.crypto.subtle).
 * Zero external cryptographic dependencies.
 *
 * Binary Package Layout:
 * [256 bytes: Encrypted AES Key (RSA-OAEP 2048-bit with SHA-256)]
 * + [12 bytes: Initialization Vector (AES-GCM IV)]
 * + [4 bytes: Metadata Length (uint32 big-endian)]
 * + [N bytes: Metadata JSON (UTF-8 encoded)]
 * + [Remaining bytes: AES-GCM Ciphertext + 16-byte Auth Tag]
 */

// ============================================================================
// Types & Interfaces
// ============================================================================

export interface RsaKeyPairPem {
  publicKeyPem: string;
  privateKeyPem: string;
}

export interface EncryptedPackage {
  packageBuffer: ArrayBuffer;
  sha256Hex: string;
  rawAesKeyHex: string;
}

export interface DecryptedPackage {
  fileBuffer: ArrayBuffer;
  fileName: string;
  fileType: string;
  unwrappedAesKeyHex: string;
}

export interface PackageMetadata {
  fileName: string;
  fileType: string;
  hash: string;
  // Aliases for compatibility
  filename?: string;
  filetype?: string;
  sha256Hex?: string;
}

// ============================================================================
// Web Crypto Environment Accessor
// ============================================================================

/**
 * Accesses the native Crypto object, prioritizing window.crypto in browsers
 * and falling back to globalThis.crypto in other environments.
 */
function getCrypto(): Crypto {
  if (typeof window !== "undefined" && window.crypto) {
    return window.crypto;
  }
  if (typeof globalThis !== "undefined" && globalThis.crypto) {
    return globalThis.crypto as unknown as Crypto;
  }
  throw new Error("Web Crypto API is not available in the current environment.");
}

/**
 * Accesses the native SubtleCrypto object (window.crypto.subtle).
 */
function getSubtleCrypto(): SubtleCrypto {
  const cryptoInstance = getCrypto();
  if (!cryptoInstance.subtle) {
    throw new Error("Web Crypto SubtleCrypto API (crypto.subtle) is not available.");
  }
  return cryptoInstance.subtle;
}

// ============================================================================
// Helper Functions: Conversions & PEM Sanitization
// ============================================================================

/**
 * Converts an ArrayBuffer or Uint8Array view into a Base64-encoded string.
 * Employs chunked slicing to safely handle large buffers without call-stack overflow.
 */
export function arrayBufferToBase64(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  const CHUNK_SIZE = 0x8000; // 32KB chunk limit
  let binaryString = "";
  for (let i = 0; i < bytes.length; i += CHUNK_SIZE) {
    const chunk = bytes.subarray(i, i + CHUNK_SIZE);
    binaryString += String.fromCharCode.apply(null, chunk as unknown as number[]);
  }
  return btoa(binaryString);
}

/**
 * Converts a Base64-encoded string into an ArrayBuffer.
 * Automatically ignores whitespace and newlines.
 */
export function base64ToArrayBuffer(base64: string): ArrayBuffer {
  const sanitized = base64.replace(/\s+/g, "");
  const binaryString = atob(sanitized);
  const bytes = new Uint8Array(binaryString.length);
  for (let i = 0; i < binaryString.length; i++) {
    bytes[i] = binaryString.charCodeAt(i);
  }
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Converts an ArrayBuffer or Uint8Array view into a lowercase hex string.
 */
export function arrayBufferToHex(buffer: ArrayBuffer | Uint8Array): string {
  const bytes = buffer instanceof Uint8Array ? buffer : new Uint8Array(buffer);
  let hex = "";
  for (let i = 0; i < bytes.length; i++) {
    hex += bytes[i].toString(16).padStart(2, "0");
  }
  return hex;
}

/**
 * Converts a hexadecimal string into an ArrayBuffer.
 */
export function hexToArrayBuffer(hex: string): ArrayBuffer {
  const cleanHex = hex.replace(/\s+/g, "");
  if (cleanHex.length % 2 !== 0) {
    throw new Error("Invalid hex string: length must be even.");
  }
  const bytes = new Uint8Array(cleanHex.length / 2);
  for (let i = 0; i < cleanHex.length; i += 2) {
    const byte = parseInt(cleanHex.substring(i, i + 2), 16);
    if (isNaN(byte)) {
      throw new Error(`Invalid hexadecimal byte at index ${i}: "${cleanHex.substring(i, i + 2)}"`);
    }
    bytes[i / 2] = byte;
  }
  return bytes.buffer.slice(bytes.byteOffset, bytes.byteOffset + bytes.byteLength);
}

/**
 * Strips PEM header/footer lines and all whitespace, returning the raw Base64 payload.
 */
export function sanitizePem(pem: string): string {
  return pem
    .replace(/-----BEGIN [^-]+-----/g, "")
    .replace(/-----END [^-]+-----/g, "")
    .replace(/\s+/g, "");
}

/**
 * Formats a Base64 string into RFC 7468 PEM format with 64-character line wraps.
 */
export function formatAsPem(base64: string, label: string): string {
  const cleanBase64 = sanitizePem(base64);
  const lines = cleanBase64.match(/.{1,64}/g) || [];
  return `-----BEGIN ${label}-----\n${lines.join("\n")}\n-----END ${label}-----`;
}

/**
 * Converts a PEM string into an ArrayBuffer containing the DER binary bytes.
 */
export function pemToArrayBuffer(pem: string): ArrayBuffer {
  return base64ToArrayBuffer(sanitizePem(pem));
}

/**
 * Imports a PEM-encoded RSA-OAEP public key (SPKI format).
 */
export async function importRsaPublicKey(pem: string): Promise<CryptoKey> {
  if (!pem || typeof pem !== "string" || !pem.trim()) {
    throw new Error("Recipient Public Key is missing or empty.");
  }
  const subtle = getSubtleCrypto();
  try {
    const derBuffer = pemToArrayBuffer(pem);
    return await subtle.importKey(
      "spki",
      derBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["encrypt"]
    );
  } catch (err) {
    throw new Error(
      `Invalid RSA Public Key: failed to parse SPKI PEM format. Please ensure valid -----BEGIN PUBLIC KEY----- encoding.`
    );
  }
}

/**
 * Imports a PEM-encoded RSA-OAEP private key (PKCS#8 format).
 */
export async function importRsaPrivateKey(pem: string): Promise<CryptoKey> {
  if (!pem || typeof pem !== "string" || !pem.trim()) {
    throw new Error("Secret Master Key (RSA Private Key) is missing or empty.");
  }
  const subtle = getSubtleCrypto();
  try {
    const derBuffer = pemToArrayBuffer(pem);
    return await subtle.importKey(
      "pkcs8",
      derBuffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256",
      },
      true,
      ["decrypt"]
    );
  } catch (err) {
    throw new Error(
      `Invalid RSA Private Key: failed to parse PKCS#8 PEM format. Please ensure valid -----BEGIN PRIVATE KEY----- encoding.`
    );
  }
}

// ============================================================================
// Core Functions
// ============================================================================

/**
 * 1. Generates an RSA-OAEP 2048-bit keypair using SHA-256.
 * Exports public key as standard SPKI Base64 with PEM headers.
 * Exports private key as PKCS#8 Base64 with PEM headers.
 *
 * @returns {Promise<RsaKeyPairPem>} { publicKeyPem, privateKeyPem }
 */
export async function generateRsaKeyPair(): Promise<RsaKeyPairPem> {
  const subtle = getSubtleCrypto();

  const keyPair = await subtle.generateKey(
    {
      name: "RSA-OAEP",
      modulusLength: 2048,
      publicExponent: new Uint8Array([1, 0, 1]), // 65537
      hash: "SHA-256",
    },
    true,
    ["encrypt", "decrypt"]
  );

  const spkiBuffer = await subtle.exportKey("spki", keyPair.publicKey);
  const pkcs8Buffer = await subtle.exportKey("pkcs8", keyPair.privateKey);

  const publicKeyPem = formatAsPem(arrayBufferToBase64(spkiBuffer), "PUBLIC KEY");
  const privateKeyPem = formatAsPem(arrayBufferToBase64(pkcs8Buffer), "PRIVATE KEY");

  return {
    publicKeyPem,
    privateKeyPem,
  };
}

/**
 * 2. Computes the SHA-256 digest of an ArrayBuffer and returns it as a lowercase hex string.
 *
 * @param {ArrayBuffer} data - The buffer to hash
 * @returns {Promise<string>} Hex-encoded SHA-256 digest
 */
export async function computeSha256(data: ArrayBuffer): Promise<string> {
  const subtle = getSubtleCrypto();
  const hashBuffer = await subtle.digest("SHA-256", data);
  return arrayBufferToHex(hashBuffer);
}

/**
 * Computes a standard SHA-256 fingerprint for a PEM-encoded RSA public or private key.
 * Formats as readable SHA256:xx:xx:xx...
 */
export async function computeKeyFingerprint(pem: string): Promise<string> {
  if (!pem || typeof pem !== "string" || !pem.trim()) return "";
  try {
    const der = pemToArrayBuffer(pem);
    const hashHex = await computeSha256(der);
    const pairs = hashHex.match(/.{1,2}/g) || [];
    return `SHA256:${pairs.join(":")}`;
  } catch {
    return "Invalid Key";
  }
}

/** Normalize raw hex or formatted SHA256 fingerprints to full 64-character hex. */
export function normalizeSha256Fingerprint(fingerprint: string | undefined | null): string {
  if (!fingerprint) return "";
  const hex = fingerprint.trim().replace(/^SHA256:/i, "").replace(/[:\s]/g, "").toLowerCase();
  return /^[0-9a-f]{64}$/.test(hex) ? hex : "";
}

/** Display a full SHA-256 fingerprint in colon-separated byte pairs. */
export function formatSha256Fingerprint(fingerprint: string | undefined | null): string {
  const hex = normalizeSha256Fingerprint(fingerprint);
  if (!hex) return fingerprint || "";
  return "SHA256:" + (hex.match(/.{2}/g) || []).join(":");
}

/**
 * 3. Encrypts a file buffer using hybrid cryptography:
 * - Generates a 32-byte (256-bit) AES session key and a 12-byte random IV.
 * - Encrypts fileBuffer using AES-256-GCM.
 * - Computes the plaintext SHA-256 checksum.
 * - Encrypts the raw 32-byte AES key using recipient's RSA-2048 public key via RSA-OAEP (256 bytes).
 * - Packs into a binary ArrayBuffer with layout:
 *   [256 bytes: Encrypted AES Key] + [12 bytes: IV] + [4 bytes: Metadata Length] + [N bytes: Metadata JSON] + [Remaining: Ciphertext + Tag]
 *
 * @param {ArrayBuffer} fileBuffer - Plaintext file contents
 * @param {string} fileName - Original file name
 * @param {string} fileType - MIME type of the file
 * @param {string} recipientPubKeyPem - Recipient's RSA public key in PEM format
 * @returns {Promise<EncryptedPackage>} { packageBuffer, sha256Hex, rawAesKeyHex }
 */
export async function encryptHybrid(
  fileBuffer: ArrayBuffer,
  fileName: string,
  fileType: string,
  recipientPubKeyPem: string
): Promise<EncryptedPackage> {
  const cryptoInstance = getCrypto();
  const subtle = getSubtleCrypto();

  // 1. Generate random 32-byte AES-256 key and 12-byte IV
  const rawAesKey = new Uint8Array(32);
  cryptoInstance.getRandomValues(rawAesKey);

  const iv = new Uint8Array(12);
  cryptoInstance.getRandomValues(iv);

  const rawAesKeyHex = arrayBufferToHex(rawAesKey);

  // 2. Compute plaintext SHA-256 checksum
  const sha256Hex = await computeSha256(fileBuffer);

  // 3. Encrypt fileBuffer using AES-256-GCM
  const aesKey = await subtle.importKey(
    "raw",
    rawAesKey,
    { name: "AES-GCM" },
    false,
    ["encrypt"]
  );

  const ciphertextBuffer = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    fileBuffer
  );

  // 4. Encrypt the raw 32-byte AES key using recipient's RSA-2048 public key via RSA-OAEP
  const recipientPubKey = await importRsaPublicKey(recipientPubKeyPem);
  const encryptedAesKeyBuffer = await subtle.encrypt(
    { name: "RSA-OAEP" },
    recipientPubKey,
    rawAesKey
  );

  if (encryptedAesKeyBuffer.byteLength !== 256) {
    throw new Error(
      `Unexpected encrypted AES key length: expected 256 bytes, received ${encryptedAesKeyBuffer.byteLength} bytes.`
    );
  }

  // 5. Serialize metadata into JSON bytes
  const metadata: PackageMetadata = {
    fileName,
    fileType,
    hash: sha256Hex,
    filename: fileName,
    filetype: fileType,
    sha256Hex,
  };
  const metadataJson = JSON.stringify(metadata);
  const metadataBytes = new TextEncoder().encode(metadataJson);
  const metadataLength = metadataBytes.byteLength;

  // 6. Binary packing:
  // [256 bytes: Encrypted AES Key] + [12 bytes: IV] + [4 bytes: Metadata Length] + [N bytes: Metadata JSON] + [Remaining: Ciphertext + Tag]
  const totalLength = 256 + 12 + 4 + metadataLength + ciphertextBuffer.byteLength;
  const packageBytes = new Uint8Array(totalLength);

  // 0..255: Encrypted AES Key (256 bytes)
  packageBytes.set(new Uint8Array(encryptedAesKeyBuffer), 0);

  // 256..267: IV (12 bytes)
  packageBytes.set(iv, 256);

  // 268..271: Metadata Length (4 bytes, uint32 big-endian)
  const dataView = new DataView(
    packageBytes.buffer,
    packageBytes.byteOffset,
    packageBytes.byteLength
  );
  dataView.setUint32(268, metadataLength, false);

  // 272..(272 + N - 1): Metadata JSON bytes
  packageBytes.set(metadataBytes, 272);

  // (272 + N)..end: AES-GCM Ciphertext + Tag
  packageBytes.set(new Uint8Array(ciphertextBuffer), 272 + metadataLength);

  const packageBuffer = packageBytes.buffer.slice(
    packageBytes.byteOffset,
    packageBytes.byteOffset + packageBytes.byteLength
  );

  return {
    packageBuffer,
    sha256Hex,
    rawAesKeyHex,
  };
}

/**
 * 4. Decrypts a binary package produced by encryptHybrid:
 * - Extracts Encrypted AES Key (256 bytes), IV (12 bytes), Metadata Length (4 bytes), Metadata JSON, and Ciphertext.
 * - Unwraps AES session key using recipient's RSA private key via RSA-OAEP.
 * - Decrypts ciphertext using recovered AES key and IV via AES-256-GCM.
 * - Re-computes SHA-256 of decrypted bytes and asserts match with metadata hash.
 *
 * @param {ArrayBuffer} packageBuffer - Packed binary package
 * @param {string} recipientPrivKeyPem - Recipient's RSA private key in PEM format
 * @returns {Promise<DecryptedPackage>} { fileBuffer, fileName, fileType, unwrappedAesKeyHex }
 */
export async function decryptHybrid(
  packageBuffer: ArrayBuffer,
  recipientPrivKeyPem: string
): Promise<DecryptedPackage> {
  const subtle = getSubtleCrypto();

  const MIN_HEADER_BYTES = 256 + 12 + 4; // 272 bytes minimum
  if (packageBuffer.byteLength < MIN_HEADER_BYTES) {
    throw new Error(
      `Invalid packageBuffer: size (${packageBuffer.byteLength} bytes) is less than minimum header (${MIN_HEADER_BYTES} bytes).`
    );
  }

  // 1. Read Metadata Length (uint32 big-endian at offset 268)
  const dataView = new DataView(packageBuffer);
  const metadataLength = dataView.getUint32(268, false);

  if (metadataLength > 1000000) {
    throw new Error(
      `Invalid packageBuffer: metadata length (${metadataLength} bytes) exceeds safety threshold of 1MB.`
    );
  }

  const headerPlusMetaLength = MIN_HEADER_BYTES + metadataLength;
  // AES-GCM outputs a 16-byte authentication tag appended to the ciphertext
  const minRequiredLength = headerPlusMetaLength + 16;
  if (packageBuffer.byteLength < minRequiredLength) {
    throw new Error(
      `Invalid packageBuffer: size (${packageBuffer.byteLength} bytes) is insufficient for metadata length (${metadataLength} bytes) and AES-GCM auth tag.`
    );
  }

  // 2. Extract sections
  const encryptedAesKeyBuffer = packageBuffer.slice(0, 256);
  const ivBuffer = packageBuffer.slice(256, 268);
  const metadataBuffer = packageBuffer.slice(272, 272 + metadataLength);
  const ciphertextBuffer = packageBuffer.slice(272 + metadataLength);

  // 3. Deserialize and validate metadata JSON
  const metadataJson = new TextDecoder().decode(metadataBuffer);
  let metadata: PackageMetadata;
  try {
    metadata = JSON.parse(metadataJson);
  } catch (err) {
    throw new Error(
      `Corrupted package: failed to parse metadata JSON: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  const fileName = metadata.fileName ?? metadata.filename ?? "";
  const fileType = metadata.fileType ?? metadata.filetype ?? "";
  const expectedHash = metadata.hash ?? metadata.sha256Hex;

  if (!expectedHash) {
    throw new Error("Corrupted package: metadata missing integrity hash.");
  }

  // 4. Unwrap AES key using recipient's RSA private key via RSA-OAEP
  const recipientPrivKey = await importRsaPrivateKey(recipientPrivKeyPem);
  let rawAesKeyBuffer: ArrayBuffer;
  try {
    rawAesKeyBuffer = await subtle.decrypt(
      { name: "RSA-OAEP" },
      recipientPrivKey,
      encryptedAesKeyBuffer
    );
  } catch (err) {
    throw new Error(
      `Failed to unwrap session key with RSA private key: ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  if (rawAesKeyBuffer.byteLength !== 32) {
    throw new Error(
      `Invalid session key length: expected 32 bytes, got ${rawAesKeyBuffer.byteLength} bytes.`
    );
  }

  const unwrappedAesKeyHex = arrayBufferToHex(rawAesKeyBuffer);

  // 5. Decrypt ciphertext using recovered AES key and IV via AES-256-GCM
  const aesKey = await subtle.importKey(
    "raw",
    rawAesKeyBuffer,
    { name: "AES-GCM" },
    false,
    ["decrypt"]
  );

  let fileBuffer: ArrayBuffer;
  try {
    fileBuffer = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv: new Uint8Array(ivBuffer),
      },
      aesKey,
      ciphertextBuffer
    );
  } catch (err) {
    throw new Error(
      `Failed to decrypt file buffer with AES-256-GCM (authentication tag mismatch or data tampered): ${
        err instanceof Error ? err.message : String(err)
      }`
    );
  }

  // 6. Re-compute SHA-256 of decrypted bytes and assert match with metadata hash
  const computedHashHex = await computeSha256(fileBuffer);
  if (computedHashHex.toLowerCase() !== expectedHash.toLowerCase()) {
    throw new Error(
      `Integrity check failed: expected SHA-256 ${expectedHash}, but calculated ${computedHashHex}. File has been tampered with or corrupted.`
    );
  }

  return {
    fileBuffer,
    fileName,
    fileType,
    unwrappedAesKeyHex,
  };
}

// ============================================================================
// Client-Side Password-Protected Private Key Backup (PBKDF2 + AES-256-GCM)
// ============================================================================

export interface EncryptedKeyBackup {
  format: "vaultzero-encrypted-key";
  version: number;
  publicKeyPem: string;
  fingerprint: string;
  kdf: "PBKDF2-SHA256";
  iterations: number;
  saltHex: string;
  ivHex: string;
  ciphertextBase64: string;
  createdAt: string;
}

/**
 * Encrypts a private key using a user password via PBKDF2 (100,000 rounds) + AES-256-GCM.
 * The operation is performed 100% locally in the browser; the password and private key
 * are never transmitted to any server.
 */
export async function exportEncryptedPrivateKeyBackup(
  privateKeyPem: string,
  publicKeyPem: string,
  passphrase: string
): Promise<string> {
  if (!passphrase || passphrase.length < 8) {
    throw new Error("Backup passphrase must be at least 8 characters long.");
  }
  const subtle = getSubtleCrypto();
  const cryptoInstance = getCrypto();

  // 1. Generate 16 bytes salt and 12 bytes IV
  const salt = new Uint8Array(16);
  cryptoInstance.getRandomValues(salt);

  const iv = new Uint8Array(12);
  cryptoInstance.getRandomValues(iv);

  // 2. Derive key from password using PBKDF2
  const enc = new TextEncoder();
  const baseKey = await subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const aesKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["encrypt"]
  );

  // 3. Encrypt the raw PKCS#8 DER bytes
  const privateKeyDer = pemToArrayBuffer(privateKeyPem);
  const ciphertextBuffer = await subtle.encrypt(
    {
      name: "AES-GCM",
      iv,
    },
    aesKey,
    privateKeyDer
  );

  const fingerprint = await computeKeyFingerprint(publicKeyPem);

  const backup: EncryptedKeyBackup = {
    format: "vaultzero-encrypted-key",
    version: 1,
    publicKeyPem,
    fingerprint,
    kdf: "PBKDF2-SHA256",
    iterations: 100000,
    saltHex: arrayBufferToHex(salt),
    ivHex: arrayBufferToHex(iv),
    ciphertextBase64: arrayBufferToBase64(ciphertextBuffer),
    createdAt: new Date().toISOString(),
  };

  return JSON.stringify(backup, null, 2);
}

/**
 * Decrypts a password-protected .vaultkey backup file and restores the private/public keypair.
 */
export async function importEncryptedPrivateKeyBackup(
  backupJsonString: string,
  passphrase: string
): Promise<{ privateKeyPem: string; publicKeyPem: string }> {
  let backup: EncryptedKeyBackup;
  try {
    backup = JSON.parse(backupJsonString);
  } catch {
    throw new Error("Invalid key backup file: Malformed JSON structure.");
  }

  if (backup.format !== "vaultzero-encrypted-key" || backup.version !== 1) {
    throw new Error("Unsupported key backup format or version.");
  }

  const subtle = getSubtleCrypto();
  const salt = new Uint8Array(hexToArrayBuffer(backup.saltHex));
  const iv = new Uint8Array(hexToArrayBuffer(backup.ivHex));
  const ciphertextBuffer = base64ToArrayBuffer(backup.ciphertextBase64);

  // 1. Derive key using PBKDF2
  const enc = new TextEncoder();
  const baseKey = await subtle.importKey(
    "raw",
    enc.encode(passphrase),
    { name: "PBKDF2" },
    false,
    ["deriveKey"]
  );

  const aesKey = await subtle.deriveKey(
    {
      name: "PBKDF2",
      salt,
      iterations: backup.iterations || 100000,
      hash: "SHA-256",
    },
    baseKey,
    { name: "AES-GCM", length: 256 },
    false,
    ["decrypt"]
  );

  // 2. Decrypt PKCS#8 DER bytes
  let privateKeyDer: ArrayBuffer;
  try {
    privateKeyDer = await subtle.decrypt(
      {
        name: "AES-GCM",
        iv,
      },
      aesKey,
      ciphertextBuffer
    );
  } catch {
    throw new Error(
      "Decryption failed: Incorrect passphrase or corrupted backup file (AES-GCM authentication tag mismatch)."
    );
  }

  // 3. Re-encode as PEM
  const privateKeyPem = formatAsPem(arrayBufferToBase64(privateKeyDer), "PRIVATE KEY");

  // Validate that the decrypted private key is a valid RSA-OAEP key
  await importRsaPrivateKey(privateKeyPem);

  return {
    privateKeyPem,
    publicKeyPem: backup.publicKeyPem,
  };
}
