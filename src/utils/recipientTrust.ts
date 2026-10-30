/** Local out-of-band verification is bound to one recipient and one exact key version. */
export interface VerifiedRecipientRecord {
  recipientIdentifier: string;
  recipientId: string;
  keyId: string;
  verifiedFingerprint: string;
  verifiedAt: string;
  verificationChannel: string;
  notes?: string;
}

const STORAGE_KEY = "vaultzero_verified_recipients";

export function loadVerifiedRecipients(): Record<string, VerifiedRecipientRecord> {
  if (typeof window === "undefined" || !window.localStorage) return {};
  try { return JSON.parse(localStorage.getItem(STORAGE_KEY) || "{}"); }
  catch { return {}; }
}

export function saveVerifiedRecipient(record: VerifiedRecipientRecord): void {
  if (typeof window === "undefined" || !record.recipientId || !record.keyId || !record.verifiedFingerprint) return;
  const store = loadVerifiedRecipients();
  store[record.recipientId.toLowerCase()] = { ...record, recipientId: record.recipientId.toLowerCase() };
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

export function removeVerifiedRecipient(recipientId: string): void {
  if (typeof window === "undefined") return;
  const store = loadVerifiedRecipients(); delete store[recipientId.trim().toLowerCase()];
  localStorage.setItem(STORAGE_KEY, JSON.stringify(store));
}

export function getVerifiedRecipient(recipientId: string): VerifiedRecipientRecord | null {
  return recipientId ? loadVerifiedRecipients()[recipientId.trim().toLowerCase()] || null : null;
}

export type KeyTrustStatus = "verified_match" | "key_changed_warning" | "unverified";
export interface KeyTrustEvaluation { status: KeyTrustStatus; record?: VerifiedRecipientRecord; previousFingerprint?: string; }

export function evaluateKeyTrust(recipientId: string, keyId: string, fingerprint: string): KeyTrustEvaluation {
  if (!recipientId || !keyId || !fingerprint) return { status: "unverified" };
  const record = getVerifiedRecipient(recipientId);
  if (!record || !record.recipientId || !record.keyId) return { status: "unverified" };
  if (record.recipientId.toLowerCase() === recipientId.trim().toLowerCase()
      && record.keyId === keyId
      && record.verifiedFingerprint.toLowerCase() === fingerprint.trim().toLowerCase()) {
    return { status: "verified_match", record };
  }
  return { status: "key_changed_warning", record, previousFingerprint: record.verifiedFingerprint };
}
