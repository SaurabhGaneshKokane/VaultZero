import React, { useState, useEffect } from "react";
import {
  X,
  KeyRound,
  Copy,
  Check,
  Eye,
  EyeOff,
  RefreshCw,
  Download,
  AlertTriangle,
  Upload,
  Globe,
  Lock,
  ShieldCheck,
  Info,
} from "lucide-react";
import {
  computeKeyFingerprint,
  exportEncryptedPrivateKeyBackup,
  normalizeSha256Fingerprint,
  importEncryptedPrivateKeyBackup,
  RsaKeyPairPem,
} from "../utils/cryptoEngine";
import {
  publishPublicKey,
  rotateMyPublicKey,
  deactivateMyPublicKey,
  PublicKeyDirectoryRecord,
} from "../utils/apiClient";

interface KeyManagementModalProps {
  isOpen: boolean;
  onClose: () => void;
  publicKeyPem: string;
  privateKeyPem: string;
  onRegenerateKeys: (forRotation?: boolean) => Promise<RsaKeyPairPem>;
  onKeysRestored?: (pubPem: string, privPem: string) => void;
  isGeneratingKeys: boolean;
  accessToken: string;
  authenticatedEmail: string;
  authenticatedVaultId: string;
  currentDirectoryRecord?: PublicKeyDirectoryRecord;
  onDirectoryRecordChange: (record?: PublicKeyDirectoryRecord) => void;
}

export const KeyManagementModal: React.FC<KeyManagementModalProps> = ({
  isOpen,
  onClose,
  publicKeyPem,
  privateKeyPem,
  onRegenerateKeys,
  onKeysRestored,
  isGeneratingKeys,
  accessToken,
  authenticatedEmail,
  authenticatedVaultId,
  currentDirectoryRecord,
  onDirectoryRecordChange,
}) => {
  const [activeTab, setActiveTab] = useState<"keys" | "directory" | "backup">("keys");
  const [showPrivateKey, setShowPrivateKey] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<"pub" | "priv" | "fingerprint" | "keyid" | null>(null);
  const [fingerprint, setFingerprint] = useState<string>("");
  const [confirmRegenerate, setConfirmRegenerate] = useState<boolean>(false);

  // Cloud Directory State
  const [userEmail, setUserEmail] = useState<string>(authenticatedEmail);
  const [vaultId, setVaultId] = useState<string>(authenticatedVaultId);
  const authToken = accessToken;

  useEffect(() => {
    setUserEmail(authenticatedEmail);
    setVaultId(authenticatedVaultId);
  }, [authenticatedEmail, authenticatedVaultId]);
  const [directoryRecord, setDirectoryRecord] = useState<PublicKeyDirectoryRecord | null>(null);
  const [isDirectoryLoading, setIsDirectoryLoading] = useState<boolean>(false);
  const [directoryError, setDirectoryError] = useState<string | null>(null);
  const [directorySuccess, setDirectorySuccess] = useState<string | null>(null);
  const [rotationReason, setRotationReason] = useState<string>("");
  const [showRotationInput, setShowRotationInput] = useState<boolean>(false);
  const [rotationBackupPassword, setRotationBackupPassword] = useState("");
  const [rotationBackupConfirm, setRotationBackupConfirm] = useState("");

  // Encrypted Backup & Restore State
  const [backupPassword, setBackupPassword] = useState<string>("");
  const [confirmBackupPassword, setConfirmBackupPassword] = useState<string>("");
  const [backupStatusMsg, setBackupStatusMsg] = useState<{ type: "success" | "error"; text: string } | null>(null);
  const [isExportingBackup, setIsExportingBackup] = useState<boolean>(false);

  const [restorePassword, setRestorePassword] = useState<string>("");
  const [restoreFileContent, setRestoreFileContent] = useState<string | null>(null);
  const [restoreFileName, setRestoreFileName] = useState<string>("");
  const [isRestoring, setIsRestoring] = useState<boolean>(false);

  useEffect(() => {
    setDirectoryRecord(currentDirectoryRecord || null);
  }, [currentDirectoryRecord]);

  useEffect(() => {
    if (publicKeyPem) {
      computeKeyFingerprint(publicKeyPem).then(setFingerprint);
    } else {
      setFingerprint("");
    }
  }, [publicKeyPem]);

  if (!isOpen) return null;

  const handleCopy = async (text: string, field: "pub" | "priv" | "fingerprint" | "keyid") => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(field);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  };

  const handleDownloadFile = (content: string, filename: string, mime: string = "text/plain") => {
    const blob = new Blob([content], { type: `${mime};charset=utf-8` });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = filename;
    document.body.appendChild(a);
    a.click();
    document.body.removeChild(a);
    URL.revokeObjectURL(url);
  };

  // 1. Publish to Cloud Directory
  const handlePublishToDirectory = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!authToken || !publicKeyPem) {
      setDirectoryError("Sign in and load your local key before publishing.");
      return;
    }
    setIsDirectoryLoading(true);
    setDirectoryError(null);
    setDirectorySuccess(null);

    try {
      const record = await publishPublicKey(authToken, publicKeyPem);
      setDirectoryRecord(record);
      onDirectoryRecordChange(record);
      setDirectorySuccess(`Public key successfully published to Cloud Directory! Key ID: ${record.key_id}`);
    } catch (err: unknown) {
      setDirectoryError(err instanceof Error ? err.message : "Failed to publish public key.");
    } finally {
      setIsDirectoryLoading(false);
    }
  };

  // 2. Explicit Key Rotation in Directory
  const handleRotateKeyInDirectory = async () => {
    if (!directoryRecord || !authToken) return;
    if (rotationBackupPassword.length < 8 || rotationBackupPassword !== rotationBackupConfirm) {
      setDirectoryError("Create a matching backup passphrase of at least 8 characters before rotating this key.");
      return;
    }
    setIsDirectoryLoading(true);
    setDirectoryError(null);
    setDirectorySuccess(null);

    try {
      const pair = await onRegenerateKeys(true);
      const backupJson = await exportEncryptedPrivateKeyBackup(pair.privateKeyPem, pair.publicKeyPem, rotationBackupPassword);
      handleDownloadFile(backupJson, `vaultzero_rotated_key_${new Date().toISOString().slice(0,10)}.vaultkey`, "application/json");

      const updatedRecord = await rotateMyPublicKey(
        authToken,
        directoryRecord.key_id,
        pair.publicKeyPem,
        rotationReason || "User-initiated cryptographic key rotation"
      );

      onKeysRestored?.(pair.publicKeyPem, pair.privateKeyPem);
      setDirectoryRecord(updatedRecord);
      onDirectoryRecordChange(updatedRecord);
      setRotationBackupPassword(""); setRotationBackupConfirm("");
      setShowRotationInput(false);
      setRotationReason("");
      setDirectorySuccess(
        `Key explicitly rotated! Previous key ${directoryRecord.key_id} is marked 'rotated'. New active key: ${updatedRecord.key_id}`
      );
    } catch (err: unknown) {
      setDirectoryError(err instanceof Error ? err.message : "Key rotation failed.");
    } finally {
      setIsDirectoryLoading(false);
    }
  };

  // 3. Export Password-Encrypted Backup (.vaultkey)
  const handleExportBackup = async (e: React.FormEvent) => {
    e.preventDefault();
    setBackupStatusMsg(null);
    if (!backupPassword || backupPassword.length < 8) {
      setBackupStatusMsg({ type: "error", text: "Passphrase must be at least 8 characters." });
      return;
    }
    if (backupPassword !== confirmBackupPassword) {
      setBackupStatusMsg({ type: "error", text: "Passphrases do not match." });
      return;
    }

    setIsExportingBackup(true);
    try {
      const backupJson = await exportEncryptedPrivateKeyBackup(privateKeyPem, publicKeyPem, backupPassword);
      const filename = `vaultzero_key_backup_${new Date().toISOString().slice(0, 10)}.vaultkey`;
      handleDownloadFile(backupJson, filename, "application/json");
      setBackupStatusMsg({
        type: "success",
        text: `Encrypted backup created and downloaded as "${filename}". Store this file and your passphrase securely.`,
      });
      setBackupPassword("");
      setConfirmBackupPassword("");
    } catch (err: unknown) {
      setBackupStatusMsg({
        type: "error",
        text: err instanceof Error ? err.message : "Failed to generate encrypted key backup.",
      });
    } finally {
      setIsExportingBackup(false);
    }
  };

  // 4. Restore from Encrypted Backup (.vaultkey)
  const handleRestoreFileSelected = (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;
    setRestoreFileName(file.name);
    const reader = new FileReader();
    reader.onload = () => {
      setRestoreFileContent(reader.result as string);
    };
    reader.readAsText(file);
  };

  const handlePerformRestore = async (e: React.FormEvent) => {
    e.preventDefault();
    if (!restoreFileContent) {
      alert("Please select a .vaultkey backup file first.");
      return;
    }
    if (!restorePassword) {
      alert("Please enter the decryption passphrase.");
      return;
    }

    setIsRestoring(true);
    try {
      const restored = await importEncryptedPrivateKeyBackup(restoreFileContent, restorePassword);
      if (directoryRecord?.status === "active") {
        const restoredFingerprint = normalizeSha256Fingerprint(
          await computeKeyFingerprint(restored.publicKeyPem)
        );
        const expectedFingerprint = normalizeSha256Fingerprint(directoryRecord.fingerprint_raw_hex);
        if (!expectedFingerprint || restoredFingerprint !== expectedFingerprint) {
          throw new Error("The backup does not match the complete active-key fingerprint.");
        }
      } else if (authToken) {
        const record = await publishPublicKey(authToken, restored.publicKeyPem);
        setDirectoryRecord(record);
        onDirectoryRecordChange(record);
      }
      sessionStorage.setItem("vaultzero_pubkey_pem", restored.publicKeyPem);
      sessionStorage.setItem("vaultzero_privkey_pem", restored.privateKeyPem);

      if (onKeysRestored) {
        onKeysRestored(restored.publicKeyPem, restored.privateKeyPem);
      }

      alert("Keypair successfully decrypted and restored into browser session!");
      setRestoreFileContent(null);
      setRestoreFileName("");
      setRestorePassword("");
      onClose();
    } catch (err: unknown) {
      alert(err instanceof Error ? err.message : "Failed to decrypt backup file.");
    } finally {
      setIsRestoring(false);
    }
  };

  return (
    <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
      <div
        className="bg-white border border-slate-200 rounded-2xl max-w-2xl w-full shadow-xl overflow-hidden font-sans text-slate-800 animate-in fade-in zoom-in-95 duration-150"
        role="dialog"
        aria-labelledby="key-modal-title"
        aria-modal="true"
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-slate-200 flex items-center justify-between bg-slate-50">
          <div className="flex items-center space-x-2.5">
            <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center border border-blue-100">
              <KeyRound className="w-4 h-4" />
            </div>
            <div>
              <h2 id="key-modal-title" className="text-base font-bold text-slate-900">
                Cryptographic Identity & Key Management
              </h2>
              <p className="text-xs text-slate-500">
                RSA-2048 client-side keypair, Cloud Directory discovery, and encrypted backups
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            className="p-1.5 rounded-lg text-slate-400 hover:text-slate-600 hover:bg-slate-100 transition-colors cursor-pointer"
            aria-label="Close dialog"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Tab Navigation */}
        <div className="px-6 pt-3 border-b border-slate-200 bg-white flex space-x-4 text-xs font-medium">
          <button
            onClick={() => setActiveTab("keys")}
            className={`pb-2.5 border-b-2 transition-colors cursor-pointer ${
              activeTab === "keys"
                ? "border-blue-600 text-blue-700 font-semibold"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            Local Keypair
          </button>
          <button
            onClick={() => setActiveTab("directory")}
            className={`pb-2.5 border-b-2 transition-colors cursor-pointer flex items-center space-x-1.5 ${
              activeTab === "directory"
                ? "border-blue-600 text-blue-700 font-semibold"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <Globe className="w-3.5 h-3.5" />
            <span>Cloud Directory</span>
          </button>
          <button
            onClick={() => setActiveTab("backup")}
            className={`pb-2.5 border-b-2 transition-colors cursor-pointer flex items-center space-x-1.5 ${
              activeTab === "backup"
                ? "border-blue-600 text-blue-700 font-semibold"
                : "border-transparent text-slate-500 hover:text-slate-800"
            }`}
          >
            <Lock className="w-3.5 h-3.5" />
            <span>Password Backup & Restore</span>
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto">
          {/* TAB 1: LOCAL KEYS */}
          {activeTab === "keys" && (
            <div className="space-y-6">
              {/* Storage Disclosure Box */}
              <div className="p-3.5 bg-blue-50 border border-blue-200 rounded-xl text-xs text-blue-900 space-y-1">
                <div className="flex items-center space-x-1.5 font-semibold text-blue-950">
                  <ShieldCheck className="w-4 h-4 text-blue-600 shrink-0" />
                  <span>Browser Session Storage Isolation (RSA-2048)</span>
                </div>
                <p className="text-[11px] leading-relaxed text-blue-800">
                  Your private key is stored exclusively in this browser tab&apos;s <code>sessionStorage</code>.
                  It is never uploaded to any backend or logged.
                  Closing this tab or clearing session data will remove the keys unless backed up.
                </p>
              </div>

              {/* Section 1: Public Key */}
              <div className="space-y-3">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900 flex items-center space-x-2">
                      <span>Recipient Public Address (Lockbox)</span>
                      <span className="text-[10px] text-emerald-700 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-medium">
                        Safe to share
                      </span>
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Share this public key or publish it to the directory so senders can seal files for you.
                    </p>
                  </div>

                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => handleCopy(publicKeyPem, "pub")}
                      disabled={!publicKeyPem}
                      className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg border border-slate-200 flex items-center space-x-1 cursor-pointer transition-colors"
                    >
                      {copiedField === "pub" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedField === "pub" ? "Copied" : "Copy"}</span>
                    </button>
                    <button
                      onClick={() => handleDownloadFile(publicKeyPem, "vaultzero_public_key.pem")}
                      disabled={!publicKeyPem}
                      className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg border border-slate-200 flex items-center space-x-1 cursor-pointer transition-colors"
                    >
                      <Download className="w-3 h-3" />
                      <span>Export</span>
                    </button>
                  </div>
                </div>

                {fingerprint && (
                  <div className="flex items-center justify-between text-xs bg-slate-50 p-2.5 rounded-lg border border-slate-200 font-mono">
                    <span className="text-slate-500 text-[11px]">Fingerprint (SHA-256):</span>
                    <div className="flex items-center space-x-2">
                      <span className="text-slate-800 font-semibold">{fingerprint}</span>
                      <button
                        onClick={() => handleCopy(fingerprint, "fingerprint")}
                        className="text-slate-400 hover:text-slate-700 cursor-pointer"
                        title="Copy fingerprint"
                      >
                        {copiedField === "fingerprint" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      </button>
                    </div>
                  </div>
                )}

                <textarea
                  readOnly
                  rows={4}
                  value={publicKeyPem}
                  placeholder="Generating public key..."
                  className="w-full rounded-xl bg-slate-50 border border-slate-200 p-3 text-xs font-mono text-emerald-800 focus:outline-none resize-none select-all"
                />
              </div>

              {/* Section 2: Private Key */}
              <div className="space-y-3 pt-2 border-t border-slate-200">
                <div className="flex items-center justify-between">
                  <div>
                    <h3 className="text-sm font-semibold text-slate-900 flex items-center space-x-2">
                      <span>Secret Master Key (RSA Private Key)</span>
                      <span className="text-[10px] text-rose-700 bg-rose-50 px-2 py-0.5 rounded border border-rose-200 font-medium">
                        Never share
                      </span>
                    </h3>
                    <p className="text-xs text-slate-500 mt-0.5">
                      Used locally to unwrap the AES session key and decrypt received files.
                    </p>
                  </div>

                  <button
                    onClick={() => setShowPrivateKey(!showPrivateKey)}
                    className="px-2.5 py-1 text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 rounded-lg border border-slate-200 flex items-center space-x-1 cursor-pointer transition-colors"
                  >
                    {showPrivateKey ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                    <span>{showPrivateKey ? "Mask" : "Reveal"}</span>
                  </button>
                </div>

                {showPrivateKey ? (
                  <textarea
                    readOnly
                    rows={4}
                    value={privateKeyPem}
                    className="w-full rounded-xl bg-slate-50 border border-slate-200 p-3 text-xs font-mono text-rose-800 focus:outline-none resize-none select-all"
                  />
                ) : (
                  <div className="h-20 flex items-center justify-center rounded-xl bg-slate-50 border border-slate-200 text-xs text-slate-400 font-mono tracking-widest select-none">
                    •••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••••• (Protected in Browser Session)
                  </div>
                )}
              </div>

              {/* Regenerate Keypair Control */}
              <div className="pt-2 border-t border-slate-200 flex items-center justify-between">
                <span className="text-xs text-slate-500">
                  Need a fresh identity? You can regenerate an RSA-2048 keypair at any time.
                </span>

                {directoryRecord?.status === "active" ? (
                  <span className="text-xs text-slate-500">This active key is protected. Use the Directory tab for explicit, backed-up rotation.</span>
                ) : !confirmRegenerate ? (
                  <button
                    onClick={() => setConfirmRegenerate(true)}
                    disabled={isGeneratingKeys}
                    className="text-xs font-medium text-blue-600 hover:text-blue-700 flex items-center space-x-1.5 cursor-pointer disabled:opacity-50 shrink-0 ml-4"
                  >
                    <RefreshCw className={`w-3.5 h-3.5 ${isGeneratingKeys ? "animate-spin" : ""}`} />
                    <span>Regenerate Keypair</span>
                  </button>
                ) : (
                  <div className="flex items-center space-x-2 shrink-0 ml-4">
                    <span className="text-xs text-rose-600 font-medium">Replace current keys?</span>
                    <button
                      onClick={async () => {
                        await onRegenerateKeys();
                        setConfirmRegenerate(false);
                      }}
                      disabled={isGeneratingKeys}
                      className="px-2.5 py-1 text-xs font-semibold text-white bg-rose-600 hover:bg-rose-700 rounded-md cursor-pointer"
                    >
                      Yes, Replace
                    </button>
                    <button
                      onClick={() => setConfirmRegenerate(false)}
                      className="px-2 py-1 text-xs text-slate-500 hover:text-slate-800"
                    >
                      Cancel
                    </button>
                  </div>
                )}
              </div>
            </div>
          )}

          {/* TAB 2: CLOUD DIRECTORY PUBLISHING & ROTATION */}
          {activeTab === "directory" && (
            <div className="space-y-6">
              <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-1">
                <div className="flex items-center space-x-1.5 font-semibold text-slate-900">
                  <Globe className="w-4 h-4 text-blue-600 shrink-0" />
                  <span>Public Key Directory (Supabase PostgreSQL Relay)</span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-600">
                  Publishing your public key to the cloud directory allows senders to find your encryption key
                  by your email or VaultZero ID. The directory stores <strong>only</strong> your public key and canonical fingerprint.
                  Your private key is <strong>never</strong> transmitted.
                </p>
              </div>

              {directorySuccess && (
                <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-800 flex items-start space-x-2">
                  <Check className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  <span>{directorySuccess}</span>
                </div>
              )}

              {directoryError && (
                <div className="p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800 flex items-start space-x-2">
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  <span>{directoryError}</span>
                </div>
              )}

              {/* Publish Form */}
              <form onSubmit={handlePublishToDirectory} className="space-y-4">
                <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Email Address (Identity Verification)
                    </label>
                    <input
                      type="email"
                      required
                      value={userEmail}
                      readOnly
                      placeholder="Verified Supabase email"
                      className="w-full text-xs rounded-lg border border-slate-300 p-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      VaultZero ID (Optional handle)
                    </label>
                    <input
                      type="text"
                      value={vaultId}
                      readOnly
                      placeholder="Assigned VaultZero ID"
                      className="w-full text-xs rounded-lg border border-slate-300 p-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>
                </div>

                <div className="flex items-center justify-between pt-2">
                  <div className="text-[11px] text-slate-500">
                    Fingerprint to publish: <code className="font-mono text-slate-800">{fingerprint || "—"}</code>
                  </div>

                  <button
                    type="submit"
                    disabled={isDirectoryLoading || !publicKeyPem || !authToken}
                    className="px-4 py-2 rounded-lg bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium transition cursor-pointer disabled:opacity-50"
                  >
                    {isDirectoryLoading ? "Publishing..." : "Publish to Directory"}
                  </button>
                </div>
              </form>

              {/* Active Directory Record Details & Key Rotation */}
              {directoryRecord && (
                <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                  <div className="flex items-center justify-between">
                    <span className="text-xs font-semibold text-slate-900 flex items-center space-x-1.5">
                      <ShieldCheck className="w-4 h-4 text-emerald-600" />
                      <span>Active Key in Directory: {directoryRecord.key_id}</span>
                    </span>
                    <span className="text-[10px] bg-emerald-100 text-emerald-800 px-2 py-0.5 rounded font-mono font-medium">
                      Status: {directoryRecord.status.toUpperCase()}
                    </span>
                  </div>

                  <div className="text-xs text-slate-600 space-y-1">
                    <div>Owner: <span className="font-mono text-slate-800">{directoryRecord.owner_email}</span> ({directoryRecord.owner_vault_id})</div>
                    <div>Registered: <span className="font-mono text-slate-800">{new Date(directoryRecord.registered_at).toLocaleString()}</span></div>
                  </div>

                  {/* Explicit Key Rotation */}
                  <div className="pt-2 border-t border-slate-200">
                    {!showRotationInput ? (
                      <button
                        type="button"
                        onClick={() => setShowRotationInput(true)}
                        className="text-xs text-amber-700 hover:text-amber-800 font-medium flex items-center space-x-1 cursor-pointer"
                      >
                        <RefreshCw className="w-3.5 h-3.5" />
                        <span>Rotate Key in Directory (Explicit Key Replacement)</span>
                      </button>
                    ) : (
                      <div className="space-y-2 pt-1">
                        <p className="text-xs text-amber-800">
                          Key rotation will deactivate <strong>{directoryRecord.key_id}</strong> (marked &apos;rotated&apos;)
                          and publish a brand new RSA-2048 keypair. Existing recipients will be notified of the fingerprint change.
                        </p>
                        <p className="text-xs text-slate-700">A password-encrypted backup of the new private key downloads before the directory is changed. Save it and the passphrase.</p>
                        <input type="password" value={rotationBackupPassword} onChange={(e) => setRotationBackupPassword(e.target.value)} placeholder="New key backup passphrase (8+ characters)" className="w-full text-xs rounded-lg border border-slate-300 p-2" />
                        <input type="password" value={rotationBackupConfirm} onChange={(e) => setRotationBackupConfirm(e.target.value)} placeholder="Confirm backup passphrase" className="w-full text-xs rounded-lg border border-slate-300 p-2" />
                        <input
                          type="text"
                          value={rotationReason}
                          onChange={(e) => setRotationReason(e.target.value)}
                          placeholder="Rotation reason (e.g. Scheduled annual key rotation)..."
                          className="w-full text-xs rounded-lg border border-slate-300 p-2 focus:outline-none focus:ring-2 focus:ring-amber-500"
                        />
                        <div className="flex items-center space-x-2 pt-1">
                          <button
                            type="button"
                            onClick={handleRotateKeyInDirectory}
                            disabled={isDirectoryLoading}
                            className="px-3 py-1.5 bg-amber-600 hover:bg-amber-700 text-white rounded text-xs font-semibold cursor-pointer"
                          >
                            Confirm Rotation
                          </button>
                          <button
                            type="button"
                            onClick={() => setShowRotationInput(false)}
                            className="text-xs text-slate-500 hover:text-slate-800"
                          >
                            Cancel
                          </button>
                        </div>
                      </div>
                    )}
                  </div>
                </div>
              )}
            </div>
          )}

          {/* TAB 3: PASSWORD-ENCRYPTED BACKUP & RESTORE */}
          {activeTab === "backup" && (
            <div className="space-y-6">
              {/* Explanation Box */}
              <div className="p-3.5 bg-slate-50 border border-slate-200 rounded-xl text-xs space-y-1">
                <div className="flex items-center space-x-1.5 font-semibold text-slate-900">
                  <Lock className="w-4 h-4 text-blue-600 shrink-0" />
                  <span>Authenticated Client-Side Key Backup (PBKDF2 + AES-256-GCM)</span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-600">
                  Protect your private key with a passphrase before downloading. The backup file (<code>.vaultkey</code>)
                  derives an encryption key using 100,000 rounds of PBKDF2 with SHA-256 and encrypts the key using
                  AES-256-GCM. <strong>The backend never sees the backup, passphrase, or private key.</strong>
                </p>
              </div>

              {backupStatusMsg && (
                <div
                  className={`p-3 rounded-xl text-xs flex items-start space-x-2 ${
                    backupStatusMsg.type === "success"
                      ? "bg-emerald-50 border border-emerald-200 text-emerald-800"
                      : "bg-rose-50 border border-rose-200 text-rose-800"
                  }`}
                >
                  {backupStatusMsg.type === "success" ? (
                    <Check className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                  ) : (
                    <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                  )}
                  <span>{backupStatusMsg.text}</span>
                </div>
              )}

              {/* Sub-section A: Export Protected Backup */}
              <div className="space-y-3 p-4 bg-white border border-slate-200 rounded-xl">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                  Export Encrypted Backup (.vaultkey)
                </h4>
                <form onSubmit={handleExportBackup} className="space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <div>
                      <label className="block text-xs font-medium text-slate-700 mb-1">
                        Backup Passphrase (min 8 chars)
                      </label>
                      <input
                        type="password"
                        required
                        value={backupPassword}
                        onChange={(e) => setBackupPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="w-full text-xs rounded-lg border border-slate-300 p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                    <div>
                      <label className="block text-xs font-medium text-slate-700 mb-1">
                        Confirm Passphrase
                      </label>
                      <input
                        type="password"
                        required
                        value={confirmBackupPassword}
                        onChange={(e) => setConfirmBackupPassword(e.target.value)}
                        placeholder="••••••••••••"
                        className="w-full text-xs rounded-lg border border-slate-300 p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                      />
                    </div>
                  </div>

                  <button
                    type="submit"
                    disabled={isExportingBackup || !privateKeyPem}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-medium flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <Download className="w-3.5 h-3.5" />
                    <span>{isExportingBackup ? "Deriving Key & Encrypting..." : "Download Encrypted .vaultkey"}</span>
                  </button>
                </form>
              </div>

              {/* Sub-section B: Restore from Backup */}
              <div className="space-y-3 p-4 bg-white border border-slate-200 rounded-xl">
                <h4 className="text-xs font-bold uppercase tracking-wider text-slate-900">
                  Restore Identity from Backup (.vaultkey)
                </h4>
                <form onSubmit={handlePerformRestore} className="space-y-3">
                  <div className="flex items-center space-x-3">
                    <label className="px-3 py-2 bg-slate-100 hover:bg-slate-200 border border-slate-300 rounded-lg text-xs font-medium text-slate-700 cursor-pointer flex items-center space-x-1.5">
                      <Upload className="w-3.5 h-3.5" />
                      <span>Choose .vaultkey file</span>
                      <input
                        type="file"
                        accept=".vaultkey,.json"
                        onChange={handleRestoreFileSelected}
                        className="hidden"
                      />
                    </label>
                    <span className="text-xs text-slate-500 truncate max-w-xs">
                      {restoreFileName || "No file selected"}
                    </span>
                  </div>

                  <div>
                    <label className="block text-xs font-medium text-slate-700 mb-1">
                      Decryption Passphrase
                    </label>
                    <input
                      type="password"
                      value={restorePassword}
                      onChange={(e) => setRestorePassword(e.target.value)}
                      placeholder="Passphrase used when creating backup..."
                      className="w-full sm:w-80 text-xs rounded-lg border border-slate-300 p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                  </div>

                  <button
                    type="submit"
                    disabled={isRestoring || !restoreFileContent || !restorePassword}
                    className="px-4 py-2 bg-slate-800 hover:bg-slate-900 text-white rounded-lg text-xs font-medium flex items-center space-x-1.5 cursor-pointer disabled:opacity-50"
                  >
                    <ShieldCheck className="w-3.5 h-3.5" />
                    <span>{isRestoring ? "Decrypting..." : "Restore Keypair into Browser Session"}</span>
                  </button>
                </form>
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 bg-slate-50 border-t border-slate-200 flex items-center justify-end">
          <button
            onClick={onClose}
            className="px-4 py-2 text-xs font-medium text-slate-700 bg-white hover:bg-slate-100 border border-slate-300 rounded-lg cursor-pointer transition-colors"
          >
            Done
          </button>
        </div>
      </div>
    </div>
  );
};

export default KeyManagementModal;
