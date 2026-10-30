import React, { useState, useEffect, useRef, ChangeEvent, DragEvent } from "react";
import {
  generateRsaKeyPair,
  encryptHybrid,
  decryptHybrid,
  EncryptedPackage,
  DecryptedPackage,
  computeKeyFingerprint,
} from "../utils/cryptoEngine";
import {
  ShieldCheck,
  Shield,
  AlertTriangle,
  KeyRound,
  Send,
  Lock,
  Unlock,
  Download,
  Copy,
  Check,
  ChevronDown,
  ChevronUp,
  FileText,
  Eye,
  EyeOff,
  RefreshCw,
  Upload,
  CheckCircle2,
  CloudUpload,
  CloudDownload,
  Server,
  Info,
  X,
  FileCheck,
  ArrowRight,
  Mail,
  ExternalLink,
} from "lucide-react";
import {
  uploadVaultPackage,
  downloadVaultPackage,
  lookupRecipientPublicKey,
  BackendHealthResponse,
  UploadPackageResponse,
  PublicKeyDirectoryRecord,
} from "../utils/apiClient";
import {
  evaluateKeyTrust,
  saveVerifiedRecipient,
  getVerifiedRecipient,
  KeyTrustEvaluation,
  VerifiedRecipientRecord,
} from "../utils/recipientTrust";

// ============================================================================
// Session Storage Constants & Helpers
// ============================================================================

const SESSION_PUBKEY_KEY = "vaultzero_pubkey_pem";
const SESSION_PRIVKEY_KEY = "vaultzero_privkey_pem";

function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return "0 Bytes";
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ["Bytes", "KB", "MB", "GB"];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return `${parseFloat((bytes / Math.pow(k, i)).toFixed(dm))} ${sizes[i]}`;
}

function triggerDownload(
  buffer: ArrayBuffer,
  filename: string,
  mimeType: string = "application/octet-stream"
) {
  const blob = new Blob([buffer], { type: mimeType });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  document.body.removeChild(anchor);
  URL.revokeObjectURL(url);
}

// ============================================================================
// Props
// ============================================================================

interface VaultTabProps {
  initialMode?: "send" | "unlock";
  publicKeyPem?: string;
  privateKeyPem?: string;
  accessToken: string;
  onOpenKeyManagement?: () => void;
  backendHealth?: {
    isAvailable: boolean;
    data?: BackendHealthResponse;
    checked: boolean;
  };
}

export const VaultTab: React.FC<VaultTabProps> = ({
  initialMode = "send",
  publicKeyPem: propPubKey,
  privateKeyPem: propPrivKey,
  accessToken,
  onOpenKeyManagement,
  backendHealth: propBackendHealth,
}) => {
  // Navigation & Mode States
  const [activeMode, setActiveMode] = useState<"send" | "unlock">(initialMode);
  const [isAuditMode, setIsAuditMode] = useState<boolean>(false);
  const [showAdvancedConfig, setShowAdvancedConfig] = useState<boolean>(false);

  // Security Keys State
  const [publicKeyPem, setPublicKeyPem] = useState<string>(propPubKey || "");
  const [privateKeyPem, setPrivateKeyPem] = useState<string>(propPrivKey || "");
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Sender (Encrypt) State
  const [senderFile, setSenderFile] = useState<File | null>(null);
  const [isDraggingSenderFile, setIsDraggingSenderFile] = useState<boolean>(false);
  const [recipientPubKeyInput, setRecipientPubKeyInput] = useState<string>("");
  const [recipientFingerprint, setRecipientFingerprint] = useState<string>("");
  const [recipientIdentifier, setRecipientIdentifier] = useState<string>("");
  const [recipientSource, setRecipientSource] = useState<"directory" | "raw">("directory");
  const [directorySearchTerm, setDirectorySearchTerm] = useState<string>("");
  const [isSearchingDirectory, setIsSearchingDirectory] = useState<boolean>(false);
  const [directoryRecord, setDirectoryRecord] = useState<PublicKeyDirectoryRecord | null>(null);
  const [directorySearchError, setDirectorySearchError] = useState<string | null>(null);
  const [keyTrust, setKeyTrust] = useState<KeyTrustEvaluation>({ status: "unverified" });
  const [showVerifyModal, setShowVerifyModal] = useState<boolean>(false);
  const [verifyChannel, setVerifyChannel] = useState<string>("Signal Voice/Video Call");
  const [verifyNotes, setVerifyNotes] = useState<string>("");
  const [confirmFingerprintMatch, setConfirmFingerprintMatch] = useState<boolean>(false);
  const [isEncrypting, setIsEncrypting] = useState<boolean>(false);
  const [encryptError, setEncryptError] = useState<string | null>(null);
  const [encryptResult, setEncryptResult] = useState<{
    packageBuffer: ArrayBuffer;
    sha256Hex: string;
    rawAesKeyHex: string;
    fileName: string;
    fileType: string;
    vaultFileName: string;
    originalSize: number;
    packageSize: number;
  } | null>(null);

  // Recipient (Unlock) State
  const [vaultFile, setVaultFile] = useState<File | null>(null);
  const [vaultBuffer, setVaultBuffer] = useState<ArrayBuffer | null>(null);
  const [isDraggingVaultFile, setIsDraggingVaultFile] = useState<boolean>(false);
  const [recipientPrivKeyInput, setRecipientPrivKeyInput] = useState<string>("");
  const [isDecrypting, setIsDecrypting] = useState<boolean>(false);
  const [decryptStatus, setDecryptStatus] = useState<"idle" | "success" | "error">("idle");
  const [decryptError, setDecryptError] = useState<string | null>(null);
  const [decryptedResult, setDecryptedResult] = useState<DecryptedPackage | null>(null);

  // File Input Refs
  const senderFileInputRef = useRef<HTMLInputElement>(null);
  const vaultFileInputRef = useRef<HTMLInputElement>(null);

  // Backend Relay State
  const [isUploadingToBackend, setIsUploadingToBackend] = useState<boolean>(false);
  const [uploadBackendResult, setUploadBackendResult] = useState<UploadPackageResponse | null>(null);
  const [uploadBackendError, setUploadBackendError] = useState<string | null>(null);

  const [backendFetchId, setBackendFetchId] = useState<string>("");
  const [isFetchingFromBackend, setIsFetchingFromBackend] = useState<boolean>(false);
  const [fetchBackendError, setFetchBackendError] = useState<string | null>(null);
  const [fetchBackendSuccess, setFetchBackendSuccess] = useState<string | null>(null);

  // Sync mode if initialMode prop changes
  useEffect(() => {
    setActiveMode(initialMode);
  }, [initialMode]);

  // Sync prop keys
  useEffect(() => {
    if (propPubKey) {
      setPublicKeyPem(propPubKey);
      if (!recipientPubKeyInput) setRecipientPubKeyInput(propPubKey);
    }
    if (propPrivKey) {
      setPrivateKeyPem(propPrivKey);
      if (!recipientPrivKeyInput) setRecipientPrivKeyInput(propPrivKey);
    }
  }, [propPubKey, propPrivKey]);

  // Compute recipient public key fingerprint and evaluate trust
  useEffect(() => {
    if (recipientPubKeyInput.trim()) {
      computeKeyFingerprint(recipientPubKeyInput).then((fp) => {
        setRecipientFingerprint(fp);
        const id = recipientIdentifier.trim() || directoryRecord?.owner_email || "";
        if (id && fp && fp !== "Invalid Key") {
          setKeyTrust(evaluateKeyTrust(directoryRecord?.owner_vault_id || "", directoryRecord?.key_id || "", fp));
        } else {
          setKeyTrust({ status: "unverified" });
        }
      });
    } else {
      setRecipientFingerprint("");
      setKeyTrust({ status: "unverified" });
    }
  }, [recipientPubKeyInput, recipientIdentifier, directoryRecord]);

  // Handle Cloud Directory Recipient Lookup
  const handleDirectoryLookup = async (e?: React.FormEvent) => {
    if (e) e.preventDefault();
    const term = directorySearchTerm.trim();
    if (!term) return;

    setIsSearchingDirectory(true);
    setDirectorySearchError(null);
    try {
      const record = await lookupRecipientPublicKey(accessToken, term);
      if (!record) {
        setDirectorySearchError(`No active public key found in directory for "${term}".`);
        setDirectoryRecord(null);
      } else {
        setDirectoryRecord(record);
        setRecipientPubKeyInput(record.public_key_pem);
        setRecipientIdentifier(record.owner_email);
        setRecipientFingerprint(record.fingerprint);
        setKeyTrust(evaluateKeyTrust(record.owner_vault_id, record.key_id, record.fingerprint));
      }
    } catch (err: unknown) {
      setDirectorySearchError(err instanceof Error ? err.message : "Directory lookup failed.");
      setDirectoryRecord(null);
    } finally {
      setIsSearchingDirectory(false);
    }
  };

  // Record Out-of-Band Key Verification
  const handleSaveVerification = () => {
    const id = directoryRecord?.owner_vault_id;
    const displayId = recipientIdentifier.trim() || directoryRecord?.owner_email || "";
    if (!id || !directoryRecord?.key_id || directoryRecord.public_key_pem.trim() !== recipientPubKeyInput.trim() || !recipientFingerprint || recipientFingerprint === "Invalid Key") return;

    const record: VerifiedRecipientRecord = {
      recipientIdentifier: displayId,
      recipientId: id,
      keyId: directoryRecord.key_id,
      verifiedFingerprint: recipientFingerprint,
      verifiedAt: new Date().toISOString(),
      verificationChannel: verifyChannel,
      notes: verifyNotes.trim() || undefined,
    };

    saveVerifiedRecipient(record);
    setKeyTrust({
      status: "verified_match",
      record,
    });
    setShowVerifyModal(false);
    setConfirmFingerprintMatch(false);
    setVerifyNotes("");
  };

  // Copy to clipboard helper
  const handleCopy = async (text: string, fieldId: string) => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedField(fieldId);
      setTimeout(() => setCopiedField(null), 2000);
    } catch (err) {
      console.error("Clipboard copy failed:", err);
    }
  };

  // Drag and Drop handlers for Sender
  const handleSenderDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingSenderFile(true);
  };

  const handleSenderDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingSenderFile(false);
  };

  const handleSenderDrop = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingSenderFile(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      if (file.size > 50 * 1024 * 1024) {
        setEncryptError("File exceeds the maximum size limit of 50 MB.");
        return;
      }
      setSenderFile(file);
      setEncryptError(null);
      setEncryptResult(null);
      setUploadBackendResult(null);
      setUploadBackendError(null);
    }
  };

  const handleSenderFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      if (file.size > 50 * 1024 * 1024) {
        setEncryptError("File exceeds the maximum size limit of 50 MB.");
        return;
      }
      setSenderFile(file);
      setEncryptError(null);
      setEncryptResult(null);
      setUploadBackendResult(null);
      setUploadBackendError(null);
    }
  };

  // Encrypt & Package File
  const handleEncrypt = async () => {
    if (!senderFile) {
      setEncryptError("Please select a file to protect.");
      return;
    }
    if (!recipientPubKeyInput.trim()) {
      setEncryptError("Recipient's Public Key is required.");
      return;
    }

    setIsEncrypting(true);
    setEncryptError(null);
    setUploadBackendResult(null);
    setUploadBackendError(null);

    try {
      const fileBuffer = await senderFile.arrayBuffer();
      const encrypted: EncryptedPackage = await encryptHybrid(
        fileBuffer,
        senderFile.name,
        senderFile.type || "application/octet-stream",
        recipientPubKeyInput
      );

      const vaultFileName = `${senderFile.name}.vault`;
      setEncryptResult({
        packageBuffer: encrypted.packageBuffer,
        sha256Hex: encrypted.sha256Hex,
        rawAesKeyHex: encrypted.rawAesKeyHex,
        fileName: senderFile.name,
        fileType: senderFile.type || "application/octet-stream",
        vaultFileName,
        originalSize: fileBuffer.byteLength,
        packageSize: encrypted.packageBuffer.byteLength,
      });

      // Also set into recipient view for smooth local testing
      setVaultBuffer(encrypted.packageBuffer);
      setVaultFile(new File([encrypted.packageBuffer], vaultFileName));
      setDecryptStatus("idle");
      setDecryptError(null);
      setDecryptedResult(null);
    } catch (err) {
      console.error("Encryption failed:", err);
      setEncryptError(err instanceof Error ? err.message : "Encryption failed.");
    } finally {
      setIsEncrypting(false);
    }
  };

  // Upload encrypted package to FastAPI relay
  const handleUploadToBackend = async () => {
    if (!encryptResult) return;
    setIsUploadingToBackend(true);
    setUploadBackendError(null);
    setUploadBackendResult(null);

    try {
      const res = await uploadVaultPackage(
        accessToken,
        encryptResult.packageBuffer,
        encryptResult.vaultFileName
      );
      setUploadBackendResult(res);
    } catch (err: unknown) {
      console.error("Backend upload error:", err);
      setUploadBackendError(
        err instanceof Error ? err.message : "Failed to upload package to backend relay."
      );
    } finally {
      setIsUploadingToBackend(false);
    }
  };

  // Drag and Drop handlers for Vault Package (Unlock)
  const handleVaultDragOver = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingVaultFile(true);
  };

  const handleVaultDragLeave = (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingVaultFile(false);
  };

  const handleVaultDrop = async (e: DragEvent<HTMLDivElement>) => {
    e.preventDefault();
    setIsDraggingVaultFile(false);
    const file = e.dataTransfer.files?.[0];
    if (file) {
      setVaultFile(file);
      try {
        const buffer = await file.arrayBuffer();
        if (buffer.byteLength < 288) {
          setDecryptStatus("error");
          setDecryptError("Invalid package: File size is smaller than the minimum 288-byte .vault header.");
          return;
        }
        setVaultBuffer(buffer);
        setDecryptStatus("idle");
        setDecryptError(null);
        setDecryptedResult(null);
      } catch (err) {
        setDecryptError("Failed to read package file buffer.");
      }
    }
  };

  const handleVaultFileChange = async (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setVaultFile(file);
      try {
        const buffer = await file.arrayBuffer();
        if (buffer.byteLength < 288) {
          setDecryptStatus("error");
          setDecryptError("Invalid package: File size is smaller than the minimum 288-byte .vault header.");
          return;
        }
        setVaultBuffer(buffer);
        setDecryptStatus("idle");
        setDecryptError(null);
        setDecryptedResult(null);
      } catch (err) {
        setDecryptError("Failed to read package file buffer.");
      }
    }
  };

  // Fetch package from FastAPI relay by File ID
  const handleFetchFromBackend = async () => {
    if (!backendFetchId.trim()) {
      setFetchBackendError("Please enter a valid File ID.");
      return;
    }
    setIsFetchingFromBackend(true);
    setFetchBackendError(null);
    setFetchBackendSuccess(null);
    setDecryptStatus("idle");
    setDecryptError(null);
    setDecryptedResult(null);

    try {
      const res = await downloadVaultPackage(accessToken, backendFetchId.trim());
      setVaultBuffer(res.packageBuffer);
      setVaultFile(new File([res.packageBuffer], res.filename));
      setFetchBackendSuccess(
        `Retrieved "${res.filename}" (${formatBytes(res.sizeBytes)}). Ready to unlock.`
      );
    } catch (err: unknown) {
      console.error("Backend fetch error:", err);
      setFetchBackendError(
        err instanceof Error
          ? err.message
          : "Failed to retrieve package from backend relay."
      );
    } finally {
      setIsFetchingFromBackend(false);
    }
  };

  // Decrypt & Unlock Package
  const handleDecrypt = async () => {
    if (!vaultBuffer) {
      setDecryptStatus("error");
      setDecryptError("Please import a .vault package to unlock.");
      return;
    }
    if (!recipientPrivKeyInput.trim()) {
      setDecryptStatus("error");
      setDecryptError("Your Secret Master Key (RSA Private Key) is required to unlock this file.");
      return;
    }

    setIsDecrypting(true);
    setDecryptStatus("idle");
    setDecryptError(null);
    setDecryptedResult(null);

    try {
      const decrypted = await decryptHybrid(vaultBuffer, recipientPrivKeyInput);
      setDecryptedResult(decrypted);
      setDecryptStatus("success");
    } catch (err) {
      console.error("Decryption failed:", err);
      setDecryptStatus("error");
      setDecryptError(
        err instanceof Error ? err.message : "Decryption failed: Key mismatch or tampered data."
      );
    } finally {
      setIsDecrypting(false);
    }
  };

  const isUsingSelfKey =
    publicKeyPem && recipientPubKeyInput.trim() === publicKeyPem.trim();

  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6 space-y-8 font-sans text-slate-800">
      {/* Navigation Shell: Segmented Switch & Inspection Mode */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-5">
        {/* Segmented Switch: Send vs Unlock */}
        <div className="inline-flex p-1 rounded-xl bg-slate-100 border border-slate-200 text-xs sm:text-sm font-medium">
          <button
            onClick={() => setActiveMode("send")}
            className={`px-4 py-2 rounded-lg transition-all duration-150 cursor-pointer flex items-center space-x-2 ${
              activeMode === "send"
                ? "bg-white text-blue-700 font-semibold shadow-xs"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Send className="w-4 h-4 text-blue-600" />
            <span>Protect a File</span>
          </button>
          <button
            onClick={() => setActiveMode("unlock")}
            className={`px-4 py-2 rounded-lg transition-all duration-150 cursor-pointer flex items-center space-x-2 ${
              activeMode === "unlock"
                ? "bg-white text-blue-700 font-semibold shadow-xs"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Unlock className="w-4 h-4 text-blue-600" />
            <span>Unlock a Received File</span>
          </button>
        </div>

        {/* Audit Mode Switch & Key Shortcut */}
        <div className="flex items-center space-x-4">
          <div className="flex items-center space-x-2 text-xs">
            <span className="text-slate-500 font-medium">View:</span>
            <button
              onClick={() => setIsAuditMode(!isAuditMode)}
              className="flex items-center space-x-2 cursor-pointer focus:outline-none"
              title="Toggle between simplified user interface and technical cryptographic audit view"
            >
              <span className={!isAuditMode ? "font-semibold text-blue-700" : "text-slate-500"}>
                Simple
              </span>
              <div
                className={`w-8 h-4 rounded-full p-0.5 transition-colors duration-150 ${
                  isAuditMode ? "bg-blue-600" : "bg-slate-300"
                }`}
              >
                <div
                  className={`w-3 h-3 rounded-full bg-white transition-transform duration-150 ${
                    isAuditMode ? "translate-x-4" : "translate-x-0"
                  }`}
                />
              </div>
              <span className={isAuditMode ? "font-semibold text-blue-700" : "text-slate-500"}>
                Audit
              </span>
            </button>
          </div>

          {onOpenKeyManagement && (
            <button
              onClick={onOpenKeyManagement}
              className="hidden sm:inline-flex items-center space-x-1 text-xs text-blue-600 hover:text-blue-700 font-medium cursor-pointer"
            >
              <KeyRound className="w-3.5 h-3.5" />
              <span>Identity Keys</span>
            </button>
          )}
        </div>
      </div>

      {/* ==================================================================== */}
      {/* WORKFLOW 1: PROTECT A FILE (SEND)                                    */}
      {/* ==================================================================== */}
      {activeMode === "send" && (
        <div className="space-y-6">
          {/* Section Header */}
          <div className="space-y-1">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
              Protect a File
            </h1>
            <p className="text-xs sm:text-sm text-slate-500">
              Encrypt your file locally before sharing it with the intended recipient.
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 shadow-sm space-y-8">
            {/* Step 1: Select a Document */}
            <div className="space-y-3">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center space-x-2">
                  <span className="w-5 h-5 rounded-md bg-blue-50 text-blue-700 flex items-center justify-center font-mono text-[11px]">
                    1
                  </span>
                  <span>Select a File</span>
                </label>
                <span className="text-[11px] text-slate-400">
                  Max file size: 50 MB
                </span>
              </div>

              {/* Upload Dropzone */}
              <div
                onDragOver={handleSenderDragOver}
                onDragLeave={handleSenderDragLeave}
                onDrop={handleSenderDrop}
                onClick={() => senderFileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${
                  isDraggingSenderFile
                    ? "border-blue-500 bg-blue-50/40"
                    : "border-slate-200 hover:border-blue-400 bg-slate-50/50 hover:bg-blue-50/20"
                }`}
              >
                <input
                  ref={senderFileInputRef}
                  type="file"
                  id="sender-file-input"
                  onChange={handleSenderFileChange}
                  className="hidden"
                />

                <div className="flex flex-col items-center justify-center space-y-2">
                  <div className="w-10 h-10 rounded-lg bg-white shadow-xs border border-slate-200 text-slate-500 flex items-center justify-center">
                    <FileText className="w-5 h-5 text-blue-600" />
                  </div>
                  {senderFile ? (
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-slate-900 truncate max-w-md">
                        {senderFile.name}
                      </p>
                      <p className="text-xs text-slate-500">
                        {formatBytes(senderFile.size)} · {senderFile.type || "Binary document"}
                      </p>
                      <button
                        type="button"
                        onClick={(e) => {
                          e.stopPropagation();
                          setSenderFile(null);
                          setEncryptResult(null);
                        }}
                        className="text-xs text-rose-600 hover:text-rose-700 font-medium pt-1"
                      >
                        Remove file
                      </button>
                    </div>
                  ) : (
                    <div>
                      <p className="text-xs sm:text-sm font-medium text-slate-700">
                        Drag and drop your file here, or{" "}
                        <span className="text-blue-600 font-semibold underline">browse files</span>
                      </p>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Any document, image, archive, or binary up to 50MB
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Step 2: Choose Recipient */}
            <div className="space-y-4 pt-4 border-t border-slate-100">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center space-x-2">
                  <span className="w-5 h-5 rounded-md bg-blue-50 text-blue-700 flex items-center justify-center font-mono text-[11px]">
                    2
                  </span>
                  <span>Choose the Recipient</span>
                </label>

                {/* Sub-selector: Directory vs Raw Key */}
                <div className="flex items-center space-x-3 text-xs">
                  <div className="inline-flex rounded-lg bg-slate-100 p-0.5 border border-slate-200">
                    <button
                      type="button"
                      onClick={() => setRecipientSource("directory")}
                      className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                        recipientSource === "directory"
                          ? "bg-white text-blue-700 font-semibold shadow-xs"
                          : "text-slate-600 hover:text-slate-900"
                      }`}
                    >
                      Search Directory
                    </button>
                    <button
                      type="button"
                      onClick={() => setRecipientSource("raw")}
                      className={`px-2.5 py-1 rounded-md transition-colors cursor-pointer ${
                        recipientSource === "raw"
                          ? "bg-white text-blue-700 font-semibold shadow-xs"
                          : "text-slate-600 hover:text-slate-900"
                      }`}
                    >
                      Paste Raw PEM
                    </button>
                  </div>

                  {publicKeyPem && (
                    <button
                      type="button"
                      onClick={() => {
                        setRecipientPubKeyInput(publicKeyPem);
                        setRecipientIdentifier("Self");
                        setRecipientSource("raw");
                      }}
                      className="text-xs text-blue-600 hover:text-blue-700 font-medium cursor-pointer"
                    >
                      Use My Key
                    </button>
                  )}
                </div>
              </div>

              {/* Mode A: Public Key Directory Lookup */}
              {recipientSource === "directory" ? (
                <div className="space-y-3 bg-slate-50 p-4 rounded-xl border border-slate-200">
                  <form onSubmit={handleDirectoryLookup} className="flex gap-2">
                    <input
                      type="text"
                      value={directorySearchTerm}
                      onChange={(e) => setDirectorySearchTerm(e.target.value)}
                      placeholder="Search recipient by email (e.g. alice@example.com) or VaultZero ID..."
                      className="flex-1 text-xs bg-white rounded-lg border border-slate-300 px-3 py-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500"
                    />
                    <button
                      type="submit"
                      disabled={isSearchingDirectory || !directorySearchTerm.trim()}
                      className="px-4 py-2.5 bg-blue-600 hover:bg-blue-700 text-white text-xs font-medium rounded-lg transition disabled:opacity-50 cursor-pointer shrink-0"
                    >
                      {isSearchingDirectory ? "Searching..." : "Lookup Key"}
                    </button>
                  </form>

                  {directorySearchError && (
                    <div className="text-xs text-rose-600 bg-rose-50 p-2.5 rounded-lg border border-rose-200 flex items-center space-x-1.5">
                      <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                      <span>{directorySearchError}</span>
                    </div>
                  )}

                  {directoryRecord && (
                    <div className="bg-white p-3.5 rounded-lg border border-slate-200 space-y-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-slate-900 font-mono text-[11px]">
                          {directoryRecord.owner_email} ({directoryRecord.owner_vault_id})
                        </span>
                        <span className="text-[10px] text-emerald-800 bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200 font-mono">
                          ID: {directoryRecord.key_id}
                        </span>
                      </div>
                      <div className="text-[11px] text-slate-500">
                        Registered: {new Date(directoryRecord.registered_at).toLocaleDateString()} · Status: {directoryRecord.status.toUpperCase()}
                      </div>
                    </div>
                  )}
                </div>
              ) : (
                /* Mode B: Raw PEM Textarea */
                <div className="space-y-2">
                  <input
                    type="text"
                    value={recipientIdentifier}
                    onChange={(e) => setRecipientIdentifier(e.target.value)}
                    placeholder="Recipient identifier (email or name, e.g. bob@company.com)..."
                    className="w-full text-xs rounded-xl bg-white border border-slate-300 p-2.5 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <textarea
                    id="recipient-public-key-input"
                    rows={3}
                    value={recipientPubKeyInput}
                    onChange={(e) => setRecipientPubKeyInput(e.target.value)}
                    placeholder="Paste the recipient's RSA-2048 public key in PEM format (-----BEGIN PUBLIC KEY-----)..."
                    className="w-full rounded-xl bg-white border border-slate-300 p-3 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none select-all"
                  />
                </div>
              )}

              {/* RECIPIENT KEY VERIFICATION STATUS & OUT-OF-BAND PROTOCOL */}
              {recipientFingerprint && recipientFingerprint !== "Invalid Key" ? (
                <div className="space-y-2">
                  {/* Trust Evaluation Banner */}
                  {keyTrust.status === "verified_match" && (
                    <div className="p-3 bg-emerald-50 border border-emerald-200 rounded-xl text-xs text-emerald-900 flex items-start justify-between gap-2">
                      <div className="flex items-start space-x-2">
                        <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-semibold text-emerald-950">
                            Fingerprint Verified Out-of-Band
                          </div>
                          <div className="text-[11px] text-emerald-800 mt-0.5">
                            Verified via {keyTrust.record?.verificationChannel} on{" "}
                            {keyTrust.record?.verifiedAt ? new Date(keyTrust.record.verifiedAt).toLocaleDateString() : "recently"}.
                            Fingerprint: <code className="font-mono text-emerald-950">{recipientFingerprint}</code>
                          </div>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setShowVerifyModal(true)}
                        className="text-[11px] text-emerald-700 hover:text-emerald-900 underline shrink-0 cursor-pointer"
                      >
                        Update
                      </button>
                    </div>
                  )}

                  {keyTrust.status === "key_changed_warning" && (
                    <div className="p-3.5 bg-rose-50 border-2 border-rose-400 rounded-xl text-xs text-rose-900 space-y-2">
                      <div className="flex items-start space-x-2">
                        <AlertTriangle className="w-5 h-5 text-rose-600 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-bold text-rose-950 text-sm">
                            SECURITY ALERT: Recipient Public Key Has Changed!
                          </div>
                          <p className="text-[11px] text-rose-800 mt-1 leading-relaxed">
                            This recipient was previously verified with fingerprint:
                            <code className="block font-mono bg-white/70 p-1 rounded border border-rose-200 my-1 text-slate-800 select-all">
                              {keyTrust.previousFingerprint}
                            </code>
                            The key currently presented in the directory is:
                            <code className="block font-mono bg-white/70 p-1 rounded border border-rose-200 my-1 text-rose-900 font-bold select-all">
                              {recipientFingerprint}
                            </code>
                            A changed key may indicate legitimate key rotation, or an active <strong>Man-in-the-Middle (MITM)</strong> adversary.
                            <strong> Do NOT encrypt confidential files until you confirm this new fingerprint with the recipient out-of-band.</strong>
                          </p>
                        </div>
                      </div>
                      <div className="flex items-center space-x-3 pt-1">
                        <button
                          type="button"
                          onClick={() => setShowVerifyModal(true)}
                          className="px-3 py-1.5 bg-rose-600 hover:bg-rose-700 text-white rounded-lg text-xs font-semibold cursor-pointer"
                        >
                          Verify New Key Out-of-Band
                        </button>
                        <button
                          type="button"
                          onClick={() => {
                            setRecipientPubKeyInput("");
                            setDirectoryRecord(null);
                          }}
                          className="text-xs text-rose-700 hover:text-rose-900 underline cursor-pointer"
                        >
                          Cancel / Reject Key
                        </button>
                      </div>
                    </div>
                  )}

                  {keyTrust.status === "unverified" && (
                    <div className="p-3 bg-blue-50 border border-blue-200 rounded-xl text-xs text-blue-900 flex items-start justify-between gap-3">
                      <div className="flex items-start space-x-2">
                        <Info className="w-4 h-4 text-blue-600 shrink-0 mt-0.5" />
                        <div>
                          <div className="font-semibold text-blue-950">
                            Unverified Public Key (Online Directory)
                          </div>
                          <div className="text-[11px] text-blue-800 mt-0.5 leading-relaxed">
                            A public key from an online directory cannot independently prove authenticity.
                            Fingerprint: <code className="font-mono text-blue-950 font-semibold">{recipientFingerprint}</code>.
                            Verify this fingerprint with the recipient over a trusted separate channel (e.g. Signal, phone, in-person).
                          </div>
                        </div>
                      </div>
                      <button
                        type="button"
                        onClick={() => setShowVerifyModal(true)}
                        className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg text-xs font-medium shrink-0 cursor-pointer transition shadow-xs"
                      >
                        Verify Out-of-Band
                      </button>
                    </div>
                  )}
                </div>
              ) : recipientPubKeyInput.trim() ? (
                <div className="text-xs text-rose-600 bg-rose-50 p-2 rounded-lg border border-rose-200 flex items-center space-x-1.5">
                  <AlertTriangle className="w-3.5 h-3.5 shrink-0" />
                  <span>Invalid public key format (Must be 2048-bit RSA in SubjectPublicKeyInfo PEM format)</span>
                </div>
              ) : null}
            </div>

            {/* Step 3: Encryption Configuration */}
            <div className="space-y-3 pt-4 border-t border-slate-100">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center space-x-2">
                  <span className="w-5 h-5 rounded-md bg-blue-50 text-blue-700 flex items-center justify-center font-mono text-[11px]">
                    3
                  </span>
                  <span>Encryption Configuration</span>
                </label>

                <button
                  type="button"
                  onClick={() => setShowAdvancedConfig(!showAdvancedConfig)}
                  className="text-xs text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
                >
                  <span>{showAdvancedConfig ? "Hide Technical Details" : "Show Technical Details"}</span>
                  {showAdvancedConfig ? <ChevronUp className="w-3.5 h-3.5" /> : <ChevronDown className="w-3.5 h-3.5" />}
                </button>
              </div>

              {/* Compact Security Summary */}
              <div className="grid grid-cols-2 sm:grid-cols-4 gap-2 text-xs">
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Payload Cipher</span>
                  <span className="font-semibold text-slate-900 font-mono text-[11px]">AES-256-GCM</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Key Wrap</span>
                  <span className="font-semibold text-slate-900 font-mono text-[11px]">RSA-OAEP-2048</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Digest & Tag</span>
                  <span className="font-semibold text-slate-900 font-mono text-[11px]">SHA-256 / 128-bit</span>
                </div>
                <div className="p-2.5 bg-slate-50 rounded-lg border border-slate-200">
                  <span className="text-[10px] text-slate-500 block">Execution</span>
                  <span className="font-semibold text-emerald-700 font-mono text-[11px]">Client Hardware</span>
                </div>
              </div>

              {/* Advanced Technical Details */}
              {showAdvancedConfig && (
                <div className="p-3 bg-slate-50 rounded-xl border border-slate-200 space-y-2 text-xs text-slate-600 font-mono animate-in fade-in duration-150">
                  <div className="text-[11px] font-semibold text-slate-800">
                    Binary Envelope Memory Offsets:
                  </div>
                  <ul className="text-[11px] space-y-1 list-disc list-inside text-slate-600">
                    <li>0..255 (256 bytes): RSA-OAEP Encrypted Session Key</li>
                    <li>256..267 (12 bytes): AES-GCM Initialization Vector (IV, fresh per file)</li>
                    <li>268..271 (4 bytes): uint32 big-endian metadata length</li>
                    <li>272..(272+N): UTF-8 JSON metadata (filename, mime, SHA-256)</li>
                    <li>Remaining bytes: AES-256-GCM ciphertext + 16-byte GMAC authentication tag</li>
                  </ul>
                  <p className="text-[10px] text-slate-500 pt-1 font-sans">
                    Zero Nonce Reuse: Every file encryption generates a fresh, cryptographically random
                    32-byte AES key and 96-bit IV via <code>window.crypto.getRandomValues</code>.
                  </p>
                </div>
              )}
            </div>

            {/* Step 4: Protect File Action */}
            <div className="pt-2">
              <button
                id="encrypt-package-btn"
                onClick={handleEncrypt}
                disabled={isEncrypting || !senderFile || !recipientPubKeyInput.trim()}
                className="w-full py-3.5 px-6 rounded-xl font-semibold text-sm text-white bg-blue-600 hover:bg-blue-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center space-x-2 cursor-pointer"
              >
                {isEncrypting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Encrypting & Protecting File...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>Encrypt & Protect File</span>
                  </>
                )}
              </button>

              {encryptError && (
                <div className="mt-3 flex items-start space-x-2 p-3 bg-rose-50 border border-rose-200 rounded-xl text-xs text-rose-800">
                  <AlertTriangle className="w-4 h-4 shrink-0 text-rose-600 mt-0.5" />
                  <span>{encryptError}</span>
                </div>
              )}
            </div>

            {/* Step 5: Export Protected Package (Success Panel) */}
            {encryptResult && (
              <div className="pt-6 border-t border-slate-200 space-y-4 animate-in fade-in duration-200">
                <div className="flex items-center space-x-2.5 text-emerald-900">
                  <div className="w-7 h-7 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0">
                    <CheckCircle2 className="w-4 h-4" />
                  </div>
                  <div>
                    <h3 className="text-sm font-bold text-slate-900">
                      File Successfully Protected
                    </h3>
                    <p className="text-xs text-slate-500">
                      Sealed into an encrypted <code>.vault</code> package. Only the recipient&apos;s private key can open it.
                    </p>
                  </div>
                </div>

                {/* Package Summary Card */}
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2 text-xs">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-2">
                    <div>
                      <span className="text-slate-500 block text-[11px]">Package Name:</span>
                      <span className="font-semibold text-slate-900 font-mono">
                        {encryptResult.vaultFileName}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block text-[11px]">Encrypted Size:</span>
                      <span className="font-semibold text-slate-900">
                        {formatBytes(encryptResult.packageSize)} ({encryptResult.packageSize} bytes)
                      </span>
                    </div>
                  </div>

                  {isAuditMode && (
                    <div className="pt-2 border-t border-slate-200 space-y-1 font-mono text-[11px]">
                      <div className="text-slate-500">Plaintext SHA-256 Digest:</div>
                      <div className="text-slate-800 break-all select-all">{encryptResult.sha256Hex}</div>
                    </div>
                  )}
                </div>

                {/* Export Options: Local Download, Email Transfer, or Zero-Knowledge Relay */}
                <div className="space-y-4">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                    <button
                      id="download-vault-btn"
                      onClick={() =>
                        triggerDownload(
                          encryptResult.packageBuffer,
                          encryptResult.vaultFileName,
                          "application/octet-stream"
                        )
                      }
                      className="py-3 px-4 rounded-xl text-xs font-semibold text-slate-800 bg-white hover:bg-slate-50 border border-slate-300 shadow-xs flex items-center justify-center space-x-2 cursor-pointer transition-colors"
                    >
                      <Download className="w-4 h-4 text-slate-600" />
                      <span>Download .vault Package</span>
                    </button>

                    <button
                      id="relay-backend-btn"
                      onClick={handleUploadToBackend}
                      disabled={isUploadingToBackend}
                      className="py-3 px-4 rounded-xl text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-xs flex items-center justify-center space-x-2 cursor-pointer transition-colors disabled:opacity-50"
                    >
                      {isUploadingToBackend ? (
                        <>
                          <RefreshCw className="w-4 h-4 animate-spin" />
                          <span>Relaying to Server...</span>
                        </>
                      ) : (
                        <>
                          <CloudUpload className="w-4 h-4" />
                          <span>Relay to Server (Zero-Knowledge)</span>
                        </>
                      )}
                    </button>
                  </div>

                  {/* Secure File Transfer via Email Attachment */}
                  <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-3">
                    <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-1">
                      <div className="flex items-center space-x-2">
                        <div className="w-6 h-6 rounded-md bg-blue-100 text-blue-700 flex items-center justify-center">
                          <Mail className="w-3.5 h-3.5" />
                        </div>
                        <div>
                          <h4 className="text-xs font-bold text-slate-900">Send via Email Attachment</h4>
                          <p className="text-[11px] text-slate-500">
                            Transfer the protected .vault file as an attachment in your mail app.
                          </p>
                        </div>
                      </div>
                      <span className="text-[10px] font-semibold text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded self-start sm:self-auto">
                        AES-256-GCM Authenticated
                      </span>
                    </div>

                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-2.5">
                      <button
                        type="button"
                        onClick={() =>
                          triggerDownload(
                            encryptResult.packageBuffer,
                            encryptResult.vaultFileName,
                            "application/octet-stream"
                          )
                        }
                        className="py-2.5 px-3 rounded-lg text-xs font-semibold text-slate-800 bg-white hover:bg-slate-50 border border-slate-300 shadow-xs flex items-center justify-center space-x-2 cursor-pointer transition-colors"
                      >
                        <Download className="w-3.5 h-3.5 text-blue-600" />
                        <span>1. Download {encryptResult.vaultFileName}</span>
                      </button>

                      <a
                        href={`mailto:${
                          (recipientIdentifier.includes("@") ? recipientIdentifier : directoryRecord?.owner_email) || ""
                        }?subject=${encodeURIComponent(
                          `Secure File: ${encryptResult.fileName} (VaultZero Protected)`
                        )}&body=${encodeURIComponent(
                          `Hello,\n\nI have prepared a secure, client-side encrypted file for you using VaultZero:\n\n` +
                            `File: ${encryptResult.fileName}\n` +
                            `Size: ${formatBytes(encryptResult.originalSize)}\n` +
                            `Encryption: AES-256-GCM authenticated payload + RSA-2048-OAEP session key\n\n` +
                            `[ATTACHMENT REQUIRED]\n` +
                            `The encrypted package "${encryptResult.vaultFileName}" is attached to this email message.\n\n` +
                            `HOW TO UNLOCK & VERIFY:\n` +
                            `1. Download the attached "${encryptResult.vaultFileName}" file to your device.\n` +
                            `2. Open VaultZero and navigate to "Unlock a Protected File".\n` +
                            `3. Drop the file and provide your matching RSA-2048 private key to decrypt locally.\n\n` +
                            `Tamper Detection: Authenticated by a 128-bit GMAC tag. Any transit tampering or modification will trigger immediate cryptographic rejection.`
                        )}`}
                        className="py-2.5 px-3 rounded-lg text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 shadow-xs flex items-center justify-center space-x-1.5 cursor-pointer transition-colors text-center"
                      >
                        <Mail className="w-3.5 h-3.5" />
                        <span>2. Compose Email in Mail App</span>
                        <ExternalLink className="w-3 h-3 text-blue-200" />
                      </a>
                    </div>

                    {/* Email Transport & Metadata Disclosure */}
                    <div className="p-3 bg-white border border-slate-200 rounded-lg text-[11px] text-slate-600 space-y-1.5 leading-relaxed">
                      <div className="font-semibold text-slate-800 flex items-center space-x-1.5">
                        <Info className="w-3.5 h-3.5 text-blue-600 shrink-0" />
                        <span>Email Transport Metadata Disclosure & Sandbox Notice:</span>
                      </div>
                      <p>
                        <strong>Browser Sandbox Constraint:</strong> Browsers cannot automatically attach local files to email drafts for OS security reasons. Please click <em>1. Download</em> first, then attach the downloaded <code>{encryptResult.vaultFileName}</code> file inside your email client.
                      </p>
                      <p>
                        <strong>Transport Metadata Visibility:</strong> Email providers and relays (Gmail, Outlook, Proton, etc.) can inspect transport headers (sender, recipient, subject, timestamp, and .vault file size). However, they have <strong>zero access</strong> to unencrypted file contents, which are mathematically sealed under the recipient&apos;s RSA-2048 public key.
                      </p>
                    </div>
                  </div>

                  {/* Relay Success Banner with File ID */}
                  {uploadBackendResult && (
                    <div className="p-4 bg-blue-50 border border-blue-200 rounded-xl space-y-2 text-xs">
                      <div className="flex items-center justify-between">
                        <span className="font-semibold text-blue-900 flex items-center space-x-1.5">
                          <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                          <span>Package Relayed Successfully</span>
                        </span>
                        <span className="text-[10px] text-blue-700 font-mono">
                          Zero-Plaintext Stored
                        </span>
                      </div>

                      <div className="space-y-1">
                        <span className="text-[11px] text-slate-600">Share this File ID with the recipient:</span>
                        <div className="flex items-center space-x-2">
                          <input
                            type="text"
                            readOnly
                            value={uploadBackendResult.file_id}
                            className="flex-1 bg-white border border-slate-300 rounded-lg px-2.5 py-1.5 font-mono text-blue-900 text-xs select-all focus:outline-none"
                          />
                          <button
                            onClick={() => handleCopy(uploadBackendResult.file_id, "file_id")}
                            className="px-3 py-1.5 bg-blue-600 hover:bg-blue-700 text-white rounded-lg font-medium text-xs flex items-center space-x-1 cursor-pointer"
                          >
                            {copiedField === "file_id" ? <Check className="w-3.5 h-3.5" /> : <Copy className="w-3.5 h-3.5" />}
                            <span>{copiedField === "file_id" ? "Copied" : "Copy ID"}</span>
                          </button>
                        </div>
                      </div>
                    </div>
                  )}

                  {uploadBackendError && (
                    <div className="p-3 bg-amber-50 border border-amber-200 rounded-xl text-xs text-amber-900 space-y-1">
                      <div className="font-semibold flex items-center space-x-1">
                        <AlertTriangle className="w-3.5 h-3.5 text-amber-600" />
                        <span>Relay Notice</span>
                      </div>
                      <p>{uploadBackendError}</p>
                      <p className="text-[11px] text-slate-500">
                        You can still share the package manually using the &quot;Download .vault Package&quot; button.
                      </p>
                    </div>
                  )}
                </div>
              </div>
            )}
          </div>
        </div>
      )}

      {/* ==================================================================== */}
      {/* WORKFLOW 2: UNLOCK A PROTECTED FILE (RECEIVE)                         */}
      {/* ==================================================================== */}
      {activeMode === "unlock" && (
        <div className="space-y-6">
          {/* Section Header */}
          <div className="space-y-1">
            <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
              Unlock a Protected File
            </h1>
            <p className="text-xs sm:text-sm text-slate-500">
              Decrypt a received VaultZero package using the corresponding private key.
            </p>
          </div>

          <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 shadow-sm space-y-8">
            {/* Email Attachment Helper for Recipients */}
            <div className="p-3.5 bg-blue-50/70 border border-blue-200 rounded-xl text-xs flex items-start space-x-3 text-blue-900">
              <div className="w-7 h-7 rounded-lg bg-blue-100 text-blue-700 flex items-center justify-center shrink-0 mt-0.5">
                <Mail className="w-4 h-4" />
              </div>
              <div className="space-y-0.5">
                <span className="font-semibold text-blue-950">Received a .vault File via Email?</span>
                <p className="text-[11px] text-blue-800 leading-relaxed">
                  Save the <code>.vault</code> file attachment from your email client to your computer. Then drop it into <strong>Option B (Local File Dropzone)</strong> below. Decryption and 128-bit GMAC authentication run strictly inside your browser without uploading your private key.
                </p>
              </div>
            </div>

            {/* Step 1: Import Package */}
            <div className="space-y-3">
              <label className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center space-x-2">
                <span className="w-5 h-5 rounded-md bg-blue-50 text-blue-700 flex items-center justify-center font-mono text-[11px]">
                  1
                </span>
                <span>Import .vault Package</span>
              </label>

              {/* Sub-option A: Fetch by File ID */}
              <div className="p-4 bg-slate-50 border border-slate-200 rounded-xl space-y-2">
                <div className="flex items-center justify-between text-xs">
                  <span className="font-semibold text-slate-800 flex items-center space-x-1.5">
                    <CloudDownload className="w-4 h-4 text-blue-600" />
                    <span>Option A: Fetch from Server Relay by File ID</span>
                  </span>
                  <span className="text-[11px] text-slate-500">FastAPI Relay</span>
                </div>

                <div className="flex flex-col sm:flex-row gap-2">
                  <input
                    type="text"
                    value={backendFetchId}
                    onChange={(e) => {
                      setBackendFetchId(e.target.value);
                      setFetchBackendError(null);
                    }}
                    onKeyDown={(e) => {
                      if (e.key === "Enter") {
                        e.preventDefault();
                        handleFetchFromBackend();
                      }
                    }}
                    placeholder="Enter File ID (e.g. vX9_kL82mqZw1pRtA4bcDg)..."
                    className="flex-1 bg-white border border-slate-300 rounded-xl px-3 py-2 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500"
                  />
                  <button
                    onClick={handleFetchFromBackend}
                    disabled={isFetchingFromBackend || !backendFetchId.trim()}
                    className="px-4 py-2 bg-blue-600 hover:bg-blue-700 text-white rounded-xl text-xs font-medium transition shadow-xs disabled:opacity-40 flex items-center justify-center space-x-1.5 cursor-pointer shrink-0"
                  >
                    {isFetchingFromBackend ? (
                      <>
                        <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                        <span>Fetching...</span>
                      </>
                    ) : (
                      <>
                        <CloudDownload className="w-3.5 h-3.5" />
                        <span>Fetch Package</span>
                      </>
                    )}
                  </button>
                </div>

                {fetchBackendSuccess && (
                  <div className="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-lg p-2.5 flex items-center space-x-1.5">
                    <CheckCircle2 className="w-4 h-4 text-emerald-600 shrink-0" />
                    <span>{fetchBackendSuccess}</span>
                  </div>
                )}

                {fetchBackendError && (
                  <div className="text-xs text-rose-800 bg-rose-50 border border-rose-200 rounded-lg p-2.5 flex items-start space-x-1.5">
                    <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0 mt-0.5" />
                    <span>{fetchBackendError}</span>
                  </div>
                )}
              </div>

              {/* Divider */}
              <div className="relative flex py-1 items-center">
                <div className="flex-grow border-t border-slate-200"></div>
                <span className="flex-shrink mx-4 text-[11px] font-semibold text-slate-400 uppercase tracking-wider bg-white px-2">
                  OR
                </span>
                <div className="flex-grow border-t border-slate-200"></div>
              </div>

              {/* Sub-option B: Local File Dropzone */}
              <div
                onDragOver={handleVaultDragOver}
                onDragLeave={handleVaultDragLeave}
                onDrop={handleVaultDrop}
                onClick={() => vaultFileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-colors ${
                  isDraggingVaultFile
                    ? "border-blue-500 bg-blue-50/40"
                    : "border-slate-200 hover:border-blue-400 bg-slate-50/50 hover:bg-blue-50/20"
                }`}
              >
                <input
                  ref={vaultFileInputRef}
                  type="file"
                  id="vault-file-input"
                  accept=".vault,application/octet-stream"
                  onChange={handleVaultFileChange}
                  className="hidden"
                />

                <div className="flex flex-col items-center justify-center space-y-2">
                  <div className="w-10 h-10 rounded-lg bg-white shadow-xs border border-slate-200 text-slate-500 flex items-center justify-center">
                    <Upload className="w-5 h-5 text-blue-600" />
                  </div>
                  {vaultFile ? (
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-slate-900 truncate max-w-md">
                        {vaultFile.name}
                      </p>
                      <p className="text-xs text-slate-500">
                        {formatBytes(vaultFile.size)} · Protected Vault Package
                      </p>
                      <span className="inline-block text-[11px] text-blue-600 font-medium pt-1">
                        Click or drop another .vault package to replace
                      </span>
                    </div>
                  ) : (
                    <div>
                      <p className="text-xs sm:text-sm font-medium text-slate-700">
                        Drop your <span className="text-blue-600 font-semibold">.vault</span> package here, or browse files
                      </p>
                      <p className="text-[11px] text-slate-400 mt-1">
                        Encrypted hybrid package containing wrapped key and ciphertext
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Step 2: Select Private Key */}
            <div className="space-y-3 pt-4 border-t border-slate-100">
              <div className="flex items-center justify-between">
                <label className="text-xs font-bold uppercase tracking-wider text-slate-900 flex items-center space-x-2">
                  <span className="w-5 h-5 rounded-md bg-blue-50 text-blue-700 flex items-center justify-center font-mono text-[11px]">
                    2
                  </span>
                  <span>Select Secret Master Key (Private Key)</span>
                </label>

                {privateKeyPem && (
                  <span className="text-xs text-emerald-700 flex items-center space-x-1 font-medium bg-emerald-50 px-2 py-0.5 rounded border border-emerald-200">
                    <Check className="w-3 h-3" />
                    <span>Loaded from session</span>
                  </span>
                )}
              </div>

              <div className="space-y-1.5">
                <textarea
                  id="recipient-privkey-input"
                  rows={3}
                  value={recipientPrivKeyInput}
                  onChange={(e) => setRecipientPrivKeyInput(e.target.value)}
                  placeholder="Paste your RSA-2048 private key in PEM format (-----BEGIN PRIVATE KEY-----)..."
                  className="w-full rounded-xl bg-white border border-slate-300 p-3 text-xs font-mono text-slate-900 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 focus:border-transparent resize-none select-all"
                />

                <div className="flex items-center space-x-1.5 text-[11px] text-slate-500">
                  <Lock className="w-3.5 h-3.5 text-slate-400 shrink-0" />
                  <span>
                    Confidentiality Guarantee: Private keys never leave this browser tab. Decryption executes entirely client-side.
                  </span>
                </div>
              </div>
            </div>

            {/* Step 3: Verify and Decrypt Action */}
            <div className="pt-2">
              <button
                id="decrypt-package-btn"
                onClick={handleDecrypt}
                disabled={isDecrypting || !vaultBuffer || !recipientPrivKeyInput.trim()}
                className="w-full py-3.5 px-6 rounded-xl font-semibold text-sm text-white bg-blue-600 hover:bg-blue-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center space-x-2 cursor-pointer"
              >
                {isDecrypting ? (
                  <>
                    <RefreshCw className="w-4 h-4 animate-spin" />
                    <span>Unwrapping & Decrypting...</span>
                  </>
                ) : (
                  <>
                    <Unlock className="w-4 h-4" />
                    <span>Verify & Decrypt</span>
                  </>
                )}
              </button>
            </div>

            {/* Step 4: Decryption Success / Recovered File */}
            {decryptStatus === "success" && decryptedResult && (
              <div className="p-5 bg-emerald-50/80 border border-emerald-200 rounded-2xl space-y-4 animate-in fade-in duration-200">
                <div className="flex items-start space-x-3">
                  <div className="w-7 h-7 rounded-lg bg-emerald-100 text-emerald-700 flex items-center justify-center shrink-0 mt-0.5">
                    <ShieldCheck className="w-4 h-4" />
                  </div>
                  <div className="space-y-0.5">
                    <h3 className="text-sm font-bold text-emerald-950">
                      File Verified & Integrity Intact
                    </h3>
                    <p className="text-xs text-emerald-800 leading-relaxed">
                      Authenticated decryption succeeded. The 128-bit GMAC authentication tag
                      and plaintext SHA-256 matched with zero data tampering.
                    </p>
                  </div>
                </div>

                {/* Recovered File Card */}
                <div className="bg-white border border-emerald-200 rounded-xl p-4 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                  <div>
                    <span className="text-slate-500 block text-[11px]">Recovered Filename:</span>
                    <span className="font-semibold text-slate-900 font-mono break-all">
                      {decryptedResult.fileName}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[11px]">Document Size:</span>
                    <span className="font-medium text-slate-800">
                      {formatBytes(decryptedResult.fileBuffer.byteLength)}
                    </span>
                  </div>
                  <div>
                    <span className="text-slate-500 block text-[11px]">MIME Type:</span>
                    <span className="font-medium text-slate-800">
                      {decryptedResult.fileType || "application/octet-stream"}
                    </span>
                  </div>
                  {isAuditMode && (
                    <div>
                      <span className="text-slate-500 block text-[11px]">Unwrapped AES Key:</span>
                      <span className="font-mono text-slate-800 text-[10px] truncate block">
                        {decryptedResult.unwrappedAesKeyHex.slice(0, 16)}...
                      </span>
                    </div>
                  )}
                </div>

                <button
                  id="download-recovered-btn"
                  onClick={() =>
                    triggerDownload(
                      decryptedResult.fileBuffer,
                      decryptedResult.fileName,
                      decryptedResult.fileType || "application/octet-stream"
                    )
                  }
                  className="w-full py-3 px-5 rounded-xl font-semibold text-xs sm:text-sm text-white bg-emerald-600 hover:bg-emerald-700 active:scale-[0.99] transition shadow-xs flex items-center justify-center space-x-2 cursor-pointer"
                >
                  <Download className="w-4 h-4" />
                  <span>Download Decrypted File ({decryptedResult.fileName})</span>
                </button>
              </div>
            )}

            {/* Decryption Failure Banner */}
            {decryptStatus === "error" && (
              <div className="p-4 bg-rose-50 border border-rose-200 rounded-xl space-y-2 text-xs text-rose-900 animate-in fade-in">
                <div className="flex items-center space-x-2 font-semibold text-rose-950">
                  <AlertTriangle className="w-4 h-4 text-rose-600 shrink-0" />
                  <span>Decryption Rejected by Cryptographic Engine</span>
                </div>
                <p className="text-[11px] text-rose-800 leading-relaxed">
                  Either the secret master key does not match the public key used during encryption,
                  or the ciphertext was modified in transit. Authenticated decryption prevents
                  releasing any corrupted or unverified bytes.
                </p>
                {decryptError && (
                  <div className="bg-white border border-rose-200 rounded-lg p-2.5 font-mono text-rose-900 text-[11px] break-all">
                    {decryptError}
                  </div>
                )}
              </div>
            )}
          </div>
        </div>
      )}

      {/* Out-of-Band Key Verification Modal */}
      {showVerifyModal && (
        <div className="fixed inset-0 z-50 overflow-y-auto bg-slate-900/40 backdrop-blur-xs flex items-center justify-center p-4">
          <div className="bg-white border border-slate-200 rounded-2xl max-w-lg w-full p-6 shadow-xl space-y-4 font-sans text-slate-800 animate-in fade-in zoom-in-95 duration-150">
            <div className="flex items-center justify-between border-b border-slate-200 pb-3">
              <div className="flex items-center space-x-2">
                <ShieldCheck className="w-5 h-5 text-blue-600" />
                <h3 className="text-sm font-bold text-slate-900">
                  Out-of-Band Recipient Verification
                </h3>
              </div>
              <button
                type="button"
                onClick={() => setShowVerifyModal(false)}
                className="text-slate-400 hover:text-slate-600 p-1 rounded-lg"
              >
                <X className="w-4 h-4" />
              </button>
            </div>

            <p className="text-xs text-slate-600 leading-relaxed">
              Online directories can be compromised or spoofed. To guarantee that you are sealing files
              for the real recipient (preventing Man-in-the-Middle attacks), directly compare this fingerprint
              with them over a separate, authentic communication channel.
            </p>

            {/* Recipient & Fingerprint Display */}
            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1.5 text-xs">
              <div className="text-slate-500 text-[11px]">Recipient Identifier:</div>
              <div className="font-semibold text-slate-900 font-mono">
                {recipientIdentifier || directoryRecord?.owner_email || "Selected Recipient"}
              </div>
              <div className="text-slate-500 text-[11px] pt-1">SHA-256 Public Key Fingerprint:</div>
              <div className="p-2 bg-white rounded border border-slate-300 font-mono text-xs text-slate-900 font-bold select-all break-all">
                {recipientFingerprint}
              </div>
            </div>

            {/* Verification Channel Picker */}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-700">
                Verification Channel (Documented Record):
              </label>
              <select
                value={verifyChannel}
                onChange={(e) => setVerifyChannel(e.target.value)}
                className="w-full text-xs rounded-lg border border-slate-300 p-2 bg-white focus:outline-none focus:ring-2 focus:ring-blue-500"
              >
                <option value="Signal Voice/Video Call">Signal Voice/Video Call</option>
                <option value="In-Person Direct Comparison">In-Person Direct Comparison</option>
                <option value="Telephone Call">Telephone Call</option>
                <option value="Encrypted Chat (Signal/Matrix)">Encrypted Chat (Signal/Matrix)</option>
                <option value="Cryptographically Signed PGP Message">Cryptographically Signed PGP Message</option>
              </select>
            </div>

            {/* Optional Notes */}
            <div className="space-y-1">
              <label className="block text-xs font-medium text-slate-700">
                Verification Notes (Optional):
              </label>
              <input
                type="text"
                value={verifyNotes}
                onChange={(e) => setVerifyNotes(e.target.value)}
                placeholder="e.g. Confirmed with Alice via Signal call on Oct 29..."
                className="w-full text-xs rounded-lg border border-slate-300 p-2 focus:outline-none focus:ring-2 focus:ring-blue-500"
              />
            </div>

            {/* Mandatory Attestation Checkbox */}
            <label className="flex items-start space-x-2.5 p-3 rounded-xl bg-blue-50 border border-blue-200 text-xs text-blue-950 cursor-pointer">
              <input
                type="checkbox"
                checked={confirmFingerprintMatch}
                onChange={(e) => setConfirmFingerprintMatch(e.target.checked)}
                className="mt-0.5 rounded text-blue-600 focus:ring-blue-500"
              />
              <span className="leading-snug">
                I have verified out-of-band that every character of this SHA-256 fingerprint matches the recipient&apos;s genuine key.
              </span>
            </label>

            {/* Modal Actions */}
            <div className="flex items-center justify-end space-x-2 pt-2 border-t border-slate-200">
              <button
                type="button"
                onClick={() => setShowVerifyModal(false)}
                className="px-3 py-1.5 text-xs text-slate-600 hover:text-slate-800"
              >
                Cancel
              </button>
              <button
                type="button"
                disabled={!confirmFingerprintMatch || !directoryRecord || directoryRecord.public_key_pem.trim() !== recipientPubKeyInput.trim()}
                onClick={handleSaveVerification}
                className="px-4 py-2 bg-emerald-600 hover:bg-emerald-700 disabled:opacity-50 text-white rounded-lg text-xs font-semibold cursor-pointer transition shadow-xs"
              >
                Save Out-of-Band Verification
              </button>
            </div>
          </div>
        </div>
      )}
    </div>
  );
};

export default VaultTab;
