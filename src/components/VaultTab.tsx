import React, { useState, useEffect, useRef, ChangeEvent, DragEvent } from "react";
import {
  generateRsaKeyPair,
  encryptHybrid,
  decryptHybrid,
  EncryptedPackage,
  DecryptedPackage,
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
} from "lucide-react";

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
// Main VaultTab Component (Enterprise Light Theme)
// ============================================================================

export const VaultTab: React.FC = () => {
  // Navigation & Mode States
  const [activeMode, setActiveMode] = useState<"send" | "unlock">("send");
  const [isAuditMode, setIsAuditMode] = useState<boolean>(false);
  const [isKeysDrawerOpen, setIsKeysDrawerOpen] = useState<boolean>(false);
  const [showPrivateKeyText, setShowPrivateKeyText] = useState<boolean>(false);

  // Security Keys State
  const [publicKeyPem, setPublicKeyPem] = useState<string>("");
  const [privateKeyPem, setPrivateKeyPem] = useState<string>("");
  const [isGeneratingKeys, setIsGeneratingKeys] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Sender (Encrypt) State
  const [senderFile, setSenderFile] = useState<File | null>(null);
  const [isDraggingSenderFile, setIsDraggingSenderFile] = useState<boolean>(false);
  const [recipientPubKeyInput, setRecipientPubKeyInput] = useState<string>("");
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

  // Initialize or restore session keys on mount
  useEffect(() => {
    const savedPub = sessionStorage.getItem(SESSION_PUBKEY_KEY);
    const savedPriv = sessionStorage.getItem(SESSION_PRIVKEY_KEY);
    if (savedPub && savedPriv) {
      setPublicKeyPem(savedPub);
      setPrivateKeyPem(savedPriv);
      setRecipientPubKeyInput((prev) => (prev ? prev : savedPub));
      setRecipientPrivKeyInput((prev) => (prev ? prev : savedPriv));
    } else {
      handleGenerateKeys(true);
    }
  }, []);

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

  // Generate / Regenerate RSA-2048 Keypair
  const handleGenerateKeys = async (isInitialAuto: boolean = false) => {
    setIsGeneratingKeys(true);
    try {
      const keys = await generateRsaKeyPair();
      setPublicKeyPem(keys.publicKeyPem);
      setPrivateKeyPem(keys.privateKeyPem);

      sessionStorage.setItem(SESSION_PUBKEY_KEY, keys.publicKeyPem);
      sessionStorage.setItem(SESSION_PRIVKEY_KEY, keys.privateKeyPem);

      setRecipientPubKeyInput(keys.publicKeyPem);
      setRecipientPrivKeyInput(keys.privateKeyPem);
    } catch (err) {
      console.error("Key generation failed:", err);
    } finally {
      setIsGeneratingKeys(false);
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
      setSenderFile(file);
      setEncryptError(null);
      setEncryptResult(null);
    }
  };

  const handleSenderFileChange = (e: ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (file) {
      setSenderFile(file);
      setEncryptError(null);
      setEncryptResult(null);
    }
  };

  // Encrypt & Package File
  const handleEncrypt = async () => {
    if (!senderFile) {
      setEncryptError("Please select a file to protect.");
      return;
    }
    if (!recipientPubKeyInput.trim()) {
      setEncryptError("Recipient's Public Address / Lockbox is required.");
      return;
    }

    setIsEncrypting(true);
    setEncryptError(null);
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

      // Prepare recipient section with this package for testing
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
        setVaultBuffer(buffer);
        setDecryptStatus("idle");
        setDecryptError(null);
        setDecryptedResult(null);
      } catch (err) {
        setDecryptError("Failed to read package file buffer.");
      }
    }
  };

  // Decrypt & Unlock Package
  const handleDecrypt = async () => {
    if (!vaultBuffer) {
      setDecryptStatus("error");
      setDecryptError("Please upload a .vault package to unlock.");
      return;
    }
    if (!recipientPrivKeyInput.trim()) {
      setDecryptStatus("error");
      setDecryptError("Your Secret Master Key is required to unlock this file.");
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

  return (
    <div className="w-full max-w-5xl mx-auto px-4 space-y-6 text-slate-800 font-sans">
      {/* ==================================================================== */}
      {/* Navigation Shell: Segmented Control & Inspector Mode Switch           */}
      {/* ==================================================================== */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-5">
        {/* Segmented Control: Send vs Unlock */}
        <div className="inline-flex p-1.5 rounded-2xl bg-slate-100 border border-slate-200 text-xs sm:text-sm font-medium shadow-sm">
          <button
            onClick={() => setActiveMode("send")}
            className={`px-4 py-2 rounded-xl transition-all duration-200 cursor-pointer flex items-center space-x-2 ${
              activeMode === "send"
                ? "bg-white text-blue-600 font-semibold shadow-sm"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Send className="w-4 h-4 text-blue-600" />
            <span>Send Protected File</span>
          </button>
          <button
            onClick={() => setActiveMode("unlock")}
            className={`px-4 py-2 rounded-xl transition-all duration-200 cursor-pointer flex items-center space-x-2 ${
              activeMode === "unlock"
                ? "bg-white text-blue-600 font-semibold shadow-sm"
                : "text-slate-600 hover:text-slate-900"
            }`}
          >
            <Unlock className="w-4 h-4 text-blue-600" />
            <span>Unlock Received File</span>
          </button>
        </div>

        {/* Inspector Mode Switch: Simple Mode | Cryptographic Audit Mode */}
        <div className="flex items-center space-x-2.5 self-end sm:self-auto bg-white px-3.5 py-1.5 rounded-xl border border-slate-200 text-xs shadow-sm">
          <span className="text-slate-500 font-medium">Mode:</span>
          <button
            onClick={() => setIsAuditMode(!isAuditMode)}
            className="flex items-center space-x-2 cursor-pointer focus:outline-none group"
            title="Toggle between simplified user interface and full technical cryptographic audit telemetry"
          >
            <span
              className={`font-medium transition-colors ${
                !isAuditMode ? "text-blue-600 font-semibold" : "text-slate-400"
              }`}
            >
              Simple
            </span>
            <div
              className={`w-9 h-5 rounded-full p-0.5 transition-colors duration-200 ease-in-out ${
                isAuditMode ? "bg-blue-600" : "bg-slate-300"
              }`}
            >
              <div
                className={`w-4 h-4 rounded-full bg-white shadow-sm transform transition-transform duration-200 ease-in-out ${
                  isAuditMode ? "translate-x-4" : "translate-x-0"
                }`}
              />
            </div>
            <span
              className={`font-medium transition-colors ${
                isAuditMode ? "text-blue-600 font-semibold" : "text-slate-400"
              }`}
            >
              Audit
            </span>
          </button>
        </div>
      </div>

      {/* ==================================================================== */}
      {/* Expandable "My Security Keys" Banner / Drawer                         */}
      {/* ==================================================================== */}
      <section className="bg-white border border-slate-200 rounded-2xl p-4 sm:p-5 shadow-sm transition-all duration-300">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3">
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-blue-50 text-blue-600 border border-blue-100">
              <KeyRound className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h2 className="text-sm sm:text-base font-semibold text-slate-900">
                  My Security Identity
                </h2>
                <span className="inline-flex items-center px-2 py-0.5 rounded-full text-[10px] font-medium bg-emerald-50 text-emerald-700 border border-emerald-200">
                  <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1 animate-pulse"></span>
                  Active In Browser
                </span>
              </div>
              <p className="text-xs text-slate-500 mt-0.5">
                {isAuditMode
                  ? "RSA-OAEP 2048-bit (SHA-256) Keypair stored in private browser session"
                  : "Your unique cryptographic lockbox. Share your public address with others to receive protected files."}
              </p>
            </div>
          </div>

          <div className="flex items-center space-x-2 self-start sm:self-auto">
            {/* Quick Copy Public Address Button */}
            <button
              onClick={() => handleCopy(publicKeyPem, "quick-pub")}
              disabled={!publicKeyPem}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-medium text-slate-700 bg-slate-100 hover:bg-slate-200 border border-slate-200 transition shadow-sm disabled:opacity-40 cursor-pointer"
            >
              {copiedField === "quick-pub" ? (
                <>
                  <Check className="w-3.5 h-3.5 text-emerald-600" />
                  <span className="text-emerald-700 font-semibold">Address Copied!</span>
                </>
              ) : (
                <>
                  <Copy className="w-3.5 h-3.5 text-slate-500" />
                  <span>Copy My Public Address</span>
                </>
              )}
            </button>

            {/* Expand / Collapse Drawer Button */}
            <button
              onClick={() => setIsKeysDrawerOpen(!isKeysDrawerOpen)}
              className="inline-flex items-center space-x-1 px-2.5 py-1.5 rounded-xl text-xs text-slate-600 hover:text-slate-900 bg-slate-50 hover:bg-slate-100 border border-slate-200 transition cursor-pointer"
            >
              <span>{isKeysDrawerOpen ? "Hide Details" : "Details"}</span>
              {isKeysDrawerOpen ? (
                <ChevronUp className="w-3.5 h-3.5" />
              ) : (
                <ChevronDown className="w-3.5 h-3.5" />
              )}
            </button>
          </div>
        </div>

        {/* Drawer Content */}
        {isKeysDrawerOpen && (
          <div className="mt-5 pt-4 border-t border-slate-200 space-y-4 animate-in fade-in duration-200">
            <div className="flex items-center justify-between">
              <span className="text-xs text-slate-500">
                You can freely distribute your Public Address. Your Secret Master Key remains safely stored in this browser session.
              </span>
              <button
                id="generate-keys-btn"
                onClick={() => handleGenerateKeys(false)}
                disabled={isGeneratingKeys}
                className="text-xs font-medium text-blue-600 hover:text-blue-700 flex items-center space-x-1.5 cursor-pointer disabled:opacity-40"
              >
                <RefreshCw className={`w-3.5 h-3.5 ${isGeneratingKeys ? "animate-spin" : ""}`} />
                <span>{isGeneratingKeys ? "Regenerating..." : "Regenerate Keys"}</span>
              </button>
            </div>

            <div className="grid grid-cols-1 lg:grid-cols-2 gap-4">
              {/* Public Address Card */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1.5">
                    <span className="text-xs font-semibold text-slate-800">
                      {isAuditMode ? "SPKI Public Key (PEM)" : "Recipient's Public Address / Lockbox"}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-emerald-50 text-emerald-700 border border-emerald-200 font-medium">
                      Safe to share
                    </span>
                  </div>
                  <button
                    onClick={() => handleCopy(publicKeyPem, "drawer-pub")}
                    className="text-[11px] text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
                  >
                    {copiedField === "drawer-pub" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                    <span>{copiedField === "drawer-pub" ? "Copied" : "Copy"}</span>
                  </button>
                </div>
                <textarea
                  id="public-key-textarea"
                  readOnly
                  rows={4}
                  value={publicKeyPem}
                  placeholder="Generating public key..."
                  className="w-full rounded-lg bg-white border border-slate-300 p-2.5 text-[11px] font-mono text-emerald-700 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none selection:bg-blue-100"
                />
              </div>

              {/* Secret Master Key Card */}
              <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 space-y-2">
                <div className="flex items-center justify-between">
                  <div className="flex items-center space-x-1.5">
                    <span className="text-xs font-semibold text-slate-800">
                      {isAuditMode ? "PKCS#8 Private Key (PEM)" : "Your Secret Master Key"}
                    </span>
                    <span className="text-[10px] px-1.5 py-0.2 rounded bg-rose-50 text-rose-700 border border-rose-200 font-medium">
                      Never share
                    </span>
                  </div>
                  <div className="flex items-center space-x-2">
                    <button
                      onClick={() => setShowPrivateKeyText(!showPrivateKeyText)}
                      className="text-[11px] text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
                    >
                      {showPrivateKeyText ? <EyeOff className="w-3 h-3" /> : <Eye className="w-3 h-3" />}
                      <span>{showPrivateKeyText ? "Mask" : "Reveal"}</span>
                    </button>
                    <button
                      onClick={() => handleCopy(privateKeyPem, "drawer-priv")}
                      className="text-[11px] text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
                    >
                      {copiedField === "drawer-priv" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                      <span>{copiedField === "drawer-priv" ? "Copied" : "Copy"}</span>
                    </button>
                  </div>
                </div>
                {showPrivateKeyText ? (
                  <textarea
                    id="private-key-textarea"
                    readOnly
                    rows={4}
                    value={privateKeyPem}
                    className="w-full rounded-lg bg-white border border-slate-300 p-2.5 text-[11px] font-mono text-rose-700 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none selection:bg-blue-100"
                  />
                ) : (
                  <div className="h-[88px] flex items-center justify-center rounded-lg bg-white border border-slate-300 text-xs text-slate-400 font-mono">
                    •••••••••••••••••••••••••••••••••••••••••••••••••• (Protected in Session)
                  </div>
                )}
              </div>
            </div>
          </div>
        )}
      </section>

      {/* ==================================================================== */}
      {/* MODE 1: [ 📤 Send Protected File ]                                   */}
      {/* ==================================================================== */}
      {activeMode === "send" && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-7 shadow-sm space-y-6">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Protect & Package a File</h2>
              <p className="text-xs sm:text-sm text-slate-500 mt-1">
                {isAuditMode
                  ? "Symmetric file encryption via AES-256-GCM; session key encrypted via recipient's RSA-OAEP public key."
                  : "Your file is encrypted locally in your browser before saving or sharing. Only the recipient with the matching secret key can unlock it."}
              </p>
            </div>

            {/* Drag & Drop Dropzone */}
            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-700">
                1. Select Document
              </label>
              <div
                onDragOver={handleSenderDragOver}
                onDragLeave={handleSenderDragLeave}
                onDrop={handleSenderDrop}
                onClick={() => senderFileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-2xl p-7 text-center cursor-pointer transition-all duration-200 group ${
                  isDraggingSenderFile
                    ? "border-blue-500 bg-blue-50/50 ring-4 ring-blue-500/10 shadow-sm"
                    : "border-slate-300 hover:border-blue-500 bg-slate-50/60 hover:bg-blue-50/20"
                }`}
              >
                <input
                  ref={senderFileInputRef}
                  type="file"
                  id="sender-file-input"
                  onChange={handleSenderFileChange}
                  className="hidden"
                />

                <div className="flex flex-col items-center justify-center space-y-2.5">
                  <div className="p-3 rounded-2xl bg-white shadow-sm border border-slate-200 group-hover:border-blue-300 text-slate-500 group-hover:text-blue-600 transition">
                    <FileText className="w-6 h-6" />
                  </div>
                  {senderFile ? (
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-slate-900 truncate max-w-md">
                        {senderFile.name}
                      </p>
                      <p className="text-xs text-slate-500">
                        {formatBytes(senderFile.size)} • {senderFile.type || "Document / Binary"}
                      </p>
                      <span className="inline-block text-[11px] text-blue-600 font-medium pt-1 group-hover:underline">
                        Click or drop another file to replace
                      </span>
                    </div>
                  ) : (
                    <div>
                      <p className="text-sm font-medium text-slate-700">
                        Drop your document here, or <span className="text-blue-600 font-semibold underline">browse</span>
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        Supports PDF, DOCX, Images, Archives, or any arbitrary file up to 50MB
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Recipient's Public Address Input */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold uppercase tracking-wider text-slate-700">
                  {isAuditMode ? "2. Recipient RSA-2048 Public Key (SPKI PEM)" : "2. Recipient's Public Address / Lockbox"}
                </label>
                {publicKeyPem && (
                  <button
                    type="button"
                    onClick={() => setRecipientPubKeyInput(publicKeyPem)}
                    className="text-xs text-blue-600 hover:text-blue-700 cursor-pointer font-medium"
                  >
                    Use My Own Address (Self-Lock)
                  </button>
                )}
              </div>
              <textarea
                id="sender-recipient-pubkey"
                rows={4}
                value={recipientPubKeyInput}
                onChange={(e) => setRecipientPubKeyInput(e.target.value)}
                placeholder={
                  isAuditMode
                    ? "-----BEGIN PUBLIC KEY-----\n..."
                    : "Paste recipient's public lockbox address here (auto-populated with your own address for testing)..."
                }
                className="w-full rounded-xl bg-white border border-slate-300 p-3 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none selection:bg-blue-100"
              />
            </div>

            {/* Primary Action Button */}
            <div>
              <button
                id="encrypt-package-btn"
                onClick={handleEncrypt}
                disabled={isEncrypting || !senderFile || !recipientPubKeyInput.trim()}
                className="w-full py-3.5 px-6 rounded-xl font-medium text-sm text-white bg-blue-600 hover:bg-blue-700 active:scale-[0.99] transition shadow-sm disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center space-x-2 cursor-pointer"
              >
                {isEncrypting ? (
                  <>
                    <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>Encrypting & Sealing File...</span>
                  </>
                ) : (
                  <>
                    <Lock className="w-4 h-4" />
                    <span>
                      {isAuditMode
                        ? "Encrypt & Package File (Hybrid AES-256 + RSA-OAEP)"
                        : "Encrypt & Create Protected File"}
                    </span>
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
          </div>

          {/* Encryption Result & Inspection */}
          {encryptResult && (
            <div className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-5 animate-in fade-in duration-300">
              <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-200 pb-4">
                <div className="flex items-center space-x-2.5">
                  <div className="p-2 rounded-xl bg-emerald-50 text-emerald-700 border border-emerald-200">
                    <CheckCircle2 className="w-5 h-5" />
                  </div>
                  <div>
                    <h3 className="text-base font-semibold text-slate-900">
                      File Successfully Protected
                    </h3>
                    <p className="text-xs text-slate-500">
                      Your document has been sealed into an encrypted <code className="text-blue-600 font-semibold">.vault</code> envelope.
                    </p>
                  </div>
                </div>

                <div className="flex items-center space-x-2">
                  <button
                    onClick={() => setActiveMode("unlock")}
                    className="text-xs font-medium text-blue-600 hover:text-blue-700 bg-blue-50 hover:bg-blue-100 px-3 py-1.5 rounded-lg border border-blue-200 transition cursor-pointer"
                  >
                    Open in Unlock Tab →
                  </button>
                </div>
              </div>

              {/* Simple Mode Summary Card */}
              {!isAuditMode ? (
                <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-3">
                  <div className="grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                    <div>
                      <span className="text-slate-500 block">Package Name:</span>
                      <span className="font-semibold text-slate-800 font-mono">
                        {encryptResult.vaultFileName}
                      </span>
                    </div>
                    <div>
                      <span className="text-slate-500 block">Package Size:</span>
                      <span className="font-semibold text-slate-800">
                        {formatBytes(encryptResult.packageSize)}
                      </span>
                    </div>
                  </div>
                  <div className="text-xs text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-lg p-2.5 flex items-center space-x-2">
                    <ShieldCheck className="w-4 h-4 shrink-0 text-emerald-600" />
                    <span>
                      Protected with military-grade 256-bit encryption. The file is unreadable in transit and can only be opened by the recipient with their matching secret master key.
                    </span>
                  </div>
                </div>
              ) : (
                /* Cryptographic Audit Mode Details Card */
                <div className="space-y-4">
                  <div className="flex items-center justify-between text-xs text-slate-600">
                    <span className="font-semibold uppercase tracking-wider text-blue-600 flex items-center space-x-1.5">
                      <span className="w-2 h-2 rounded-full bg-blue-500 animate-ping"></span>
                      <span>Cryptographic Inspection Telemetry</span>
                    </span>
                    <span className="font-mono text-slate-500 text-[11px]">
                      Offset Layout Verified
                    </span>
                  </div>

                  <div className="space-y-3 text-xs">
                    {/* AES Session Key */}
                    <div>
                      <div className="flex items-center justify-between text-slate-600 mb-1">
                        <span>Generated AES-256 Session Key (Hex):</span>
                        <button
                          onClick={() => handleCopy(encryptResult.rawAesKeyHex, "aes")}
                          className="text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
                        >
                          {copiedField === "aes" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedField === "aes" ? "Copied" : "Copy"}</span>
                        </button>
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 font-mono text-amber-800 break-all select-all">
                        {encryptResult.rawAesKeyHex}
                      </div>
                    </div>

                    {/* Technical Specs Grid */}
                    <div className="grid grid-cols-1 sm:grid-cols-2 gap-3">
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5">
                        <span className="text-slate-500 block text-[11px]">RSA Wrapped Key Size:</span>
                        <span className="font-mono font-medium text-emerald-700">
                          256 bytes (RSA-OAEP 2048-bit)
                        </span>
                      </div>

                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5">
                        <span className="text-slate-500 block text-[11px]">AEAD Cipher & Tag:</span>
                        <span className="font-mono font-medium text-blue-700">
                          AES-256-GCM (128-bit GMAC Tag)
                        </span>
                      </div>
                    </div>

                    {/* SHA-256 Checksum */}
                    <div>
                      <div className="flex items-center justify-between text-slate-600 mb-1">
                        <span>Plaintext SHA-256 Digest:</span>
                        <button
                          onClick={() => handleCopy(encryptResult.sha256Hex, "hash")}
                          className="text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
                        >
                          {copiedField === "hash" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                          <span>{copiedField === "hash" ? "Copied" : "Copy"}</span>
                        </button>
                      </div>
                      <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 font-mono text-cyan-800 break-all select-all">
                        {encryptResult.sha256Hex}
                      </div>
                    </div>

                    {/* Total Package Size */}
                    <div className="flex items-center justify-between bg-slate-50 border border-slate-200 rounded-lg p-2.5 font-mono">
                      <span className="text-slate-500">Total .vault Package Size:</span>
                      <span className="font-semibold text-slate-900">
                        {formatBytes(encryptResult.packageSize)} ({encryptResult.packageSize} bytes)
                      </span>
                    </div>
                  </div>
                </div>
              )}

              {/* Download .vault Package Button */}
              <button
                id="download-vault-btn"
                onClick={() =>
                  triggerDownload(
                    encryptResult.packageBuffer,
                    encryptResult.vaultFileName,
                    "application/octet-stream"
                  )
                }
                className="w-full py-3 px-5 rounded-xl font-medium text-sm text-white bg-blue-600 hover:bg-blue-700 active:scale-[0.99] transition shadow-sm flex items-center justify-center space-x-2 cursor-pointer"
              >
                <Download className="w-4 h-4" />
                <span>Download {encryptResult.vaultFileName}</span>
              </button>
            </div>
          )}
        </div>
      )}

      {/* ==================================================================== */}
      {/* MODE 2: [ 📥 Unlock Received File ]                                  */}
      {/* ==================================================================== */}
      {activeMode === "unlock" && (
        <div className="space-y-6 animate-in fade-in duration-200">
          <div className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-7 shadow-sm space-y-6">
            <div>
              <h2 className="text-lg font-semibold text-slate-900">Unlock a Protected Document</h2>
              <p className="text-xs sm:text-sm text-slate-500 mt-1">
                {isAuditMode
                  ? "Unwrap session key with RSA private key, decrypt ciphertext with AES-256-GCM, and verify GMAC tag."
                  : "Upload a .vault package and use your secret master key to decrypt and verify the document."}
              </p>
            </div>

            {/* Drag & Drop Dropzone for .vault */}
            <div className="space-y-2">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-700">
                1. Upload .vault Package
              </label>
              <div
                onDragOver={handleVaultDragOver}
                onDragLeave={handleVaultDragLeave}
                onDrop={handleVaultDrop}
                onClick={() => vaultFileInputRef.current?.click()}
                className={`border-2 border-dashed rounded-2xl p-7 text-center cursor-pointer transition-all duration-200 group ${
                  isDraggingVaultFile
                    ? "border-blue-500 bg-blue-50/50 ring-4 ring-blue-500/10 shadow-sm"
                    : "border-slate-300 hover:border-blue-500 bg-slate-50/60 hover:bg-blue-50/20"
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

                <div className="flex flex-col items-center justify-center space-y-2.5">
                  <div className="p-3 rounded-2xl bg-white shadow-sm border border-slate-200 group-hover:border-blue-300 text-slate-500 group-hover:text-blue-600 transition">
                    <Upload className="w-6 h-6" />
                  </div>
                  {vaultFile ? (
                    <div className="space-y-1">
                      <p className="text-sm font-semibold text-slate-900 truncate max-w-md">
                        {vaultFile.name}
                      </p>
                      <p className="text-xs text-slate-500">
                        {formatBytes(vaultFile.size)} • Protected Vault Package
                      </p>
                      <span className="inline-block text-[11px] text-blue-600 font-medium pt-1 group-hover:underline">
                        Click or drop another package to replace
                      </span>
                    </div>
                  ) : (
                    <div>
                      <p className="text-sm font-medium text-slate-700">
                        Drop your <span className="text-blue-600 font-semibold">.vault</span> package here, or browse
                      </p>
                      <p className="text-xs text-slate-500 mt-1">
                        Encrypted envelope containing wrapped session key & encrypted payload
                      </p>
                    </div>
                  )}
                </div>
              </div>
            </div>

            {/* Secret Master Key Input */}
            <div className="space-y-2">
              <div className="flex items-center justify-between">
                <label className="text-xs font-semibold uppercase tracking-wider text-slate-700">
                  {isAuditMode ? "2. Recipient RSA-2048 Private Key (PKCS#8 PEM)" : "2. Your Secret Master Key"}
                </label>
                {privateKeyPem && (
                  <span className="text-xs text-emerald-700 flex items-center space-x-1 font-medium bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                    <Check className="w-3 h-3" />
                    <span>Loaded from session</span>
                  </span>
                )}
              </div>
              <textarea
                id="recipient-privkey-input"
                rows={4}
                value={recipientPrivKeyInput}
                onChange={(e) => setRecipientPrivKeyInput(e.target.value)}
                placeholder="Paste your secret master key in PEM format..."
                className="w-full rounded-xl bg-white border border-slate-300 p-3 text-xs font-mono text-slate-800 placeholder-slate-400 focus:outline-none focus:ring-2 focus:ring-blue-500 resize-none selection:bg-blue-100"
              />
            </div>

            {/* Primary Action Button */}
            <div>
              <button
                id="decrypt-package-btn"
                onClick={handleDecrypt}
                disabled={isDecrypting || !vaultBuffer || !recipientPrivKeyInput.trim()}
                className="w-full py-3.5 px-6 rounded-xl font-medium text-sm text-white bg-blue-600 hover:bg-blue-700 active:scale-[0.99] transition shadow-sm disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center space-x-2 cursor-pointer"
              >
                {isDecrypting ? (
                  <>
                    <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                      <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                      <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                    </svg>
                    <span>Unwrapping & Decrypting...</span>
                  </>
                ) : (
                  <>
                    <Unlock className="w-4 h-4" />
                    <span>
                      {isAuditMode
                        ? "Unwrap Envelope & Decrypt (AES-GCM + RSA-OAEP)"
                        : "Unlock Document"}
                    </span>
                  </>
                )}
              </button>
            </div>
          </div>

          {/* Decryption Success Banner (Soft Pastel Emerald) */}
          {decryptStatus === "success" && decryptedResult && (
            <div className="bg-emerald-50/90 border border-emerald-200 rounded-2xl p-6 shadow-sm space-y-4 animate-in fade-in duration-300">
              <div className="flex items-start space-x-3.5">
                <div className="p-2 rounded-xl bg-emerald-100 text-emerald-700 border border-emerald-300 shrink-0 mt-0.5">
                  <ShieldCheck className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-base font-semibold text-emerald-900">
                    {isAuditMode
                      ? "File verified & integrity intact (AES-GCM GMAC Valid)"
                      : "File is genuine and has not been altered"}
                  </h3>
                  <p className="text-xs text-emerald-700 leading-relaxed">
                    {isAuditMode
                      ? "Authenticated decryption succeeded. The 128-bit GMAC tag and SHA-256 plaintext checksum matched perfectly with zero data tampering."
                      : "Verified with mathematical certainty. The document has not been tampered with, corrupted, or altered in transit."}
                  </p>
                </div>
              </div>

              {/* Recovered File Info Card */}
              <div className="bg-white rounded-xl p-4 border border-emerald-200 grid grid-cols-1 sm:grid-cols-2 gap-3 text-xs">
                <div>
                  <span className="text-slate-500 block text-[11px]">Original Filename:</span>
                  <span className="font-semibold text-slate-900 font-mono break-all">
                    {decryptedResult.fileName}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Document Type:</span>
                  <span className="font-medium text-slate-800">
                    {decryptedResult.fileType || "application/octet-stream"}
                  </span>
                </div>
                <div>
                  <span className="text-slate-500 block text-[11px]">Document Size:</span>
                  <span className="font-medium text-slate-800">
                    {formatBytes(decryptedResult.fileBuffer.byteLength)}
                  </span>
                </div>
                {isAuditMode && (
                  <div>
                    <span className="text-slate-500 block text-[11px]">Recovered AES Key:</span>
                    <span className="font-mono text-amber-800 truncate block">
                      {decryptedResult.unwrappedAesKeyHex.substring(0, 16)}...
                    </span>
                  </div>
                )}
              </div>

              {/* Download Recovered File */}
              <button
                id="download-recovered-btn"
                onClick={() =>
                  triggerDownload(
                    decryptedResult.fileBuffer,
                    decryptedResult.fileName,
                    decryptedResult.fileType || "application/octet-stream"
                  )
                }
                className="w-full py-3 px-5 rounded-xl font-medium text-sm text-white bg-emerald-600 hover:bg-emerald-700 active:scale-[0.99] transition shadow-sm flex items-center justify-center space-x-2 cursor-pointer"
              >
                <Download className="w-4 h-4" />
                <span>
                  {isAuditMode
                    ? `Download Recovered File (${decryptedResult.fileName})`
                    : `Download Unlocked Document (${decryptedResult.fileName})`}
                </span>
              </button>
            </div>
          )}

          {/* Decryption Failure Banner (Soft Pastel Crimson) */}
          {decryptStatus === "error" && (
            <div className="bg-rose-50/90 border border-rose-200 rounded-2xl p-6 shadow-sm space-y-3 animate-in fade-in duration-300">
              <div className="flex items-start space-x-3.5">
                <div className="p-2 rounded-xl bg-rose-100 text-rose-700 border border-rose-300 shrink-0 mt-0.5">
                  <AlertTriangle className="w-6 h-6" />
                </div>
                <div className="space-y-1">
                  <h3 className="text-base font-semibold text-rose-900">
                    {isAuditMode
                      ? "Decryption Failed: Key mismatch or tampered data"
                      : "Unable to unlock document"}
                  </h3>
                  <p className="text-xs text-rose-700 leading-relaxed">
                    {isAuditMode
                      ? "The cryptographic engine rejected the package. Either the private key does not match the public key used during encryption, or the ciphertext was altered in transit."
                      : "Decryption was rejected. This happens if the wrong secret key was used or if the file was modified or corrupted in transit."}
                  </p>
                </div>
              </div>

              {decryptError && (
                <div className="bg-white border border-rose-200 rounded-xl p-3 text-xs font-mono text-rose-800 break-all">
                  {decryptError}
                </div>
              )}
            </div>
          )}
        </div>
      )}
    </div>
  );
};

export default VaultTab;
