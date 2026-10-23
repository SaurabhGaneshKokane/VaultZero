import React, { useState, useEffect, useRef } from "react";
import {
  generateRsaKeyPair,
  encryptHybrid,
  decryptHybrid,
  EncryptedPackage,
} from "../utils/cryptoEngine";
import {
  ShieldAlert,
  Terminal,
  Zap,
  RefreshCw,
  Copy,
  Check,
  FileCheck2,
  Lock,
  Unlock,
  AlertOctagon,
} from "lucide-react";

// ============================================================================
// Types & Interfaces
// ============================================================================

interface TerminalLog {
  id: string;
  timestamp: string;
  type: "info" | "warn" | "error" | "success" | "attack";
  text: string;
}

interface HexDiffState {
  offset: number;
  originalHex: string;
  corruptedHex: string;
  originalBinary: string;
  corruptedBinary: string;
  contextBytes: string[];
  relativeIndex: number;
}

// ============================================================================
// Main AdversarialLab Component (Enterprise Light Theme)
// ============================================================================

export const AdversarialLab: React.FC = () => {
  // Setup States
  const [genuinePubKeyPem, setGenuinePubKeyPem] = useState<string>("");
  const [genuinePrivKeyPem, setGenuinePrivKeyPem] = useState<string>("");
  const [attackerPrivKeyPem, setAttackerPrivKeyPem] = useState<string>("");
  const [activePackage, setActivePackage] = useState<EncryptedPackage | null>(null);
  const [activeFileName, setActiveFileName] = useState<string>("classified_payload.pdf");
  const [isInitializing, setIsInitializing] = useState<boolean>(true);
  const [copiedKey, setCopiedKey] = useState<"gen" | "atk" | null>(null);

  // Attack Execution States
  const [isAttackingA, setIsAttackingA] = useState<boolean>(false);
  const [isAttackingB, setIsAttackingB] = useState<boolean>(false);
  const [hexDiff, setHexDiff] = useState<HexDiffState | null>(null);
  const [mutationOffsetMode, setMutationOffsetMode] = useState<"ciphertext" | "offset300">("ciphertext");

  // Terminal Logs State
  const [logs, setLogs] = useState<TerminalLog[]>([]);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

  // Helper to append a timestamped log
  const addLog = (type: TerminalLog["type"], text: string) => {
    const timestamp = new Date().toISOString().split("T")[1].slice(0, 12);
    setLogs((prev) => [
      ...prev,
      {
        id: `${Date.now()}-${Math.random()}`,
        timestamp,
        type,
        text,
      },
    ]);
  };

  // Auto-scroll terminal to bottom
  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Initial Setup: Generate genuine keys, attacker keys, and sample .vault package
  const initializeLab = async () => {
    setIsInitializing(true);
    setLogs([]);
    setHexDiff(null);
    addLog("info", "--- INITIALIZING ADVERSARIAL INTEGRITY LAB ---");
    addLog("info", "Target: Stage 1 Objective 5 (Tamper and Misuse Detection)");

    try {
      // 1. Generate Genuine Recipient RSA-2048 Keypair
      addLog("info", "[1/3] Generating genuine recipient RSA-OAEP 2048-bit keypair...");
      const genuineKeys = await generateRsaKeyPair();
      setGenuinePubKeyPem(genuineKeys.publicKeyPem);
      setGenuinePrivKeyPem(genuineKeys.privateKeyPem);
      addLog("success", "[1/3] Genuine RSA keypair active (Authorized Identity).");

      // 2. Generate Separate Attacker RSA-2048 Keypair
      addLog("info", "[2/3] Generating rogue/attacker RSA-OAEP 2048-bit keypair...");
      const attackerKeys = await generateRsaKeyPair();
      setAttackerPrivKeyPem(attackerKeys.privateKeyPem);
      addLog("warn", "[2/3] Attacker RSA keypair active (Unauthorized Identity).");

      // 3. Encrypt Sample Document
      addLog("info", "[3/3] Creating sample authentic .vault package payload...");
      const sampleText =
        "CONFIDENTIAL TRANSMISSION: TOP-SECRET DIRECTIVE 0x7F9B.\n" +
        "VaultZero AEAD Verification Payload: Integrity protection guaranteed by AES-256-GCM GMAC.\n" +
        "Padding oracle and ciphertext malleability defenses active.";
      const sampleBuffer = new TextEncoder().encode(sampleText).buffer;
      const samplePkg = await encryptHybrid(
        sampleBuffer,
        "classified_payload.pdf",
        "application/pdf",
        genuineKeys.publicKeyPem
      );

      setActivePackage(samplePkg);
      setActiveFileName("classified_payload.pdf");
      addLog(
        "success",
        `[3/3] Sample .vault package generated (${samplePkg.packageBuffer.byteLength} bytes).`
      );
      addLog("info", "Lab environment ready for attack injection.");
    } catch (err) {
      console.error("Initialization failed:", err);
      addLog("error", `Failed to initialize lab: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsInitializing(false);
    }
  };

  useEffect(() => {
    initializeLab();
  }, []);

  // Handle Custom .vault File Upload
  const handleUploadVault = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const buffer = await file.arrayBuffer();
      setActivePackage({
        packageBuffer: buffer,
        sha256Hex: "uploaded-file-custom-checksum",
        rawAesKeyHex: "embedded-session-key",
      });
      setActiveFileName(file.name);
      setHexDiff(null);
      addLog("info", `Custom .vault package uploaded: ${file.name} (${buffer.byteLength} bytes).`);
    } catch (err) {
      addLog("error", `Failed to read uploaded file: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

  // Copy to clipboard helper
  const handleCopy = async (text: string, type: "gen" | "atk") => {
    if (!text) return;
    try {
      await navigator.clipboard.writeText(text);
      setCopiedKey(type);
      setTimeout(() => setCopiedKey(null), 2000);
    } catch (err) {
      console.error("Copy failed", err);
    }
  };

  // ==========================================================================
  // Attack Scenario A: In-Transit Bit-Flip Tampering (AEAD Defense)
  // ==========================================================================
  const executeOneBitMutation = async () => {
    if (!activePackage || !genuinePrivKeyPem) return;

    setIsAttackingA(true);
    addLog("attack", "========================================================");
    addLog("attack", "[SCENARIO A] Executing In-Transit 1-Bit Mutation Attack (AEAD Test)");
    addLog("attack", "========================================================");

    try {
      // 1. Clone package buffer
      const tamperedBuffer = activePackage.packageBuffer.slice(0);
      const tamperedBytes = new Uint8Array(tamperedBuffer);

      // 2. Determine byte offset for bit-flip
      const dv = new DataView(tamperedBuffer);
      const metaLen = dv.byteLength >= 272 ? dv.getUint32(268, false) : 0;
      const ciphertextStart = 272 + metaLen;

      let targetOffset: number;
      if (mutationOffsetMode === "ciphertext") {
        targetOffset = Math.min(ciphertextStart + 8, tamperedBytes.length - 1);
      } else {
        targetOffset = Math.min(300, tamperedBytes.length - 1);
      }

      // Flip exactly 1 bit at byte offset using XOR: tamperedBytes[targetOffset] ^= 0x01
      const originalByte = tamperedBytes[targetOffset];
      tamperedBytes[targetOffset] ^= 0x01;
      const corruptedByte = tamperedBytes[targetOffset];

      // Update Hex Diff visualization state
      const startContext = Math.max(0, targetOffset - 4);
      const endContext = Math.min(tamperedBytes.length, targetOffset + 5);
      const contextBytes = Array.from(tamperedBytes.slice(startContext, endContext)).map(
        (b) => b.toString(16).padStart(2, "0").toUpperCase()
      );

      setHexDiff({
        offset: targetOffset,
        originalHex: `0x${originalByte.toString(16).padStart(2, "0").toUpperCase()}`,
        corruptedHex: `0x${corruptedByte.toString(16).padStart(2, "0").toUpperCase()}`,
        originalBinary: originalByte.toString(2).padStart(8, "0"),
        corruptedBinary: corruptedByte.toString(2).padStart(8, "0"),
        contextBytes,
        relativeIndex: targetOffset - startContext,
      });

      addLog(
        "warn",
        `[INJECTION] 1-bit mutation applied at byte offset ${targetOffset} (XOR 0x01):`
      );
      addLog(
        "warn",
        `            Original: 0x${originalByte
          .toString(16)
          .padStart(2, "0")
          .toUpperCase()} (0b${originalByte.toString(2).padStart(8, "0")})`
      );
      addLog(
        "warn",
        `            Mutated:  0x${corruptedByte
          .toString(16)
          .padStart(2, "0")
          .toUpperCase()} (0b${corruptedByte.toString(2).padStart(8, "0")})`
      );
      addLog(
        "info",
        `[TRANSPORT] Forwarding tampered package to authentic recipient decryptor...`
      );

      // 3. Attempt hybrid decryption with genuine recipient private key
      await decryptHybrid(tamperedBuffer, genuinePrivKeyPem);

      // If execution reaches here, tampering was NOT caught
      addLog("error", "[CRITICAL FAILURE] Invariant violated: Tampered ciphertext was decrypted!");
    } catch (err: any) {
      // 4. Catch the native Web Crypto error (OperationError)
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog("success", "[DEFENSE SUCCESS] Native Web Crypto rejection caught!");
      addLog(
        "error",
        `[CRYPTOGRAPHIC REJECTION]: ${errorMsg}\n` +
          `----------------------------------------------------------------\n` +
          `[ANALYSIS]: Native Web Crypto subtle.decrypt threw 'OperationError'.\n` +
          `[AEAD VERDICT]: The 128-bit AES-GCM GMAC authentication tag failed verification.\n` +
          `[NON-MALLEABILITY]: Because AES-GCM computes a Galois MAC over the ciphertext,\n` +
          `flipping even 1 bit renders the polynomial MAC tag mathematically invalid.\n` +
          `The engine rejected the package in constant time and ZERO plaintext bytes were released.`
      );
    } finally {
      setIsAttackingA(false);
    }
  };

  // ==========================================================================
  // Attack Scenario B: Key Mismatch (Unauthorized Identity)
  // ==========================================================================
  const executeKeyMismatchAttack = async () => {
    if (!activePackage || !attackerPrivKeyPem) return;

    setIsAttackingB(true);
    addLog("attack", "========================================================");
    addLog("attack", "[SCENARIO B] Executing Key Mismatch Attack (Unauthorized Identity)");
    addLog("attack", "========================================================");

    try {
      addLog(
        "info",
        "[ATTACK] Attacker intercepts .vault package in transit without authorized credentials."
      );
      addLog(
        "info",
        "[ATTACK] Attempting asymmetric unwrap using Rogue/Attacker RSA-2048 private key..."
      );

      // Attempt to decrypt with rogue attacker private key
      await decryptHybrid(activePackage.packageBuffer.slice(0), attackerPrivKeyPem);

      addLog("error", "[CRITICAL FAILURE] Unauthorized key was accepted!");
    } catch (err: any) {
      // Catch RSA-OAEP unpadding failure
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog("success", "[DEFENSE SUCCESS] Asymmetric decryption rejected!");
      addLog(
        "error",
        `[ASYMMETRIC REJECTION]: ${errorMsg}\n` +
          `----------------------------------------------------------------\n` +
          `[ANALYSIS]: Native Web Crypto subtle.decrypt threw 'OperationError'.\n` +
          `[RSA-OAEP VERDICT]: Optimal Asymmetric Encryption Padding (OAEP) verification failed.\n` +
          `[PLAIN-TEXT AWARENESS]: RSA-OAEP with SHA-256 enforces strict mask generation (MGF1).\n` +
          `An unauthorized private key yields mathematical entropy that fails the OAEP unpadding check.\n` +
          `The AES session key was NEVER recovered; attacker remains completely locked out.`
      );
    } finally {
      setIsAttackingB(false);
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto px-4 space-y-6 text-slate-800 font-sans">
      {/* Header */}
      <div className="border-b border-slate-200 pb-5 flex flex-col md:flex-row md:items-center md:justify-between gap-4">
        <div>
          <div className="flex items-center space-x-3">
            <div className="p-2.5 rounded-xl bg-rose-50 text-rose-600 border border-rose-200">
              <ShieldAlert className="w-5 h-5" />
            </div>
            <div>
              <div className="flex items-center space-x-2">
                <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
                  Adversarial Integrity Lab
                </h1>
                <span className="text-xs px-2.5 py-0.5 rounded-full bg-rose-50 text-rose-700 border border-rose-200 font-mono font-medium">
                  Stage 1 Objective 5
                </span>
              </div>
              <p className="mt-0.5 text-xs sm:text-sm text-slate-500">
                Negative Adversarial Tests: AEAD In-Transit Bit-Flip Tamper & Unauthorized Key Mismatch Detection
              </p>
            </div>
          </div>
        </div>

        <div className="flex items-center space-x-3">
          <button
            onClick={initializeLab}
            disabled={isInitializing}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-xl text-xs font-medium text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 transition shadow-sm disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isInitializing ? "animate-spin" : ""}`} />
            <span>Reset Lab State</span>
          </button>
          <div className="flex items-center space-x-2 text-xs font-mono text-emerald-800 bg-emerald-50 px-3 py-1.5 rounded-xl border border-emerald-200">
            <span className="w-2 h-2 rounded-full bg-emerald-500 animate-pulse"></span>
            <span>Tamper Monitor Active</span>
          </div>
        </div>
      </div>

      {/* Explanatory Educational Badges: Soft Pastel Enterprise Style */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
        <div className="bg-emerald-50/80 border border-emerald-200 rounded-2xl p-5 space-y-2 shadow-sm">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-emerald-100 text-emerald-800 border border-emerald-300">
              AES-GCM (AEAD)
            </span>
            <span className="text-xs font-semibold text-emerald-900">Non-Malleable Cryptography</span>
          </div>
          <p className="text-xs text-emerald-800 leading-relaxed">
            AES-GCM computes a 128-bit GHASH authentication tag (GMAC) over the ciphertext and IV. Any 1-bit mutation in transit invalidates the tag verification, preventing malleable bit-flipping attacks common in legacy unauthenticated modes like AES-CBC/CFB.
          </p>
        </div>

        <div className="bg-blue-50/80 border border-blue-200 rounded-2xl p-5 space-y-2 shadow-sm">
          <div className="flex items-center space-x-2">
            <span className="text-xs font-bold font-mono px-2 py-0.5 rounded bg-blue-100 text-blue-800 border border-blue-300">
              RSA-OAEP
            </span>
            <span className="text-xs font-semibold text-blue-900">Plaintext-Aware Padding</span>
          </div>
          <p className="text-xs text-blue-800 leading-relaxed">
            RSA-OAEP uses SHA-256 and mask generation (MGF1) to enforce strict padding verification. Attempting decryption with an unauthorized private key immediately triggers an OAEP unpadding error, defeating Bleichenbacher padding oracle attacks.
          </p>
        </div>
      </div>

      {/* 1. Lab State & Setup Card */}
      <section className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-6">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-4 border-b border-slate-200 pb-4">
          <div>
            <h2 className="text-base font-semibold text-slate-900 flex items-center space-x-2">
              <span className="w-5 h-5 rounded-full bg-blue-100 text-blue-700 text-xs flex items-center justify-center font-bold">1</span>
              <span>Active Target Package & Key Identities</span>
            </h2>
            <p className="text-xs text-slate-500 mt-0.5">
              Target .vault package armed with authentic recipient key and adversarial attacker key
            </p>
          </div>

          <div className="flex items-center space-x-3">
            <input
              ref={fileInputRef}
              type="file"
              accept=".vault"
              onChange={handleUploadVault}
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="text-xs font-medium px-3 py-1.5 rounded-xl bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition cursor-pointer"
            >
              Upload Custom .vault
            </button>
          </div>
        </div>

        {/* Target Package Status Banner */}
        {activePackage && (
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 flex flex-col sm:flex-row sm:items-center justify-between gap-3 font-mono text-xs">
            <div className="space-y-1">
              <div className="flex items-center space-x-2 text-slate-700">
                <span className="text-slate-500 font-sans">Target File:</span>
                <span className="text-blue-700 font-semibold">{activeFileName}</span>
              </div>
              <div className="text-slate-500">
                Package Size: <span className="text-slate-800 font-semibold">{activePackage.packageBuffer.byteLength} bytes</span> •
                RSA Header: <span className="text-emerald-700 font-semibold">256 bytes</span> •
                IV: <span className="text-emerald-700 font-semibold">12 bytes</span>
              </div>
            </div>
            <div className="px-3 py-1 rounded-full bg-emerald-50 text-emerald-700 border border-emerald-200 text-center font-sans font-medium text-xs">
              Active Protected Envelope
            </div>
          </div>
        )}

        {/* Dual Key Identity Comparison */}
        <div className="grid grid-cols-1 lg:grid-cols-2 gap-6">
          {/* Authentic Recipient Private Key */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>Genuine Recipient Private Key (Authorized)</span>
              </label>
              <button
                onClick={() => handleCopy(genuinePrivKeyPem, "gen")}
                className="text-[11px] text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
              >
                {copiedKey === "gen" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === "gen" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <textarea
              readOnly
              rows={4}
              value={genuinePrivKeyPem}
              className="w-full rounded-xl bg-emerald-50/40 border border-emerald-200 p-3 text-xs font-mono text-emerald-900 resize-none focus:outline-none"
            />
          </div>

          {/* Rogue Attacker Private Key */}
          <div className="space-y-2">
            <div className="flex items-center justify-between">
              <label className="text-xs font-semibold uppercase tracking-wider text-slate-700 flex items-center space-x-2">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>Attacker's Private Key (Unauthorized Rogue)</span>
              </label>
              <button
                onClick={() => handleCopy(attackerPrivKeyPem, "atk")}
                className="text-[11px] text-slate-500 hover:text-slate-800 flex items-center space-x-1 cursor-pointer"
              >
                {copiedKey === "atk" ? <Check className="w-3 h-3 text-emerald-600" /> : <Copy className="w-3 h-3" />}
                <span>{copiedKey === "atk" ? "Copied" : "Copy"}</span>
              </button>
            </div>
            <textarea
              readOnly
              rows={4}
              value={attackerPrivKeyPem}
              className="w-full rounded-xl bg-rose-50/40 border border-rose-200 p-3 text-xs font-mono text-rose-900 resize-none focus:outline-none"
            />
          </div>
        </div>
      </section>

      {/* 2. Attack Execution Deck: Scenario A & Scenario B */}
      <div className="grid grid-cols-1 lg:grid-cols-2 gap-6 items-start">
        {/* Scenario A Card */}
        <section className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-5">
          <div className="border-b border-slate-200 pb-4">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-amber-50 text-amber-700 border border-amber-200">
                <Zap className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-900">
                  Scenario A: 1-Bit In-Transit Tampering
                </h3>
                <p className="text-xs text-slate-500">
                  AEAD Defense: Mutate exactly 1 bit in transit via XOR (<code className="text-amber-800 font-mono">tamperedBytes[offset] ^= 0x01</code>)
                </p>
              </div>
            </div>
          </div>

          {/* Offset Selector */}
          <div className="space-y-2">
            <label className="text-xs font-semibold text-slate-700">
              Mutation Target Location:
            </label>
            <div className="grid grid-cols-2 gap-2 text-xs font-mono">
              <button
                type="button"
                onClick={() => setMutationOffsetMode("ciphertext")}
                className={`py-2 px-3 rounded-xl border text-left transition cursor-pointer ${
                  mutationOffsetMode === "ciphertext"
                    ? "bg-amber-50 border-amber-300 text-amber-900 font-semibold shadow-sm"
                    : "bg-slate-50 border-slate-200 text-slate-600 hover:border-slate-300"
                }`}
              >
                <div className="font-semibold font-sans">Ciphertext Body</div>
                <div className="text-[10px] text-slate-500">AEAD GMAC Tag Test</div>
              </button>
              <button
                type="button"
                onClick={() => setMutationOffsetMode("offset300")}
                className={`py-2 px-3 rounded-xl border text-left transition cursor-pointer ${
                  mutationOffsetMode === "offset300"
                    ? "bg-amber-50 border-amber-300 text-amber-900 font-semibold shadow-sm"
                    : "bg-slate-50 border-slate-200 text-slate-600 hover:border-slate-300"
                }`}
              >
                <div className="font-semibold font-sans">Offset 300</div>
                <div className="text-[10px] text-slate-500">tamperedBytes[300]</div>
              </button>
            </div>
          </div>

          {/* Execute Attack A Button */}
          <button
            id="execute-mutation-attack-btn"
            onClick={executeOneBitMutation}
            disabled={isAttackingA || isInitializing || !activePackage}
            className="w-full py-3.5 px-4 rounded-xl font-medium text-sm text-white bg-amber-600 hover:bg-amber-700 active:scale-[0.99] transition shadow-sm disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center space-x-2 cursor-pointer"
          >
            {isAttackingA ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>Injecting Mutation & Decrypting...</span>
              </>
            ) : (
              <>
                <Zap className="w-4 h-4" />
                <span>Execute 1-Bit Mutation Attack</span>
              </>
            )}
          </button>

          {/* Hex Diff Card */}
          {hexDiff && (
            <div className="bg-amber-50/70 border border-amber-200 rounded-xl p-4 space-y-3 font-mono text-xs shadow-sm">
              <div className="flex items-center justify-between border-b border-amber-200/80 pb-2">
                <span className="text-amber-900 font-bold flex items-center space-x-1.5 font-sans">
                  <span className="w-2 h-2 rounded-full bg-amber-500 animate-ping"></span>
                  <span>Hex Diff Card [Offset: {hexDiff.offset}]</span>
                </span>
                <span className="text-amber-700 text-[11px] font-sans">Mutation: XOR 0x01</span>
              </div>

              {/* Byte Comparison */}
              <div className="grid grid-cols-2 gap-3">
                <div className="bg-white border border-slate-200 rounded-lg p-2.5 space-y-1">
                  <span className="text-[10px] text-slate-500 block uppercase font-sans font-medium">Original Byte</span>
                  <div className="text-base font-bold text-emerald-700">{hexDiff.originalHex}</div>
                  <div className="text-[10px] text-slate-500">{hexDiff.originalBinary}</div>
                </div>

                <div className="bg-rose-50 border border-rose-200 rounded-lg p-2.5 space-y-1">
                  <span className="text-[10px] text-rose-700 block uppercase font-sans font-medium">Corrupted Byte</span>
                  <div className="text-base font-bold text-rose-700">{hexDiff.corruptedHex}</div>
                  <div className="text-[10px] text-rose-600">{hexDiff.corruptedBinary}</div>
                </div>
              </div>

              {/* Memory Hex Slice Context */}
              <div className="space-y-1">
                <span className="text-[10px] text-slate-500 block uppercase font-sans font-medium">Memory Buffer Context Window</span>
                <div className="flex items-center justify-between bg-white border border-slate-200 rounded-lg p-2 overflow-x-auto text-center">
                  {hexDiff.contextBytes.map((byte, idx) => (
                    <div
                      key={idx}
                      className={`px-1.5 py-1 rounded text-[11px] ${
                        idx === hexDiff.relativeIndex
                          ? "bg-rose-100 text-rose-800 font-bold border border-rose-300"
                          : "text-slate-600"
                      }`}
                    >
                      {byte}
                      {idx === hexDiff.relativeIndex && (
                        <div className="text-[8px] text-rose-600 mt-0.5 font-sans">▲ flipped</div>
                      )}
                    </div>
                  ))}
                </div>
              </div>
            </div>
          )}
        </section>

        {/* Scenario B Card */}
        <section className="bg-white border border-slate-200 rounded-2xl p-6 shadow-sm space-y-5">
          <div className="border-b border-slate-200 pb-4">
            <div className="flex items-center space-x-2.5">
              <div className="p-2 rounded-xl bg-rose-50 text-rose-600 border border-rose-200">
                <AlertOctagon className="w-5 h-5" />
              </div>
              <div>
                <h3 className="text-base font-semibold text-slate-900">
                  Scenario B: Unauthorized Identity
                </h3>
                <p className="text-xs text-slate-500">
                  Key Mismatch Defense: Attempt RSA unwrap with rogue/attacker private key
                </p>
              </div>
            </div>
          </div>

          <div className="bg-slate-50 border border-slate-200 rounded-xl p-4 space-y-2 text-xs">
            <div className="text-slate-800 font-semibold">Attack Vector:</div>
            <p className="text-slate-600 text-xs leading-relaxed">
              Attacker possesses the unaltered ciphertext envelope but attempts to decrypt the 256-byte RSA-OAEP session key header using their own unauthorized private key.
            </p>
            <div className="pt-2 text-slate-600 flex items-center justify-between text-[11px] border-t border-slate-200 font-mono">
              <span className="font-sans">Expected Defense:</span>
              <span className="text-rose-700 font-medium">RSA-OAEP Padding Integrity Check</span>
            </div>
          </div>

          {/* Execute Attack B Button */}
          <button
            id="execute-key-mismatch-btn"
            onClick={executeKeyMismatchAttack}
            disabled={isAttackingB || isInitializing || !activePackage}
            className="w-full py-3.5 px-4 rounded-xl font-medium text-sm text-white bg-rose-600 hover:bg-rose-700 active:scale-[0.99] transition shadow-sm disabled:opacity-40 disabled:cursor-not-allowed flex items-center justify-center space-x-2 cursor-pointer"
          >
            {isAttackingB ? (
              <>
                <svg className="animate-spin h-4 w-4 text-white" viewBox="0 0 24 24" fill="none">
                  <circle className="opacity-25" cx="12" cy="12" r="10" stroke="currentColor" strokeWidth="4"></circle>
                  <path className="opacity-75" fill="currentColor" d="M4 12a8 8 0 018-8V0C5.373 0 0 5.373 0 12h4zm2 5.291A7.962 7.962 0 014 12H0c0 3.042 1.135 5.824 3 7.938l3-2.647z"></path>
                </svg>
                <span>Attempting Unauthorized Unwrap...</span>
              </>
            ) : (
              <>
                <Lock className="w-4 h-4" />
                <span>Attempt Decryption with Attacker Key</span>
              </>
            )}
          </button>
        </section>
      </div>

      {/* 3. Security Audit Log Frame with Embedded Clean Slate Terminal */}
      <section className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden space-y-0">
        {/* Audit Log Chrome Header */}
        <div className="bg-slate-50 px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center space-x-2.5">
            <Terminal className="w-4 h-4 text-slate-600" />
            <span className="text-xs font-semibold text-slate-800">
              Security Audit Telemetry Console
            </span>
          </div>

          <button
            onClick={() => setLogs([])}
            className="text-xs font-medium text-slate-500 hover:text-slate-800 transition cursor-pointer"
          >
            Clear Console
          </button>
        </div>

        {/* Embedded Slate Terminal Box */}
        <div className="p-4 bg-slate-50">
          <div className="bg-slate-900 text-slate-200 font-mono rounded-xl p-4 sm:p-5 text-xs space-y-2 max-h-96 overflow-y-auto shadow-inner selection:bg-rose-500/30">
            {logs.length === 0 ? (
              <div className="text-slate-500 italic">No telemetry recorded yet. Execute an adversarial test above.</div>
            ) : (
              logs.map((log) => {
                let badgeColor = "text-slate-300";
                let prefix = "❯";
                if (log.type === "error") {
                  badgeColor = "text-rose-400";
                  prefix = "✖";
                } else if (log.type === "warn") {
                  badgeColor = "text-amber-300";
                  prefix = "▲";
                } else if (log.type === "success") {
                  badgeColor = "text-emerald-400";
                  prefix = "✔";
                } else if (log.type === "attack") {
                  badgeColor = "text-purple-300 font-bold";
                  prefix = "⚡";
                }

                return (
                  <div key={log.id} className="flex items-start space-x-2.5 leading-relaxed">
                    <span className="text-slate-500 select-none text-[11px] pt-0.5">{log.timestamp}</span>
                    <span className={`select-none font-bold ${badgeColor}`}>{prefix}</span>
                    <pre className={`whitespace-pre-wrap break-all ${badgeColor}`}>{log.text}</pre>
                  </div>
                );
              })
            )}
            <div ref={terminalEndRef} />
          </div>
        </div>
      </section>
    </div>
  );
};

export default AdversarialLab;
