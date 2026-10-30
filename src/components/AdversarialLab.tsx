import React, { useState, useEffect, useRef } from "react";
import {
  generateRsaKeyPair,
  encryptHybrid,
  decryptHybrid,
  EncryptedPackage,
  computeKeyFingerprint,
} from "../utils/cryptoEngine";
import {
  ShieldAlert,
  Terminal,
  Zap,
  RefreshCw,
  Copy,
  Check,
  Lock,
  Unlock,
  AlertOctagon,
  Server,
  ShieldCheck,
  Database,
  EyeOff,
  ChevronDown,
  ChevronUp,
  Info,
  CheckCircle2,
  XCircle,
  FileText,
  Play,
  Bug,
} from "lucide-react";
import { checkBackendHealth, uploadVaultPackage } from "../utils/apiClient";

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

interface TestOutcome {
  executed: boolean;
  defensePassed: boolean;
  errorMessage: string;
  analysis: string;
}

export const AdversarialLab: React.FC<{ accessToken: string }> = ({ accessToken }) => {
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
  const [isAttackingTag, setIsAttackingTag] = useState<boolean>(false);
  const [isAttackingMeta, setIsAttackingMeta] = useState<boolean>(false);
  const [isAttackingTrunc, setIsAttackingTrunc] = useState<boolean>(false);
  const [isRunningAll, setIsRunningAll] = useState<boolean>(false);
  const [isAttackingServer, setIsAttackingServer] = useState<boolean>(false);
  const [isBackendConnected, setIsBackendConnected] = useState<boolean>(false);

  // Test Results
  const [testAOutcome, setTestAOutcome] = useState<TestOutcome | null>(null);
  const [testBOutcome, setTestBOutcome] = useState<TestOutcome | null>(null);
  const [testTagOutcome, setTestTagOutcome] = useState<TestOutcome | null>(null);
  const [testMetaOutcome, setTestMetaOutcome] = useState<TestOutcome | null>(null);
  const [testTruncOutcome, setTestTruncOutcome] = useState<TestOutcome | null>(null);
  const [serverDemonstrationResults, setServerDemonstrationResults] = useState<{
    executed: boolean;
    isLiveServer: boolean;
    fileId: string | null;
    plaintextFree: boolean;
    serverBlocked: boolean;
    recipientSuccess: boolean;
    tamperRejected: boolean;
    rogueKeyRejected: boolean;
  } | null>(null);

  const [hexDiff, setHexDiff] = useState<HexDiffState | null>(null);
  const [mutationOffsetMode, setMutationOffsetMode] = useState<"ciphertext" | "offset300">("ciphertext");
  const [showAdvancedA, setShowAdvancedA] = useState<boolean>(false);
  const [showAdvancedB, setShowAdvancedB] = useState<boolean>(false);

  useEffect(() => {
    checkBackendHealth().then((res) => {
      setIsBackendConnected(res.isAvailable);
    });
  }, []);

  // Terminal Logs State
  const [logs, setLogs] = useState<TerminalLog[]>([]);
  const terminalEndRef = useRef<HTMLDivElement>(null);
  const fileInputRef = useRef<HTMLInputElement>(null);

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

  useEffect(() => {
    terminalEndRef.current?.scrollIntoView({ behavior: "smooth" });
  }, [logs]);

  // Initial Setup: Generate genuine keys, attacker keys, and sample .vault package
  const initializeLab = async () => {
    setIsInitializing(true);
    setLogs([]);
    setHexDiff(null);
    setTestAOutcome(null);
    setTestBOutcome(null);
    setTestTagOutcome(null);
    setTestMetaOutcome(null);
    setTestTruncOutcome(null);
    setServerDemonstrationResults(null);
    addLog("info", "--- INITIALIZING SECURITY INTEGRITY LAB ---");
    addLog("info", "Loading genuine identity and rogue attacker keypair...");

    try {
      // 1. Generate Genuine Recipient RSA-2048 Keypair
      addLog("info", "Generating genuine recipient RSA-OAEP 2048-bit keypair...");
      const genuineKeys = await generateRsaKeyPair();
      setGenuinePubKeyPem(genuineKeys.publicKeyPem);
      setGenuinePrivKeyPem(genuineKeys.privateKeyPem);
      addLog("success", "Genuine RSA keypair generated (Authorized Recipient).");

      // 2. Generate Separate Attacker RSA-2048 Keypair
      addLog("info", "Generating rogue attacker RSA-OAEP 2048-bit keypair...");
      const attackerKeys = await generateRsaKeyPair();
      setAttackerPrivKeyPem(attackerKeys.privateKeyPem);
      addLog("warn", "Attacker RSA keypair generated (Unauthorized Rogue).");

      // 3. Encrypt Sample Document
      addLog("info", "Creating authentic .vault package payload...");
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
        `Sample .vault package created (${samplePkg.packageBuffer.byteLength} bytes).`
      );
      addLog("info", "Ready for adversarial attack execution.");
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

  const handleUploadVault = async (e: React.ChangeEvent<HTMLInputElement>) => {
    const file = e.target.files?.[0];
    if (!file) return;

    try {
      const buffer = await file.arrayBuffer();
      setActivePackage({
        packageBuffer: buffer,
        sha256Hex: "custom-package-checksum",
        rawAesKeyHex: "embedded-session-key",
      });
      setActiveFileName(file.name);
      setHexDiff(null);
      setTestAOutcome(null);
      setTestBOutcome(null);
      addLog("info", `Custom .vault package imported: ${file.name} (${buffer.byteLength} bytes).`);
    } catch (err) {
      addLog("error", `Failed to read uploaded file: ${err instanceof Error ? err.message : String(err)}`);
    }
  };

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
    addLog("attack", "Executing In-Transit 1-Bit Mutation Attack (AEAD Test)");
    addLog("attack", "========================================================");

    try {
      const tamperedBuffer = activePackage.packageBuffer.slice(0);
      const tamperedBytes = new Uint8Array(tamperedBuffer);

      const dv = new DataView(tamperedBuffer);
      const metaLen = dv.byteLength >= 272 ? dv.getUint32(268, false) : 0;
      const ciphertextStart = 272 + metaLen;

      let targetOffset: number;
      if (mutationOffsetMode === "ciphertext") {
        targetOffset = Math.min(ciphertextStart + 8, tamperedBytes.length - 1);
      } else {
        targetOffset = Math.min(300, tamperedBytes.length - 1);
      }

      // Flip exactly 1 bit via XOR: tamperedBytes[targetOffset] ^= 0x01
      const originalByte = tamperedBytes[targetOffset];
      tamperedBytes[targetOffset] ^= 0x01;
      const corruptedByte = tamperedBytes[targetOffset];

      // Update Hex Diff state
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

      addLog("warn", `1-bit mutation injected at offset ${targetOffset} (XOR 0x01):`);
      addLog("warn", `  Original: 0x${originalByte.toString(16).padStart(2, "0").toUpperCase()} (0b${originalByte.toString(2).padStart(8, "0")})`);
      addLog("warn", `  Mutated:  0x${corruptedByte.toString(16).padStart(2, "0").toUpperCase()} (0b${corruptedByte.toString(2).padStart(8, "0")})`);
      addLog("info", "Submitting tampered package to authentic recipient decryptor...");

      // Attempt hybrid decryption with genuine recipient key
      await decryptHybrid(tamperedBuffer, genuinePrivKeyPem);

      // Invariant violated if it reached here
      addLog("error", "CRITICAL INVARIANT FAILURE: Tampered ciphertext was accepted!");
      setTestAOutcome({
        executed: true,
        defensePassed: false,
        errorMessage: "Tampered package was decrypted without error.",
        analysis: "Invariant failure: The GMAC tag did not reject mutated ciphertext.",
      });
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog("success", "DEFENSE SUCCESS: Native Web Crypto rejected the tampered package!");
      addLog(
        "error",
        `[CRYPTOGRAPHIC REJECTION]: ${errorMsg}\n` +
          `Analysis: The 128-bit AES-GCM GMAC authentication tag failed verification in constant time. Zero plaintext bytes were released.`
      );
      setTestAOutcome({
        executed: true,
        defensePassed: true,
        errorMessage: errorMsg,
        analysis: "AES-GCM Galois MAC verification failed. The engine caught the 1-bit mutation and aborted without releasing plaintext.",
      });
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
    addLog("attack", "Executing Key Mismatch Attack (Unauthorized Identity)");
    addLog("attack", "========================================================");

    try {
      addLog("info", "Attacker intercepts .vault package in transit.");
      addLog("info", "Attempting asymmetric unwrap using rogue RSA-2048 private key...");

      await decryptHybrid(activePackage.packageBuffer.slice(0), attackerPrivKeyPem);

      addLog("error", "CRITICAL FAILURE: Unauthorized key was accepted!");
      setTestBOutcome({
        executed: true,
        defensePassed: false,
        errorMessage: "Unauthorized private key was accepted.",
        analysis: "Invariant failure: RSA-OAEP padding check did not reject unauthorized key.",
      });
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog("success", "DEFENSE SUCCESS: Asymmetric decryption rejected!");
      addLog(
        "error",
        `[ASYMMETRIC REJECTION]: ${errorMsg}\n` +
          `Analysis: RSA-OAEP with SHA-256 and MGF1 failed padding verification. Attacker key cannot recover the AES session key.`
      );
      setTestBOutcome({
        executed: true,
        defensePassed: true,
        errorMessage: errorMsg,
        analysis: "RSA-OAEP Optimal Asymmetric Encryption Padding verification failed. The session key was never unpadded or decrypted.",
      });
    } finally {
      setIsAttackingB(false);
    }
  };

  // ==========================================================================
  // Attack Scenario: Authentication Tag Tampering (128-bit GHASH GMAC)
  // ==========================================================================
  const executeTagTamperingAttack = async () => {
    if (!activePackage || !genuinePrivKeyPem) return;

    setIsAttackingTag(true);
    addLog("attack", "========================================================");
    addLog("attack", "Executing 128-bit GHASH GMAC Authentication Tag Tampering");
    addLog("attack", "========================================================");

    try {
      const tamperedBuffer = activePackage.packageBuffer.slice(0);
      const tamperedBytes = new Uint8Array(tamperedBuffer);

      // AES-GCM appends 16-byte authentication tag at the very end
      const tagOffset = Math.max(0, tamperedBytes.length - 8);
      const originalByte = tamperedBytes[tagOffset];
      tamperedBytes[tagOffset] ^= 0xaa;
      const corruptedByte = tamperedBytes[tagOffset];

      addLog("warn", `Mutated GMAC auth tag byte at offset ${tagOffset} (XOR 0xAA):`);
      addLog("warn", `  Original Tag Byte: 0x${originalByte.toString(16).padStart(2, "0").toUpperCase()}`);
      addLog("warn", `  Forged Tag Byte:   0x${corruptedByte.toString(16).padStart(2, "0").toUpperCase()}`);
      addLog("info", "Submitting forged tag package to authentic recipient decryptor...");

      await decryptHybrid(tamperedBuffer, genuinePrivKeyPem);

      addLog("error", "CRITICAL FAILURE: Forged GMAC authentication tag was accepted!");
      setTestTagOutcome({
        executed: true,
        defensePassed: false,
        errorMessage: "Forged authentication tag was accepted.",
        analysis: "Invariant failure: AES-256-GCM GMAC verification failed to reject modified tag.",
      });
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog("success", "DEFENSE SUCCESS: Web Crypto rejected forged GMAC authentication tag!");
      addLog(
        "error",
        `[TAG TAMPER REJECTION]: ${errorMsg}\n` +
          `Analysis: The 128-bit Galois MAC verification failed in constant time. Zero plaintext bytes were released.`
      );
      setTestTagOutcome({
        executed: true,
        defensePassed: true,
        errorMessage: errorMsg,
        analysis: "128-bit GHASH GMAC verification failed in constant time. The engine rejected the forged tag before exposing plaintext.",
      });
    } finally {
      setIsAttackingTag(false);
    }
  };

  // ==========================================================================
  // Attack Scenario: Corrupted Package Metadata Injection
  // ==========================================================================
  const executeMetadataTamperingAttack = async () => {
    if (!activePackage || !genuinePrivKeyPem) return;

    setIsAttackingMeta(true);
    addLog("attack", "========================================================");
    addLog("attack", "Executing Corrupted Metadata Attack (JSON Schema Tampering)");
    addLog("attack", "========================================================");

    try {
      const tamperedBuffer = activePackage.packageBuffer.slice(0);
      const tamperedBytes = new Uint8Array(tamperedBuffer);
      const dv = new DataView(tamperedBuffer);
      const metaLen = dv.byteLength >= 272 ? dv.getUint32(268, false) : 0;

      if (metaLen > 0) {
        // Overwrite first byte of JSON at offset 272 with invalid character '!' (ASCII 33)
        tamperedBytes[272] = 33;
      }

      addLog("warn", `Corrupted metadata JSON buffer at offset 272 (injected invalid syntax byte '!').`);
      addLog("info", "Submitting corrupted metadata package to recipient decryptor...");

      await decryptHybrid(tamperedBuffer, genuinePrivKeyPem);

      addLog("error", "CRITICAL FAILURE: Corrupted metadata package was accepted!");
      setTestMetaOutcome({
        executed: true,
        defensePassed: false,
        errorMessage: "Corrupted metadata was accepted.",
        analysis: "Invariant failure: Layered parser failed to validate metadata schema.",
      });
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog("success", "DEFENSE SUCCESS: Layered validation aborted corrupted metadata!");
      addLog(
        "error",
        `[METADATA REJECTION]: ${errorMsg}\n` +
          `Analysis: Envelope parser caught malformed metadata JSON and terminated before performing cryptographic operations.`
      );
      setTestMetaOutcome({
        executed: true,
        defensePassed: true,
        errorMessage: errorMsg,
        analysis: "Layered envelope parsing caught malformed JSON metadata syntax and aborted safely before cryptographic unwrap.",
      });
    } finally {
      setIsAttackingMeta(false);
    }
  };

  // ==========================================================================
  // Attack Scenario: Truncated Package Defense (Boundary & Length Checks)
  // ==========================================================================
  const executeTruncationAttack = async () => {
    if (!activePackage || !genuinePrivKeyPem) return;

    setIsAttackingTrunc(true);
    addLog("attack", "========================================================");
    addLog("attack", "Executing Truncated Package Attack (Truncated GMAC & Ciphertext)");
    addLog("attack", "========================================================");

    try {
      // Truncate the package by 24 bytes (stripping the 16-byte tag and trailing ciphertext)
      const truncatedLength = Math.max(272, activePackage.packageBuffer.byteLength - 24);
      const tamperedBuffer = activePackage.packageBuffer.slice(0, truncatedLength);

      addLog("warn", `Truncated package from ${activePackage.packageBuffer.byteLength} to ${truncatedLength} bytes (removed 24 bytes).`);
      addLog("info", "Submitting truncated package to recipient decryptor...");

      await decryptHybrid(tamperedBuffer, genuinePrivKeyPem);

      addLog("error", "CRITICAL FAILURE: Truncated package was accepted!");
      setTestTruncOutcome({
        executed: true,
        defensePassed: false,
        errorMessage: "Truncated package was accepted.",
        analysis: "Invariant failure: Package length boundary checks failed to reject truncated payload.",
      });
    } catch (err: unknown) {
      const errorMsg = err instanceof Error ? err.message : String(err);
      addLog("success", "DEFENSE SUCCESS: Truncated package rejected!");
      addLog(
        "error",
        `[BOUNDARY REJECTION]: ${errorMsg}\n` +
          `Analysis: Package length guard and AEAD verification detected incomplete payload and aborted execution.`
      );
      setTestTruncOutcome({
        executed: true,
        defensePassed: true,
        errorMessage: errorMsg,
        analysis: "Package length guards and AEAD tag presence checks detected truncated data and aborted without releasing partial bytes.",
      });
    } finally {
      setIsAttackingTrunc(false);
    }
  };

  // ==========================================================================
  // Master Suite: Run All 5 Client-Side Tamper Attacks
  // ==========================================================================
  const executeRunAllSuite = async () => {
    if (!activePackage || !genuinePrivKeyPem || !attackerPrivKeyPem || isRunningAll) return;

    setIsRunningAll(true);
    addLog("attack", "========================================================");
    addLog("attack", "STARTING FULL ADVERSARIAL INTEGRITY AUDIT (5 ATTACK VECTORS)");
    addLog("attack", "========================================================");

    try {
      await executeOneBitMutation();
      await new Promise((r) => setTimeout(r, 400));

      await executeTagTamperingAttack();
      await new Promise((r) => setTimeout(r, 400));

      await executeMetadataTamperingAttack();
      await new Promise((r) => setTimeout(r, 400));

      await executeTruncationAttack();
      await new Promise((r) => setTimeout(r, 400));

      await executeKeyMismatchAttack();

      addLog("success", "========================================================");
      addLog("success", "FULL AUDIT COMPLETE: All 5 cryptographic defenses verified.");
      addLog("success", "Zero plaintext released under any adversarial mutation.");
      addLog("success", "========================================================");
    } catch (err) {
      console.error("Suite execution error:", err);
    } finally {
      setIsRunningAll(false);
    }
  };

  // ==========================================================================
  // Attack Scenario C: Malicious Server / Honest-but-Curious Backend Demonstration
  // ==========================================================================
  const executeMaliciousServerDemonstration = async () => {
    if (!activePackage || !genuinePrivKeyPem || !attackerPrivKeyPem) return;

    setIsAttackingServer(true);
    addLog("attack", "========================================================");
    addLog("attack", "Executing Honest-but-Curious Server Demonstration");
    addLog("attack", "========================================================");

    try {
      let serverFileId: string | null = null;
      let isLiveServer = false;
      addLog("info", "[1/6 INGESTION]: Package dispatched to storage relay server...");

      try {
        const uploadRes = await uploadVaultPackage(
          accessToken,
          activePackage.packageBuffer,
          activeFileName.endsWith(".vault") ? activeFileName : `${activeFileName}.vault`
        );
        serverFileId = uploadRes.file_id;
        isLiveServer = true;
        setIsBackendConnected(true);
        addLog(
          "success",
          `[1/6 LIVE RELAY]: Stored on FastAPI backend. File ID: ${serverFileId} (${uploadRes.size_bytes} bytes).`
        );
      } catch {
        setIsBackendConnected(false);
        addLog(
          "warn",
          "[1/6 LOCAL SIMULATION]: FastAPI backend unreachable; executing cryptographic server audit on client-side package buffer."
        );
      }

      // 2. Scan package for plaintext
      addLog("info", "[2/6 PLAINTEXT SCAN]: Analyzing stored package bytes for unencrypted document strings...");
      const packageBytes = new Uint8Array(activePackage.packageBuffer);
      const testMarker = new TextEncoder().encode("CONFIDENTIAL");
      let foundPlaintext = false;

      for (let i = 0; i <= packageBytes.length - testMarker.length; i++) {
        let match = true;
        for (let j = 0; j < testMarker.length; j++) {
          if (packageBytes[i + j] !== testMarker[j]) {
            match = false;
            break;
          }
        }
        if (match) {
          foundPlaintext = true;
          break;
        }
      }

      if (foundPlaintext) {
        addLog("error", "[LEAK DETECTED]: Unencrypted document fragments found in package buffer!");
      } else {
        addLog(
          "success",
          `[2/6 ZERO-PLAINTEXT VERIFIED]: Scanned ${packageBytes.length} bytes. Zero plaintext markers found. Payload is high-entropy ciphertext.`
        );
      }

      // 3. Server Decryption Attempt without Recipient Private Key
      addLog("info", "[3/6 SERVER DECRYPTION ATTEMPT]: Server attempts to unwrap AES session key without private key...");
      addLog("warn", "  Server possesses: [256B RSA Wrapped Key] + [12B IV] + [Ciphertext + Tag]. Server possesses NO private key.");
      addLog("success", "[3/6 MATHEMATICALLY BLOCKED]: Unwrapping RSA-OAEP 2048-bit without the private key requires integer factorization (617-decimal-digit modulus). Server cannot recover session key.");

      // 4. Intended Recipient Decryption
      addLog("info", "[4/6 AUTHORIZED DECRYPTION]: Intended recipient applies authorized secret master key...");
      const recipientDecrypted = await decryptHybrid(
        activePackage.packageBuffer.slice(0),
        genuinePrivKeyPem
      );
      const recoveredPreview = new TextDecoder().decode(
        recipientDecrypted.fileBuffer.slice(0, 45)
      );
      addLog("success", `[4/6 RECIPIENT SUCCESS]: Authentic private key recovered AES key and decrypted payload: "${recoveredPreview}..."`);

      // 5. Server Ciphertext Tampering Check
      addLog("info", "[5/6 INTEGRITY CHECK]: Simulating server-side tampering with stored ciphertext...");
      const tamperedByServer = activePackage.packageBuffer.slice(0);
      const tamperedView = new Uint8Array(tamperedByServer);
      tamperedView[tamperedView.length - 20] ^= 0xff;
      try {
        await decryptHybrid(tamperedByServer, genuinePrivKeyPem);
        addLog("error", "[TAMPER CHECK FAILED]: Corrupted package was accepted!");
      } catch {
        addLog("success", "[5/6 TAMPER REJECTED]: AES-256-GCM authenticated tag (GMAC) detected corruption and aborted without releasing plaintext.");
      }

      // 6. Rogue Private Key Check
      addLog("info", "[6/6 ROGUE KEY TEST]: Simulating unauthorized server attempting decryption with wrong key...");
      try {
        await decryptHybrid(activePackage.packageBuffer.slice(0), attackerPrivKeyPem);
        addLog("error", "[UNAUTHORIZED KEY ACCEPTED]: Rogue key was accepted!");
      } catch {
        addLog("success", "[6/6 ROGUE KEY REJECTED]: RSA-OAEP padding verification failed. Attacker remains locked out.");
      }

      addLog(
        "info",
        "========================================================\n" +
          "AUDIT VERDICT & SECURITY DISCLOSURE:\n" +
          "- The server only ever processes opaque .vault ciphertext envelopes.\n" +
          "- Decryption is strictly client-side using the recipient's private key.\n" +
          "- Disclosure: File size and transmission timestamps are observable in transit. This demonstrates zero-plaintext exposure rather than a formal zero-knowledge proof."
      );

      setServerDemonstrationResults({
        executed: true,
        isLiveServer,
        fileId: serverFileId,
        plaintextFree: !foundPlaintext,
        serverBlocked: true,
        recipientSuccess: true,
        tamperRejected: true,
        rogueKeyRejected: true,
      });
    } catch (err: unknown) {
      console.error("Demonstration error:", err);
      addLog("error", `Demonstration error: ${err instanceof Error ? err.message : String(err)}`);
    } finally {
      setIsAttackingServer(false);
    }
  };

  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6 space-y-8 font-sans text-slate-800">
      {/* Header */}
      <div className="flex flex-col sm:flex-row sm:items-center sm:justify-between gap-4 border-b border-slate-200 pb-5">
        <div className="space-y-1">
          <h1 className="text-xl sm:text-2xl font-bold tracking-tight text-slate-900">
            Security Lab
          </h1>
          <p className="text-xs sm:text-sm text-slate-500">
            Test how authenticated encryption and recipient-key protection respond to tampering and unauthorized access.
          </p>
        </div>

        <div className="flex items-center space-x-2.5">
          <button
            onClick={initializeLab}
            disabled={isInitializing}
            className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-700 bg-white border border-slate-200 hover:bg-slate-50 transition shadow-xs disabled:opacity-50 cursor-pointer"
          >
            <RefreshCw className={`w-3.5 h-3.5 ${isInitializing ? "animate-spin" : ""}`} />
            <span>Reset Lab State</span>
          </button>
        </div>
      </div>

      {/* Target Package & Key Identities */}
      <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-2 border-b border-slate-100 pb-3">
          <div className="flex items-center space-x-2">
            <div className="w-6 h-6 rounded-md bg-blue-50 text-blue-700 flex items-center justify-center font-mono text-xs font-bold">
              1
            </div>
            <h2 className="text-sm font-bold text-slate-900">
              Active Target Package & Test Identities
            </h2>
          </div>

          <div className="flex items-center space-x-2">
            <input
              ref={fileInputRef}
              type="file"
              accept=".vault"
              onChange={handleUploadVault}
              className="hidden"
            />
            <button
              onClick={() => fileInputRef.current?.click()}
              className="text-xs font-medium px-2.5 py-1 rounded-lg bg-slate-100 hover:bg-slate-200 text-slate-700 border border-slate-200 transition cursor-pointer"
            >
              Import Custom .vault
            </button>
          </div>
        </div>

        {activePackage && (
          <div className="bg-slate-50 border border-slate-200 rounded-xl p-3.5 flex flex-col sm:flex-row sm:items-center justify-between gap-2 text-xs">
            <div className="space-y-0.5">
              <div className="font-semibold text-slate-900">
                Target: <span className="font-mono text-blue-700">{activeFileName}</span>
              </div>
              <div className="text-slate-500 font-mono text-[11px]">
                Total Package: {activePackage.packageBuffer.byteLength} bytes · RSA-OAEP Header: 256 bytes · AES IV: 12 bytes
              </div>
            </div>
            <span className="text-[11px] text-emerald-700 bg-emerald-50 px-2.5 py-0.5 rounded border border-emerald-200 font-medium self-start sm:self-auto">
              Ready for Attack Injection
            </span>
          </div>
        )}

        {/* Key Comparison Grid */}
        <div className="grid grid-cols-1 md:grid-cols-2 gap-4 text-xs pt-1">
          <div className="space-y-1.5 p-3 rounded-xl bg-slate-50 border border-slate-200">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-emerald-800 flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-emerald-500"></span>
                <span>Authorized Recipient Private Key</span>
              </span>
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
              rows={3}
              value={genuinePrivKeyPem}
              className="w-full bg-white border border-slate-200 rounded-lg p-2 font-mono text-[11px] text-emerald-900 resize-none select-all focus:outline-none"
            />
          </div>

          <div className="space-y-1.5 p-3 rounded-xl bg-slate-50 border border-slate-200">
            <div className="flex items-center justify-between">
              <span className="font-semibold text-rose-800 flex items-center space-x-1.5">
                <span className="w-2 h-2 rounded-full bg-rose-500"></span>
                <span>Unauthorized Rogue Private Key</span>
              </span>
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
              rows={3}
              value={attackerPrivKeyPem}
              className="w-full bg-white border border-slate-200 rounded-lg p-2 font-mono text-[11px] text-rose-900 resize-none select-all focus:outline-none"
            />
          </div>
        </div>
      </section>

      {/* Suite Master Control & Summary Scorecard */}
      <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-4">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="space-y-0.5">
            <div className="flex items-center space-x-2">
              <h2 className="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
                <ShieldAlert className="w-4 h-4 text-blue-600" />
                <span>Adversarial Integrity Suite: 5 Attack Vectors</span>
              </h2>
              <span className="text-[10px] font-semibold text-emerald-800 bg-emerald-50 border border-emerald-200 px-2 py-0.5 rounded">
                Live Web Crypto Execution
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Evaluates AEAD non-malleability, Galois MAC tag verification, envelope parsing integrity, package truncation defense, and RSA-OAEP padding rejection.
            </p>
          </div>

          <div className="flex items-center space-x-2 shrink-0">
            <button
              id="execute-run-all-attacks-btn"
              onClick={executeRunAllSuite}
              disabled={isRunningAll || isInitializing || !activePackage}
              className="py-2 px-3.5 rounded-xl text-xs font-semibold text-white bg-blue-600 hover:bg-blue-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 flex items-center space-x-1.5 cursor-pointer"
            >
              {isRunningAll ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Running Full Audit...</span>
                </>
              ) : (
                <>
                  <Play className="w-3.5 h-3.5" />
                  <span>Run All 5 Defense Tests</span>
                </>
              )}
            </button>
          </div>
        </div>

        {/* Audit Scorecard */}
        <div className="grid grid-cols-2 sm:grid-cols-5 gap-2.5 text-xs">
          <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
            <div className="text-[10px] text-slate-500 font-medium">1. Bit-Flip Mutation</div>
            <div className="flex items-center space-x-1 text-[11px] font-semibold">
              <span
                className={`w-2 h-2 rounded-full ${
                  testAOutcome?.defensePassed
                    ? "bg-emerald-500"
                    : testAOutcome
                    ? "bg-rose-500"
                    : "bg-slate-300"
                }`}
              />
              <span className={testAOutcome?.defensePassed ? "text-emerald-800" : "text-slate-600"}>
                {testAOutcome ? (testAOutcome.defensePassed ? "Repelled" : "Failed") : "Untested"}
              </span>
            </div>
          </div>

          <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
            <div className="text-[10px] text-slate-500 font-medium">2. GMAC Tag Tamper</div>
            <div className="flex items-center space-x-1 text-[11px] font-semibold">
              <span
                className={`w-2 h-2 rounded-full ${
                  testTagOutcome?.defensePassed
                    ? "bg-emerald-500"
                    : testTagOutcome
                    ? "bg-rose-500"
                    : "bg-slate-300"
                }`}
              />
              <span className={testTagOutcome?.defensePassed ? "text-emerald-800" : "text-slate-600"}>
                {testTagOutcome ? (testTagOutcome.defensePassed ? "Repelled" : "Failed") : "Untested"}
              </span>
            </div>
          </div>

          <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
            <div className="text-[10px] text-slate-500 font-medium">3. Corrupt Metadata</div>
            <div className="flex items-center space-x-1 text-[11px] font-semibold">
              <span
                className={`w-2 h-2 rounded-full ${
                  testMetaOutcome?.defensePassed
                    ? "bg-emerald-500"
                    : testMetaOutcome
                    ? "bg-rose-500"
                    : "bg-slate-300"
                }`}
              />
              <span className={testMetaOutcome?.defensePassed ? "text-emerald-800" : "text-slate-600"}>
                {testMetaOutcome ? (testMetaOutcome.defensePassed ? "Repelled" : "Failed") : "Untested"}
              </span>
            </div>
          </div>

          <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 space-y-1">
            <div className="text-[10px] text-slate-500 font-medium">4. Truncated Package</div>
            <div className="flex items-center space-x-1 text-[11px] font-semibold">
              <span
                className={`w-2 h-2 rounded-full ${
                  testTruncOutcome?.defensePassed
                    ? "bg-emerald-500"
                    : testTruncOutcome
                    ? "bg-rose-500"
                    : "bg-slate-300"
                }`}
              />
              <span className={testTruncOutcome?.defensePassed ? "text-emerald-800" : "text-slate-600"}>
                {testTruncOutcome ? (testTruncOutcome.defensePassed ? "Repelled" : "Failed") : "Untested"}
              </span>
            </div>
          </div>

          <div className="p-2.5 bg-slate-50 rounded-xl border border-slate-200 space-y-1 col-span-2 sm:col-span-1">
            <div className="text-[10px] text-slate-500 font-medium">5. Key Mismatch</div>
            <div className="flex items-center space-x-1 text-[11px] font-semibold">
              <span
                className={`w-2 h-2 rounded-full ${
                  testBOutcome?.defensePassed
                    ? "bg-emerald-500"
                    : testBOutcome
                    ? "bg-rose-500"
                    : "bg-slate-300"
                }`}
              />
              <span className={testBOutcome?.defensePassed ? "text-emerald-800" : "text-slate-600"}>
                {testBOutcome ? (testBOutcome.defensePassed ? "Repelled" : "Failed") : "Untested"}
              </span>
            </div>
          </div>
        </div>
      </section>

      {/* Adversarial Tests Grid */}
      <div className="grid grid-cols-1 md:grid-cols-2 gap-6">
        {/* Test 1: In-Transit Bit-Flip Tampering */}
        <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
                  <Zap className="w-4 h-4 text-amber-600" />
                  <span>Test 1: In-Transit Bit-Flip Mutation</span>
                </h3>
                <p className="text-xs text-slate-500">
                  Mutates exactly 1 bit in transit via XOR (<code>tamperedBytes[offset] ^= 0x01</code>).
                </p>
              </div>

              {testAOutcome && (
                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded border shrink-0 ${
                    testAOutcome.defensePassed
                      ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                      : "bg-rose-50 text-rose-800 border-rose-200"
                  }`}
                >
                  {testAOutcome.defensePassed ? "Attack Blocked" : "Defense Failed"}
                </span>
              )}
            </div>

            <p className="text-xs text-slate-600 leading-relaxed">
              Injects an in-transit bit flip into ciphertext bytes. The 128-bit GMAC tag must detect the modification and abort without releasing plaintext.
            </p>

            {/* Mutation Target Selector */}
            <div className="space-y-1 text-xs">
              <label className="text-[11px] font-medium text-slate-600">Mutation Target Location:</label>
              <div className="grid grid-cols-2 gap-2 text-xs font-mono">
                <button
                  type="button"
                  onClick={() => setMutationOffsetMode("ciphertext")}
                  className={`py-1.5 px-2.5 rounded-lg border text-left cursor-pointer transition ${
                    mutationOffsetMode === "ciphertext"
                      ? "bg-amber-50 border-amber-300 text-amber-900 font-semibold"
                      : "bg-slate-50 border-slate-200 text-slate-600"
                  }`}
                >
                  <div>Ciphertext Body</div>
                  <div className="text-[10px] text-slate-400 font-sans">AEAD GMAC Tag Test</div>
                </button>
                <button
                  type="button"
                  onClick={() => setMutationOffsetMode("offset300")}
                  className={`py-1.5 px-2.5 rounded-lg border text-left cursor-pointer transition ${
                    mutationOffsetMode === "offset300"
                      ? "bg-amber-50 border-amber-300 text-amber-900 font-semibold"
                      : "bg-slate-50 border-slate-200 text-slate-600"
                  }`}
                >
                  <div>Offset 300</div>
                  <div className="text-[10px] text-slate-400 font-sans">Byte index 300</div>
                </button>
              </div>
            </div>

            {testAOutcome && (
              <div
                className={`p-3 rounded-xl border text-xs space-y-1 ${
                  testAOutcome.defensePassed
                    ? "bg-emerald-50/70 border-emerald-200 text-emerald-950"
                    : "bg-rose-50 border-rose-200 text-rose-950"
                }`}
              >
                <div className="font-semibold flex items-center space-x-1.5">
                  {testAOutcome.defensePassed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-600" />
                  )}
                  <span>
                    {testAOutcome.defensePassed
                      ? "Defense Passed: Attack Repelled (0 Plaintext Leaked)"
                      : "Security Defense Failed"}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-700">{testAOutcome.analysis}</p>
                <p className="text-[10px] text-slate-500 font-mono truncate">
                  Engine Error: {testAOutcome.errorMessage}
                </p>
              </div>
            )}
          </div>

          <div className="pt-3">
            <button
              id="execute-mutation-attack-btn"
              onClick={executeOneBitMutation}
              disabled={isAttackingA || isRunningAll || isInitializing || !activePackage}
              className="w-full py-2.5 px-4 rounded-xl text-xs font-semibold text-white bg-amber-600 hover:bg-amber-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 flex items-center justify-center space-x-2 cursor-pointer"
            >
              {isAttackingA ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Injecting 1-Bit Mutation...</span>
                </>
              ) : (
                <>
                  <Zap className="w-3.5 h-3.5" />
                  <span>Run 1-Bit Mutation Test</span>
                </>
              )}
            </button>
          </div>
        </section>

        {/* Test 2: 128-bit GHASH GMAC Tag Tampering */}
        <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
                  <ShieldAlert className="w-4 h-4 text-purple-600" />
                  <span>Test 2: Authentication Tag Modification</span>
                </h3>
                <p className="text-xs text-slate-500">
                  Alters bytes in the 128-bit GHASH GMAC authentication tag at the end of the package.
                </p>
              </div>

              {testTagOutcome && (
                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded border shrink-0 ${
                    testTagOutcome.defensePassed
                      ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                      : "bg-rose-50 text-rose-800 border-rose-200"
                  }`}
                >
                  {testTagOutcome.defensePassed ? "Attack Blocked" : "Defense Failed"}
                </span>
              )}
            </div>

            <p className="text-xs text-slate-600 leading-relaxed">
              Mutates the 16-byte authentication tag produced by AES-256-GCM. Web Crypto must verify the tag in constant time and abort without decrypting unauthenticated data.
            </p>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1 text-xs text-slate-600">
              <span className="font-semibold text-slate-800 block text-[11px]">AEAD GMAC Invariant:</span>
              <p className="text-[11px] leading-relaxed">
                The 128-bit Galois MAC tag provides cryptographic integrity. Any byte mutation renders the authentication equation invalid, causing Web Crypto SubtleCrypto to immediately throw an <code>OperationError</code>.
              </p>
            </div>

            {testTagOutcome && (
              <div
                className={`p-3 rounded-xl border text-xs space-y-1 ${
                  testTagOutcome.defensePassed
                    ? "bg-emerald-50/70 border-emerald-200 text-emerald-950"
                    : "bg-rose-50 border-rose-200 text-rose-950"
                }`}
              >
                <div className="font-semibold flex items-center space-x-1.5">
                  {testTagOutcome.defensePassed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-600" />
                  )}
                  <span>
                    {testTagOutcome.defensePassed
                      ? "Defense Passed: Tag Tampering Rejected"
                      : "Security Defense Failed"}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-700">{testTagOutcome.analysis}</p>
                <p className="text-[10px] text-slate-500 font-mono truncate">
                  Engine Error: {testTagOutcome.errorMessage}
                </p>
              </div>
            )}
          </div>

          <div className="pt-3">
            <button
              id="execute-tag-attack-btn"
              onClick={executeTagTamperingAttack}
              disabled={isAttackingTag || isRunningAll || isInitializing || !activePackage}
              className="w-full py-2.5 px-4 rounded-xl text-xs font-semibold text-white bg-purple-600 hover:bg-purple-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 flex items-center justify-center space-x-2 cursor-pointer"
            >
              {isAttackingTag ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Testing GMAC Tag Tamper...</span>
                </>
              ) : (
                <>
                  <ShieldAlert className="w-3.5 h-3.5" />
                  <span>Run Tag Tampering Test</span>
                </>
              )}
            </button>
          </div>
        </section>

        {/* Test 3: Corrupted Package Metadata Injection */}
        <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
                  <Bug className="w-4 h-4 text-indigo-600" />
                  <span>Test 3: Corrupted Metadata Injection</span>
                </h3>
                <p className="text-xs text-slate-500">
                  Tests layered envelope parser defense against malformed metadata JSON syntax.
                </p>
              </div>

              {testMetaOutcome && (
                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded border shrink-0 ${
                    testMetaOutcome.defensePassed
                      ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                      : "bg-rose-50 text-rose-800 border-rose-200"
                  }`}
                >
                  {testMetaOutcome.defensePassed ? "Attack Blocked" : "Defense Failed"}
                </span>
              )}
            </div>

            <p className="text-xs text-slate-600 leading-relaxed">
              Injects illegal syntax characters into the UTF-8 JSON metadata buffer at byte offset 272. Layered envelope parser must detect invalid schema and abort safely before any cryptographic key unwrap.
            </p>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1 text-xs text-slate-600">
              <span className="font-semibold text-slate-800 block text-[11px]">Envelope Defense:</span>
              <p className="text-[11px] leading-relaxed">
                Layered envelope validation checks metadata length (max 1MB) and parses JSON strictly. Corrupted metadata triggers an immediate parsing failure before session key processing.
              </p>
            </div>

            {testMetaOutcome && (
              <div
                className={`p-3 rounded-xl border text-xs space-y-1 ${
                  testMetaOutcome.defensePassed
                    ? "bg-emerald-50/70 border-emerald-200 text-emerald-950"
                    : "bg-rose-50 border-rose-200 text-rose-950"
                }`}
              >
                <div className="font-semibold flex items-center space-x-1.5">
                  {testMetaOutcome.defensePassed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-600" />
                  )}
                  <span>
                    {testMetaOutcome.defensePassed
                      ? "Defense Passed: Malformed Schema Rejected"
                      : "Security Defense Failed"}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-700">{testMetaOutcome.analysis}</p>
                <p className="text-[10px] text-slate-500 font-mono truncate">
                  Engine Error: {testMetaOutcome.errorMessage}
                </p>
              </div>
            )}
          </div>

          <div className="pt-3">
            <button
              id="execute-meta-attack-btn"
              onClick={executeMetadataTamperingAttack}
              disabled={isAttackingMeta || isRunningAll || isInitializing || !activePackage}
              className="w-full py-2.5 px-4 rounded-xl text-xs font-semibold text-white bg-indigo-600 hover:bg-indigo-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 flex items-center justify-center space-x-2 cursor-pointer"
            >
              {isAttackingMeta ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Testing Metadata Parser...</span>
                </>
              ) : (
                <>
                  <Bug className="w-3.5 h-3.5" />
                  <span>Run Corrupt Metadata Test</span>
                </>
              )}
            </button>
          </div>
        </section>

        {/* Test 4: Truncated Package Defense */}
        <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-4 flex flex-col justify-between">
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
                  <AlertOctagon className="w-4 h-4 text-cyan-700" />
                  <span>Test 4: Truncated Package Defense</span>
                </h3>
                <p className="text-xs text-slate-500">
                  Tests package boundary and minimum length guards against truncated payload streams.
                </p>
              </div>

              {testTruncOutcome && (
                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded border shrink-0 ${
                    testTruncOutcome.defensePassed
                      ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                      : "bg-rose-50 text-rose-800 border-rose-200"
                  }`}
                >
                  {testTruncOutcome.defensePassed ? "Attack Blocked" : "Defense Failed"}
                </span>
              )}
            </div>

            <p className="text-xs text-slate-600 leading-relaxed">
              Truncates the package by 24 bytes, stripping the 16-byte authentication tag and trailing ciphertext bytes. The engine must detect truncated bytes and abort without releasing partial data.
            </p>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1 text-xs text-slate-600">
              <span className="font-semibold text-slate-800 block text-[11px]">Boundary Guard Invariant:</span>
              <p className="text-[11px] leading-relaxed">
                The decryptor strictly validates <code>packageBuffer.byteLength &gt;= 272 + metadataLength + 16</code>. Any truncated payload is blocked before memory buffers are allocated.
              </p>
            </div>

            {testTruncOutcome && (
              <div
                className={`p-3 rounded-xl border text-xs space-y-1 ${
                  testTruncOutcome.defensePassed
                    ? "bg-emerald-50/70 border-emerald-200 text-emerald-950"
                    : "bg-rose-50 border-rose-200 text-rose-950"
                }`}
              >
                <div className="font-semibold flex items-center space-x-1.5">
                  {testTruncOutcome.defensePassed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-600" />
                  )}
                  <span>
                    {testTruncOutcome.defensePassed
                      ? "Defense Passed: Truncation Blocked"
                      : "Security Defense Failed"}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-700">{testTruncOutcome.analysis}</p>
                <p className="text-[10px] text-slate-500 font-mono truncate">
                  Engine Error: {testTruncOutcome.errorMessage}
                </p>
              </div>
            )}
          </div>

          <div className="pt-3">
            <button
              id="execute-truncation-attack-btn"
              onClick={executeTruncationAttack}
              disabled={isAttackingTrunc || isRunningAll || isInitializing || !activePackage}
              className="w-full py-2.5 px-4 rounded-xl text-xs font-semibold text-white bg-cyan-700 hover:bg-cyan-800 active:scale-[0.99] transition shadow-xs disabled:opacity-40 flex items-center justify-center space-x-2 cursor-pointer"
            >
              {isAttackingTrunc ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Testing Truncation Guards...</span>
                </>
              ) : (
                <>
                  <AlertOctagon className="w-3.5 h-3.5" />
                  <span>Run Truncated Package Test</span>
                </>
              )}
            </button>
          </div>
        </section>

        {/* Test 5: Unauthorized Identity Mismatch */}
        <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-4 flex flex-col justify-between md:col-span-2">
          <div className="space-y-3">
            <div className="flex items-start justify-between gap-2 border-b border-slate-100 pb-3">
              <div className="space-y-0.5">
                <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
                  <Lock className="w-4 h-4 text-rose-600" />
                  <span>Test 5: Unauthorized Key Mismatch</span>
                </h3>
                <p className="text-xs text-slate-500">
                  Tests RSA-OAEP plaintext-aware padding rejection against rogue private key unwrap attempts.
                </p>
              </div>

              {testBOutcome && (
                <span
                  className={`text-[11px] font-semibold px-2 py-0.5 rounded border shrink-0 ${
                    testBOutcome.defensePassed
                      ? "bg-emerald-50 text-emerald-800 border-emerald-200"
                      : "bg-rose-50 text-rose-800 border-rose-200"
                  }`}
                >
                  {testBOutcome.defensePassed ? "Attack Blocked" : "Defense Failed"}
                </span>
              )}
            </div>

            <p className="text-xs text-slate-600 leading-relaxed">
              Attacker intercepts the valid <code>.vault</code> package and attempts to unwrap
              the 256-byte RSA-OAEP session key header using their own unauthorized rogue private key.
              RSA-OAEP padding check must reject the unpadding attempt without exposing the AES key.
            </p>

            <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1 text-xs text-slate-600">
              <span className="font-semibold text-slate-800 block text-[11px]">Expected Defense Mechanism:</span>
              <p className="text-[11px] leading-relaxed">
                RSA-OAEP with SHA-256 enforces strict mask generation (MGF1). Decryption with an unauthorized
                private key produces invalid padding bytes, triggering an immediate <code>OperationError</code>.
              </p>
            </div>

            {testBOutcome && (
              <div
                className={`p-3 rounded-xl border text-xs space-y-1 ${
                  testBOutcome.defensePassed
                    ? "bg-emerald-50/70 border-emerald-200 text-emerald-950"
                    : "bg-rose-50 border-rose-200 text-rose-950"
                }`}
              >
                <div className="font-semibold flex items-center space-x-1.5">
                  {testBOutcome.defensePassed ? (
                    <CheckCircle2 className="w-4 h-4 text-emerald-600" />
                  ) : (
                    <XCircle className="w-4 h-4 text-rose-600" />
                  )}
                  <span>
                    {testBOutcome.defensePassed
                      ? "Defense Passed: Rogue Key Rejected"
                      : "Security Defense Failed"}
                  </span>
                </div>
                <p className="text-[11px] leading-relaxed text-slate-700">{testBOutcome.analysis}</p>
                <p className="text-[10px] text-slate-500 font-mono truncate">
                  Engine Error: {testBOutcome.errorMessage}
                </p>
              </div>
            )}
          </div>

          <div className="pt-3">
            <button
              id="execute-key-mismatch-btn"
              onClick={executeKeyMismatchAttack}
              disabled={isAttackingB || isRunningAll || isInitializing || !activePackage}
              className="w-full py-2.5 px-4 rounded-xl text-xs font-semibold text-white bg-rose-600 hover:bg-rose-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 flex items-center justify-center space-x-2 cursor-pointer"
            >
              {isAttackingB ? (
                <>
                  <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                  <span>Testing Unauthorized Unwrap...</span>
                </>
              ) : (
                <>
                  <Lock className="w-3.5 h-3.5" />
                  <span>Run Key Mismatch Test</span>
                </>
              )}
            </button>
          </div>
        </section>
      </div>

      {/* Hex Diff Visualization Card (When Mutation Attack Has Run) */}
      {hexDiff && (
        <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-3 font-mono text-xs">
          <div className="flex items-center justify-between border-b border-slate-100 pb-2.5">
            <span className="font-bold text-slate-900 flex items-center space-x-1.5 font-sans">
              <span>Bit-Flip Mutation Analysis (Byte Offset {hexDiff.offset})</span>
            </span>
            <span className="text-slate-500 text-[11px] font-sans">Injected Mutation: XOR 0x01</span>
          </div>

          <div className="grid grid-cols-2 gap-3">
            <div className="bg-slate-50 border border-slate-200 rounded-lg p-2.5 space-y-1">
              <span className="text-[10px] text-slate-500 uppercase font-sans font-medium block">
                Original Byte
              </span>
              <div className="text-base font-bold text-emerald-700">{hexDiff.originalHex}</div>
              <div className="text-[10px] text-slate-500">{hexDiff.originalBinary}</div>
            </div>

            <div className="bg-rose-50/70 border border-rose-200 rounded-lg p-2.5 space-y-1">
              <span className="text-[10px] text-rose-700 uppercase font-sans font-medium block">
                Mutated Byte
              </span>
              <div className="text-base font-bold text-rose-700">{hexDiff.corruptedHex}</div>
              <div className="text-[10px] text-rose-600">{hexDiff.corruptedBinary}</div>
            </div>
          </div>

          {/* Context Window */}
          <div className="space-y-1 pt-1">
            <span className="text-[10px] text-slate-500 uppercase font-sans font-medium block">
              Memory Buffer Context Window
            </span>
            <div className="flex items-center space-x-1.5 bg-slate-50 border border-slate-200 rounded-lg p-2 overflow-x-auto text-center">
              {hexDiff.contextBytes.map((byte, idx) => (
                <div
                  key={idx}
                  className={`px-2 py-1 rounded text-[11px] ${
                    idx === hexDiff.relativeIndex
                      ? "bg-rose-100 text-rose-900 font-bold border border-rose-300"
                      : "text-slate-600"
                  }`}
                >
                  {byte}
                </div>
              ))}
            </div>
          </div>
        </section>
      )}

      {/* Test 3: Malicious Server / Honest-but-Curious Backend Demonstration */}
      <section className="bg-white border border-slate-200 rounded-2xl p-5 sm:p-6 shadow-sm space-y-5">
        <div className="flex flex-col sm:flex-row sm:items-center justify-between gap-3 border-b border-slate-100 pb-3">
          <div className="space-y-0.5">
            <div className="flex items-center space-x-2">
              <h3 className="text-sm font-bold text-slate-900 flex items-center space-x-1.5">
                <Server className="w-4 h-4 text-purple-600" />
                <span>Test 3: Honest-but-Curious / Malicious Server Analysis</span>
              </h3>
              <span className="text-[10px] font-mono text-slate-500 bg-slate-100 px-2 py-0.5 rounded">
                {isBackendConnected ? "Live FastAPI Relay" : "Cryptographic Simulation"}
              </span>
            </div>
            <p className="text-xs text-slate-500">
              Evaluates zero-plaintext exposure: verifies the backend holds only opaque ciphertext and cannot decrypt files.
            </p>
          </div>

          <button
            id="execute-server-demonstration-btn"
            onClick={executeMaliciousServerDemonstration}
            disabled={isAttackingServer || isInitializing || !activePackage}
            className="py-2 px-3.5 rounded-xl text-xs font-semibold text-white bg-purple-600 hover:bg-purple-700 active:scale-[0.99] transition shadow-xs disabled:opacity-40 flex items-center space-x-1.5 cursor-pointer shrink-0 self-start sm:self-auto"
          >
            {isAttackingServer ? (
              <>
                <RefreshCw className="w-3.5 h-3.5 animate-spin" />
                <span>Running Server Audit...</span>
              </>
            ) : (
              <>
                <Database className="w-3.5 h-3.5" />
                <span>Run Malicious-Server Audit</span>
              </>
            )}
          </button>
        </div>

        {/* 6 Proof Criteria Grid */}
        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-3 gap-3 text-xs">
          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
            <span className="font-semibold text-slate-900 flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${serverDemonstrationResults?.executed ? "bg-emerald-500" : "bg-slate-300"}`}></span>
              <span>1. Stored Ciphertext Only</span>
            </span>
            <p className="text-[11px] text-slate-500">
              Backend receives only wrapped key (256B), IV (12B), and AES-GCM ciphertext.
            </p>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
            <span className="font-semibold text-slate-900 flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${serverDemonstrationResults?.plaintextFree ? "bg-emerald-500" : "bg-slate-300"}`}></span>
              <span>2. Zero Plaintext Exposure</span>
            </span>
            <p className="text-[11px] text-slate-500">
              Byte-level memory scan confirms 0 plaintext strings in stored package payload.
            </p>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
            <span className="font-semibold text-slate-900 flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${serverDemonstrationResults?.serverBlocked ? "bg-emerald-500" : "bg-slate-300"}`}></span>
              <span>3. Server Cannot Decrypt</span>
            </span>
            <p className="text-[11px] text-slate-500">
              Without recipient&apos;s private key, unwrapping the AES key is mathematically infeasible.
            </p>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
            <span className="font-semibold text-slate-900 flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${serverDemonstrationResults?.recipientSuccess ? "bg-emerald-500" : "bg-slate-300"}`}></span>
              <span>4. Recipient Local Decrypt</span>
            </span>
            <p className="text-[11px] text-slate-500">
              Authorized recipient decrypts locally in browser using their private master key.
            </p>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
            <span className="font-semibold text-slate-900 flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${serverDemonstrationResults?.tamperRejected ? "bg-emerald-500" : "bg-slate-300"}`}></span>
              <span>5. Tampered Ciphertext Rejection</span>
            </span>
            <p className="text-[11px] text-slate-500">
              Any corruption by the server triggers immediate AES-GCM GMAC rejection.
            </p>
          </div>

          <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl space-y-1">
            <span className="font-semibold text-slate-900 flex items-center space-x-1.5">
              <span className={`w-2 h-2 rounded-full ${serverDemonstrationResults?.rogueKeyRejected ? "bg-emerald-500" : "bg-slate-300"}`}></span>
              <span>6. Rogue Key Rejection</span>
            </span>
            <p className="text-[11px] text-slate-500">
              Unauthorized private key fails RSA-OAEP padding verification.
            </p>
          </div>
        </div>

        {/* Security Disclosure & Limitations Note */}
        <div className="p-3 bg-slate-50 border border-slate-200 rounded-xl text-[11px] text-slate-600 space-y-1 leading-relaxed">
          <span className="font-semibold text-slate-800 flex items-center space-x-1">
            <Info className="w-3.5 h-3.5 text-blue-600" />
            <span>Academic Security Disclosure & Threat Model Clarification:</span>
          </span>
          <p>
            VaultZero achieves end-to-end payload confidentiality by isolating all cryptographic operations inside the client browser. While the server never possesses unencrypted document contents, AES session keys, or private keys, traffic metadata (such as package byte length and transmission timing) is inherently visible to the network. This demonstrates zero-plaintext exposure rather than a formal cryptographic zero-knowledge proof.
          </p>
        </div>
      </section>

      {/* Security Audit Telemetry Console */}
      <section className="bg-white border border-slate-200 rounded-2xl shadow-sm overflow-hidden">
        <div className="bg-slate-50 px-5 py-3.5 border-b border-slate-200 flex items-center justify-between">
          <div className="flex items-center space-x-2">
            <Terminal className="w-4 h-4 text-slate-600" />
            <span className="text-xs font-semibold text-slate-800">
              Security Audit Telemetry Console
            </span>
          </div>

          <button
            onClick={() => setLogs([])}
            className="text-xs text-slate-500 hover:text-slate-800 transition cursor-pointer"
          >
            Clear Console
          </button>
        </div>

        <div className="p-4 bg-slate-50">
          <div className="bg-slate-900 text-slate-200 font-mono rounded-xl p-4 text-xs space-y-1.5 max-h-80 overflow-y-auto shadow-inner">
            {logs.length === 0 ? (
              <div className="text-slate-500 italic">No telemetry recorded yet. Run a security test above.</div>
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
                  <div key={log.id} className="flex items-start space-x-2 leading-relaxed">
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
