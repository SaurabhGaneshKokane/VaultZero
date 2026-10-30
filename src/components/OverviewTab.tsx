import React from "react";
import {
  ShieldCheck,
  Unlock,
  KeyRound,
  FileCheck2,
  Lock,
  ArrowRight,
  Send,
  Download,
  Shield,
  Layers,
  Cpu,
  CheckCircle,
} from "lucide-react";

interface OverviewTabProps {
  onNavigateToSend: () => void;
  onNavigateToUnlock: () => void;
  onNavigateToLab: () => void;
  onNavigateToBenchmarks: () => void;
}

export const OverviewTab: React.FC<OverviewTabProps> = ({
  onNavigateToSend,
  onNavigateToUnlock,
  onNavigateToLab,
  onNavigateToBenchmarks,
}) => {
  return (
    <div className="w-full max-w-5xl mx-auto px-4 sm:px-6 py-6 space-y-10 font-sans text-slate-800">
      {/* Hero Section */}
      <section className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-10 shadow-sm">
        <div className="max-w-3xl space-y-4">
          <div className="inline-flex items-center space-x-2 text-xs font-semibold text-blue-700 bg-blue-50 px-3 py-1 rounded-md border border-blue-100">
            <Lock className="w-3.5 h-3.5 text-blue-600" />
            <span>Client-Side Zero-Knowledge Cryptography</span>
          </div>

          <h1 className="text-2xl sm:text-4xl font-bold tracking-tight text-slate-900 leading-tight">
            Your files. Your keys. Your control.
          </h1>

          <p className="text-sm sm:text-base text-slate-600 leading-relaxed max-w-2xl">
            VaultZero encrypts your documents locally in your browser before they are ever
            stored or transmitted. Only the recipient holding the corresponding private key
            can decrypt and unlock the original payload.
          </p>

          {/* Primary Action Buttons */}
          <div className="pt-3 flex flex-col sm:flex-row items-stretch sm:items-center gap-3">
            <button
              onClick={onNavigateToSend}
              className="px-6 py-3 rounded-xl bg-blue-600 hover:bg-blue-700 active:scale-[0.99] text-white font-medium text-sm transition-all shadow-sm flex items-center justify-center space-x-2 cursor-pointer"
            >
              <Send className="w-4 h-4" />
              <span>Protect a File</span>
              <ArrowRight className="w-4 h-4 ml-1 opacity-80" />
            </button>

            <button
              onClick={onNavigateToUnlock}
              className="px-6 py-3 rounded-xl bg-white hover:bg-slate-50 border border-slate-300 text-slate-800 font-medium text-sm transition-all shadow-sm flex items-center justify-center space-x-2 cursor-pointer"
            >
              <Unlock className="w-4 h-4 text-slate-600" />
              <span>Unlock a Received File</span>
            </button>
          </div>
        </div>
      </section>

      {/* 4 Core Cryptographic Pillars */}
      <section className="space-y-4">
        <div>
          <h2 className="text-lg font-bold text-slate-900">
            Core Cryptographic Protections
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            Cryptographic mechanisms executed directly in client hardware via W3C Web Crypto.
          </p>
        </div>

        <div className="grid grid-cols-1 md:grid-cols-2 gap-4">
          {/* Card 1 */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-2.5 shadow-sm hover:border-slate-300 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-blue-50 text-blue-600 flex items-center justify-center shrink-0">
                <Cpu className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900">
                Client-Side Encryption
              </h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              Every document is encrypted entirely inside the browser using standard
              AES-256-GCM. Unencrypted plaintext never crosses the network or touches any
              relay server.
            </p>
          </div>

          {/* Card 2 */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-2.5 shadow-sm hover:border-slate-300 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-emerald-50 text-emerald-600 flex items-center justify-center shrink-0">
                <ShieldCheck className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900">
                Authenticated File Protection (AEAD)
              </h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              A 128-bit Galois Message Authentication Code (GMAC) authenticates both the
              ciphertext and the initialization vector. Any single-bit corruption in transit
              causes immediate decryption rejection.
            </p>
          </div>

          {/* Card 3 */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-2.5 shadow-sm hover:border-slate-300 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-indigo-50 text-indigo-600 flex items-center justify-center shrink-0">
                <KeyRound className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900">
                Recipient-Key Protection
              </h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              The one-time symmetric AES key is wrapped using the intended recipient&apos;s
              RSA-2048 public key via RSA-OAEP with SHA-256, ensuring only the matching
              private key can unwrap it.
            </p>
          </div>

          {/* Card 4 */}
          <div className="bg-white border border-slate-200 rounded-xl p-5 space-y-2.5 shadow-sm hover:border-slate-300 transition-colors">
            <div className="flex items-center space-x-3">
              <div className="w-8 h-8 rounded-lg bg-slate-100 text-slate-700 flex items-center justify-center shrink-0">
                <FileCheck2 className="w-4 h-4" />
              </div>
              <h3 className="text-sm font-semibold text-slate-900">
                File Integrity Verification
              </h3>
            </div>
            <p className="text-xs text-slate-600 leading-relaxed">
              A SHA-256 digest is generated before packaging and verified after local
              decryption, confirming that the recovered document perfectly matches the
              original byte-for-byte.
            </p>
          </div>
        </div>
      </section>

      {/* 4-Step Secure Workflow */}
      <section className="bg-white border border-slate-200 rounded-2xl p-6 sm:p-8 shadow-sm space-y-6">
        <div>
          <h2 className="text-base sm:text-lg font-bold text-slate-900">
            End-to-End Cryptographic Workflow
          </h2>
          <p className="text-xs text-slate-500 mt-0.5">
            How protected file transfer operates from local encryption to recipient decryption.
          </p>
        </div>

        <div className="grid grid-cols-1 sm:grid-cols-2 lg:grid-cols-4 gap-4">
          {/* Step 1 */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <div className="w-6 h-6 rounded-md bg-blue-600 text-white flex items-center justify-center text-xs font-bold font-mono">
              1
            </div>
            <h4 className="text-xs font-semibold text-slate-900">
              Select Document
            </h4>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Choose any file up to 50MB. Plaintext is read into local browser memory only.
            </p>
          </div>

          {/* Step 2 */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <div className="w-6 h-6 rounded-md bg-blue-600 text-white flex items-center justify-center text-xs font-bold font-mono">
              2
            </div>
            <h4 className="text-xs font-semibold text-slate-900">
              Specify Recipient
            </h4>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Paste the recipient&apos;s RSA-2048 public key or use your own key for testing.
            </p>
          </div>

          {/* Step 3 */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <div className="w-6 h-6 rounded-md bg-blue-600 text-white flex items-center justify-center text-xs font-bold font-mono">
              3
            </div>
            <h4 className="text-xs font-semibold text-slate-900">
              Encrypt & Package
            </h4>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Generate AES-256 key, encrypt payload, wrap key with RSA-OAEP, and seal into <code>.vault</code>.
            </p>
          </div>

          {/* Step 4 */}
          <div className="p-4 rounded-xl bg-slate-50 border border-slate-200 space-y-2">
            <div className="w-6 h-6 rounded-md bg-blue-600 text-white flex items-center justify-center text-xs font-bold font-mono">
              4
            </div>
            <h4 className="text-xs font-semibold text-slate-900">
              Transfer & Unlock
            </h4>
            <p className="text-[11px] text-slate-500 leading-relaxed">
              Exchange the <code>.vault</code> package directly or via the zero-knowledge relay by File ID.
            </p>
          </div>
        </div>
      </section>

      {/* Verification Labs Callout */}
      <section className="grid grid-cols-1 sm:grid-cols-2 gap-4">
        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
          <div className="flex items-center space-x-2 text-slate-900 font-semibold text-sm">
            <Layers className="w-4 h-4 text-purple-600" />
            <span>Adversarial Testing Lab</span>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            Test negative security cases: inject 1-bit mutations into ciphertext, simulate unauthorized
            key unwrap attempts, and verify that the backend holds zero plaintext.
          </p>
          <button
            onClick={onNavigateToLab}
            className="text-xs font-medium text-blue-600 hover:text-blue-700 flex items-center space-x-1 cursor-pointer"
          >
            <span>Open Security Lab</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>

        <div className="p-5 rounded-xl bg-white border border-slate-200 space-y-3 shadow-sm">
          <div className="flex items-center space-x-2 text-slate-900 font-semibold text-sm">
            <Cpu className="w-4 h-4 text-emerald-600" />
            <span>Performance Benchmarks</span>
          </div>
          <p className="text-xs text-slate-600 leading-relaxed">
            Measure actual browser encryption and decryption throughput across 12KB, 50KB, 2MB,
            and 10MB payloads with published literature comparisons.
          </p>
          <button
            onClick={onNavigateToBenchmarks}
            className="text-xs font-medium text-blue-600 hover:text-blue-700 flex items-center space-x-1 cursor-pointer"
          >
            <span>Open Benchmark Suite</span>
            <ArrowRight className="w-3.5 h-3.5" />
          </button>
        </div>
      </section>
    </div>
  );
};
