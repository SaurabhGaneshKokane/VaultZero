import React, { useState } from "react";
import { VaultTab } from "./components/VaultTab";
import { AdversarialLab } from "./components/AdversarialLab";
import { BenchmarkTab } from "./components/BenchmarkTab";
import { ShieldCheck, ShieldAlert, Gauge, Lock } from "lucide-react";

export const App: React.FC = () => {
  const [activeTab, setActiveTab] = useState<"core" | "adversarial" | "benchmark">("core");

  return (
    <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans selection:bg-blue-100 selection:text-blue-900">
      {/* Top Header & Navigation Shell */}
      <header className="border-b border-slate-200 bg-white/90 sticky top-0 z-50 backdrop-blur-md">
        <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
          <div className="flex flex-col md:flex-row md:items-center md:justify-between py-3.5 gap-4">
            {/* Branding & Header */}
            <div className="flex items-center space-x-3.5">
              <div className="p-2.5 rounded-xl bg-blue-600 text-white shadow-sm border border-blue-700">
                <Lock className="w-5 h-5" />
              </div>
              <div>
                <h1 className="font-bold text-lg sm:text-xl tracking-tight text-slate-900 flex items-center gap-2">
                  <span>VaultZero: End-to-End Hybrid Cryptographic Vault</span>
                </h1>
                <p className="text-xs text-slate-500 flex items-center space-x-2">
                  <span>AES-256-GCM (AEAD) + RSA-OAEP-2048</span>
                  <span className="text-slate-300">•</span>
                  <span className="text-emerald-700 font-mono text-[11px] flex items-center gap-1 bg-emerald-50 px-2 py-0.5 rounded-full border border-emerald-200">
                    <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 animate-pulse"></span>
                    Native WebCrypto
                  </span>
                </p>
              </div>
            </div>

            {/* 3 Selectable Tabs */}
            <nav className="flex items-center bg-slate-100 p-1 rounded-2xl border border-slate-200 text-xs sm:text-sm font-medium self-start md:self-auto overflow-x-auto max-w-full">
              {/* Tab 1: Core Vault */}
              <button
                id="tab-core-vault"
                onClick={() => setActiveTab("core")}
                className={`px-4 py-2 rounded-xl transition-all duration-200 cursor-pointer flex items-center space-x-2 whitespace-nowrap ${
                  activeTab === "core"
                    ? "bg-blue-600 text-white shadow-sm font-semibold"
                    : "text-slate-600 hover:text-slate-900 hover:bg-white"
                }`}
              >
                <ShieldCheck className="w-4 h-4" />
                <span>Core Vault</span>
              </button>

              {/* Tab 2: Adversarial Lab */}
              <button
                id="tab-adversarial-lab"
                onClick={() => setActiveTab("adversarial")}
                className={`px-4 py-2 rounded-xl transition-all duration-200 cursor-pointer flex items-center space-x-2 whitespace-nowrap ${
                  activeTab === "adversarial"
                    ? "bg-rose-600 text-white shadow-sm font-semibold"
                    : "text-slate-600 hover:text-slate-900 hover:bg-white"
                }`}
              >
                <ShieldAlert className="w-4 h-4" />
                <span>Adversarial Lab</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono hidden lg:inline ${
                  activeTab === "adversarial"
                    ? "bg-rose-700 text-rose-100"
                    : "bg-rose-100 text-rose-700 border border-rose-200"
                }`}>
                  Tamper
                </span>
              </button>

              {/* Tab 3: Benchmark Suite */}
              <button
                id="tab-benchmark-suite"
                onClick={() => setActiveTab("benchmark")}
                className={`px-4 py-2 rounded-xl transition-all duration-200 cursor-pointer flex items-center space-x-2 whitespace-nowrap ${
                  activeTab === "benchmark"
                    ? "bg-emerald-600 text-white shadow-sm font-semibold"
                    : "text-slate-600 hover:text-slate-900 hover:bg-white"
                }`}
              >
                <Gauge className="w-4 h-4" />
                <span>Benchmark Suite</span>
                <span className={`text-[10px] px-1.5 py-0.2 rounded-full font-mono hidden lg:inline ${
                  activeTab === "benchmark"
                    ? "bg-emerald-700 text-emerald-100"
                    : "bg-emerald-100 text-emerald-700 border border-emerald-200"
                }`}>
                  Metrics
                </span>
              </button>
            </nav>
          </div>
        </div>
      </header>

      {/* Main Tab Content */}
      <main className="flex-1 py-4 sm:py-6">
        {activeTab === "core" && <VaultTab />}
        {activeTab === "adversarial" && <AdversarialLab />}
        {activeTab === "benchmark" && <BenchmarkTab />}
      </main>

      {/* Footer with Academic Citation */}
      <footer className="border-t border-slate-200 bg-white py-6 px-4 sm:px-6 lg:px-8 mt-auto text-center font-mono text-xs text-slate-500">
        <div className="max-w-7xl mx-auto space-y-1.5">
          <p className="text-slate-800 font-semibold tracking-wide">
            Shah & Anchor Kutchhi Engineering College, CNS Micro-Project Stage 2
          </p>
          <p className="text-slate-500 text-[11px]">
            VaultZero Cryptographic Subsystem • Cryptography & Network Security (CNS) • Zero-Knowledge Hybrid Encryption
          </p>
        </div>
      </footer>
    </div>
  );
};

export default App;
