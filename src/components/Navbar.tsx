import React, { useState } from "react";
import {
  ShieldCheck,
  ShieldAlert,
  Gauge,
  KeyRound,
  Menu,
  X,
  Lock,
  Server,
  Home,
} from "lucide-react";
import { BackendHealthResponse } from "../utils/apiClient";

export type AppTab = "overview" | "vault" | "lab" | "benchmarks";

interface NavbarProps {
  activeTab: AppTab;
  setActiveTab: (tab: AppTab) => void;
  onOpenKeyManagement: () => void;
  backendHealth: {
    isAvailable: boolean;
    data?: BackendHealthResponse;
    checked: boolean;
  };
  hasKeyPair: boolean;
  authenticatedEmail: string;
  onSignOut: () => void;
}

export const Navbar: React.FC<NavbarProps> = ({
  activeTab,
  setActiveTab,
  onOpenKeyManagement,
  backendHealth,
  hasKeyPair,
  authenticatedEmail,
  onSignOut,
}) => {
  const [mobileMenuOpen, setMobileMenuOpen] = useState(false);

  const navItems: { id: AppTab; label: string; icon: React.ComponentType<{ className?: string }> }[] = [
    { id: "overview", label: "Overview", icon: Home },
    { id: "vault", label: "Core Vault", icon: ShieldCheck },
    { id: "lab", label: "Security Lab", icon: ShieldAlert },
    { id: "benchmarks", label: "Benchmarks", icon: Gauge },
  ];

  const handleTabClick = (tab: AppTab) => {
    setActiveTab(tab);
    setMobileMenuOpen(false);
  };

  return (
    <header className="sticky top-0 z-40 bg-white/95 backdrop-blur-sm border-b border-slate-200">
      <div className="max-w-7xl mx-auto px-4 sm:px-6 lg:px-8">
        <div className="flex items-center justify-between h-16 gap-4">
          {/* Zone 1: Brand Wordmark */}
          <div className="flex items-center space-x-3 shrink-0">
            <button
              onClick={() => handleTabClick("overview")}
              className="flex items-center space-x-2.5 text-left group cursor-pointer focus:outline-none"
            >
              <div className="w-9 h-9 rounded-lg bg-blue-600 flex items-center justify-center text-white shadow-sm transition-transform duration-150 group-hover:scale-105">
                <Lock className="w-5 h-5" />
              </div>
              <div className="flex flex-col">
                <div className="flex items-center space-x-1.5">
                  <span className="text-base font-bold tracking-tight text-slate-900 group-hover:text-blue-600 transition-colors">
                    VaultZero
                  </span>
                  <span className="text-[11px] font-medium text-slate-400 hidden sm:inline">
                    /
                  </span>
                  <span className="text-[11px] font-medium text-slate-500 hidden sm:inline">
                    Secure File Transfer
                  </span>
                </div>
                <span className="text-[10px] text-slate-400 font-mono tracking-tight sm:hidden">
                  Hybrid Cryptography
                </span>
              </div>
            </button>
          </div>

          {/* Zone 2: Desktop Navigation Links (Clean, unboxed with subtle hover/active highlight) */}
          <nav className="hidden md:flex items-center space-x-1 font-medium text-xs lg:text-sm">
            {navItems.map((item) => {
              const Icon = item.icon;
              const isActive = activeTab === item.id;
              return (
                <button
                  key={item.id}
                  onClick={() => handleTabClick(item.id)}
                  className={`px-3 py-2 rounded-lg transition-colors flex items-center space-x-1.5 whitespace-nowrap cursor-pointer ${
                    isActive
                      ? "bg-blue-50 text-blue-700 font-semibold"
                      : "text-slate-600 hover:text-slate-900 hover:bg-slate-50"
                  }`}
                >
                  <Icon className={`w-4 h-4 ${isActive ? "text-blue-600" : "text-slate-400"}`} />
                  <span>{item.label}</span>
                </button>
              );
            })}
          </nav>

          {/* Zone 3: Security Status & Key Management Entry */}
          <div className="flex items-center space-x-2.5 shrink-0">
            {/* Real Security Status Indicator (Quiet unboxed format) */}
            <div className="hidden lg:flex items-center space-x-2 text-xs text-slate-500 bg-slate-50 px-3 py-1.5 rounded-lg border border-slate-200">
              <span className="text-[11px] font-mono text-slate-700 font-medium">
                WebCrypto AES-256 + RSA
              </span>
              <span className="text-slate-300" aria-hidden="true">·</span>
              <span className="inline-flex items-center text-[11px] text-emerald-700 font-medium">
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1"></span>
                In-Browser
              </span>
            </div>

            {/* Key Management Trigger */}
            <button
              onClick={onOpenKeyManagement}
              className="inline-flex items-center space-x-1.5 px-3 py-1.5 rounded-lg text-xs font-medium text-slate-700 bg-white hover:bg-slate-50 border border-slate-200 shadow-sm transition-colors cursor-pointer"
              title="Manage and inspect browser RSA-2048 keypair"
            >
              <KeyRound className="w-3.5 h-3.5 text-blue-600" />
              <span className="hidden sm:inline">Identity & Keys</span>
              <span className="sm:hidden">Keys</span>
              {hasKeyPair && (
                <span className="w-1.5 h-1.5 rounded-full bg-emerald-500" title="Keypair active"></span>
              )}
            </button>

            <div className="hidden sm:flex items-center gap-2 text-xs text-slate-500">
              <span className="max-w-36 truncate" title={authenticatedEmail}>{authenticatedEmail}</span>
              <button onClick={onSignOut} className="text-blue-700 hover:underline">Sign out</button>
            </div>

            {/* Mobile Hamburger Button */}
            <button
              onClick={() => setMobileMenuOpen(!mobileMenuOpen)}
              className="md:hidden p-2 rounded-lg text-slate-600 hover:text-slate-900 hover:bg-slate-100 transition-colors focus:outline-none"
              aria-label="Toggle navigation menu"
            >
              {mobileMenuOpen ? <X className="w-5 h-5" /> : <Menu className="w-5 h-5" />}
            </button>
          </div>
        </div>
      </div>

      {/* Mobile Drawer Menu */}
      {mobileMenuOpen && (
        <div className="md:hidden border-t border-slate-200 bg-white px-4 pt-3 pb-4 space-y-1.5 shadow-lg">
          {navItems.map((item) => {
            const Icon = item.icon;
            const isActive = activeTab === item.id;
            return (
              <button
                key={item.id}
                onClick={() => handleTabClick(item.id)}
                className={`w-full text-left px-3.5 py-2.5 rounded-lg text-sm font-medium transition-colors flex items-center space-x-2.5 cursor-pointer ${
                  isActive
                    ? "bg-blue-50 text-blue-700 font-semibold"
                    : "text-slate-700 hover:bg-slate-50"
                }`}
              >
                <Icon className={`w-4 h-4 ${isActive ? "text-blue-600" : "text-slate-400"}`} />
                <span>{item.label}</span>
              </button>
            );
          })}

          <div className="pt-2.5 border-t border-slate-100 mt-2 flex items-center justify-between text-xs text-slate-500 px-1">
            <span className="truncate mr-3">{authenticatedEmail}</span>
            <button onClick={onSignOut} className="text-blue-700">Sign out</button>
          </div>
          <div className="pt-2.5 border-t border-slate-100 mt-2 flex items-center justify-between text-xs text-slate-500 px-1">
            <span>Security Engine: Native WebCrypto</span>
            <span className="inline-flex items-center text-emerald-700 font-medium text-[11px]">
              <span className="w-1.5 h-1.5 rounded-full bg-emerald-500 mr-1"></span>
              {backendHealth.isAvailable ? "Relay Online" : "Local Mode"}
            </span>
          </div>
        </div>
      )}
    </header>
  );
};
