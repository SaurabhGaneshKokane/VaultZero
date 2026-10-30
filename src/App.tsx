import React, { useEffect, useState } from "react";
import { Navbar, AppTab } from "./components/Navbar";
import { OverviewTab } from "./components/OverviewTab";
import { VaultTab } from "./components/VaultTab";
import { AdversarialLab } from "./components/AdversarialLab";
import { BenchmarkTab } from "./components/BenchmarkTab";
import { KeyManagementModal } from "./components/KeyManagementModal";
import { AuthScreen } from "./components/AuthScreen";
import { KeyRecoveryGate } from "./components/KeyRecoveryGate";
import { generateRsaKeyPair, computeKeyFingerprint, RsaKeyPairPem } from "./utils/cryptoEngine";
import { checkBackendHealth, fetchUserProfile, fetchKeyById, publishPublicKey, BackendHealthResponse, PublicKeyDirectoryRecord, UserProfileResponse } from "./utils/apiClient";
import { useAuth } from "./context/AuthContext";

const SESSION_PUBKEY_KEY = "vaultzero_pubkey_pem";
const SESSION_PRIVKEY_KEY = "vaultzero_privkey_pem";

type KeyState = "checking" | "create" | "restore" | "ready" | "error";

export const App: React.FC = () => {
  const { session, user, loading: authLoading, signOut } = useAuth();
  const [activeTab, setActiveTab] = useState<AppTab>("overview");
  const [vaultMode, setVaultMode] = useState<"send" | "unlock">("send");
  const [publicKeyPem, setPublicKeyPem] = useState("");
  const [privateKeyPem, setPrivateKeyPem] = useState("");
  const [isGeneratingKeys, setIsGeneratingKeys] = useState(false);
  const [isKeyModalOpen, setIsKeyModalOpen] = useState(false);
  const [backendHealth, setBackendHealth] = useState<{ isAvailable: boolean; data?: BackendHealthResponse; checked: boolean }>({ isAvailable: false, checked: false });
  const [profile, setProfile] = useState<UserProfileResponse | null>(null);
  const [activeDirectoryRecord, setActiveDirectoryRecord] = useState<PublicKeyDirectoryRecord | undefined>();
  const [keyState, setKeyState] = useState<KeyState>("checking");
  const [keyError, setKeyError] = useState("");

  useEffect(() => {
    if (authLoading) return;
    let cancelled = false;
    setProfile(null); setActiveDirectoryRecord(undefined); setPublicKeyPem(""); setPrivateKeyPem("");
    sessionStorage.removeItem(SESSION_PUBKEY_KEY); sessionStorage.removeItem(SESSION_PRIVKEY_KEY);
    if (!session?.access_token || !user) { setKeyState("checking"); return; }

    const initializeAccount = async () => {
      setKeyState("checking"); setKeyError("");
      try {
        const accountProfile = await fetchUserProfile(session.access_token);
        if (cancelled) return;
        setProfile(accountProfile);
        if (accountProfile.active_key) {
          const record = await fetchKeyById(session.access_token, accountProfile.active_key.key_id);
          if (cancelled) return;
          setActiveDirectoryRecord(record);
        }
        const storedPublic = sessionStorage.getItem(SESSION_PUBKEY_KEY);
        const storedPrivate = sessionStorage.getItem(SESSION_PRIVKEY_KEY);
        if (storedPublic && storedPrivate) {
          const localFingerprint = await computeKeyFingerprint(storedPublic);
          if (cancelled) return;
          if (accountProfile.active_key && localFingerprint.toLowerCase() !== accountProfile.active_key.fingerprint.toLowerCase()) {
            sessionStorage.removeItem(SESSION_PUBKEY_KEY); sessionStorage.removeItem(SESSION_PRIVKEY_KEY);
            setKeyState("restore"); return;
          }
          setPublicKeyPem(storedPublic); setPrivateKeyPem(storedPrivate);
          if (accountProfile.active_key) setKeyState("ready");
          else setKeyState("create");
          return;
        }
        if (accountProfile.active_key) { setKeyState("restore"); return; }
        setIsGeneratingKeys(true);
        const pair = await generateRsaKeyPair();
        if (cancelled) return;
        setPublicKeyPem(pair.publicKeyPem); setPrivateKeyPem(pair.privateKeyPem);
        setKeyState("create");
      } catch (cause) {
        if (!cancelled) { setKeyError(cause instanceof Error ? cause.message : "Could not initialize your account."); setKeyState("error"); }
      } finally { if (!cancelled) setIsGeneratingKeys(false); }
    };
    void initializeAccount();
    return () => { cancelled = true; };
  }, [authLoading, user?.id]);

  useEffect(() => {
    let mounted = true;
    const probe = async () => {
      const result = await checkBackendHealth();
      if (mounted) setBackendHealth({ isAvailable: result.isAvailable, data: result.data, checked: true });
    };
    void probe(); const interval = setInterval(probe, 30000);
    return () => { mounted = false; clearInterval(interval); };
  }, []);

  const handleRegenerateKeys = async (forRotation = false): Promise<RsaKeyPairPem> => {
    if (!forRotation && profile?.active_key) throw new Error("An active key already protects your account. Use explicit key rotation.");
    setIsGeneratingKeys(true);
    try {
      const pair = await generateRsaKeyPair();
      if (!forRotation) {
        sessionStorage.setItem(SESSION_PUBKEY_KEY, pair.publicKeyPem); sessionStorage.setItem(SESSION_PRIVKEY_KEY, pair.privateKeyPem);
        setPublicKeyPem(pair.publicKeyPem); setPrivateKeyPem(pair.privateKeyPem);
      }
      return pair;
    } finally { setIsGeneratingKeys(false); }
  };

  const handleKeyReady = (pub: string, priv: string, record?: PublicKeyDirectoryRecord) => {
    sessionStorage.setItem(SESSION_PUBKEY_KEY, pub); sessionStorage.setItem(SESSION_PRIVKEY_KEY, priv);
    setPublicKeyPem(pub); setPrivateKeyPem(priv);
    if (record) {
      setActiveDirectoryRecord(record);
      setProfile((current) => current ? { ...current, active_key: { key_id: record.key_id, algorithm: record.algorithm, key_size_bits: record.key_size_bits, fingerprint: record.fingerprint, registered_at: record.registered_at, status: record.status } } : current);
    }
    setKeyState("ready");
  };

  if (authLoading) return <div className="min-h-screen grid place-items-center text-sm text-slate-500">Restoring secure session?</div>;
  if (!session || !user) return <AuthScreen />;
  if (keyState === "checking") return <div className="min-h-screen grid place-items-center text-sm text-slate-500">Checking your account and key recovery status?</div>;
  if (keyState === "error") return <main className="min-h-screen grid place-items-center p-6"><div className="max-w-lg rounded-xl border border-rose-200 bg-rose-50 p-5 text-sm text-rose-800">{keyError}<button onClick={() => void signOut()} className="block mt-4 underline">Sign out</button></div></main>;
  if (keyState === "create" || keyState === "restore") return <KeyRecoveryGate mode={keyState} accessToken={session.access_token} email={user.email || ""} publicKeyPem={publicKeyPem} privateKeyPem={privateKeyPem} expectedFingerprint={activeDirectoryRecord?.fingerprint_raw_hex} onReady={handleKeyReady} />;

  return <div className="min-h-screen bg-slate-50 text-slate-900 flex flex-col font-sans selection:bg-blue-100 selection:text-blue-900">
    <Navbar activeTab={activeTab} setActiveTab={setActiveTab} onOpenKeyManagement={() => setIsKeyModalOpen(true)} backendHealth={backendHealth} hasKeyPair={Boolean(publicKeyPem && privateKeyPem)} authenticatedEmail={user.email || ""} onSignOut={() => void signOut()} />
    <main className="flex-1 py-6">
      {activeTab === "overview" && <OverviewTab onNavigateToSend={() => { setVaultMode("send"); setActiveTab("vault"); }} onNavigateToUnlock={() => { setVaultMode("unlock"); setActiveTab("vault"); }} onNavigateToLab={() => setActiveTab("lab")} onNavigateToBenchmarks={() => setActiveTab("benchmarks")} />}
      {activeTab === "vault" && <VaultTab initialMode={vaultMode} publicKeyPem={publicKeyPem} privateKeyPem={privateKeyPem} accessToken={session.access_token} onOpenKeyManagement={() => setIsKeyModalOpen(true)} backendHealth={backendHealth} />}
      {activeTab === "lab" && <AdversarialLab accessToken={session.access_token} />}
      {activeTab === "benchmarks" && <BenchmarkTab />}
    </main>
    <KeyManagementModal isOpen={isKeyModalOpen} onClose={() => setIsKeyModalOpen(false)} publicKeyPem={publicKeyPem} privateKeyPem={privateKeyPem} onRegenerateKeys={handleRegenerateKeys} onKeysRestored={(pub, priv) => { setPublicKeyPem(pub); setPrivateKeyPem(priv); sessionStorage.setItem(SESSION_PUBKEY_KEY, pub); sessionStorage.setItem(SESSION_PRIVKEY_KEY, priv); }} isGeneratingKeys={isGeneratingKeys} accessToken={session.access_token} authenticatedEmail={user.email || ""} authenticatedVaultId={profile?.vault_id || ""} currentDirectoryRecord={activeDirectoryRecord} onDirectoryRecordChange={(record) => { setActiveDirectoryRecord(record); if (record) setProfile((current) => current ? { ...current, active_key: { key_id: record.key_id, algorithm: record.algorithm, key_size_bits: record.key_size_bits, fingerprint: record.fingerprint, registered_at: record.registered_at, status: record.status } } : current); }} />
  </div>;
};

export default App;
