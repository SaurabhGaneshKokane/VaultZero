import React, { useState } from "react";
import { Download, KeyRound, ShieldCheck, Upload } from "lucide-react";
import { computeKeyFingerprint, exportEncryptedPrivateKeyBackup, formatSha256Fingerprint, importEncryptedPrivateKeyBackup, normalizeSha256Fingerprint } from "../utils/cryptoEngine";
import { publishPublicKey, PublicKeyDirectoryRecord } from "../utils/apiClient";

interface Props {
  mode: "create" | "restore";
  accessToken: string;
  email: string;
  publicKeyPem?: string;
  privateKeyPem?: string;
  expectedFingerprint?: string;
  onReady: (publicPem: string, privatePem: string, record?: PublicKeyDirectoryRecord) => void;
}

export const KeyRecoveryGate: React.FC<Props> = ({ mode, accessToken, email, publicKeyPem = "", privateKeyPem = "", expectedFingerprint, onReady }) => {
  const [fileText, setFileText] = useState("");
  const [fileName, setFileName] = useState("");
  const [passphrase, setPassphrase] = useState("");
  const [confirm, setConfirm] = useState("");
  const [busy, setBusy] = useState(false);
  const [error, setError] = useState("");
  const [info, setInfo] = useState("");

  const createAndRegister = async (event: React.FormEvent) => {
    event.preventDefault(); setError(""); setInfo("");
    if (passphrase.length < 8) { setError("Use a backup passphrase with at least 8 characters."); return; }
    if (passphrase !== confirm) { setError("The backup passphrases do not match."); return; }
    setBusy(true);
    try {
      const backup = await exportEncryptedPrivateKeyBackup(privateKeyPem, publicKeyPem, passphrase);
      const blob = new Blob([backup], { type: "application/json;charset=utf-8" });
      const href = URL.createObjectURL(blob); const link = document.createElement("a");
      link.href = href; link.download = `vaultzero_key_backup_${new Date().toISOString().slice(0,10)}.vaultkey`;
      document.body.appendChild(link); link.click(); link.remove(); URL.revokeObjectURL(href);
      const record = await publishPublicKey(accessToken, publicKeyPem);
      onReady(publicKeyPem, privateKeyPem, record);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Could not create the encrypted key backup."); }
    finally { setBusy(false); }
  };

  const restore = async (event: React.FormEvent) => {
    event.preventDefault(); setError(""); setInfo("");
    if (!fileText || !passphrase) { setError("Choose your .vaultkey backup and enter its passphrase."); return; }
    setBusy(true);
    try {
      const pair = await importEncryptedPrivateKeyBackup(fileText, passphrase);
      const fingerprint = normalizeSha256Fingerprint(await computeKeyFingerprint(pair.publicKeyPem));
      if (mode === "restore") {
        const expected = normalizeSha256Fingerprint(expectedFingerprint);
        if (!expected) {
          setError("The complete active-key fingerprint is unavailable. Refresh your account and try again; no key was changed.");
          return;
        }
        if (fingerprint !== expected) {
          setError("This backup belongs to a different key. Your account?s active key was not changed. Select the matching backup.");
          return;
        }
      }
      let record: PublicKeyDirectoryRecord | undefined;
      if (mode === "create") record = await publishPublicKey(accessToken, pair.publicKeyPem);
      onReady(pair.publicKeyPem, pair.privateKeyPem, record);
    } catch (cause) { setError(cause instanceof Error ? cause.message : "Backup could not be restored."); }
    finally { setBusy(false); }
  };

  const onFile = (event: React.ChangeEvent<HTMLInputElement>) => {
    const file = event.target.files?.[0]; if (!file) return;
    setFileName(file.name); const reader = new FileReader();
    reader.onload = () => setFileText(typeof reader.result === "string" ? reader.result : "");
    reader.readAsText(file);
  };

  const creating = mode === "create";
  return <main className="min-h-screen bg-slate-50 flex items-center justify-center p-5">
    <section className="w-full max-w-xl bg-white border border-slate-200 shadow-sm rounded-2xl p-7 space-y-5">
      <div className="flex gap-3"><div className="w-10 h-10 rounded-xl bg-blue-50 text-blue-700 grid place-items-center">{creating ? <ShieldCheck className="w-5 h-5"/> : <KeyRound className="w-5 h-5"/>}</div><div><h1 className="text-lg font-bold text-slate-900">{creating ? "Secure your recovery key" : "Restore your key"}</h1><p className="text-sm text-slate-600">Signed in as {email}</p></div></div>
      {creating ? <><p className="text-sm text-slate-700">Your private key stays in this browser. Before we publish its public key, create and save an encrypted <code>.vaultkey</code> backup. Keep the backup and passphrase separately; VaultZero cannot recover a lost private key.</p><form onSubmit={createAndRegister} className="space-y-3"><label className="block text-sm font-medium">Backup passphrase<input required minLength={8} type="password" value={passphrase} onChange={e=>setPassphrase(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-300 p-2.5"/></label><label className="block text-sm font-medium">Confirm passphrase<input required type="password" value={confirm} onChange={e=>setConfirm(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-300 p-2.5"/></label><button disabled={busy} className="w-full flex justify-center items-center gap-2 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold py-2.5"><Download className="w-4 h-4"/>{busy ? "Creating backup and registering?" : "Download encrypted backup and register key"}</button></form></> : <><p className="text-sm text-slate-700">This account already has an active public key on another session or device. Restore the matching encrypted backup; VaultZero will not generate or publish a replacement automatically.</p><div className="rounded-lg bg-slate-50 p-3"><p className="text-xs font-semibold text-slate-600">Expected SHA-256 fingerprint</p><code className="block mt-1 text-xs break-all select-all">{formatSha256Fingerprint(expectedFingerprint)}</code></div><form onSubmit={restore} className="space-y-3"><label className="block text-sm font-medium">Encrypted .vaultkey backup<input required type="file" accept=".vaultkey,application/json" onChange={onFile} className="mt-1 block w-full text-sm"/>{fileName && <span className="text-xs text-slate-500">{fileName}</span>}</label><label className="block text-sm font-medium">Backup passphrase<input required type="password" value={passphrase} onChange={e=>setPassphrase(e.target.value)} className="mt-1 w-full rounded-lg border border-slate-300 p-2.5"/></label><button disabled={busy} className="w-full flex justify-center items-center gap-2 rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold py-2.5"><Upload className="w-4 h-4"/>{busy ? "Restoring?" : "Restore matching key"}</button></form></>}
      {error && <p role="alert" className="text-sm text-rose-700 bg-rose-50 border border-rose-200 rounded-lg p-3">{error}</p>}{info && <p role="status" className="text-sm text-emerald-700">{info}</p>}
      <p className="text-xs text-slate-500">Only the public key and fingerprint are sent to the directory. Passwords, backup passphrases, private keys, and file contents stay in your browser.</p>
    </section>
  </main>;
};
