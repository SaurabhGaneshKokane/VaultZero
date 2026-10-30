import React, { useState } from "react";
import { LockKeyhole, Mail, ShieldCheck } from "lucide-react";
import { useAuth } from "../context/AuthContext";

export const AuthScreen: React.FC = () => {
  const { signIn, signUp, configurationError } = useAuth();
  const [mode, setMode] = useState<"login" | "signup">("login");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [busy, setBusy] = useState(false);
  const [message, setMessage] = useState("");
  const [error, setError] = useState("");

  const submit = async (event: React.FormEvent) => {
    event.preventDefault();
    setBusy(true); setError(""); setMessage("");
    try {
      if (mode === "signup") {
        const result = await signUp(email, password);
        setMessage(result.emailConfirmationRequired
          ? "Check your inbox and verify your email, then return here to sign in."
          : "Your account is ready. VaultZero will prepare your recovery-protected key next.");
      } else {
        await signIn(email, password);
      }
    } catch (cause) {
      setError(cause instanceof Error ? cause.message : "Authentication failed.");
    } finally { setBusy(false); }
  };

  return <main className="min-h-screen bg-slate-50 flex items-center justify-center p-5">
    <section className="w-full max-w-md bg-white border border-slate-200 shadow-sm rounded-2xl p-7 space-y-6">
      <div className="flex items-center gap-3">
        <div className="w-11 h-11 rounded-xl bg-blue-600 text-white grid place-items-center"><LockKeyhole className="w-5 h-5" /></div>
        <div><h1 className="text-xl font-bold text-slate-900">VaultZero</h1><p className="text-xs text-slate-500">Private file encryption, in your browser</p></div>
      </div>
      {configurationError ? <div className="rounded-lg bg-amber-50 border border-amber-200 p-3 text-sm text-amber-900">{configurationError}</div> : <>
        <div><h2 className="text-lg font-semibold text-slate-900">{mode === "login" ? "Sign in" : "Create your account"}</h2><p className="mt-1 text-sm text-slate-600">Email verification is handled by Supabase Auth. Passwords are never sent to VaultZero?s backend.</p></div>
        <form onSubmit={submit} className="space-y-4">
          <label className="block text-sm font-medium text-slate-700">Email<div className="mt-1 relative"><Mail className="absolute left-3 top-3 w-4 h-4 text-slate-400" /><input required type="email" autoComplete="email" value={email} onChange={e=>setEmail(e.target.value)} className="w-full rounded-lg border border-slate-300 py-2.5 pl-9 pr-3 outline-none focus:ring-2 focus:ring-blue-500" /></div></label>
          <label className="block text-sm font-medium text-slate-700">Password<div className="mt-1 relative"><ShieldCheck className="absolute left-3 top-3 w-4 h-4 text-slate-400" /><input required minLength={8} type="password" autoComplete={mode === "login" ? "current-password" : "new-password"} value={password} onChange={e=>setPassword(e.target.value)} className="w-full rounded-lg border border-slate-300 py-2.5 pl-9 pr-3 outline-none focus:ring-2 focus:ring-blue-500" /></div></label>
          {error && <p role="alert" className="text-sm text-rose-700 bg-rose-50 border border-rose-200 rounded-lg p-3">{error}</p>}
          {message && <p role="status" className="text-sm text-emerald-800 bg-emerald-50 border border-emerald-200 rounded-lg p-3">{message}</p>}
          <button disabled={busy} className="w-full rounded-lg bg-blue-600 hover:bg-blue-700 disabled:opacity-50 text-white font-semibold py-2.5">{busy ? "Please wait?" : mode === "login" ? "Sign in" : "Create account"}</button>
        </form>
        <button type="button" onClick={()=>{setMode(mode === "login" ? "signup" : "login");setError("");setMessage("");}} className="text-sm text-blue-700 hover:underline">{mode === "login" ? "New to VaultZero? Create an account" : "Already registered? Sign in"}</button>
      </>}
    </section>
  </main>;
};
