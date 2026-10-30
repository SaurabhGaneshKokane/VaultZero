import React, { createContext, useContext, useEffect, useMemo, useState } from "react";
import type { Session, User } from "@supabase/supabase-js";
import { supabase, supabaseConfigured } from "../lib/supabase";

interface AuthContextValue {
  session: Session | null;
  user: User | null;
  loading: boolean;
  configurationError: string | null;
  signUp: (email: string, password: string) => Promise<{ emailConfirmationRequired: boolean }>;
  signIn: (email: string, password: string) => Promise<void>;
  signOut: () => Promise<void>;
}

const AuthContext = createContext<AuthContextValue | null>(null);

export const AuthProvider: React.FC<React.PropsWithChildren> = ({ children }) => {
  const [session, setSession] = useState<Session | null>(null);
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    if (!supabase) {
      setLoading(false);
      return;
    }
    let mounted = true;
    const { data } = supabase.auth.onAuthStateChange((_event, nextSession) => {
      if (mounted) {
        setSession(nextSession);
        setLoading(false);
      }
    });
    supabase.auth.getSession().then(({ data: result }) => {
      if (mounted) {
        setSession(result.session);
        setLoading(false);
      }
    }).catch(() => mounted && setLoading(false));
    return () => {
      mounted = false;
      data.subscription.unsubscribe();
    };
  }, []);

  const value = useMemo<AuthContextValue>(() => ({
    session,
    user: session?.user ?? null,
    loading,
    configurationError: supabaseConfigured ? null : "Set VITE_SUPABASE_URL and VITE_SUPABASE_ANON_KEY in the frontend environment, then restart Vite.",
    signUp: async (email, password) => {
      if (!supabase) throw new Error("Supabase Auth is not configured.");
      const { data, error } = await supabase.auth.signUp({ email: email.trim(), password });
      if (error) throw error;
      return { emailConfirmationRequired: !data.session };
    },
    signIn: async (email, password) => {
      if (!supabase) throw new Error("Supabase Auth is not configured.");
      const { error } = await supabase.auth.signInWithPassword({ email: email.trim(), password });
      if (error) throw error;
    },
    signOut: async () => {
      if (!supabase) return;
      const { error } = await supabase.auth.signOut();
      if (error) throw error;
    },
  }), [session, loading]);

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
};

export function useAuth(): AuthContextValue {
  const context = useContext(AuthContext);
  if (!context) throw new Error("useAuth must be used inside AuthProvider.");
  return context;
}
