import { useCallback, useEffect, useMemo, useState, type ReactNode } from "react";
import type { Session } from "@supabase/supabase-js";

import { clearNetraSessionState, supabase, SUPABASE_AUTH_ENABLED } from "../../lib/supabase";
import { AuthContext, type NetraAuthState, type NetraProfile } from "./AuthContext";
import { requiredMfaStep } from "./authPolicy";
const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";

function safeErrorCode(payload: unknown, fallback: string) {
  if (!payload || typeof payload !== "object") return fallback;
  const record = payload as Record<string, unknown>;
  if (typeof record.code === "string") return record.code;
  if (record.error && typeof record.error === "object" && typeof (record.error as Record<string, unknown>).code === "string") {
    return String((record.error as Record<string, unknown>).code);
  }
  return fallback;
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<NetraAuthState>(
    SUPABASE_AUTH_ENABLED ? { status: "initializing" } : { status: "signed_out" },
  );

  const resolveSession = useCallback(async (session: Session | null, event?: string) => {
    if (!session) {
      setState({ status: "signed_out" });
      return;
    }
    if (event === "PASSWORD_RECOVERY" || window.location.pathname === "/auth/recovery" || window.location.pathname === "/auth/invite") {
      setState({ status: "recovery", session });
      return;
    }
    setState({ status: "resolving_profile", session });
    try {
      const response = await fetch(`${API_BASE}/auth/me`, {
        headers: { Authorization: `Bearer ${session.access_token}`, Accept: "application/json" },
      });
      const payload = await response.json().catch(() => ({}));
      if (!response.ok) {
        setState({ status: "profile_denied", code: safeErrorCode(payload, "profile_not_provisioned") });
        return;
      }
      const profile = payload as NetraProfile;
      const [assurance, factorsResult] = await Promise.all([
        supabase!.auth.mfa.getAuthenticatorAssuranceLevel(),
        supabase!.auth.mfa.listFactors(),
      ]);
      if (assurance.error || factorsResult.error) {
        setState({ status: "profile_denied", code: "mfa_state_unavailable" });
        return;
      }
      const factors = factorsResult.data.totp.filter((factor) => factor.status === "verified");
      const requiredStep = requiredMfaStep(profile, assurance.data, factors);
      if (requiredStep === "enroll") {
        setState({ status: "mfa_enrollment_required", session, profile });
        return;
      }
      if (requiredStep === "challenge") {
        setState({ status: "mfa_challenge_required", session, profile, factors });
        return;
      }
      if (profile.role === "Admin") {
        setState({ status: "privileged", session, profile: { ...profile, aal: "aal2" }, aal: "aal2" });
        return;
      }
      const aal = assurance.data.currentLevel === "aal2" ? "aal2" : "aal1";
      setState({ status: "authenticated", session, profile: { ...profile, aal }, aal });
    } catch {
      setState({ status: "profile_denied", code: "profile_resolution_unavailable" });
    }
  }, []);

  useEffect(() => {
    if (!supabase) return undefined;
    let mounted = true;
    supabase.auth.getSession().then(({ data }) => {
      if (mounted) void resolveSession(data.session);
    }).catch(() => {
      if (mounted) setState({ status: "signed_out" });
    });
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (mounted) void resolveSession(session, event);
    });
    return () => {
      mounted = false;
      subscription.unsubscribe();
    };
  }, [resolveSession]);

  const signIn = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, message: "Authentication is not configured for this build." };
    const { data, error } = await supabase.auth.signInWithPassword({ email: email.trim().toLowerCase(), password });
    if (error || !data.session) return { ok: false, message: "Invalid login credentials." };
    await resolveSession(data.session);
    return { ok: true };
  }, [resolveSession]);

  const signOut = useCallback(async () => {
    if (supabase) await supabase.auth.signOut({ scope: "global" });
    clearNetraSessionState();
    setState({ status: "signed_out" });
  }, []);

  const refreshAssurance = useCallback(async () => {
    if (!supabase) return;
    const { data } = await supabase.auth.getSession();
    await resolveSession(data.session);
  }, [resolveSession]);

  const session = "session" in state ? state.session : null;
  const value = useMemo(() => ({ state, session, signIn, signOut, refreshAssurance }), [refreshAssurance, session, signIn, signOut, state]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
