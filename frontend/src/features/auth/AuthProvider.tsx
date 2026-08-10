import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";
import type { Session } from "@supabase/supabase-js";

import { clearNetraSessionState, supabase, SUPABASE_AUTH_ENABLED } from "../../lib/supabase";
import { AuthContext, type NetraAuthState, type NetraProfile } from "./AuthContext";
import { requiredMfaStep } from "./authPolicy";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";
const AUTH_RESOLUTION_TIMEOUT_MS = 10_000;

function safeErrorCode(payload: unknown, fallback: string) {
  if (!payload || typeof payload !== "object") return fallback;
  const record = payload as Record<string, unknown>;
  if (typeof record.code === "string") return record.code;
  if (record.error && typeof record.error === "object" && typeof (record.error as Record<string, unknown>).code === "string") {
    return String((record.error as Record<string, unknown>).code);
  }
  return fallback;
}

function withTimeout<T>(operation: Promise<T>, timeoutMs = AUTH_RESOLUTION_TIMEOUT_MS): Promise<T> {
  return new Promise((resolve, reject) => {
    const timer = window.setTimeout(() => reject(new Error("authentication_resolution_timeout")), timeoutMs);
    operation.then(
      (value) => {
        window.clearTimeout(timer);
        resolve(value);
      },
      (error) => {
        window.clearTimeout(timer);
        reject(error);
      },
    );
  });
}

function replaceSession(state: NetraAuthState, session: Session): NetraAuthState {
  if (!("session" in state)) return state;
  return { ...state, session };
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [state, setState] = useState<NetraAuthState>(
    SUPABASE_AUTH_ENABLED ? { status: "initializing" } : { status: "signed_out" },
  );
  const mountedRef = useRef(true);
  const resolvedUserRef = useRef<string | null>(null);
  const resolutionRef = useRef<{ userId: string; promise: Promise<boolean> } | null>(null);
  const resolutionGenerationRef = useRef(0);

  const resolveSession = useCallback(async (session: Session | null, event?: string, force = false): Promise<boolean> => {
    if (!session) {
      resolvedUserRef.current = null;
      resolutionRef.current = null;
      resolutionGenerationRef.current += 1;
      if (mountedRef.current) setState({ status: "signed_out" });
      return false;
    }
    if (event === "PASSWORD_RECOVERY" || window.location.pathname === "/auth/recovery" || window.location.pathname === "/auth/invite") {
      if (mountedRef.current) setState({ status: "recovery", session });
      return true;
    }
    if (!force && resolvedUserRef.current === session.user.id) {
      if (mountedRef.current) setState((current) => replaceSession(current, session));
      return true;
    }
    if (!force && resolutionRef.current?.userId === session.user.id) return resolutionRef.current.promise;

    const generation = ++resolutionGenerationRef.current;
    const resolution = (async () => {
      if (mountedRef.current) setState({ status: "resolving_profile", session });
      const controller = new AbortController();
      const timeout = window.setTimeout(() => controller.abort(), AUTH_RESOLUTION_TIMEOUT_MS);
      try {
        const response = await fetch(`${API_BASE}/auth/me`, {
          headers: { Authorization: `Bearer ${session.access_token}`, Accept: "application/json" },
          signal: controller.signal,
        });
        const payload = await response.json().catch(() => ({}));
        if (!response.ok) {
          if (mountedRef.current && generation === resolutionGenerationRef.current) {
            setState({ status: "profile_denied", code: safeErrorCode(payload, "profile_not_provisioned") });
          }
          return false;
        }
        const profile = payload as NetraProfile;
        const [assurance, factorsResult] = await withTimeout(Promise.all([
          supabase!.auth.mfa.getAuthenticatorAssuranceLevel(),
          supabase!.auth.mfa.listFactors(),
        ]));
        if (assurance.error || factorsResult.error) {
          if (mountedRef.current && generation === resolutionGenerationRef.current) {
            setState({ status: "profile_denied", code: "mfa_state_unavailable" });
          }
          return false;
        }
        const factors = factorsResult.data.totp.filter((factor) => factor.status === "verified");
        const requiredStep = requiredMfaStep(profile, assurance.data, factors);
        if (!mountedRef.current || generation !== resolutionGenerationRef.current) return false;
        resolvedUserRef.current = session.user.id;
        if (requiredStep === "enroll") {
          setState({ status: "mfa_enrollment_required", session, profile });
          return true;
        }
        if (requiredStep === "challenge") {
          setState({ status: "mfa_challenge_required", session, profile, factors });
          return true;
        }
        if (profile.role === "Admin") {
          setState({ status: "privileged", session, profile: { ...profile, aal: "aal2" }, aal: "aal2" });
          return true;
        }
        const aal = assurance.data.currentLevel === "aal2" ? "aal2" : "aal1";
        setState({ status: "authenticated", session, profile: { ...profile, aal }, aal });
        return true;
      } catch {
        if (mountedRef.current && generation === resolutionGenerationRef.current) {
          setState({ status: "profile_denied", code: "profile_resolution_unavailable" });
        }
        return false;
      } finally {
        window.clearTimeout(timeout);
      }
    })();
    resolutionRef.current = { userId: session.user.id, promise: resolution };
    const result = await resolution;
    if (resolutionRef.current?.promise === resolution) resolutionRef.current = null;
    return result;
  }, []);

  useEffect(() => {
    if (!supabase) return undefined;
    mountedRef.current = true;
    const { data: { subscription } } = supabase.auth.onAuthStateChange((event, session) => {
      if (!mountedRef.current) return;
      if (event === "SIGNED_OUT") {
        void resolveSession(null, event);
        return;
      }
      if (event === "TOKEN_REFRESHED" && session && resolvedUserRef.current === session.user.id) {
        setState((current) => replaceSession(current, session));
        return;
      }
      // Supabase Auth callbacks must return immediately. Deferring profile and
      // MFA calls prevents them from deadlocking the Auth client's lock.
      window.setTimeout(() => {
        if (mountedRef.current) void resolveSession(session, event);
      }, 0);
    });
    return () => {
      mountedRef.current = false;
      subscription.unsubscribe();
    };
  }, [resolveSession]);

  const signIn = useCallback(async (email: string, password: string) => {
    if (!supabase) return { ok: false, message: "Authentication is not configured for this build." };
    const { data, error } = await supabase.auth.signInWithPassword({ email: email.trim().toLowerCase(), password });
    if (error || !data.session) return { ok: false, message: "Invalid login credentials." };
    const resolved = await resolveSession(data.session, "SIGNED_IN");
    return resolved ? { ok: true } : { ok: false, message: "Your Netra access could not be verified." };
  }, [resolveSession]);

  const signOut = useCallback(async () => {
    if (supabase) await supabase.auth.signOut({ scope: "global" });
    clearNetraSessionState();
    resolvedUserRef.current = null;
    resolutionRef.current = null;
    resolutionGenerationRef.current += 1;
    setState({ status: "signed_out" });
  }, []);

  const refreshAssurance = useCallback(async () => {
    if (!supabase) return;
    const { data } = await supabase.auth.getSession();
    await resolveSession(data.session, "MFA_CHALLENGE_VERIFIED", true);
  }, [resolveSession]);

  const session = "session" in state ? state.session : null;
  const value = useMemo(() => ({ state, session, signIn, signOut, refreshAssurance }), [refreshAssurance, session, signIn, signOut, state]);
  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
