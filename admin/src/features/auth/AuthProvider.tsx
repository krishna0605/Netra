import { useCallback, useEffect, useMemo, useRef, useState, type ReactNode } from "react";

import { AuthContext, STEP_UP_WINDOW_MS, type AdminProfile, type AuthStage, type AuthValue } from "./AuthContext";
import { ApiFailure, fetchAdminSession } from "../../data/client";
import { supabase } from "../../lib/supabase";

/**
 * Administrative session state.
 *
 * The session lives here and nowhere else — the Supabase client is configured
 * with `persistSession: false`, so closing the tab or reloading ends it. That
 * is why `stage` starts at "resolving" and settles on "anonymous" rather than
 * attempting to restore anything.
 */

/** Never say whether an address exists; a sign-in form is an enumeration oracle otherwise. */
const GENERIC_REJECTION = "Those credentials were not accepted.";

/**
 * Anti-enumeration must not swallow infrastructure failures.
 *
 * A suspended project, a rate limit and a wrong password all arrive here as
 * "sign-in failed". Reporting them identically is actively harmful: it sends
 * someone hunting for a credential problem that does not exist. Only genuine
 * credential rejections get the generic message; everything else says plainly
 * that the service, not the password, is the problem — which reveals nothing
 * about whether any particular account exists.
 */
function describeFailure(error: unknown): string {
  const status = typeof error === "object" && error !== null ? Number((error as { status?: number }).status ?? 0) : 0;

  if (status === 429) {
    return "Too many attempts. Wait a minute before trying again.";
  }
  if (status === 402 || status === 403) {
    return "Sign-in is unavailable: the authentication service is currently restricted. This is not a problem with your credentials.";
  }
  if (status === 0 || status >= 500) {
    return "Sign-in is unavailable. The authentication service could not be reached.";
  }
  return GENERIC_REJECTION;
}

/**
 * Resolve administrative standing from the server.
 *
 * Returns null when the account may not administer the organization, which the
 * caller turns into the "not permitted" stage. A network failure is not a
 * refusal and must not be silently treated as one, so it propagates.
 */
async function profileFor(email: string, userId: string): Promise<AdminProfile | null> {
  try {
    const session = await fetchAdminSession();
    return {
      userId,
      email: session.email || email,
      displayName: session.name || email.split("@")[0] || email,
      role: session.isOwner ? "Owner" : session.role,
      organizationName: session.organization.name,
      isOwner: session.isOwner,
      isAdministrative: true,
    };
  } catch (failure) {
    // 401/403/404 are the server answering the question: this account is not
    // an administrator. Anything else is the question going unanswered.
    //
    // step_up_required is excluded deliberately. It shares the 401 status but
    // means the opposite — the account is permitted and merely needs to touch
    // its authenticator again. Reading it as a refusal would lock an
    // administrator out of their own console for having been signed in a while.
    if (failure instanceof ApiFailure && failure.code === "step_up_required") {
      throw failure;
    }
    if (failure instanceof ApiFailure && (failure.status === 401 || failure.status === 403 || failure.status === 404)) {
      return null;
    }
    throw failure;
  }
}

export function AuthProvider({ children }: { children: ReactNode }) {
  const [stage, setStage] = useState<AuthStage>("resolving");
  const [profile, setProfile] = useState<AdminProfile | null>(null);
  const [verifiedAt, setVerifiedAt] = useState<string | null>(null);
  const [error, setError] = useState("");
  const [busy, setBusy] = useState(false);

  const pendingEmail = useRef("");

  // No restoration by design. Any session Supabase may still hold in memory
  // from a hot reload is discarded so development matches production.
  useEffect(() => {
    let cancelled = false;
    void supabase.auth.signOut({ scope: "local" }).finally(() => {
      if (!cancelled) setStage("anonymous");
    });
    return () => {
      cancelled = true;
    };
  }, []);

  const settleAfterFactor = useCallback(async (email: string, userId: string) => {
    let resolved: AdminProfile | null;
    try {
      resolved = await profileFor(email, userId);
    } catch (failure) {
      // The directory could not be asked. Refusing here would tell an
      // administrator they lack permission they actually hold, so say what
      // happened and leave them able to retry.
      setProfile(null);
      setError(
        failure instanceof ApiFailure
          ? failure.message
          : "Could not confirm your administrative access. Try again.",
      );
      setStage("anonymous");
      return;
    }
    if (!resolved || !resolved.isAdministrative) {
      setProfile(null);
      setStage("not_permitted");
      return;
    }
    setProfile(resolved);
    setVerifiedAt(new Date().toISOString());
    setStage("choosing");
  }, []);

  const signIn = useCallback(
    async (email: string, password: string) => {
      setBusy(true);
      setError("");
      try {
        const { data, error: signInError } = await supabase.auth.signInWithPassword({
          email: email.trim().toLowerCase(),
          password,
        });

        if (signInError || !data.session) {
          setError(signInError ? describeFailure(signInError) : GENERIC_REJECTION);
          return;
        }

        pendingEmail.current = data.user?.email ?? email.trim().toLowerCase();

        const { data: assurance } = await supabase.auth.mfa.getAuthenticatorAssuranceLevel();
        const needsSecondFactor = assurance?.nextLevel === "aal2" && assurance.currentLevel !== "aal2";

        if (needsSecondFactor) {
          setStage("challenge");
          return;
        }

        await settleAfterFactor(pendingEmail.current, data.user?.id ?? "");
      } catch {
        setError("Sign-in is unavailable. Check your connection and try again.");
      } finally {
        setBusy(false);
      }
    },
    [settleAfterFactor],
  );

  const verifyCode = useCallback(
    async (code: string) => {
      setBusy(true);
      setError("");
      try {
        const { data: factors, error: listError } = await supabase.auth.mfa.listFactors();
        const totp = factors?.totp?.find((factor) => factor.status === "verified") ?? factors?.totp?.[0];

        if (listError || !totp) {
          setError("No authenticator is enrolled on this account.");
          return;
        }

        const { error: verifyError } = await supabase.auth.mfa.challengeAndVerify({
          factorId: totp.id,
          code: code.trim(),
        });

        if (verifyError) {
          const status = Number((verifyError as { status?: number }).status ?? 0);
          setError(
            status === 0 || status >= 402
              ? describeFailure(verifyError)
              : "That code was not accepted. Codes expire after 30 seconds.",
          );
          return;
        }

        const { data } = await supabase.auth.getUser();
        await settleAfterFactor(pendingEmail.current || (data.user?.email ?? ""), data.user?.id ?? "");
      } catch {
        setError("Verification is unavailable. Check your connection and try again.");
      } finally {
        setBusy(false);
      }
    },
    [settleAfterFactor],
  );

  const chooseAdministration = useCallback(() => {
    setStage((current) => (current === "choosing" ? "active" : current));
  }, []);

  const returnToChooser = useCallback(() => {
    setStage((current) => (current === "active" ? "choosing" : current));
  }, []);

  const signOut = useCallback(async () => {
    setBusy(true);
    try {
      // Local scope, not global. Both consoles authenticate the same Supabase
      // user, so a global sign-out would revoke every refresh token that user
      // holds — ending their investigation session too. Leaving Administration
      // must not eject someone from work they had open elsewhere.
      await supabase.auth.signOut({ scope: "local" });
    } catch {
      // Signing out locally must succeed even if the network call does not.
    } finally {
      pendingEmail.current = "";
      setProfile(null);
      setVerifiedAt(null);
      setError("");
      setStage("anonymous");
      setBusy(false);
    }
  }, []);

  const isStepUpFresh = useCallback(
    (maxAgeMs: number = STEP_UP_WINDOW_MS) => {
      if (!verifiedAt) return false;
      return Date.now() - Date.parse(verifiedAt) < maxAgeMs;
    },
    [verifiedAt],
  );

  const clearError = useCallback(() => setError(""), []);

  const value = useMemo<AuthValue>(
    () => ({
      stage,
      profile,
      verifiedAt,
      error,
      busy,
      signIn,
      verifyCode,
      chooseAdministration,
      returnToChooser,
      signOut,
      clearError,
      isStepUpFresh,
    }),
    [stage, profile, verifiedAt, error, busy, signIn, verifyCode, chooseAdministration, returnToChooser, signOut, clearError, isStepUpFresh],
  );

  return <AuthContext.Provider value={value}>{children}</AuthContext.Provider>;
}
