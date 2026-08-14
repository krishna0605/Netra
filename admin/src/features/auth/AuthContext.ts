import { createContext, useContext } from "react";

/** Where the operator is in the sign-in journey. Drives which screen renders. */
export type AuthStage =
  | "resolving"
  | "anonymous"
  | "challenge"
  | "choosing"
  | "active"
  | "not_permitted";

export type AdminProfile = {
  userId: string;
  email: string;
  displayName: string;
  role: string;
  organizationName: string;
  isOwner: boolean;
  /** Whether this account may reach the administrative workspace at all. */
  isAdministrative: boolean;
};

/** Why a step-up did not happen. "" means it did. */
export type StepUpResult = "" | string;

export type AuthValue = {
  stage: AuthStage;
  profile: AdminProfile | null;
  /** When the second factor was last satisfied — drives step-up freshness. */
  verifiedAt: string | null;
  error: string;
  busy: boolean;

  signIn: (email: string, password: string) => Promise<void>;
  verifyCode: (code: string) => Promise<void>;
  /** Re-prove the authenticator mid-session so a destructive write carries
   *  proof rather than a claim. Returns "" on success, else a sentence. */
  stepUp: (code: string) => Promise<StepUpResult>;
  chooseAdministration: () => void;
  returnToChooser: () => void;
  signOut: () => Promise<void>;
  clearError: () => void;

  /** True when the second factor was satisfied within the window. */
  isStepUpFresh: (maxAgeMs?: number) => boolean;
};

export const AuthContext = createContext<AuthValue | null>(null);

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}

/** Five minutes, matching the step-up window the backend plan enforces. */
export const STEP_UP_WINDOW_MS = 5 * 60 * 1000;
export const IDLE_TIMEOUT_MS = 15 * 60 * 1000;
export const IDLE_WARN_MS = 2 * 60 * 1000;
