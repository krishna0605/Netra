import { createContext, useContext } from "react";
import type { Session } from "@supabase/supabase-js";
import type { CapabilityMap } from "../../lib/capabilities";

type DeploymentModuleAccess = { enabled: boolean; visible: boolean; reason: string };

export type NetraProfile = {
  user: string;
  department: string;
  role: string;
  aal: "aal1" | "aal2";
  mfaPolicy: "all_required" | "admin_required" | "optional";
  mfaEnrollmentRequired: boolean;
  privilegedAdminReady: boolean;
  account: { active: boolean; mustChangePassword: boolean; mfaRequired: boolean; mfaResetRequired: boolean };
  assuranceLevel: "aal1" | "aal2";
  workspaces: {
    investigation: { available: boolean; requiredAal: "aal2" };
    administration: { available: boolean; permission: "manage_users"; requiredAal: "aal2"; stepUpRequired: boolean };
  };
  organization: { id: string; name: string; slug: string };
  capabilities: CapabilityMap;
  deployment: {
    profile: string;
    hostCaptureEnabled: boolean;
    replayEnabled: boolean;
    sensorCaptureEnabled: boolean;
    modules: Record<"lab" | "sensors" | "schedules" | "integrations" | "retention" | "system", DeploymentModuleAccess>;
  };
};

export type TotpFactor = {
  id: string;
  friendly_name?: string;
  status: "verified" | "unverified";
  factor_type: "totp";
};

export type NetraAuthState =
  | { status: "initializing" }
  | { status: "signed_out" }
  | { status: "resolving_profile"; session: Session }
  | { status: "profile_denied"; code: string }
  | { status: "recovery"; session: Session }
  | { status: "mfa_enrollment_required"; session: Session; profile: NetraProfile }
  | { status: "mfa_challenge_required"; session: Session; profile: NetraProfile; factors: TotpFactor[] }
  | { status: "authenticated"; session: Session; profile: NetraProfile; aal: "aal1" | "aal2" }
  | { status: "privileged"; session: Session; profile: NetraProfile; aal: "aal2" };

export type AuthContextValue = {
  state: NetraAuthState;
  session: Session | null;
  signIn: (email: string, password: string) => Promise<{ ok: boolean; message?: string }>;
  signOut: () => Promise<void>;
  refreshAssurance: () => Promise<void>;
};

export const AuthContext = createContext<AuthContextValue | null>(null);

export function useAuth() {
  const value = useContext(AuthContext);
  if (!value) throw new Error("useAuth must be used inside AuthProvider");
  return value;
}
