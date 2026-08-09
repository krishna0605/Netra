import type { NetraProfile, TotpFactor } from "./AuthContext";


export function requiredMfaStep(
  profile: NetraProfile,
  assurance: { currentLevel: string | null; nextLevel: string | null },
  verifiedFactors: TotpFactor[],
) {
  if (profile.role === "Admin" && verifiedFactors.length === 0) return "enroll" as const;
  if (assurance.nextLevel === "aal2" && assurance.currentLevel !== "aal2") return "challenge" as const;
  if (profile.role === "Admin" && assurance.currentLevel !== "aal2") return "challenge" as const;
  return "allow" as const;
}
