import type { NetraProfile, TotpFactor } from "./AuthContext";


export function requiredMfaStep(
  profile: NetraProfile,
  assurance: { currentLevel: string | null; nextLevel: string | null },
  verifiedFactors: TotpFactor[],
) {
  if (profile.mfaPolicy === "all_required" && verifiedFactors.length === 0) return "enroll" as const;
  if (assurance.nextLevel === "aal2" && assurance.currentLevel !== "aal2") return "challenge" as const;
  if (profile.mfaPolicy === "all_required" && assurance.currentLevel !== "aal2") return "challenge" as const;
  return "allow" as const;
}
