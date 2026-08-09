import { describe, expect, it } from "vitest";

import type { NetraProfile, TotpFactor } from "./AuthContext";
import { requiredMfaStep } from "./authPolicy";


const profile = (role: string): NetraProfile => ({
  user: "officer@netra.test",
  role,
  aal: "aal1",
  mfaPolicy: "admin_required",
  mfaEnrollmentRequired: role === "Admin",
  privilegedAdminReady: false,
  organization: { id: "org", name: "Netra", slug: "netra" },
});

const factor: TotpFactor = {
  id: "factor-id",
  factor_type: "totp",
  status: "verified",
  friendly_name: "Netra authenticator",
};

describe("MFA policy", () => {
  it("requires enrollment for an administrator without a verified factor", () => {
    expect(requiredMfaStep(profile("Admin"), { currentLevel: "aal1", nextLevel: "aal1" }, [])).toBe("enroll");
  });

  it("requires a challenge whenever an enrolled session can reach aal2", () => {
    expect(requiredMfaStep(profile("Investigator"), { currentLevel: "aal1", nextLevel: "aal2" }, [factor])).toBe("challenge");
  });

  it("allows an administrator only after aal2", () => {
    expect(requiredMfaStep(profile("Admin"), { currentLevel: "aal2", nextLevel: "aal2" }, [factor])).toBe("allow");
  });
});
