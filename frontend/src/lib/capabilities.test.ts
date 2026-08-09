import { describe, expect, it } from "vitest";

import { capabilityAvailable, capabilityReason, type CapabilityMap } from "./capabilities";

const capabilities: CapabilityMap = {
  sse: {
    key: "sse",
    implemented: true,
    enabled: true,
    state: "available",
    reason: "Bounded SSE is available.",
    requires_aal2: false,
    durable_consumer: null,
  },
  integration_external_sync: {
    key: "integration_external_sync",
    implemented: false,
    enabled: false,
    state: "not_implemented",
    reason: "No reviewed adapter is installed.",
    requires_aal2: false,
    durable_consumer: null,
  },
};

describe("capability helpers", () => {
  it("enables controls only for authoritative available state", () => {
    expect(capabilityAvailable(capabilities, "sse")).toBe(true);
    expect(capabilityAvailable(capabilities, "integration_external_sync")).toBe(false);
    expect(capabilityAvailable(capabilities, "unknown")).toBe(false);
  });

  it("uses the server reason with a safe fallback", () => {
    expect(capabilityReason(capabilities, "integration_external_sync")).toBe("No reviewed adapter is installed.");
    expect(capabilityReason(capabilities, "unknown")).toBe("This feature is unavailable.");
  });
});
