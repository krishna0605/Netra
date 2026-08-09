export type CapabilityState = "available" | "disabled" | "not_implemented" | "degraded";

export type CapabilityDefinition = {
  key: string;
  implemented: boolean;
  enabled: boolean;
  state: CapabilityState;
  reason: string;
  requires_aal2: boolean;
  durable_consumer: string | null;
};

export type CapabilityMap = Record<string, CapabilityDefinition>;

export function capabilityAvailable(capabilities: CapabilityMap, key: string) {
  return capabilities[key]?.state === "available";
}

export function capabilityReason(capabilities: CapabilityMap, key: string, fallback = "This feature is unavailable.") {
  return capabilities[key]?.reason || fallback;
}
