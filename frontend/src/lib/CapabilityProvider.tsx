import { useEffect, useMemo, useState, type ReactNode } from "react";

import { capabilityAvailable, capabilityReason, type CapabilityMap } from "./capabilities";
import { CapabilityContext, type CapabilityContextValue } from "./CapabilityContext";

const API_BASE = import.meta.env.VITE_API_BASE_URL ?? "/api";

export function CapabilityProvider({ children }: { children: ReactNode }) {
  const [capabilities, setCapabilities] = useState<CapabilityMap>({});
  const [loaded, setLoaded] = useState(false);

  useEffect(() => {
    const controller = new AbortController();
    fetch(`${API_BASE}/capabilities`, {
      headers: { Accept: "application/json" },
      signal: controller.signal,
    })
      .then(async (response) => {
        const payload = await response.json().catch(() => ({}));
        if (!response.ok || !payload || typeof payload !== "object") return;
        const results = (payload as Record<string, unknown>).results;
        if (results && typeof results === "object") setCapabilities(results as CapabilityMap);
      })
      .catch(() => undefined)
      .finally(() => {
        if (!controller.signal.aborted) setLoaded(true);
      });
    return () => controller.abort();
  }, []);

  const value = useMemo<CapabilityContextValue>(() => ({
    capabilities,
    loaded,
    available: (key) => capabilityAvailable(capabilities, key),
    reason: (key) => capabilityReason(capabilities, key),
  }), [capabilities, loaded]);

  return <CapabilityContext.Provider value={value}>{children}</CapabilityContext.Provider>;
}
