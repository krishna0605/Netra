import { createContext } from "react";

import type { CapabilityMap } from "./capabilities";

export type CapabilityContextValue = {
  capabilities: CapabilityMap;
  loaded: boolean;
  available: (key: string) => boolean;
  reason: (key: string) => string;
};

export const CapabilityContext = createContext<CapabilityContextValue | null>(null);
