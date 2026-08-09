import { useContext } from "react";

import { CapabilityContext } from "./CapabilityContext";

export function useCapabilities() {
  const value = useContext(CapabilityContext);
  if (!value) throw new Error("useCapabilities must be used inside CapabilityProvider");
  return value;
}
