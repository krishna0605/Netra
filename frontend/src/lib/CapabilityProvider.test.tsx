import { render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";

import { CapabilityProvider } from "./CapabilityProvider";
import { useCapabilities } from "./useCapabilities";

function EmailCapabilityStatus() {
  const { available, loaded, reason } = useCapabilities();
  if (!loaded) return <p>loading</p>;
  return (
    <p>
      {available("password_recovery") ? "available" : "disabled"}
      {reason("password_recovery")}
    </p>
  );
}

describe("CapabilityProvider", () => {
  afterEach(() => vi.unstubAllGlobals());

  it("uses the authoritative public capability response", async () => {
    const fetchMock = vi.fn().mockResolvedValue({
      ok: true,
      json: async () => ({
        results: {
          password_recovery: {
            key: "password_recovery",
            implemented: true,
            enabled: false,
            state: "disabled",
            reason: "Password recovery requires an approved custom SMTP domain.",
            requires_aal2: false,
            durable_consumer: null,
          },
        },
      }),
    });
    vi.stubGlobal("fetch", fetchMock);

    render(<CapabilityProvider><EmailCapabilityStatus /></CapabilityProvider>);

    await waitFor(() => expect(screen.getByText(/disabledPassword recovery requires/)).toBeInTheDocument());
    expect(fetchMock).toHaveBeenCalledWith("/api/capabilities", expect.objectContaining({ signal: expect.any(AbortSignal) }));
  });

  it("fails closed when capability discovery is unavailable", async () => {
    vi.stubGlobal("fetch", vi.fn().mockRejectedValue(new Error("offline")));

    render(<CapabilityProvider><EmailCapabilityStatus /></CapabilityProvider>);

    await waitFor(() => expect(screen.getByText(/disabledThis feature is unavailable/)).toBeInTheDocument());
  });
});
