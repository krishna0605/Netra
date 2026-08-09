import { describe, expect, it } from "vitest";

import { clearNetraSessionState } from "../../lib/supabase";

describe("frontend session ownership", () => {
  it("does not create token-shaped localStorage entries during cleanup", () => {
    window.localStorage.setItem("netra-theme", "dark");
    clearNetraSessionState();
    expect(Object.keys(window.localStorage).filter((key) => /(access|refresh|token)/i.test(key))).toEqual([]);
    expect(window.localStorage.getItem("netra-theme")).toBe("dark");
  });
});
