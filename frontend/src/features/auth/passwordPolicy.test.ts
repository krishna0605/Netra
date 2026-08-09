import { describe, expect, it } from "vitest";

import { passwordChecks, validPassword } from "./passwordPolicy";


describe("password policy", () => {
  it("requires length, case, number, and symbol", () => {
    expect(validPassword("short1!A")).toBe(false);
    expect(validPassword("longbutnosymbol1A")).toBe(false);
    expect(validPassword("Strong Netra1!")).toBe(true);
  });

  it("rejects passwords over the bounded maximum", () => {
    expect(validPassword(`Aa1!${"x".repeat(125)}`)).toBe(false);
    expect(passwordChecks("Aa1! secure password").every((check) => check.met)).toBe(true);
  });
});
