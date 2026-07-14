import { describe, expect, it } from "vitest";

import { readStoredAccessToken } from "./supabase";

function storageWith(value: string | null) {
  return {
    getItem: (key: string) => (key === "sb-projectref-auth-token" ? value : null),
  };
}

describe("readStoredAccessToken", () => {
  it("restores a non-expired Supabase session before protected API bootstrap", () => {
    const value = JSON.stringify({ access_token: "session-token", expires_at: 2_000 });
    expect(readStoredAccessToken(storageWith(value), "https://projectref.supabase.co", 1_000)).toBe("session-token");
  });

  it("rejects expired, malformed, and project-mismatched sessions", () => {
    expect(readStoredAccessToken(storageWith(JSON.stringify({ access_token: "expired", expires_at: 999 })), "https://projectref.supabase.co", 1_000)).toBe("");
    expect(readStoredAccessToken(storageWith("not-json"), "https://projectref.supabase.co", 1_000)).toBe("");
    expect(readStoredAccessToken(storageWith(JSON.stringify({ access_token: "token" })), "https://another.supabase.co", 1_000)).toBe("");
  });
});
