import { describe, expect, it } from "vitest";
import config from "../../../vercel.json";

const headers = Object.fromEntries(config.headers[0].headers.map((entry: { key: string; value: string }) => [entry.key, entry.value]));
const csp = headers["Content-Security-Policy"];

describe("production browser security policy", () => {
  it("allows only exact API and Supabase connection origins", () => {
    expect(csp).toContain("https://netra-api-production.up.railway.app");
    expect(csp).toContain("https://frjzewpyjgirorbguegm.supabase.co");
    expect(csp).not.toContain("*.supabase.co");
    expect(csp).not.toContain("*.up.railway.app");
    expect(csp).not.toContain("wss:");
  });

  it("blocks script injection, framing, arbitrary images and referrer leakage", () => {
    expect(csp).toContain("script-src 'self'");
    expect(csp).not.toContain("'unsafe-eval'");
    expect(csp).toContain("img-src 'self' data: blob:");
    expect(csp).toContain("frame-ancestors 'none'");
    expect(csp).toContain("base-uri 'none'");
    expect(headers["Referrer-Policy"]).toBe("no-referrer");
    expect(headers["Cross-Origin-Opener-Policy"]).toBe("same-origin");
    expect(headers["Cross-Origin-Resource-Policy"]).toBe("same-origin");
  });
});
