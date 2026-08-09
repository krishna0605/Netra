import { describe, expect, it } from "vitest";

import consoleSource from "./NetraConsole.tsx?raw";

describe("console module boundary", () => {
  it("keeps the public console entry composition-only", () => {
    expect(consoleSource.split(/\r?\n/).length).toBeLessThan(40);
    expect(consoleSource).not.toContain("fetch(");
    expect(consoleSource).not.toContain("createContext(");
  });
});
