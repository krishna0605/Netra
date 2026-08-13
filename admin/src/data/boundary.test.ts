import { describe, expect, it } from "vitest";
import { readdirSync, readFileSync, statSync } from "node:fs";
import { join, relative } from "node:path";

/**
 * The transport boundary, enforced.
 *
 * Every screen reads through the store so that wiring the backend means
 * rewriting function bodies in client.ts and nothing else. That property is
 * easy to state and easy to break — a single convenient import of a seed
 * constant leaves one screen showing fixtures forever, and it looks correct
 * until the data diverges.
 *
 * This already happened once. Roles and organization moved into the snapshot
 * and four consumers kept reading the seed file, so a cloned role never
 * appeared in the users filter or the create-user picker. Nothing failed;
 * the screens were simply wrong.
 */

const SRC = join(import.meta.dirname, "..");

/**
 * client.ts owns the seed data. store.tsx needs it for its empty state.
 * AuthProvider uses it only for the local-development profile fallback, which
 * is fenced behind IS_LOCAL and goes away with the /me endpoint. Tests may
 * read fixtures freely.
 */
const ALLOWED = new Set(["data/client.ts", "data/store.tsx", "features/auth/AuthProvider.tsx"]);

function sourceFiles(dir: string): string[] {
  return readdirSync(dir).flatMap((entry) => {
    const full = join(dir, entry);
    if (statSync(full).isDirectory()) return sourceFiles(full);
    return /\.tsx?$/.test(entry) ? [full] : [];
  });
}

describe("transport boundary", () => {
  const files = sourceFiles(SRC).map((full) => ({
    path: relative(SRC, full).replace(/\\/g, "/"),
    body: readFileSync(full, "utf8"),
  }));

  it("finds source to check", () => {
    expect(files.length).toBeGreaterThan(20);
  });

  it("keeps seed data out of screens and components", () => {
    const offenders = files
      .filter((file) => !file.path.includes(".test."))
      .filter((file) => !ALLOWED.has(file.path))
      .filter((file) => /from ["'][^"']*\/mock["']|from ["']\.\/mock["']/.test(file.body))
      .map((file) => file.path);

    expect(
      offenders,
      `These read seed data directly instead of the store, so they will keep showing fixtures after the backend lands:\n  ${offenders.join("\n  ")}`,
    ).toEqual([]);
  });

  it("routes every data call through the store rather than a bare fetch", () => {
    const offenders = files
      .filter((file) => !file.path.includes(".test."))
      .filter((file) => !file.path.startsWith("data/") && !file.path.startsWith("lib/"))
      // supabase.auth.* is the identity provider, not the directory, and is
      // allowed to talk to the network directly from the auth feature.
      .filter((file) => !file.path.startsWith("features/auth/"))
      .filter((file) => /\bfetch\s*\(/.test(file.body))
      .map((file) => file.path);

    expect(offenders, `These issue their own requests instead of going through the store:\n  ${offenders.join("\n  ")}`).toEqual([]);
  });

  it("exposes one operation per planned endpoint", () => {
    const store = files.find((file) => file.path === "data/store.tsx")!.body;

    // If a screen needs something the store cannot do, it will reach around
    // the boundary to get it. Keeping this list honest is what prevents that.
    for (const operation of [
      "createUser",
      "changeRole",
      "setPassword",
      "setStatus",
      "resetAuthenticator",
      "revokeSession",
      "revokeUserSessions",
      "revokeAllSessions",
      "grantPermission",
      "removeGrant",
      "createRole",
      "setRolePermission",
      "updateOrganization",
      "transferOwnership",
      "refetch",
    ]) {
      expect(store, `store is missing ${operation}`).toContain(operation);
    }
  });
});
