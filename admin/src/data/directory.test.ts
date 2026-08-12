import { beforeEach, describe, expect, it } from "vitest";

import { ApiFailure, directoryApi, resetDirectory } from "./client";
import { generatePassword, passwordStrength } from "./store";

beforeEach(() => {
  // Each test starts from the seed. The module holds one state, as a server
  // does, so without this they would pass or fail by ordering.
  resetDirectory();
});

describe("generatePassword", () => {
  it("produces something the strength meter rates highly", () => {
    for (let attempt = 0; attempt < 20; attempt += 1) {
      expect(passwordStrength(generatePassword()).score).toBeGreaterThanOrEqual(3);
    }
  });

  it("omits characters that are misread when a password is written down or dictated", () => {
    const generated = Array.from({ length: 40 }, () => generatePassword()).join("");
    for (const ambiguous of ["I", "l", "O", "0", "1"]) {
      expect(generated).not.toContain(ambiguous);
    }
  });

  it("does not repeat", () => {
    const seen = new Set(Array.from({ length: 50 }, () => generatePassword()));
    expect(seen.size).toBe(50);
  });
});

describe("passwordStrength", () => {
  it("rates a short password weak", () => {
    expect(passwordStrength("abc").score).toBeLessThanOrEqual(2);
  });

  it("reports nothing for an empty value rather than 'weak'", () => {
    expect(passwordStrength("")).toEqual({ score: 0, label: "" });
  });
});

describe("changeRole", () => {
  it("preserves explicit grants and revocations across a role change", async () => {
    const before = await directoryApi.read();
    const target = before.users.find((user) => user.permissions.some((p) => p.source !== "role"));
    expect(target).toBeDefined();

    const overridesBefore = target!.permissions
      .filter((permission) => permission.source !== "role")
      .map((permission) => `${permission.source}:${permission.key}`)
      .sort();
    expect(overridesBefore.length).toBeGreaterThan(0);

    const after = await directoryApi.changeRole(target!.id, "investigator", "Promoted during a reshuffle.");
    const updated = after.users.find((user) => user.id === target!.id)!;

    const overridesAfter = updated.permissions
      .filter((permission) => permission.source !== "role")
      .map((permission) => `${permission.source}:${permission.key}`)
      .sort();

    // A temporary grant silently vanishing on a promotion is a nasty way to
    // lose access, and nobody would think to look for it.
    expect(overridesAfter).toEqual(overridesBefore);
    expect(updated.roleSlug).toBe("investigator");
  });
});

describe("createUser", () => {
  it("refuses an address already in use", async () => {
    const before = await directoryApi.read();
    const existing = before.users[0].email;

    await expect(
      directoryApi.createUser({
        name: "Duplicate",
        email: existing.toUpperCase(),
        department: "Cell",
        roleSlug: "viewer",
        mustChangePassword: true,
      }),
    ).rejects.toBeInstanceOf(ApiFailure);
  });

  it("records the creation in the audit trail", async () => {
    const { snapshot } = await directoryApi.createUser({
      name: "New Person",
      email: "new.person@gcc.gov.in",
      department: "Cell",
      roleSlug: "viewer",
      mustChangePassword: true,
    });

    expect(snapshot.audit[0].action).toBe("user.created");
    expect(snapshot.audit[0].targetId).toBe("new.person@gcc.gov.in");
  });
});

describe("audit chain", () => {
  it("links each entry to the one before it", async () => {
    await directoryApi.setStatus(63, "active", "Restored for the purposes of this test.");
    const snapshot = await directoryApi.read();

    for (let index = 0; index < snapshot.audit.length - 1; index += 1) {
      const newer = snapshot.audit[index];
      const older = snapshot.audit[index + 1];
      expect(newer.previousHash).toBe(older.eventHash);
      expect(newer.chainIndex).toBe(older.chainIndex + 1);
    }
  });
});

describe("setPassword", () => {
  it("ends every session for that account when asked", async () => {
    const before = await directoryApi.read();
    const withSessions = before.sessions[0].userId;
    expect(before.sessions.some((session) => session.userId === withSessions)).toBe(true);

    const after = await directoryApi.setPassword({
      userId: withSessions,
      reason: "Credential reported as shared.",
      requireChange: true,
      revokeSessions: true,
    });

    // A password change that leaves an old session signed in has not locked
    // anyone out, which is the entire point of doing it.
    expect(after.sessions.some((session) => session.userId === withSessions)).toBe(false);
  });

  it("never writes the password into stored state", async () => {
    await directoryApi.setPassword({
      userId: 41,
      reason: "Routine replacement for this test.",
      requireChange: true,
      revokeSessions: false,
    });

    expect(JSON.stringify(window.localStorage.getItem("netra.directory.v1"))).not.toContain("password:");
  });
});

describe("roles", () => {
  it("refuses to edit a standard role at the boundary, not only in the interface", async () => {
    await expect(directoryApi.setRolePermission("analyst", "export", true)).rejects.toMatchObject({
      code: "system_role_locked",
    });
  });

  it("clones a role with the base role's permissions", async () => {
    const { created } = await directoryApi.createRole({
      name: "Records Desk",
      description: "",
      baseSlug: "analyst",
    });

    const snapshot = await directoryApi.read();
    const base = snapshot.roles.find((role) => role.slug === "analyst")!;

    expect(created.isSystem).toBe(false);
    expect([...created.permissions].sort()).toEqual([...base.permissions].sort());
  });

  it("allows editing a cloned role", async () => {
    await directoryApi.createRole({ name: "Editable Role", description: "", baseSlug: "viewer" });
    const after = await directoryApi.setRolePermission("editable_role", "export", true);
    const role = after.roles.find((entry) => entry.slug === "editable_role")!;
    expect(role.permissions).toContain("export");
  });
});

describe("transferOwnership", () => {
  it("leaves exactly one owner", async () => {
    const before = await directoryApi.read();
    const candidate = before.users.find((user) => !user.isOwner && user.status === "active")!;

    const after = await directoryApi.transferOwnership(candidate.id, "Handing over at the end of a posting.");

    expect(after.users.filter((user) => user.isOwner)).toHaveLength(1);
    expect(after.users.find((user) => user.isOwner)!.id).toBe(candidate.id);
  });

  it("refuses an inactive recipient", async () => {
    const before = await directoryApi.read();
    const inactive = before.users.find((user) => user.status === "deactivated")!;

    await expect(directoryApi.transferOwnership(inactive.id, "Should not be permitted.")).rejects.toMatchObject({
      code: "inactive_target",
    });
  });
});
