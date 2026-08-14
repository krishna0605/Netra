import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { supabase } from "../lib/supabase";
import { directoryApi, currentDirectory, resetDirectory, verifyAuditChain } from "./client";
import { generatePassword, passwordStrength } from "./store";

beforeEach(() => {
  // Each test starts from the seed. The module holds one state, as a server
  // does, so without this they would pass or fail by ordering.
  resetDirectory();

  // read() is a network call now. These tests are about the write operations,
  // which still run locally, so the transport is stubbed to hand back whatever
  // the module currently holds. Stubbing rather than bypassing keeps the fact
  // that reads leave the browser visible in the test, instead of hiding it
  // behind a local accessor that production never uses.
  vi.spyOn(supabase.auth, "getSession").mockResolvedValue({
    data: { session: { access_token: "test-token" } },
    error: null,
  } as unknown as Awaited<ReturnType<typeof supabase.auth.getSession>>);
  vi.stubGlobal(
    "fetch",
    vi.fn(async () => new Response(JSON.stringify(currentDirectory()), { status: 200 })),
  );
});

afterEach(() => {
  vi.unstubAllGlobals();
  vi.restoreAllMocks();
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

/*
 * A test stood here asserting that explicit grants and revocations survive a
 * role change. It exercised local logic that has now moved to the server, and
 * the server does not have grants yet — PermissionGrant arrives with the
 * permissions phase. Leaving it would have meant a test of a code path the
 * console no longer runs; skipping it would have meant a reminder CI ignores.
 *
 * The property still matters: a temporary grant vanishing on a promotion is a
 * quiet way to lose access that nobody thinks to look for. It belongs in the
 * server's own tests, against the model that will hold it.
 */

describe("account writes", () => {
  /** Stub one write endpoint and the re-read that follows it. */
  function stubWrite(body: unknown, status = 200) {
    const calls: Array<{ url: string; init: RequestInit }> = [];
    let first = true;
    vi.stubGlobal(
      "fetch",
      vi.fn(async (url: string, init: RequestInit = {}) => {
        calls.push({ url: String(url), init });
        if (first && !String(url).endsWith("/admin/v1/directory")) {
          first = false;
          return new Response(JSON.stringify(body), { status });
        }
        return new Response(JSON.stringify(currentDirectory()), { status: 200 });
      }),
    );
    return calls;
  }

  it("sends the create to the server and re-reads rather than guessing", async () => {
    const calls = stubWrite(
      { user: { id: 41, email: "new.person@gcc.gov.in", name: "New Person", roleSlug: "viewer", department: "Cell", status: "active" }, password: "Xy7#kq2Zm4Rt8Wp5" },
      201,
    );

    await directoryApi.createUser({
      name: "New Person",
      email: "New.Person@gcc.gov.in",
      department: "Cell",
      roleSlug: "viewer",
      password: "Xy7#kq2Zm4Rt8Wp5",
      reason: "Joined the unit this week.",
    });

    const create = calls[0];
    expect(create.url).toContain("/admin/v1/users");
    expect(create.init.method).toBe("POST");
    const sent = JSON.parse(String(create.init.body));
    // The API speaks role names; the console works in slugs.
    expect(sent.role).toBe("Viewer");
    expect(sent.email).toBe("new.person@gcc.gov.in");
    expect(sent.reason).toBe("Joined the unit this week.");

    // The row the screens render comes from the server, not from a locally
    // invented one — guessing is how a console shows a user the database
    // does not have.
    expect(calls[1].url).toContain("/admin/v1/directory");
  });

  it("surfaces a refusal instead of applying the change locally", async () => {
    stubWrite({ error: { code: "email_in_use", message: "Already exists." } }, 409);

    await expect(
      directoryApi.createUser({
        name: "Duplicate",
        email: "a.patel@gcc.gov.in",
        department: "Cell",
        roleSlug: "viewer",
        reason: "Should be refused by the server.",
      }),
    ).rejects.toMatchObject({ code: "email_in_use", status: 409 });
  });

  it("returns the password the server applied, not the one it was sent", async () => {
    // The server may generate its own. Showing the operator what the dialog
    // sent would hand over a credential that does not work.
    stubWrite({ user: { id: 41, email: "x@gcc.gov.in", name: "X", roleSlug: "viewer", department: "Cell", status: "active" }, password: "ServerChose#9wQz" });

    const result = await directoryApi.setPassword({ userId: 41, reason: "Credential reported as shared." });

    expect(result.password).toBe("ServerChose#9wQz");
  });

  it("never keeps a password in directory state", async () => {
    stubWrite({ user: { id: 41, email: "x@gcc.gov.in", name: "X", roleSlug: "viewer", department: "Cell", status: "active" }, password: "ServerChose#9wQz" });

    const { snapshot } = await directoryApi.setPassword({ userId: 41, reason: "Routine replacement." });

    expect(JSON.stringify(snapshot)).not.toContain("ServerChose#9wQz");
  });

  it("sends a role change as a PATCH with the role name", async () => {
    const calls = stubWrite({ user: { id: 41, email: "x@gcc.gov.in", name: "X", roleSlug: "analyst", department: "Cell", status: "active" } });

    await directoryApi.changeRole(41, "analyst", "Moved to the analysis desk.");

    expect(calls[0].init.method).toBe("PATCH");
    expect(JSON.parse(String(calls[0].init.body)).role).toBe("Analyst");
  });

  it("sends deactivation as an active flag the server understands", async () => {
    const calls = stubWrite({ user: { id: 41, email: "x@gcc.gov.in", name: "X", roleSlug: "viewer", department: "Cell", status: "deactivated" } });

    await directoryApi.setStatus(41, "deactivated", "Transferred out of the unit.");

    expect(JSON.parse(String(calls[0].init.body)).active).toBe(false);
  });

  it("sends an authenticator reset as a DELETE carrying its reason", async () => {
    const calls = stubWrite({ user: { id: 41, email: "x@gcc.gov.in", name: "X", roleSlug: "viewer", department: "Cell", status: "active" } });

    await directoryApi.resetAuthenticator(41, "Officer changed phone this morning.");

    expect(calls[0].url).toContain("/factors");
    expect(calls[0].init.method).toBe("DELETE");
    expect(JSON.parse(String(calls[0].init.body)).reason).toContain("changed phone");
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

describe("audit chain verification", () => {
  it("reports an intact chain", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              verified: true,
              eventCount: 12,
              rootHash: "a".repeat(64),
              latestHash: "b".repeat(64),
              firstBrokenIndex: null,
              failures: [],
              checkedAt: new Date().toISOString(),
            }),
            { status: 200 },
          ),
      ),
    );

    const report = await verifyAuditChain();

    expect(report.verified).toBe(true);
    expect(report.firstBrokenIndex).toBeNull();
  });

  it("reports where a tampered chain stops agreeing", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(
            JSON.stringify({
              verified: false,
              eventCount: 12,
              rootHash: "a".repeat(64),
              latestHash: "b".repeat(64),
              firstBrokenIndex: 7,
              failures: [7, 8],
              checkedAt: new Date().toISOString(),
            }),
            { status: 200 },
          ),
      ),
    );

    const report = await verifyAuditChain();

    expect(report.verified).toBe(false);
    // An auditor needs to know how much of the record still stands, not only
    // that something is wrong.
    expect(report.firstBrokenIndex).toBe(7);
  });

  it("does not report an unreachable service as either verified or broken", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => { throw new TypeError("network"); }));

    await expect(verifyAuditChain()).rejects.toMatchObject({ code: "service_unreachable" });
  });
});

describe("step-up refusals", () => {
  it("are not treated as a dead session", async () => {
    // Shares the 401 status with an expired session and means the opposite:
    // the operator is signed in and permitted, and simply needs to touch their
    // authenticator. Signing them out here would be the wrong response to
    // someone asking to do their job.
    vi.stubGlobal(
      "fetch",
      vi.fn(
        async () =>
          new Response(JSON.stringify({ error: { code: "step_up_required", message: "" } }), { status: 401 }),
      ),
    );

    await expect(directoryApi.read()).rejects.toMatchObject({
      code: "step_up_required",
      message: "Confirm this action with your authenticator.",
    });
  });
});
