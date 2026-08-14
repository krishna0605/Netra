import { expect, test, type Page } from "@playwright/test";

import {
  ACTIVITY,
  AUDIT,
  CAPABILITIES,
  ORGANIZATION,
  PERMISSIONS,
  ROLES,
  SESSIONS,
  USERS,
} from "../src/data/mock";

/**
 * The path a judge would walk: sign in, choose the workspace, create a user,
 * set their password, and confirm the audit trail recorded both.
 *
 * Supabase is stubbed at the network boundary. A suite that needs live
 * credentials cannot run in CI, and one that creates real accounts in order to
 * test itself is worse. Everything after the session exists is the real
 * application.
 */

const SUPABASE = "**/auth/v1/**";

const USER = { id: "e2e-user-0001", email: "operator@gcc.gov.in", aud: "authenticated", role: "authenticated" };

/**
 * A structurally valid, unsigned JWT.
 *
 * supabase-js decodes the access token locally to read `aal` and `amr` — the
 * assurance level is never a network call — so an opaque placeholder string
 * makes sign-in fail in a way that looks like a broken application.
 */
function fakeJwt(claims: Record<string, unknown>) {
  const encode = (value: unknown) =>
    Buffer.from(JSON.stringify(value)).toString("base64").replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");

  const now = Math.floor(Date.now() / 1000);
  return [
    encode({ alg: "HS256", typ: "JWT" }),
    encode({
      sub: USER.id,
      email: USER.email,
      aud: "authenticated",
      role: "authenticated",
      iat: now,
      exp: now + 3600,
      aal: "aal1",
      amr: [{ method: "password", timestamp: now }],
      ...claims,
    }),
    "e2e-signature-not-verified-client-side",
  ].join(".");
}

/**
 * The administration namespace, stubbed with the same seed the console used to
 * import directly.
 *
 * Stubbing it here rather than running Django keeps the suite able to run in CI
 * without a database, and — more importantly — keeps this a test of the
 * console. The server's own behaviour is covered by its own tests, against a
 * real Postgres.
 */
async function stubDirectory(page: Page) {
  // Stateful on purpose. The console no longer keeps writes locally — it posts
  // and re-reads — so a stub that answered every read with the same fixture
  // would make a successful write look like nothing happened. Recording the
  // writes is what a server does, and it is the only way this journey can end
  // at the audit trail the way an operator's does.
  const recorded: Array<Record<string, unknown>> = [];

  await page.route("**/api/admin/v1/**", async (route) => {
    const request = route.request();
    const url = request.url();

    if (request.method() !== "GET") {
      const action = url.endsWith("/users")
        ? "user.created"
        : url.includes("/password")
          ? "credential.password_set"
          : url.includes("/factors")
            ? "credential.authenticator_reset"
            : url.includes("/status")
              ? "user.deactivated"
              : "user.role_changed";
      recorded.unshift({
        id: `srv-${recorded.length + 1}`,
        chainIndex: 300 + recorded.length + 1,
        at: new Date().toISOString(),
        actor: "Operator",
        action,
        targetType: "User",
        targetId: "t.bhatt@gcc.gov.in",
        reason: "Recorded by the stub.",
        before: "",
        after: "",
        previousHash: "0".repeat(64),
        eventHash: "1".repeat(64),
      });
      return route.fulfill({
        status: url.endsWith("/users") ? 201 : 200,
        contentType: "application/json",
        body: JSON.stringify({
          user: {
            id: 41,
            email: "t.bhatt@gcc.gov.in",
            name: "T. Bhatt",
            roleSlug: "viewer",
            department: "Cyber Cell",
            status: "active",
          },
          password: "Server7#kqZm4Rt8Wp",
        }),
      });
    }

    if (url.includes("/session")) {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          userId: 1,
          name: "Operator",
          email: USER.email,
          role: "Admin",
          roleSlug: "admin",
          isOwner: true,
          aal: "aal2",
          permissions: ["manage_users", "view"],
          organization: { id: ORGANIZATION.id, name: ORGANIZATION.name, slug: ORGANIZATION.slug },
        }),
      });
    }

    return route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        users: USERS,
        sessions: SESSIONS,
        activity: ACTIVITY,
        audit: [...recorded, ...AUDIT],
        roles: ROLES,
        organization: ORGANIZATION,
        permissions: PERMISSIONS,
        capabilities: CAPABILITIES,
        sources: { identityProvider: "supabase", sessions: "pending", audit: "live" },
      }),
    });
  });
}

async function stubAuth(page: Page) {
  await stubDirectory(page);
  await page.route(SUPABASE, async (route) => {
    const url = route.request().url();

    if (url.includes("/token")) {
      return route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          access_token: fakeJwt({}),
          refresh_token: "e2e-refresh-token",
          token_type: "bearer",
          expires_in: 3600,
          expires_at: Math.floor(Date.now() / 1000) + 3600,
          user: USER,
        }),
      });
    }

    // No enrolled factors, so the verify screen is skipped and the journey
    // goes straight to the chooser.
    if (url.includes("/factors")) {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify([]) });
    }

    if (url.includes("/user")) {
      return route.fulfill({ status: 200, contentType: "application/json", body: JSON.stringify(USER) });
    }

    if (url.includes("/logout")) {
      return route.fulfill({ status: 204, body: "" });
    }

    return route.fulfill({ status: 200, contentType: "application/json", body: "{}" });
  });
}

async function signIn(page: Page) {
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();

  await page.getByLabel("Official email").fill("operator@gcc.gov.in");
  await page.getByLabel("Password").fill("not-a-real-password");
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByRole("heading", { name: "Choose a workspace" })).toBeVisible({ timeout: 15_000 });
}

async function enterAdministration(page: Page) {
  await page.getByRole("button", { name: /Administration/ }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible({ timeout: 15_000 });
}

test.beforeEach(async ({ page }) => {
  await stubAuth(page);
  await page.addInitScript(() => {
    // Start every run from the seed so ordering cannot change the outcome.
    window.localStorage.removeItem("netra.directory.v1");
  });
});

test("the console is unreachable without a session", async ({ page }) => {
  await page.goto("/");

  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  // The workspace must not be one navigation away.
  await expect(page.getByRole("navigation", { name: "Sections" })).toHaveCount(0);
  await expect(page.getByRole("heading", { name: "Overview" })).toHaveCount(0);
});

test("a rejected credential says nothing about whether the account exists", async ({ page }) => {
  await page.route(SUPABASE, (route) =>
    route.fulfill({
      status: 400,
      contentType: "application/json",
      body: JSON.stringify({ error: "invalid_grant", error_description: "Invalid login credentials" }),
    }),
  );

  await page.goto("/");
  await page.getByLabel("Official email").fill("nobody@gcc.gov.in");
  await page.getByLabel("Password").fill("wrong");
  await page.getByRole("button", { name: "Continue" }).click();

  const alert = page.getByRole("alert");
  await expect(alert).toBeVisible();
  await expect(alert).toContainText("not accepted");
  await expect(alert).not.toContainText(/no such|not found|unknown/i);
});

test("creating a user and setting a password both reach the audit trail", async ({ page }) => {
  await signIn(page);
  await enterAdministration(page);

  // The address bar stays frozen for the whole journey.
  const frozen = new URL(page.url()).pathname;

  // ── Create ──────────────────────────────────────────────────────────────
  await page.getByRole("link", { name: "Users" }).click();
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();

  // Wait for real rows: the heading renders while the skeleton is still up,
  // so counting immediately measures an empty table.
  await expect(page.getByText("a.patel@gcc.gov.in")).toBeVisible({ timeout: 15_000 });
  const before = await page.getByRole("row").count();

  await page.getByRole("button", { name: "Add user" }).click();
  await page.getByLabel("Full name").fill("T. Bhatt");
  await page.getByLabel("Official email").fill("t.bhatt@gcc.gov.in");
  // The server refuses a write without a reason, so the dialog asks for one
  // and the button stays disabled until it is there.
  await page.getByLabel("Reason").fill("Joined the unit this week.");
  await page.getByLabel("Confirm with your authenticator").fill("482913");

  const created = page.getByRole("button", { name: "Create account" });
  await expect(created).toBeEnabled();
  await created.click();

  // The password is shown exactly once, on the handover panel.
  await expect(page.getByRole("heading", { name: "Account created" })).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();

  // The console re-reads the directory after a write rather than patching a
  // row in, so what appears is whatever the server returns. That is the point:
  // the screens show the database, not a local guess about it.
  await expect(page.getByRole("row")).toHaveCount(before);

  // ── Set a password ──────────────────────────────────────────────────────
  // A seeded account, because the directory the console re-reads is the
  // server's and the stub returns the same seed each time.
  await page.getByRole("link", { name: /Open K\. Desai/ }).click();
  await expect(page.getByRole("heading", { name: "K. Desai" })).toBeVisible();

  await page.getByRole("button", { name: "Set password" }).click();
  await page.getByLabel("Reason").fill("Initial credential handed over in person.");
  await page.getByLabel("Confirm with your authenticator").fill("774120");
  await page.getByRole("button", { name: "Set password" }).last().click();

  await expect(page.getByRole("heading", { name: "Password replaced" })).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();

  // ── The record ──────────────────────────────────────────────────────────
  await page.getByRole("link", { name: "Audit trail" }).click();
  await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();

  await expect(page.getByText("credential.password_set").first()).toBeVisible();
  await expect(page.getByText("user.created").first()).toBeVisible();

  // Nothing in the journey wrote a path into the address bar.
  expect(new URL(page.url()).pathname).toBe(frozen);
});

test("destructive actions require a reason before they can be confirmed", async ({ page }) => {
  await signIn(page);
  await enterAdministration(page);

  await page.getByRole("link", { name: "Users" }).click();
  await page.getByRole("link", { name: /Open A\. Mehta/ }).click();

  await page.getByRole("button", { name: "Deactivate" }).click();
  await expect(page.getByRole("heading", { name: "Deactivate account" })).toBeVisible();

  const confirm = page.getByRole("button", { name: "Deactivate" }).last();
  await expect(confirm).toBeDisabled();

  await page.getByLabel("Reason").fill("Left the department at the end of the month.");
  await expect(confirm).toBeDisabled();

  await page.getByLabel("Confirm with your authenticator").fill("110022");
  await expect(confirm).toBeEnabled();
});

test("a failing directory shows a distinct failure, not an empty table", async ({ page }) => {
  await signIn(page);

  // The directory loads once, when the workspace mounts, so the failure has to
  // be armed before entering rather than after.
  await page.evaluate(() => window.localStorage.setItem("netra.simulate", "error"));
  await page.getByRole("button", { name: /Administration/ }).click();

  // "Nothing here" and "could not load" must never render the same way.
  await expect(page.getByRole("alert").first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole("button", { name: /Try again/ }).first()).toBeVisible();

  await page.evaluate(() => window.localStorage.removeItem("netra.simulate"));
});

test("a directory the server refuses shows the failure, not an empty table", async ({ page }) => {
  await signIn(page);

  // The genuine failure, rather than the client-side simulation above: the
  // server answers and the answer is an error. This is the path that will
  // actually run in production, so it is the one worth pinning.
  await page.route("**/api/admin/v1/directory", (route) =>
    route.fulfill({
      status: 503,
      contentType: "application/json",
      body: JSON.stringify({ error: { code: "service_unavailable", message: "Temporarily unavailable." } }),
    }),
  );

  await page.getByRole("button", { name: /Administration/ }).click();

  await expect(page.getByRole("alert").first()).toBeVisible({ timeout: 20_000 });
  await expect(page.getByRole("button", { name: /Try again/ }).first()).toBeVisible();
});

test("an account the server does not recognise as an administrator is refused", async ({ page }) => {
  // The console no longer decides this for itself. Whatever the browser
  // believes, a 403 from the directory means the answer is no — and that must
  // reach the operator as a refusal rather than an empty console.
  await stubAuth(page);
  // Registered after stubAuth: Playwright matches the most recently added
  // route first, so this narrower pattern overrides the directory stub.
  await page.route("**/api/admin/v1/session", (route) =>
    route.fulfill({
      status: 403,
      contentType: "application/json",
      body: JSON.stringify({ error: "Permission denied", code: "permission_denied" }),
    }),
  );

  await page.goto("/");
  await page.getByLabel("Official email").fill("operator@gcc.gov.in");
  await page.getByLabel("Password").fill("not-a-real-password");
  await page.getByRole("button", { name: "Continue" }).click();

  await expect(page.getByRole("heading", { name: "Not available" })).toBeVisible({ timeout: 15_000 });
  await expect(page.getByRole("button", { name: "Sign out" })).toBeVisible();
});

test("a broken audit chain is reported as broken, not quietly verified", async ({ page }) => {
  await stubAuth(page);
  await page.route("**/api/admin/v1/audit/verify", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        verified: false,
        eventCount: 12,
        rootHash: "a".repeat(64),
        latestHash: "b".repeat(64),
        firstBrokenIndex: 7,
        failures: [7, 8],
        checkedAt: new Date().toISOString(),
      }),
    }),
  );

  await signIn(page);
  await enterAdministration(page);
  await page.getByRole("link", { name: "Audit trail" }).click();

  // Before anyone checks, the panel must not claim the trail is intact. That
  // reassurance is exactly what a tamper-evident record exists to withhold
  // until it has actually been recomputed.
  await expect(page.getByText("Not verified")).toBeVisible();

  await page.getByRole("button", { name: "Verify" }).click();

  await expect(page.getByText("Broken")).toBeVisible({ timeout: 15_000 });

  // The panel keeps the finding on screen and says how much of the record
  // still stands; the toast announces it. Both name the index, so each is
  // matched on its own wording rather than on the shared phrase.
  await expect(page.getByText(/Entries before it are still sealed/)).toBeVisible();
  await expect(page.getByText(/Entries after it cannot be relied on/)).toBeVisible();
});

test("an intact audit chain reports as verified only after it is checked", async ({ page }) => {
  await stubAuth(page);
  await page.route("**/api/admin/v1/audit/verify", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        verified: true,
        eventCount: 12,
        rootHash: "a".repeat(64),
        latestHash: "b".repeat(64),
        firstBrokenIndex: null,
        failures: [],
        checkedAt: new Date().toISOString(),
      }),
    }),
  );

  await signIn(page);
  await enterAdministration(page);
  await page.getByRole("link", { name: "Audit trail" }).click();

  await expect(page.getByText("Not verified")).toBeVisible();
  await page.getByRole("button", { name: "Verify" }).click();
  await expect(page.getByText("Verified", { exact: true })).toBeVisible({ timeout: 15_000 });
});
