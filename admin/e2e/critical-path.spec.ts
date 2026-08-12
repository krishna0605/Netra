import { expect, test, type Page } from "@playwright/test";

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

async function stubAuth(page: Page) {
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
  await page.getByLabel("Confirm with your authenticator").fill("482913");

  const created = page.getByRole("button", { name: "Create account" });
  await expect(created).toBeEnabled();
  await created.click();

  // The password is shown exactly once, on the handover panel.
  await expect(page.getByRole("heading", { name: "Account created" })).toBeVisible();
  await page.getByRole("button", { name: "Done" }).click();

  await expect(page.getByRole("row")).toHaveCount(before + 1);
  await expect(page.getByText("t.bhatt@gcc.gov.in")).toBeVisible();

  // ── Set a password ──────────────────────────────────────────────────────
  await page.getByRole("link", { name: /Open T. Bhatt/ }).click();
  await expect(page.getByRole("heading", { name: "T. Bhatt" })).toBeVisible();

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
