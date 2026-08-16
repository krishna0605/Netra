import AxeBuilder from "@axe-core/playwright";
import { expect, test, type Page } from "@playwright/test";

import { installNetraFixture } from "./netra-fixtures";

async function openInvestigation(page: Page) {
  await page.goto("/");
  const chooser = page.getByRole("heading", { name: "Choose a workspace" });
  const investigation = page.getByRole("heading", { name: /^Start Investigation$/i });
  await expect(chooser.or(investigation)).toBeVisible();
  if (await chooser.isVisible()) await page.getByRole("button", { name: /Investigation/ }).click();
  await expect(investigation).toBeVisible();
}

async function openAdministration(page: Page) {
  await page.goto("/");
  await page.evaluate(() => window.sessionStorage.removeItem("netra-last-workspace"));
  await page.reload();
  const chooser = page.getByRole("heading", { name: "Choose a workspace" });
  await expect(chooser).toBeVisible();
  await page.getByRole("button", { name: /Administration/ }).click();
}

test("AAL1 user is sent to the MFA challenge and cannot mount a workspace", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal1", verifiedFactor: true });
  await page.goto("/");
  await expect(page).toHaveURL(/\/login\/mfa/);
  await expect(page.getByRole("heading", { name: "Verify your authenticator." })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Choose a workspace" })).toHaveCount(0);
});

test("user without a factor is required to enroll regardless of role", async ({ page }) => {
  await installNetraFixture(page, { role: "Investigator", aal: "aal1", verifiedFactor: false, enrollmentRequired: true });
  await page.goto("/");
  await expect(page).toHaveURL(/\/login\/mfa/);
  await expect(page.getByRole("heading", { name: "Set up an authenticator." })).toBeVisible();
});

test("Investigator receives only Investigation", async ({ page }) => {
  await installNetraFixture(page, { role: "Investigator", aal: "aal2", verifiedFactor: true });
  await openInvestigation(page);
  await expect(page.getByRole("button", { name: /Administration/ })).toHaveCount(0);
});

test("manage_users account can open Administration while the address remains root", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });
  await openAdministration(page);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await expect(page).toHaveURL(/\/$/);
});

test("an authenticated dual-access user is offered the chooser from the universal sign-in page", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });
  await page.goto("/login");
  await page.evaluate(() => window.sessionStorage.setItem("netra-last-workspace", "administration"));
  await expect(page.getByRole("heading", { name: "Sign in" })).toBeVisible();
  await page.getByRole("button", { name: "Continue" }).click();
  await expect(page.getByRole("heading", { name: "Choose a workspace" })).toBeVisible();
});

test("a dual-access investigator can return to the chooser without signing out", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });
  await openInvestigation(page);
  await page.getByRole("button", { name: "Switch workspace" }).click();
  await expect(page.getByRole("heading", { name: "Choose a workspace" })).toBeVisible();
  await expect(page.getByText("Opening workspace", { exact: true })).toHaveCount(0);
});

test("a refused Administration switch falls back to Investigation", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true, denyAdministrationSwitch: true });
  await page.goto("/");
  await page.getByRole("button", { name: /Administration/ }).click();
  await expect(page.getByRole("heading", { name: /^Start Investigation$/i })).toBeVisible();
  await expect(page.getByRole("heading", { name: "Overview" })).toHaveCount(0);
});

test("guessed internal paths reveal no console", async ({ page }) => {
  await page.goto("/administration");
  await expect(page.getByText("404 / ROUTE NOT FOUND")).toBeVisible();
  await expect(page.getByRole("navigation", { name: "Sections" })).toHaveCount(0);
});

test("investigation and administration shells pass the blocking accessibility gate", async ({ page }) => {
  await page.emulateMedia({ reducedMotion: "reduce" });
  await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });
  await openInvestigation(page);
  await expect(page.getByRole("heading", { name: /^Start Investigation$/i })).toBeVisible();
  await page.waitForTimeout(400);
  let results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(results.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);

  await openAdministration(page);
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.waitForTimeout(400);
  results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
  expect(results.violations.filter((item) => ["serious", "critical"].includes(item.impact ?? ""))).toEqual([]);
});

test("authenticated application opens no external WebSocket and stores no token in localStorage", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await installNetraFixture(page, { role: "Investigator", aal: "aal2", verifiedFactor: true });
  await openInvestigation(page);
  expect(sockets.filter((url) => !url.startsWith("ws://127.0.0.1:4173/"))).toEqual([]);
  const keys = await page.evaluate(() => Object.keys(window.localStorage));
  expect(keys.filter((key) => /(access|refresh|token)/i.test(key))).toEqual([]);
});
