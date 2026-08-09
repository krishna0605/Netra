import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

import { fixtureRoutes, installNetraFixture } from "./netra-fixtures";

test("Admin enrollment reaches the TOTP setup journey without a real provider call", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal1", verifiedFactor: false, enrollmentRequired: true });
  await page.goto("/auth/mfa");
  await expect(page.getByRole("heading", { name: "Set up an authenticator." })).toBeVisible();
  await page.getByRole("button", { name: "Begin secure setup" }).click();
  await expect(page.getByLabel("Manual authenticator setup key")).toContainText("SYNTHETICTOTPSECRET");
  await page.getByLabel("Six-digit code").fill("123456");
  await page.getByRole("button", { name: "Verify and continue" }).click();
  await expect(page.getByLabel("Manual authenticator setup key")).toHaveCount(0);
});

test("AAL1 Administrator cannot open the privileged workspace", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal1", verifiedFactor: true });
  await page.goto(fixtureRoutes.admin);
  await expect(page).toHaveURL(/\/auth\/mfa/);
  await expect(page.getByRole("heading", { name: "Verify your authenticator." })).toBeVisible();
});

test("Investigator cannot open the Administrator workspace", async ({ page }) => {
  await installNetraFixture(page, { role: "Investigator", aal: "aal1", verifiedFactor: false });
  await page.goto(fixtureRoutes.admin);
  await expect(page).not.toHaveURL(/\/app\/admin\/users/);
  await expect(page.getByRole("heading", { name: "Organization users" })).toHaveCount(0);
});

test("AAL2 Administrator can open organization user management", async ({ page }) => {
  await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });
  await page.goto(fixtureRoutes.admin);
  await expect(page.getByRole("heading", { name: "Organization users" })).toBeVisible();
});

test("case and analysis routes remain keyboard reachable", async ({ page }) => {
  await installNetraFixture(page, { role: "Investigator", aal: "aal1", verifiedFactor: false });
  await page.goto(fixtureRoutes.cases);
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  await page.keyboard.press("Tab");
  await expect(page.locator(":focus")).toBeVisible();
  await page.goto(fixtureRoutes.analysis);
  await expect(page.getByRole("heading", { name: "Investigation Dashboard" })).toBeVisible();
});

const authenticatedAxeRoutes = [
  ["MFA enrollment", "/auth/mfa", { role: "Admin", aal: "aal1", verifiedFactor: false, enrollmentRequired: true }, /Set up an authenticator/i],
  ["MFA challenge", "/auth/mfa", { role: "Admin", aal: "aal1", verifiedFactor: true }, /Verify your authenticator/i],
  ["case list", fixtureRoutes.cases, { role: "Investigator", aal: "aal1", verifiedFactor: false }, /^Cases$/i],
  ["analysis", fixtureRoutes.analysis, { role: "Investigator", aal: "aal1", verifiedFactor: false }, /Investigation Dashboard/i],
  ["Admin users", fixtureRoutes.admin, { role: "Admin", aal: "aal2", verifiedFactor: true }, /Organization users/i],
] as const;

for (const [name, path, fixture, heading] of authenticatedAxeRoutes) {
  test(`${name} has no serious or critical automated accessibility findings`, async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await installNetraFixture(page, fixture);
    await page.goto(path);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
    const results = await new AxeBuilder({ page }).withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"]).analyze();
    const blocking = results.violations.filter((violation) => ["serious", "critical"].includes(violation.impact ?? ""));
    expect(blocking, blocking.map((violation) => `${violation.id}: ${violation.help}`).join("\n")).toEqual([]);
  });
}

test("authenticated routes do not open WebSockets or persist token-shaped local storage", async ({ page }) => {
  const sockets: string[] = [];
  page.on("websocket", (socket) => sockets.push(socket.url()));
  await installNetraFixture(page, { role: "Investigator", aal: "aal1", verifiedFactor: false });
  await page.goto(fixtureRoutes.analysis);
  await expect(page.getByRole("heading", { name: /Investigation Dashboard/i })).toBeVisible();
  const applicationSockets = sockets.filter((url) => !url.startsWith("ws://127.0.0.1:4173/"));
  expect(applicationSockets).toEqual([]);
  const keys = await page.evaluate(() => Object.keys(window.localStorage));
  expect(keys.filter((key) => /(access|refresh|token)/i.test(key))).toEqual([]);
});
