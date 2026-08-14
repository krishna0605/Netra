import { expect, test } from "@playwright/test";

import { installNetraFixture } from "./netra-fixtures";

test("Administration navigation is internal and every API call carries the console context", async ({ page }) => {
  const adminRequests: Array<{ url: string; context: string | null }> = [];
  page.on("request", (request) => {
    if (request.url().includes("/api/admin/v1/")) {
      adminRequests.push({ url: request.url(), context: request.headers()["x-netra-context-id"] ?? null });
    }
  });
  await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });
  await page.goto("/");
  await expect(page.getByRole("heading", { name: "Choose a workspace." })).toBeVisible();
  await page.getByRole("button", { name: /Administration/ }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  await page.getByRole("link", { name: "Users" }).first().click();
  await expect(page.getByRole("heading", { name: "Users" })).toBeVisible();
  await expect(page.getByText("a.patel@gcc.gov.in")).toBeVisible();
  await page.getByRole("link", { name: /^Audit/ }).click();
  await expect(page.getByRole("heading", { name: "Audit trail" })).toBeVisible();

  expect(new URL(page.url()).pathname).toBe("/");
  expect(adminRequests.length).toBeGreaterThan(0);
  expect(adminRequests.every((request) => request.context === "33333333-3333-4333-8333-333333333333")).toBe(true);
});

test("refresh revalidates the session before restoring private content", async ({ page }) => {
  const fixture = await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });
  await page.goto("/");
  await page.getByRole("button", { name: /Administration/ }).click();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  const before = fixture.authMeRequests();
  await page.reload();
  await expect(page.getByRole("heading", { name: "Overview" })).toBeVisible();
  expect(fixture.authMeRequests()).toBeGreaterThan(before);
  expect(new URL(page.url()).pathname).toBe("/");
});
