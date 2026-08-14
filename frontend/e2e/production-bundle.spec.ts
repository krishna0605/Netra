import { expect, test } from "@playwright/test";

import { installNetraFixture } from "./netra-fixtures";

test("production bundle keeps chart routes, settings, and one sign-in access snapshot", async ({ page }) => {
  const pageErrors: string[] = [];
  page.on("pageerror", (error) => pageErrors.push(error.message));
  const fixture = await installNetraFixture(page, { role: "Admin", aal: "aal2", verifiedFactor: true });

  await page.goto("/");
  await page.getByRole("button", { name: /Investigation/ }).first().click();
  await page.getByRole("link", { name: "Cases", exact: true }).click();
  await expect(page.getByRole("heading", { name: "Cases" })).toBeVisible();
  await expect(page.getByRole("link", { name: "Settings" })).toBeVisible();

  const journeys = [
    ["Evidence Report", /^Evidence Report$/],
    ["Suspicious Activity", /^Suspicious Activity$/],
    ["Traffic Evidence", /^Traffic Evidence$/],
    ["Settings", /^Settings$/],
    ["Start Investigation", /^Start Investigation$/],
  ] as const;

  for (const [link, heading] of journeys) {
    await page.getByRole("link", { name: link, exact: true }).click();
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
    await expect(page.getByRole("heading", { name: "Checking access" })).toHaveCount(0);
  }

  expect(pageErrors).toEqual([]);
  expect(fixture.authMeRequests()).toBe(1);
});
