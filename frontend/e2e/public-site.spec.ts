import { expect, test } from "@playwright/test";

const publicRoutes = [
  ["/", /See the traffic/i],
  ["/about", /Build conclusions from evidence/i],
  ["/updates", /Cyber risk,\s*seen clearly/i],
  ["/contact", /Bring a network-evidence workflow/i],
  ["/privacy", /^Privacy$/i],
  ["/terms", /^Terms$/i],
] as const;

for (const [path, heading] of publicRoutes) {
  test(`renders ${path}`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
  });
}

test("changelog redirects to updates", async ({ page }) => {
  await page.goto("/changelog");
  await expect(page).toHaveURL(/\/updates$/);
});

test("unknown routes use the NETRA 404", async ({ page }) => {
  await page.goto("/missing-route");
  await expect(page.getByText("404 / ROUTE NOT FOUND")).toBeVisible();
});

test("protected operations redirect to sign in", async ({ page }) => {
  await page.goto("/app/upload");
  await expect(page).toHaveURL(/\/login$/);
  await expect(page.getByRole("heading", { name: /Enter the investigation console/i })).toBeVisible();
});

test("public interactions remain keyboard accessible", async ({ page }) => {
  await page.goto("/");
  const layer = page.getByRole("button", { name: /Analysis layer/i });
  await layer.focus();
  await page.keyboard.press("Enter");
  await expect(layer).toHaveAttribute("aria-expanded", "true");
});
