import { expect, test } from "@playwright/test";

const publicRoutes = [
  ["/", /See the traffic/i],
  ["/login", /Enter the investigation console/i],
] as const;

for (const [path, heading] of publicRoutes) {
  test(`renders ${path}`, async ({ page }) => {
    await page.goto(path);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
  });
}

test("unknown routes use the NETRA 404", async ({ page }) => {
  await page.goto("/missing-route");
  await expect(page.getByText("404 / ROUTE NOT FOUND")).toBeVisible();
});

test("guessed protected operations return the generic 404", async ({ page }) => {
  await page.addInitScript(() => {
    window.sessionStorage.clear();
    window.localStorage.clear();
  });
  await page.route("https://netra-auth.test/**", (route) => route.abort());
  await page.goto("/app/upload");
  await expect(page.getByText("404 / ROUTE NOT FOUND")).toBeVisible();
  await expect(page.getByRole("heading", { name: /investigation console/i })).toHaveCount(0);
});

test("public interactions remain keyboard accessible", async ({ page }) => {
  await page.goto("/");
  const layer = page.getByRole("button", { name: /Analysis layer/i });
  await layer.focus();
  await page.keyboard.press("Enter");
  await expect(layer).toHaveAttribute("aria-expanded", "true");
});
