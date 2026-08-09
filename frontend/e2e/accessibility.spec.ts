import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const reviewedRoutes = [
  ["/", /See the traffic/i],
  ["/login", /Enter the investigation console/i],
  ["/auth/forgot-password", /Reset your password/i],
  ["/auth/recovery", /Choose a new password/i],
  ["/auth/invite", /Complete your account/i],
] as const;

for (const [path, heading] of reviewedRoutes) {
  test(`${path} has no serious or critical automated accessibility findings`, async ({ page }) => {
    await page.emulateMedia({ reducedMotion: "reduce" });
    await page.goto(path);
    await expect(page.getByRole("heading", { name: heading }).first()).toBeVisible();
    const results = await new AxeBuilder({ page })
      .withTags(["wcag2a", "wcag2aa", "wcag21aa", "wcag22aa"])
      .analyze();
    const blocking = results.violations.filter((violation) => ["serious", "critical"].includes(violation.impact ?? ""));
    expect(blocking, blocking.map((violation) => `${violation.id}: ${violation.help}`).join("\n")).toEqual([]);
  });
}

test("skip navigation reaches the main landmark", async ({ page }) => {
  await page.goto("/");
  await page.keyboard.press("Tab");
  const skip = page.getByRole("link", { name: "Skip to main content" });
  await expect(skip).toBeFocused();
  await page.keyboard.press("Enter");
  await expect(page.locator("#main-content").first()).toBeInViewport();
});

test("disabled password recovery makes no provider request", async ({ page }) => {
  const recoveryRequests: string[] = [];
  await page.route("**/api/capabilities", async (route) => {
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        results: {
          password_recovery: {
            key: "password_recovery",
            implemented: true,
            enabled: false,
            state: "disabled",
            reason: "Password recovery requires an approved custom SMTP domain.",
            requires_aal2: false,
            durable_consumer: null,
          },
        },
      }),
    });
  });
  page.on("request", (request) => {
    if (/\/auth\/v1\/recover/.test(request.url())) recoveryRequests.push(request.url());
  });
  await page.goto("/auth/forgot-password");
  await expect(page.getByText(/Password recovery requires an approved custom SMTP domain/i)).toBeVisible();
  await expect(page.getByLabel("Email")).toHaveCount(0);
  expect(recoveryRequests).toEqual([]);
});

test("authentication pages do not persist token-shaped local storage", async ({ page }) => {
  await page.goto("/login");
  const keys = await page.evaluate(() => Object.keys(window.localStorage));
  expect(keys.filter((key) => /(access|refresh|token)/i.test(key))).toEqual([]);
});

test("authentication routes never open WebSockets", async ({ page }) => {
  const applicationSockets: string[] = [];
  page.on("websocket", (socket) => {
    if (!/127\.0\.0\.1:4173/.test(socket.url())) applicationSockets.push(socket.url());
  });
  await page.goto("/login");
  await page.goto("/auth/forgot-password");
  expect(applicationSockets).toEqual([]);
});
