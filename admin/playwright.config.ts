import { defineConfig, devices } from "@playwright/test";

/**
 * End-to-end coverage of the critical path.
 *
 * Authentication is deliberately stubbed at the network boundary rather than
 * driven against the live Supabase project: a suite that needs real
 * credentials cannot run in CI, and one that creates real accounts to test
 * itself is worse. Everything after the session exists is genuine.
 */
export default defineConfig({
  testDir: "./e2e",
  fullyParallel: false,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? "list" : "line",
  use: {
    baseURL: "http://127.0.0.1:5180",
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
  webServer: {
    command: "npm run dev -- --host 127.0.0.1",
    url: "http://127.0.0.1:5180",
    reuseExistingServer: !process.env.CI,
    timeout: 120_000,
    env: {
      VITE_SUPABASE_URL: "https://e2e.supabase.co",
      VITE_SUPABASE_PUBLISHABLE_KEY: "sb_publishable_e2e_placeholder",
      VITE_DEPLOYMENT_PROFILE: "local",
    },
  },
});
