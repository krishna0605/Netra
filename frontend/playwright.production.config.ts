import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  testMatch: "production-bundle.spec.ts",
  outputDir: "../Miscellaneous/tmp/playwright-production-results",
  workers: 1,
  use: {
    baseURL: "http://127.0.0.1:4174",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run build && npm run preview -- --host 127.0.0.1 --port 4174",
    url: "http://127.0.0.1:4174",
    reuseExistingServer: false,
    timeout: 120_000,
    env: {
      ...process.env,
      VITE_SUPABASE_URL: "https://netra-auth.test",
      VITE_SUPABASE_PUBLISHABLE_KEY: "local-publishable-key-for-browser-tests-only",
    },
  },
  projects: [
    { name: "production-desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } } },
  ],
});
