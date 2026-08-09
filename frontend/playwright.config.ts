import { defineConfig, devices } from "@playwright/test";

export default defineConfig({
  testDir: "./e2e",
  outputDir: "../Miscellaneous/tmp/playwright-results",
  // Keep the security journeys deterministic on both local and hosted
  // runners. A bounded worker count avoids starving the mocked Auth/API
  // server while retaining zero retries for genuine failures.
  workers: 2,
  use: {
    baseURL: "http://127.0.0.1:4173",
    trace: "retain-on-failure",
  },
  webServer: {
    command: "npm run dev -- --host 127.0.0.1 --port 4173",
    url: "http://127.0.0.1:4173",
    reuseExistingServer: true,
    timeout: 120_000,
    env: {
      ...process.env,
      VITE_SUPABASE_URL: "https://netra-auth.test",
      VITE_SUPABASE_PUBLISHABLE_KEY: "local-publishable-key-for-browser-tests-only",
    },
  },
  projects: [
    { name: "desktop", use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } } },
    { name: "mobile", use: { ...devices["Pixel 7"] } },
  ],
});
