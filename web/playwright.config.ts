import { defineConfig, devices } from "@playwright/test";

// End-to-end tests run against a core that serves the built console
// (`task build` then `task run`, or the Compose stack). WT_E2E_URL overrides the address.
// Development cores serve a self-signed certificate, which the tests accept.
export default defineConfig({
  testDir: "e2e",
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  reporter: process.env.CI ? [["list"], ["html", { open: "never" }]] : "list",
  use: {
    baseURL: process.env.WT_E2E_URL ?? "https://127.0.0.1:8443",
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
  },
  projects: [{ name: "chromium", use: { ...devices["Desktop Chrome"] } }],
});
