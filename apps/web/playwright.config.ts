import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "e2e",
  testMatch: "*.e2e.ts",
  timeout: 180000,
  use: {
    actionTimeout: 15000,
    navigationTimeout: 30000,
    baseURL: "http://localhost:5173",
    trace: "retain-on-failure",
    channel: process.env.PLAYWRIGHT_CHANNEL,
  },
});
