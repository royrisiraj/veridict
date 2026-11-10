import { defineConfig } from "@playwright/test";
export default defineConfig({
  testDir: "./tests", timeout: 30000, fullyParallel: false, workers: 1,
  use: { baseURL: "http://127.0.0.1:3000", trace: "retain-on-failure", screenshot: "only-on-failure" },
  webServer: [
    { command: "node scripts/start-backend.mjs", url: "http://127.0.0.1:8000/health", reuseExistingServer: !process.env.CI, timeout: 30000 },
    { command: "node scripts/start-frontend.mjs", url: "http://127.0.0.1:3000", reuseExistingServer: !process.env.CI, timeout: 60000 },
  ],
});
