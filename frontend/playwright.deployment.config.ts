import { defineConfig } from "@playwright/test";
import base from "./playwright.config";
const servers = Array.isArray(base.webServer) ? base.webServer : [];
export default defineConfig({
  ...base, testMatch: "deployment.spec.ts",
  webServer: servers.map((server, index) => {
    const env: Record<string, string> = index === 0 ? { RUNTIME_MODE: "serverless" } : { BACKEND_PROTECTION_BYPASS: "veridict-server-only-canary" };
    return { ...server, reuseExistingServer: false, env };
  }),
});
