import { test, expect } from "@playwright/test";

test("serverless fixture preview survives refresh and detects tampering without public-chain claims", async ({ page, request }) => {
  const browserUrls: string[] = [];
  const chunks: Promise<string>[] = [];
  page.on("request", (req) => browserUrls.push(req.url()));
  page.on("response", (response) => { if (new URL(response.url()).pathname.endsWith(".js")) chunks.push(response.text()); });
  await page.goto("/");
  await expect(page.getByTestId("deployment-mode")).toContainText("Demo fixture mode — public blockchain anchoring is not enabled.");
  await expect(page.getByRole("button", { name: "Intercept & investigate" })).toBeDisabled();
  await page.getByTestId("fixture-benign-1").click();
  await page.getByRole("link", { name: "Open full Evidence Passport" }).click();
  await expect(page.getByTestId("verification-status")).toContainText("SUPPORTED");
  await expect(page.getByTestId("verification-status")).toContainText("PUBLIC-CHAIN ANCHOR: NOT ENABLED");
  await expect(page.getByRole("heading", { name: "Evidence ledger" })).toBeVisible();
  const permalink = page.url();
  await page.reload();
  await expect(page.getByTestId("verification-status")).toContainText("SUPPORTED");
  await page.getByTestId("tamper-tls_cert").click();
  await expect(page.getByTestId("verification-status")).toContainText("TAMPERED");
  await page.getByRole("button", { name: "Reset to genuine sealed bundle" }).click();
  await expect(page.getByTestId("verification-status")).toContainText("SUPPORTED");
  expect(page.url()).toBe(permalink);
  expect(browserUrls.every((url) => new URL(url).origin === "http://127.0.0.1:3000")).toBeTruthy();
  for (const chunk of await Promise.all(chunks)) {
    expect(chunk).not.toContain("veridict-server-only-canary");
    expect(chunk).not.toContain("veridict-private-scan-canary-32-characters");
    expect(chunk).not.toContain("127.0.0.1:8000");
    expect(chunk).not.toContain("backend:8000");
  }
  const health = await request.get("/api/health");
  expect((await health.json()).verification_mode).toBe("DEMO_FIXTURE");
  const unsupported = await request.post("/api/investigate", { data: { url: "https://ordinary.example/" } });
  expect(unsupported.status()).toBe(403);
  const oversized = await request.post("/api/investigate", { data: "x".repeat(524289) });
  expect(oversized.status()).toBe(413);
  const unknown = await request.get("/api/arbitrary?url=https://other.example");
  expect(unknown.status()).toBe(404);
  const reportId = new URL(permalink).pathname.split("/").at(-1);
  const anchor = await request.get(`/api/reports/${reportId}/anchor`);
  expect((await anchor.json()).status).toBe("NOT_CONFIGURED");
  const anonymousRegistration = await request.post(`/api/reports/${reportId}/anchor`);
  expect(anonymousRegistration.status()).toBe(405);
});

test("unanchored report presentation never implies public verification (mocked status)", async ({ page, request }) => {
  const fixtures = await (await request.get("/api/fixtures")).json();
  const report = await (await request.post("/api/investigate", { data: fixtures[0].input })).json();
  report.chain_receipt = { tx_hash: null, block_number: null, contract_address: null, network: "sealed-not-anchored", mode: "unanchored" };
  report.verification.public_chain_status = "NOT_ANCHORED";
  const id = report.bundle.report_id;
  await page.route(`**/api/reports/${id}**`, async (route) => {
    const path = new URL(route.request().url()).pathname;
    await route.fulfill({ json: path.endsWith("/verify") ? report.verification : path.endsWith("/anchor") ? { report_id: id, status: "NOT_ANCHORED", chain_id: 11155111, contract_address: null, receipt: null, explorer_url: null } : report });
  });
  await page.goto(`/report/${id}`);
  await expect(page.getByTestId("verification-status")).toContainText("PUBLIC-CHAIN ANCHOR: NOT YET ANCHORED");
  await expect(page.getByText("SEALED, NOT YET ANCHORED").first()).toBeVisible();
});
