import { test, expect } from "@playwright/test";

test("intercepts a fixture, opens a passport, mutates and resets all four cases", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("fixture-suspicious-1")).toBeVisible();
  await page.screenshot({ path: "test-results/desk-desktop.png", fullPage: true });
  await expect(page.getByTestId("fixture-suspicious-1")).toHaveAttribute("href", "#sandbox");
  await page.getByTestId("fixture-suspicious-1").click({ button: "middle" });
  await expect(page.getByRole("dialog")).toBeVisible();
  await expect(page.getByRole("button", { name: /Proceed anyway/ })).toBeDisabled();
  expect(page.url()).toBe("http://127.0.0.1:3000/");
  await page.getByRole("link", { name: /Open full Evidence Passport/ }).click();
  await expect(page.getByTestId("verification-status")).toContainText("SUPPORTED");
  await page.screenshot({ path: "test-results/passport-desktop.png", fullPage: true });
  const permalink = page.url();
  await page.reload();
  await expect(page.getByTestId("verification-status")).toContainText("SUPPORTED");
  for (const [mutation, status] of [["tls_cert", "TAMPERED"], ["drop_threat_intel", "NOT_SUPPORTED"], ["alter_redirect", "TAMPERED"], ["unground_ai_claim", "NOT_SUPPORTED"]]) {
    await page.getByTestId(`tamper-${mutation}`).click();
    await expect(page.getByTestId("verification-status")).toContainText(status);
    await expect(page.getByTestId("hash-diff")).toBeVisible();
    await page.getByRole("button", { name: "Reset to genuine sealed bundle" }).click();
    await expect(page.getByTestId("verification-status")).toContainText("SUPPORTED");
  }
  expect(page.url()).toBe(permalink);
  await page.getByRole("button", { name: "tls:1", exact: true }).first().click();
  await expect(page.locator('[id="leaf-tls:1"]')).toHaveClass(/highlighted/);
});

test("custom offline input is inconclusive and private input cannot proceed", async ({ page }) => {
  await page.goto("/");
  await page.getByLabel("DESTINATION URL").fill("https://ordinary.example/");
  await page.getByRole("button", { name: "Intercept & investigate" }).click();
  await expect(page.getByRole("heading", { name: "Inconclusive", exact: true })).toBeVisible();
  await page.getByRole("button", { name: "Block navigation" }).click();
  await page.getByLabel("DESTINATION URL").fill("http://127.0.0.1/");
  await page.getByRole("button", { name: "Intercept & investigate" }).click();
  await expect(page.getByRole("heading", { name: "High risk", exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: /Proceed anyway/ })).toBeDisabled();
});

test("a failed inspection keeps navigation blocked and offers retry", async ({ page }) => {
  await page.goto("/");
  await expect(page.getByTestId("fixture-benign-1")).toBeVisible();
  await page.route("**/api/investigate", (route) => route.fulfill({ status: 503, contentType: "application/json", body: '{"detail":"Unavailable"}' }));
  await page.getByTestId("fixture-benign-1").click();
  await expect(page.getByRole("dialog").getByRole("alert")).toContainText("Navigation remains blocked");
  await expect(page.getByRole("button", { name: "Retry inspection" })).toBeVisible();
  await expect(page.getByRole("link", { name: /Open full Evidence Passport/ })).toHaveCount(0);
  expect(page.url()).toBe("http://127.0.0.1:3000/");
});

test("mobile desk has no horizontal overflow", async ({ page }) => {
  await page.setViewportSize({ width: 390, height: 844 });
  await page.goto("/");
  await expect(page.getByTestId("fixture-benign-3")).toBeVisible();
  expect(await page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth)).toBeTruthy();
  await page.screenshot({ path: "test-results/desk-mobile.png", fullPage: true });
});
