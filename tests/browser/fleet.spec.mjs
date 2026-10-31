import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const REGISTRATION_TOKEN = "browser-registration-fixture";

test.beforeAll(async ({ request }) => {
  const registered = await request.post("/register", {
    headers: { authorization: `Bearer ${REGISTRATION_TOKEN}` },
    data: {
      schema: "inspr.pharos.host-registration.v1",
      version: 1,
      name: "ares",
      role: "server",
      is_nix: true,
      heartbeat_interval_secs: 60,
    },
  });
  expect(registered.status()).toBe(201);
});

test("fleet page lists hosts under the security policy", async ({ page }) => {
  const violations = [];
  page.on("console", (message) => {
    if (message.type() === "error") violations.push(message.text());
  });
  page.on("pageerror", (error) => violations.push(error.message));

  const response = await page.goto("/");
  expect(response.status()).toBe(200);
  expect(response.headers()["content-security-policy"]).toContain("'nonce-");

  await expect(page.getByRole("heading", { name: "Fleet" })).toBeVisible();
  await expect(page.getByRole("cell", { name: "ares" })).toBeVisible();
  await expect(page.locator("[data-calendar-display]")).toHaveAttribute("data-canonical", /\d/);

  expect(violations).toEqual([]);
});

test("fleet page has no accessibility violations", async ({ page }) => {
  await page.goto("/");
  // The pinned version renderer dims aria-hidden decorative segments on purpose.
  const results = await new AxeBuilder({ page }).exclude("[data-calendar-display]").analyze();
  expect(results.violations).toEqual([]);
});

test("fleet page fits the viewport without sideways scrolling", async ({ page }) => {
  await page.goto("/");
  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(0);
});
