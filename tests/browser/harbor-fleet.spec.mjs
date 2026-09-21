import { test as base, expect } from "@playwright/test";
import { newAuthedContext, waitForHarnessTokens } from "./harness.mjs";

const test = base.extend({
  page: async ({ browser }, use) => {
    await waitForHarnessTokens();
    const context = await newAuthedContext(browser, "write");
    const page = await context.newPage();
    await use(page);
    await context.close();
  },
});

const NAV = ["Fleet", "Map", "Alerts", "Backups", "Services", "Activity", "Settings"];

test("harbor fleet keeps the shell and shows real health, backup, and grace controls", async ({
  page,
}) => {
  await page.goto("/");
  const nav = page.locator("nav.side-nav");
  await expect(nav.locator("a.side-link")).toHaveCount(7);
  for (const name of NAV) {
    await expect(nav.getByRole("link", { name, exact: true })).toBeVisible();
  }
  await expect(page.locator("aside.sidebar")).toHaveCount(1);
  await expect(page.locator(".os-badge").first()).toBeVisible();
  await expect(page.locator("[data-protection]").first()).toBeVisible();
  await expect(page.locator("a.host-name").first()).toBeVisible();
  await expect(page.locator("button.preview-button").first()).toBeVisible();
  await expect(page.locator("[data-grace-binding='awaiting-policy']")).toHaveCount(0);
  const html = await page.content();
  expect(html).not.toContain("sessionStorage");
  expect(html).not.toContain("/heartbeat-grace.json");

  await page.goto("/settings/providers");
  const grace = page.locator("[name='heartbeat_grace_secs']");
  await expect(grace).toBeVisible();
  await expect(grace).toBeEnabled();
  await expect(page.locator("[data-heartbeat-grace-settings]")).not.toHaveAttribute(
    "data-grace-binding",
    "awaiting-policy",
  );
  await expect(page.getByRole("button", { name: "Save freshness settings" })).toBeVisible();
});
