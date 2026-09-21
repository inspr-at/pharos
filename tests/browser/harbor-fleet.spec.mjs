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
}, testInfo) => {
  const host = `harbor-fleet-${testInfo.project.name}`;
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v4",
      version: 4,
      name: host,
      role: "server",
      is_nix: false,
      heartbeat_interval_secs: 60,
    },
  });
  expect(report.status()).toBe(204);
  try {
    await page.goto("/");
    const nav = page.locator("nav.side-nav");
    await expect(nav.locator("a.side-link")).toHaveCount(7);
    for (const name of NAV) {
      await expect(nav.getByRole("link", { name, exact: true })).toBeVisible();
    }
    await expect(page.locator("aside.sidebar")).toHaveCount(1);
    const card = page.locator(`article[data-host="${host}"]`);
    const badge = card.locator("[data-health-badge]");
    await expect(badge).toBeVisible();
    await expect(badge).toHaveClass(/os-badge/);
    await expect(badge).toHaveAttribute("data-health-tone", /.+/);
    await expect(card.locator("[data-protection]")).toBeVisible();
    await expect(card.locator("a.host-name")).toHaveAttribute("href", `/hosts/${host}`);
    await expect(card.locator("a.host-name")).toHaveText(host);
    await expect(card.locator("button.preview-button")).toBeVisible();
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
  } finally {
    const removal = await page.request.post(`/host-actions/${host}/remove`, {
      headers: { "x-pharos-action": "1" },
      data: { confirmation: host, disposition: "unmanaged", successor: null },
    });
    expect(removal.status()).toBe(202);
    const reonboard = await page.request.post(`/host-actions/${host}/allow-reonboarding`, {
      headers: { "x-pharos-action": "1" },
      data: { confirmation: host },
    });
    expect(reonboard.ok()).toBe(true);
  }
});
