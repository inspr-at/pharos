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

const REPORTED_DRAWER_FIELDS = [
  "[data-host-drawer-title]",
  "[data-host-drawer-role]",
  "[data-host-drawer-health-label]",
  "[data-host-drawer-posture-title]",
  "[data-host-drawer-attention]",
  "[data-host-drawer-backup]",
  "[data-host-drawer-restore]",
  "[data-host-drawer-config]",
  "[data-host-drawer-deployed]",
  "[data-host-drawer-nixpkgs]",
  "[data-host-drawer-grace]",
  "[data-host-drawer-reasons]",
  "[data-grace-source-line]",
  "[data-grace-rule]",
];

async function pageFits(page) {
  return page.evaluate(() => document.documentElement.scrollWidth <= window.innerWidth);
}

test("mobile fleet and the quick preview stay on screen", async ({ page }, testInfo) => {
  const host = `mobile-drawer-${testInfo.project.name}`;
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v5",
      version: 5,
      name: host,
      role: "production",
      is_nix: false,
      heartbeat_interval_secs: 60,
      freshness: { applicable: false },
      preferences: { kind: "server" },
    },
  });
  expect(report.status(), await report.text()).toBe(204);
  try {
    await page.goto("/");
    const card = page.locator(`article.card[data-host="${host}"]`);
    const trigger = card.locator("[data-host-drawer-trigger]");
    const drawer = page.locator("#host-quick-drawer");

    for (const width of [390, 768]) {
      await page.setViewportSize({ width, height: 900 });
      await page.locator('[data-view-button="grid"]').click();
      await expect(card).toBeVisible();
      expect(await pageFits(page)).toBe(true);
      await page.locator('[data-view-button="list"]').click();
      await expect(page.locator("main")).toHaveAttribute("data-view", "list");
      expect(await pageFits(page)).toBe(true);
      await page.locator('[data-view-button="grid"]').click();

      await card.scrollIntoViewIfNeeded();
      const before = await card.boundingBox();
      await trigger.click();
      await expect(drawer).toBeVisible();
      for (const selector of REPORTED_DRAWER_FIELDS) {
        await expect(drawer.locator(selector), selector).not.toHaveText("Not recorded");
      }
      expect(await pageFits(page)).toBe(true);
      const opened = await card.boundingBox();
      expect(Math.abs(opened.width - before.width)).toBeLessThanOrEqual(1);
      expect(Math.abs(opened.height - before.height)).toBeLessThanOrEqual(1);
      await page.keyboard.press("Escape");
      await expect(drawer).toBeHidden();
      await expect(trigger).toBeFocused();
      const closed = await card.boundingBox();
      expect(Math.abs(closed.width - before.width)).toBeLessThanOrEqual(1);
      expect(Math.abs(closed.height - before.height)).toBeLessThanOrEqual(1);
      expect(await pageFits(page)).toBe(true);
    }

    await page.setViewportSize({ width: 390, height: 844 });
    await card.locator("[data-host-actions-trigger]").click();
    const menu = page.locator("[data-host-actions-menu]:not([hidden])");
    await expect(menu).toBeVisible();
    const inside = await menu.evaluate((node) => {
      const rect = node.getBoundingClientRect();
      return rect.left >= -1
        && rect.right <= window.innerWidth + 1
        && rect.top >= -1
        && rect.bottom <= window.innerHeight + 1;
    });
    expect(inside).toBe(true);
    expect(await pageFits(page)).toBe(true);
    await page.keyboard.press("Escape");

    await page.emulateMedia({ reducedMotion: "no-preference" });
    await trigger.click();
    await expect(drawer).toBeVisible();
    const moving = await drawer.evaluate((node) => getComputedStyle(node).animationName);
    const title = await drawer.locator("[data-host-drawer-title]").textContent();
    await page.keyboard.press("Escape");
    await page.emulateMedia({ reducedMotion: "reduce" });
    await trigger.click();
    await expect(drawer).toBeVisible();
    const reduced = await drawer.evaluate((node) => getComputedStyle(node).animationName);
    await expect(drawer.locator("[data-host-drawer-title]")).toHaveText(title ?? "");
    await expect(drawer.locator("[data-host-drawer-backup]")).not.toHaveText("");
    expect(reduced).toBe("none");
    expect(moving).toContain("host-drawer-in");
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
