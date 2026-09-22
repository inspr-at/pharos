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

const HEADERS = [
  "Host and health",
  "Attention",
  "Backup and restore",
  "Heartbeat",
  "Last seen",
  "Actions",
];

test("fleet list rows match the host set and open the drawer", async ({ page }, testInfo) => {
  const hosts = [0, 1].map((index) => `list-row-${index}-${testInfo.project.name}`);
  for (const host of hosts) {
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
  }
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/");
    await page.locator('[data-view-button="list"]').click();
    await expect(page.locator("main")).toHaveAttribute("data-view", "list");
    await expect(page.locator("table.list th")).toHaveText(HEADERS);

    const gridCount = await page.locator("[data-grid] article.card, [data-grid] .onboard-tile").count();
    const rowCount = await page.locator("tbody[data-list-body] > tr").count();
    expect(rowCount).toBe(gridCount);
    expect(rowCount).toBeGreaterThanOrEqual(hosts.length);

    const row = page.locator(`tr[data-host="${hosts[0]}"]`);
    const nameLink = row.locator("a.host-name");
    await expect(nameLink).toHaveAttribute("href", `/hosts/${hosts[0]}`);
    await expect(nameLink).toHaveText(hosts[0]);
    await expect(row.locator("[data-seen][data-seen-compact]")).toHaveCount(1);
    await expect(row.locator(".beat")).toHaveCount(1);
    await expect(row.locator("a[data-daily-backup]")).toHaveAttribute("href", `/backups?host=${hosts[0]}`);

    const height = await row.evaluate((node) => node.getBoundingClientRect().height);
    expect(height).toBeGreaterThanOrEqual(64);
    expect(height).toBeLessThanOrEqual(72);

    const preview = row.locator("[data-host-drawer-trigger]");
    await preview.click();
    await expect(page.locator("#host-quick-drawer")).toBeVisible();
    await page.keyboard.press("Escape");
    await expect(page.locator("#host-quick-drawer")).toBeHidden();
    await expect(preview).toBeFocused();

    await page.setViewportSize({ width: 390, height: 844 });
    const fits = await page.evaluate(() => ({
      page: document.documentElement.scrollWidth <= window.innerWidth,
      region: document.querySelector(".list-wrap").scrollWidth > document.querySelector(".list-wrap").clientWidth,
      note: getComputedStyle(document.querySelector(".table-scroll-note")).display,
    }));
    expect(fits.page).toBe(true);
    expect(fits.region).toBe(true);
    expect(fits.note).toBe("block");
  } finally {
    for (const host of hosts) {
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
  }
});
