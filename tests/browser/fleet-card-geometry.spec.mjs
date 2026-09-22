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

function boxOf(rect) {
  return {
    x: Math.round(rect.x * 10) / 10,
    y: Math.round(rect.y * 10) / 10,
    width: Math.round(rect.width * 10) / 10,
    height: Math.round(rect.height * 10) / 10,
  };
}

function expectSameBox(actual, expected) {
  expect(Math.abs(actual.x - expected.x)).toBeLessThanOrEqual(1);
  expect(Math.abs(actual.y - expected.y)).toBeLessThanOrEqual(1);
  expect(Math.abs(actual.width - expected.width)).toBeLessThanOrEqual(1);
  expect(Math.abs(actual.height - expected.height)).toBeLessThanOrEqual(1);
}

async function cardBox(page, host) {
  return page.evaluate((name) => {
    const rect = document.querySelector(`article.card[data-host="${name}"]`).getBoundingClientRect();
    return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
  }, host);
}

test("a future heartbeat reads as clock skew", async ({ page }, testInfo) => {
  const host = `clock-skew-${testInfo.project.name}`;
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v4",
      version: 4,
      name: host,
      role: "server",
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
    await expect(card).toBeVisible();
    const shown = await page.evaluate((name) => {
      const node = document.querySelector(`article.card[data-host="${name}"]`);
      const beat = node.querySelector(".beat");
      const now = Date.now() / 1000;
      beat.dataset.last = String(now + 30);
      window.updateBeatClock(beat, now);
      const status = node.querySelector("[data-heartbeat-status]");
      return {
        status: status?.textContent || "",
        tone: status?.dataset.heartbeatTone || "",
        explain: node.querySelector("[data-heartbeat-explain]")?.textContent || "",
      };
    }, host);
    expect(shown.status).toBe("Clock skew");
    expect(shown.tone).toBe("neutral");
    expect(shown.explain).toBe("last report is ahead of Pharos");
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

test("fleet cards keep their box, route, and grid columns", async ({ page }, testInfo) => {
  const hosts = [0, 1, 2, 3, 4].map((index) => `card-geo-${index}-${testInfo.project.name}`);
  for (const host of hosts) {
    const report = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v4",
        version: 4,
        name: host,
        role: "server",
        is_nix: false,
        heartbeat_interval_secs: 60,
        freshness: { applicable: false },
        preferences: { accent: "#224466", kind: "server" },
      },
    });
    expect(report.status(), await report.text()).toBe(204);
  }
  try {
    await page.setViewportSize({ width: 1440, height: 1000 });
    await page.goto("/");
    const host = hosts[0];
    const card = page.locator(`article.card[data-host="${host}"]`);
    await expect(card).toBeVisible();
    await expect(card.locator("details")).toHaveCount(0);
    await expect(page.locator("article.card details")).toHaveCount(0);
    const nameLink = card.locator("a.host-name");
    await expect(nameLink).toHaveAttribute("href", `/hosts/${host}`);
    await expect(nameLink).toHaveText(host);

    await card.scrollIntoViewIfNeeded();
    const initial = boxOf(await cardBox(page, host));
    await card.hover();
    const hovered = boxOf(await cardBox(page, host));
    expect(hovered.width).toBe(initial.width);
    expect(hovered.height).toBe(initial.height);
    expect(Math.abs(hovered.y - initial.y)).toBeLessThanOrEqual(1.1);
    await page.mouse.move(0, 0);
    const resting = boxOf(await cardBox(page, host));
    expectSameBox(resting, initial);

    const reported = boxOf(await page.evaluate((name) => {
      const node = document.querySelector(`article.card[data-host="${name}"]`);
      const beat = node.querySelector(".beat");
      const now = Date.now() / 1000;
      beat.dataset.last = String(now - 20);
      window.updateBeatClock(beat, now);
      beat.dataset.flash = "true";
      const rect = node.getBoundingClientRect();
      return { x: rect.x, y: rect.y, width: rect.width, height: rect.height };
    }, host));
    expectSameBox(reported, resting);

    const beforeDrawer = boxOf(await cardBox(page, host));
    await card.locator("[data-host-drawer-trigger]").click();
    await expect(page.locator("#host-quick-drawer")).toBeVisible();
    const opened = boxOf(await cardBox(page, host));
    expectSameBox(opened, beforeDrawer);
    await page.locator("#host-quick-drawer [data-host-drawer-close]").click();
    await expect(page.locator("#host-quick-drawer")).toBeHidden();
    const closed = boxOf(await cardBox(page, host));
    expectSameBox(closed, beforeDrawer);

    const columnsAt = async (width) => {
      await page.setViewportSize({ width, height: 1000 });
      return page.evaluate(() => {
        const cards = [...document.querySelectorAll("[data-grid] article.card")];
        if (!cards.length) return 0;
        const firstTop = Math.min(...cards.map((node) => node.getBoundingClientRect().top));
        return cards.filter((node) => Math.abs(node.getBoundingClientRect().top - firstTop) < 8).length;
      });
    };
    expect(await columnsAt(390)).toBe(1);
    expect(await columnsAt(768)).toBe(2);
    expect(await columnsAt(1280)).toBe(2);
    expect(await columnsAt(1440)).toBe(3);
    expect(await columnsAt(1920)).toBe(4);
    expect(await columnsAt(2560)).toBe(5);
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
