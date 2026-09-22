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
      freshness: { applicable: false },
      preferences: { accent: "#224466", kind: "server" },
    },
  });
  const reportBody = await report.text();
  expect(report.status(), reportBody).toBe(204);
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

const HARBOR_BORDER = "rgba(210, 226, 234, 0.92)";
const LEGACY_SELF_AMBER = "rgba(214, 155, 49, 0.34)";

function canonicalColor(value) {
  const match = String(value).trim().match(/^rgba?\((.+)\)$/i);
  if (!match) return String(value).replace(/\s+/g, "").toLowerCase();
  const parts = match[1].split(",").map((part) => part.trim());
  const channels = parts.slice(0, 3).map((part) => String(Number(part)));
  const alpha = parts.length > 3 ? String(Number(parts[3])) : "1";
  return `rgba(${channels.join(", ")}, ${alpha})`;
}

test("harbor self and other hosts share neutral list and card borders", async ({ page }, testInfo) => {
  const selfName = process.env.PHAROS_SELF?.trim() || "csb1";
  const otherName = `harbor-border-${testInfo.project.name}`;
  const hosts = [selfName, otherName];
  for (const name of hosts) {
    const report = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v4",
        version: 4,
        name,
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
    await page.goto("/");
    await expect(page.locator(".side-mark")).toBeVisible();
    await expect(page.locator("section.summary")).toBeVisible();
    const selfCard = page.locator(`article[data-host="${selfName}"]`);
    const otherCard = page.locator(`article[data-host="${otherName}"]`);
    await expect(selfCard).toHaveAttribute("data-self", "true");
    await expect(selfCard).toHaveClass(/light/);
    await expect(selfCard.locator(".pharos-mark")).toHaveCount(1);
    await expect(otherCard).not.toHaveAttribute("data-self", "true");
    await expect(otherCard).not.toHaveClass(/\blight\b/);
    await expect(otherCard.locator(".pharos-mark")).toHaveCount(0);

    const cardBorders = await page.evaluate(({ selfName: self, otherName: other }) => {
      const border = (host) => getComputedStyle(document.querySelector(`article[data-host="${host}"]`)).borderColor;
      return { self: border(self), other: border(other) };
    }, { selfName, otherName });
    expect(canonicalColor(cardBorders.self)).toBe(HARBOR_BORDER);
    expect(canonicalColor(cardBorders.other)).toBe(HARBOR_BORDER);
    expect(canonicalColor(cardBorders.self)).not.toBe(LEGACY_SELF_AMBER);

    await page.locator("[data-view-button='list']").click();
    await expect(page.locator("main")).toHaveAttribute("data-view", "list");
    const selfRow = page.locator(`tr[data-host="${selfName}"]`);
    const otherRow = page.locator(`tr[data-host="${otherName}"]`);
    await expect(selfRow).toHaveAttribute("data-self", "true");
    await expect(selfRow).toHaveClass(/\blight\b/);
    await expect(selfRow).toHaveClass(/harbor-host/);
    await expect(otherRow).not.toHaveAttribute("data-self", "true");
    await expect(otherRow).not.toHaveClass(/\blight\b/);

    const listBorders = await page.evaluate(({ selfName: self, otherName: other }) => {
      const sides = (host) => {
        const cells = [...document.querySelectorAll(`tr[data-host="${host}"] td`)];
        return cells.map((cell) => {
          const style = getComputedStyle(cell);
          return {
            top: style.borderTopColor,
            right: style.borderRightColor,
            bottom: style.borderBottomColor,
            left: style.borderLeftColor,
          };
        });
      };
      return { self: sides(self), other: sides(other) };
    }, { selfName, otherName });
    expect(listBorders.self.length).toBeGreaterThan(1);
    expect(listBorders.other.length).toBe(listBorders.self.length);
    for (const sides of [...listBorders.self, ...listBorders.other]) {
      for (const side of Object.values(sides)) {
        expect(canonicalColor(side)).toBe(HARBOR_BORDER);
        expect(canonicalColor(side)).not.toBe(LEGACY_SELF_AMBER);
      }
    }
  } finally {
    for (const name of hosts) {
      const removal = await page.request.post(`/host-actions/${name}/remove`, {
        headers: { "x-pharos-action": "1" },
        data: { confirmation: name, disposition: "unmanaged", successor: null },
      });
      expect(removal.status()).toBe(202);
      const reonboard = await page.request.post(`/host-actions/${name}/allow-reonboarding`, {
        headers: { "x-pharos-action": "1" },
        data: { confirmation: name },
      });
      expect(reonboard.ok()).toBe(true);
    }
  }
});
