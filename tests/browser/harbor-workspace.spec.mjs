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

function backup(level, checkedAt, lastSuccessAt) {
  return {
    id: "files",
    label: "Files",
    engine: "restic",
    state: "healthy",
    configured: "enabled",
    summary: "daily files",
    schedule: "daily",
    last_success_at: lastSuccessAt,
    restore_validation: {
      level,
      state: "passed",
      ...(checkedAt == null ? {} : { checked_at: checkedAt }),
      summary: "one file restored",
    },
  };
}

async function reportHost(page, name, backupObservation) {
  const response = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v4",
      version: 4,
      name,
      role: "server",
      is_nix: false,
      heartbeat_interval_secs: 60,
      freshness: { applicable: false },
      preferences: { accent: "#224466", kind: "server" },
      service_observations: [
        { id: "sync", label: "File sync", state: "healthy", summary: "running" },
      ],
      backup_observations: [backupObservation],
    },
  });
  expect(response.status()).toBe(204);
}

async function retireHost(page, name) {
  const removal = await page.request.post(`/host-actions/${name}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: name, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  expect(
    (
      await page.request.post(`/host-actions/${name}/allow-reonboarding`, {
        headers: { "x-pharos-action": "1" },
        data: { confirmation: name },
      })
    ).ok(),
  ).toBe(true);
}

test("host workspace uses fleet protection, real grace, and private fleet return", async ({
  page,
  browser,
}, testInfo) => {
  const host = `harbor-ws-${testInfo.project.name}`;
  const savedFleet = await page.request.post("/settings/fleet.json", {
    headers: { "x-pharos-action": "1" },
    data: { nixpkgs_warn_after_days: 30, heartbeat_grace_secs: 45 },
  });
  expect(savedFleet.status()).toBe(200);
  const serverNow = (await (await page.request.get("/hosts.json")).json()).as_of;
  const recent = serverNow - 60;
  const overdue = serverNow - 31 * 24 * 60 * 60;
  try {
    await reportHost(page, host, backup("restore-sample", overdue, recent));
    await page.goto(`/hosts/${host}`);
    const html = await page.content();
    expect(html).not.toContain("sessionStorage");
    expect(html).not.toContain("localStorage");
    expect(html).not.toContain("host-task-rail");
    expect(html).not.toContain("return_q");
    await expect(page.locator("aside.sidebar")).toHaveCount(1);
    await expect(page.locator("[data-host-tab]")).toHaveCount(4);
    await expect(page.locator('[data-fleet-return]')).toHaveAttribute("href", "/");
    await expect(page.locator("[data-host-workspace-primary]")).toHaveAttribute(
      "href",
      "#host-settings-editor",
    );
    await expect(page.locator("[data-daily-backup-tone]").first()).toHaveAttribute(
      "data-daily-backup-tone",
      "good",
    );
    await expect(page.locator("[data-restore-overdue]").first()).toHaveAttribute(
      "data-restore-overdue",
      "true",
    );
    await expect(page.locator("[data-health-badge]")).toHaveAttribute("data-health-tone", "amber");
    const overview = page.locator('[data-host-section="overview"]');
    await expect(overview.locator("[data-daily-backup]")).toBeVisible();
    await expect(overview.locator("[data-daily-backup-label]")).toHaveText("Daily OK");
    await expect(overview.locator("time[data-daily-backup-date]")).toHaveAttribute("datetime", /^\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z$/);
    await expect(page.locator("[data-host-service='sync']")).toContainText("File sync");
    await expect(page.locator("[data-host-service='sync']")).toContainText("running");
    await expect(page.getByText(/^\d+ service/)).toHaveCount(0);

    await page.goto(`/hosts/${host}?section=settings`);
    const grace = page.locator("[data-heartbeat-grace]");
    await expect(grace).toBeVisible();
    await expect(grace).toHaveAttribute("data-fleet-grace-seconds", "45");
    await expect(grace).toHaveAttribute("data-grace-binding", "alerts.heartbeat_grace_secs");
    const source = grace.getByLabel("Heartbeat grace source");
    const seconds = grace.getByLabel("Heartbeat grace seconds");
    await expect(source).toBeEnabled();
    await expect(seconds).toBeDisabled();
    await source.selectOption("host");
    await seconds.fill("30");
    const review = page.getByRole("button", { name: "Review changes", exact: true });
    await expect(review).toBeEnabled();
    await review.click();
    await expect(page.locator("[data-settings-draft-review]")).toContainText(
      "Heartbeat grace: fleet default → 30 seconds",
    );
    await page
      .getByRole("dialog", { name: `Confirm changes for ${host}` })
      .getByRole("button", { name: "Discard draft", exact: true })
      .click();
    await grace.getByRole("button", { name: "Use fleet default", exact: true }).click();
    await expect(review).toBeDisabled();

    const well = page.locator(".host-color-well");
    await expect(well).toHaveCSS("width", "48px");
    await expect(well).toHaveCSS("height", "48px");
    await expect(page.locator(".preference-row").first()).toHaveCSS("min-height", "54px");
    await source.focus();
    await expect(source).toHaveCSS("outline-style", "solid");

    await page.setViewportSize({ width: 640, height: 900 });
    await expect(page.locator(".host-columns")).toHaveCSS("grid-template-columns", /none|1fr/);
    await page.evaluate(() => {
      document.body.style.zoom = "2";
    });
    await expect(well).toHaveCSS("width", "48px");

    const viewer = await newAuthedContext(browser, "read");
    try {
      const viewerPage = await viewer.newPage();
      const postedSettings = [];
      viewerPage.on("request", (request) => {
        if (request.method() === "POST" && request.url().includes("/agora/requests/host-preferences.json")) {
          postedSettings.push(request.url());
        }
      });
      await viewerPage.goto(`/hosts/${host}?section=settings`);
      await viewerPage.waitForFunction(() => {
        const root = document.querySelector("[data-color-root]");
        const main = document.querySelector(".settings-main");
        return root?.dataset.hostReported === "true" && main?.dataset.canManageFleet === "false";
      });
      await viewerPage.locator("details.settings-disclosure").first().locator("summary").click();
      await viewerPage.locator("[data-advanced] summary").click();
      await viewerPage.evaluate(() => {
        const fire = (selector, type) => {
          document.querySelector(selector)?.dispatchEvent(new Event(type, { bubbles: true }));
        };
        const down = document.querySelector("[data-alert-down]");
        if (down) down.checked = !down.checked;
        fire("[data-host-kind]", "change");
        fire("[data-grace-source]", "change");
        fire("[data-color]", "input");
        fire("[data-alert-down]", "change");
        fire("[data-alert-backup]", "change");
        fire("[data-alert-nix]", "change");
        fire("[data-nixpkgs-warn-after-days]", "input");
        fire("[data-preset]", "click");
      });
      await expect(viewerPage.locator("[data-color]")).toBeDisabled();
      await expect(viewerPage.locator("[data-preset]").first()).toBeDisabled();
      await expect(viewerPage.locator("[data-host-kind]")).toBeDisabled();
      await expect(viewerPage.locator("[data-alert-down]")).toBeDisabled();
      await expect(viewerPage.locator("[data-alert-backup]")).toBeDisabled();
      await expect(viewerPage.locator("[data-alert-nix]")).toBeDisabled();
      await expect(viewerPage.locator("[data-nixpkgs-warn-after-days]")).toBeDisabled();
      await expect(viewerPage.locator("select[data-grace-source]")).toBeDisabled();
      await expect(viewerPage.locator("[data-grace-seconds]")).toBeDisabled();
      await expect(viewerPage.locator("[data-grace-reset]")).toBeDisabled();
      const review = viewerPage.locator("[data-review-settings]");
      await expect(review).toBeDisabled();
      await expect(viewerPage.locator("[data-discard-settings]")).toBeDisabled();
      await review.click({ force: true });
      await expect(viewerPage.locator("[data-settings-draft-review]")).toHaveCount(0);
      expect(postedSettings).toEqual([]);
      await expect(viewerPage.locator("[data-host-workspace]")).toContainText(
        "Viewer access: settings and receipts stay visible, while guarded actions remain with a fleet manager.",
      );
      expect((await viewerPage.request.post("/agora/requests/host-preferences.json", {
        headers: { Accept: "application/json", "Content-Type": "application/json" },
        data: {
          host,
          preferences: { accent: "#112233", kind: "server", alerts: { suppress_down: true } },
        },
      })).status()).toBe(403);
      expect((await viewerPage.request.post(`/host-actions/${host}/remove`, {
        headers: { "x-pharos-action": "1" },
        data: { confirmation: host, disposition: "unmanaged", successor: null },
      })).status()).toBe(403);
      expect((await viewerPage.request.post("/settings/fleet.json", {
        headers: { "x-pharos-action": "1" },
        data: { nixpkgs_warn_after_days: 7, heartbeat_grace_secs: 45 },
      })).status()).toBe(403);
    } finally {
      await viewer.close();
    }
  } finally {
    await page.request.post("/settings/fleet.json", {
      headers: { "x-pharos-action": "1" },
      data: { nixpkgs_warn_after_days: 30, heartbeat_grace_secs: 15 },
    });
    await retireHost(page, host);
  }

  const diffHost = `harbor-diff-${testInfo.project.name}`;
  try {
    await reportHost(page, diffHost, backup("diff-hash", recent, recent));
    await page.goto(`/hosts/${diffHost}`);
    await expect(page.locator("[data-restore-tone]").first()).not.toHaveAttribute(
      "data-restore-tone",
      "good",
    );
    await expect(page.locator("[data-health-badge]")).not.toHaveAttribute("data-health-tone", "good");
  } finally {
    await retireHost(page, diffHost);
  }

  const unknownHost = `harbor-unknown-${testInfo.project.name}`;
  try {
    await reportHost(page, unknownHost, backup("restore-sample", null, recent));
    await page.goto(`/hosts/${unknownHost}`);
    await expect(page.locator("[data-restore-tone]").first()).not.toHaveAttribute(
      "data-restore-tone",
      "good",
    );
    await expect(page.locator("[data-restore-overdue]").first()).toHaveAttribute(
      "data-restore-overdue",
      "false",
    );
  } finally {
    await retireHost(page, unknownHost);
  }
});

test("fleet breadcrumb returns to the real fleet entry", async ({ page }, testInfo) => {
  const host = `harbor-return-${testInfo.project.name}`;
  const serverNow = (await (await page.request.get("/hosts.json")).json()).as_of;
  try {
    await reportHost(page, host, backup("restore-sample", serverNow - 60, serverNow - 60));
    await page.setViewportSize({ width: 1100, height: 280 });
    await page.goto("/");
    await page.locator('[data-view-button="list"]').click();
    await page.locator("[data-sort]").selectOption("name");
    await page.locator("input[data-search]").fill(host);
    await expect(page.locator("input[data-search]")).toHaveValue(host);
    await expect.poll(() => {
      const url = new URL(page.url());
      return url.searchParams.get("view") === "list"
        && url.searchParams.get("sort") === "name"
        && !url.searchParams.has("q")
        && !url.search.includes(host);
    }).toBe(true);
    await expect.poll(() => page.evaluate((expected) => {
      const state = window.navigation?.currentEntry?.getState?.() || null;
      const marker = state && state.pharosFleet;
      const hrefs = [...document.querySelectorAll("a[href]")].map((node) => node.getAttribute("href") || "");
      const stored = Object.values(localStorage).some((value) => String(value).includes(expected));
      return Boolean(marker)
        && marker.path === location.pathname
        && Object.keys(marker).length === 1
        && state.pharosSearch === expected
        && !hrefs.some((href) => href.includes("q=") || href.includes("return_q") || (href.includes("return_to") && href.includes(expected)))
        && sessionStorage.length === 0
        && !stored;
    }, host)).toBe(true);
    const navigationApi = await page.evaluate(() => {
      const nav = window.navigation;
      if (!nav || typeof nav.entries !== "function" || typeof nav.traverseTo !== "function") return false;
      const entries = nav.entries();
      return Array.isArray(entries) && entries.length > 0 && entries.every((entry) => typeof entry.key === "string" && "url" in entry);
    });
    expect(navigationApi).toBe(true);
    const listRow = page.locator(`[data-list-body] tr[data-host="${host}"]`);
    const listHost = listRow.locator(`a.host-name[href="/hosts/${host}"]`);
    await expect(listRow).toBeVisible();
    await expect(listHost).toBeVisible();
    await expect(listHost).toHaveAttribute("href", `/hosts/${host}`);
    await expect.poll(() => page.evaluate((expected) => {
      const row = document.querySelector(`[data-list-body] tr[data-host="${expected}"]`);
      const needle = expected.toLowerCase();
      return Boolean(row)
        && !row.hidden
        && String(row.dataset.search || "").includes(needle)
        && [...document.querySelectorAll("[data-list-body] tr[data-host]")].every((el) => el === row || el.hidden);
    }, host)).toBe(true);
    const scrolled = await page.evaluate((href) => {
      const link = document.querySelector(`[data-list-body] a.host-name[href="${href}"]`);
      const max = document.documentElement.scrollHeight - window.innerHeight;
      const target = Math.min(180, Math.max(0, max));
      window.scrollTo(0, target);
      const inView = (node) => {
        if (!node) return false;
        const rect = node.getBoundingClientRect();
        return rect.width > 0 && rect.height > 0 && rect.bottom > 0 && rect.top < window.innerHeight;
      };
      if (link && !inView(link)) {
        const top = link.getBoundingClientRect().top + window.scrollY;
        let next = Math.min(Math.max(0, max), Math.max(0, top - 40));
        if (next === 0 && max > 0) next = Math.min(max, 1);
        window.scrollTo(0, next);
      }
      return { y: window.scrollY, max, href: link?.getAttribute("href") || "", inView: inView(link) };
    }, `/hosts/${host}`);
    expect(scrolled.href).toBe(`/hosts/${host}`);
    expect(scrolled.href).not.toContain("from=");
    expect(scrolled.max).toBeGreaterThan(0);
    expect(scrolled.y).toBeGreaterThan(0);
    expect(scrolled.inView).toBe(true);
    await Promise.all([
      page.waitForURL((url) => url.pathname === `/hosts/${host}`),
      listHost.click(),
    ]);
    for (const section of ["backups", "activity", "settings"]) {
      await page.locator(`[data-host-tab][data-section="${section}"]`).click();
      await expect(page).toHaveURL(new RegExp(`[?&]section=${section}(?:&|$)`));
    }
    await expect(page.locator("[data-fleet-return]")).toHaveAttribute("href", "/");
    const beforeReturn = await page.evaluate(() => ({ session: sessionStorage.length, name: window.name }));
    expect(beforeReturn.session).toBe(0);
    expect(beforeReturn.name).not.toContain("view=");
    expect(beforeReturn.name).not.toContain(host);
    await page.locator("[data-fleet-return]").click();
    await expect.poll(() => {
      const url = new URL(page.url());
      return url.pathname === "/"
        && !url.searchParams.has("q")
        && !url.search.includes(host)
        && url.searchParams.get("view") === "list"
        && url.searchParams.get("sort") === "name";
    }).toBe(true);
    await expect(page.locator("input[data-search]")).toHaveValue(host);
    await expect(listRow).toBeVisible();
    await expect(listHost).toBeVisible();
    await expect.poll(() => page.evaluate((expected) => {
      const row = document.querySelector(`[data-list-body] tr[data-host="${expected}"]`);
      const needle = expected.toLowerCase();
      return Boolean(row)
        && !row.hidden
        && String(row.dataset.search || "").includes(needle)
        && [...document.querySelectorAll("[data-list-body] tr[data-host]")].every((el) => el === row || el.hidden);
    }, host)).toBe(true);
    await expect.poll(() => page.evaluate(() => window.scrollY)).toBeGreaterThan(0);
    expect(await page.evaluate(() => sessionStorage.length)).toBe(0);
    expect(await page.evaluate((expected) => Object.values(localStorage).some((value) => String(value).includes(expected)), host)).toBe(false);
    expect(await page.evaluate(() => window.name)).not.toContain("q=");
    expect(await page.evaluate((expected) => window.name.includes(expected), host)).toBe(false);

    const fromAlerts = await page.context().newPage();
    try {
      await fromAlerts.goto("/alerts");
      const alertsPath = new URL(fromAlerts.url()).pathname;
      await fromAlerts.goto(`/hosts/${host}?section=activity`);
      await fromAlerts.locator("[data-fleet-return]").click();
      await expect.poll(() => new URL(fromAlerts.url()).pathname).toBe("/");
      expect(new URL(fromAlerts.url()).pathname).not.toBe(alertsPath);
      expect(fromAlerts.url()).not.toContain("/hosts/");
      expect(await fromAlerts.evaluate(() => sessionStorage.length)).toBe(0);
    } finally {
      await fromAlerts.close();
    }

    const direct = await page.context().newPage();
    try {
      await direct.goto(`/hosts/${host}?section=settings`);
      await expect(direct.locator("[data-fleet-return]")).toHaveAttribute("href", "/");
      await direct.locator("[data-fleet-return]").click();
      await expect.poll(() => new URL(direct.url()).pathname).toBe("/");
      expect(direct.url()).not.toContain("section=");
      expect(direct.url()).not.toContain("/hosts/");
      expect(new URL(direct.url()).searchParams.has("q")).toBe(false);
      await expect(direct.locator("input[data-search]")).toHaveValue("");
    } finally {
      await direct.close();
    }
  } finally {
    await retireHost(page, host);
  }
});
