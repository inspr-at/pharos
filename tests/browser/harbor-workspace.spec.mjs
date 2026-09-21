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
    await expect(page.locator('[data-host-section="overview"] [data-backup-daily-ok]')).toContainText("Daily backup remains OK");
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
    await page.getByRole("button", { name: "Discard draft", exact: true }).click();
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
      await viewerPage.goto(`/hosts/${host}?section=settings`);
      await expect(viewerPage.locator("select[data-grace-source]")).toBeDisabled();
      await expect(viewerPage.locator("[data-grace-seconds]")).toBeDisabled();
      await expect(viewerPage.locator("[data-host-workspace]")).toContainText(
        "Viewer access: settings and receipts stay visible, while guarded actions remain with a fleet manager.",
      );
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
