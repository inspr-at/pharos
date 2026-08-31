import AxeBuilder from "@axe-core/playwright";
import { test as base, expect } from "@playwright/test";
import fs from "node:fs";
import {
  expectSettingsSurfaces,
  newAuthedContext,
  waitForHarnessTokens,
} from "./harness.mjs";
import { requireFixtureManifest } from "./harness-fixture.mjs";

const test = base.extend({
  page: async ({ browser }, use) => {
    await waitForHarnessTokens();
    const context = await newAuthedContext(browser, "write");
    const page = await context.newPage();
    await use(page);
    await context.close();
  },
});

function openHostSettingsTitle(host) {
  return `Open host settings for ${host}`;
}

test("fleet has no serious accessibility violations and serves hardened headers", async ({
  page,
}) => {
  const response = await page.goto("/");
  expect(response).not.toBeNull();
  const headers = response.headers();
  expect(headers["content-security-policy"]).toContain("default-src 'self'");
  expect(headers["content-security-policy"]).toContain("base-uri 'none'");
  expect(headers["content-security-policy"]).toContain("object-src 'none'");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["referrer-policy"]).toBe("no-referrer");

  const results = await new AxeBuilder({ page }).analyze();
  const serious = results.violations.filter(({ impact }) =>
    ["serious", "critical"].includes(impact),
  );
  expect(serious).toEqual([]);
});

test("sign-in recovery is accessible, no-store, and restarts with one safe action", async ({
  page,
}) => {
  const response = await page.goto(
    "/auth/recover?return_to=%2Fservices%3Fview%3Dmanaged",
  );
  expect(response?.status()).toBe(400);
  expect(response?.headers()["cache-control"]).toContain("no-store");
  expect(response?.headers()["content-security-policy"]).toContain(
    "default-src 'self'",
  );

  const recovery = page.locator("[data-auth-recovery]");
  await expect(recovery).toBeVisible();
  await expect(page.getByRole("heading", { name: "Start sign-in again" })).toBeVisible();
  const actions = recovery.getByRole("link");
  await expect(actions).toHaveCount(1);
  await expect(actions).toHaveAttribute(
    "href",
    "/auth/login?return_to=%2Fservices%3Fview%3Dmanaged",
  );

  const results = await new AxeBuilder({ page }).analyze();
  const serious = results.violations.filter(({ impact }) =>
    ["serious", "critical"].includes(impact),
  );
  expect(serious).toEqual([]);

  await actions.click();
  await expect(page).toHaveURL(/\/services\?view=managed$/);
  await expect(page.locator("main")).toBeVisible();
});

test("setup assistant traps focus, closes with Escape, and restores its trigger", async ({
  page,
}) => {
  await page.goto("/");
  const trigger = page.locator("[data-onboard-open]").first();
  await trigger.focus();
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "Add a server" });
  await expect(dialog).toBeVisible();
  await expect(page.locator("[data-assistant-path]").first()).toBeFocused();

  for (let index = 0; index < 20; index += 1) {
    await page.keyboard.press("Tab");
    const focusInsideDialog = await page.evaluate(() => {
      const active = document.activeElement;
      return Boolean(active?.closest('[role="dialog"]'));
    });
    expect(focusInsideDialog).toBe(true);
  }

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("managed server progress follows the backend's kebab-case identity states", async ({
  page,
}) => {
  await page.goto("/");
  const overlay = page.locator("[data-setup-assistant]");
  const hostKey = overlay.locator("[data-created-host-key]");
  const automatic = overlay.locator("[data-created-setup]");
  const ready = overlay.locator("[data-created-ready-text]");
  const retry = overlay.locator("[data-created-bootstrap-retry]");
  const reconcile = overlay.locator("[data-created-bootstrap-reconcile]");
  const guidance = overlay.locator("[data-created-guidance]");
  const nextSteps = overlay.locator("[data-created-next-steps]");
  const progress = overlay.locator("[data-created-progress]");
  const recovery = overlay.locator("[data-created-recovery]");
  const trustStep = overlay.locator('[data-created-progress-step="trust"]');
  const installStep = overlay.locator('[data-created-progress-step="install"]');
  const heartbeatStep = overlay.locator('[data-created-progress-step="heartbeat"]');

  const renderState = async (state, lastFailure = null) => {
    await page.evaluate(
      ({ state, lastFailure }) => {
        const assistant = document.querySelector("[data-setup-assistant]");
        assistant.hidden = false;
        renderProvisioningJob(assistant, {
          id: "setup-browser-contract",
          provider: "hetzner-cloud",
          state: "waiting-for-heartbeat",
          host_name: "lab-01",
          provider_resources: [
            {
              provider: "hetzner-cloud",
              kind: "server",
              provider_id: "1",
              name: "lab-01",
              location: "fsn1",
              state: "created",
            },
          ],
          handoff: {
            status: "provider-resource-created",
            summary: "Managed installation is coordinated by Pharos.",
            next_steps: ["Keep this setup open."],
          },
          managed_identity: {
            credential_ref: "sec_00000000000000000000",
            executor_owner: "csb1",
            state,
            ...(lastFailure ? { last_failure: lastFailure } : {}),
          },
          progress: [],
        });
      },
      { state, lastFailure },
    );
  };

  await renderState("awaiting-host-key");
  await expect(ready).toHaveText("Verify SSH host key");
  await expect(hostKey).toBeVisible();
  await expect(automatic).toBeHidden();
  await expect(trustStep).toHaveAttribute("data-state", "current");
  expect(await installStep.getAttribute("data-state")).toBeNull();

  await renderState("ready");
  await expect(ready).toHaveText("Queued for installation");
  await expect(hostKey).toBeHidden();
  await expect(automatic).toBeVisible();
  await expect(trustStep).toHaveAttribute("data-state", "done");
  await expect(installStep).toHaveAttribute("data-state", "current");
  await expect(guidance).toContainText("SSH host key is verified");
  await expect(nextSteps).toContainText("starts the reviewed NixOS installation");
  await expect(nextSteps).not.toContainText("Keep this setup open");

  await renderState("retry-required", "bootstrap_failed");
  await expect(ready).toHaveText("Known-safe retry available");
  await expect(retry).toBeVisible();

  await renderState("retry-required", "host_key_mismatch");
  await expect(hostKey).toBeVisible();
  await expect(automatic).toBeHidden();
  await expect(retry).toBeHidden();

  await renderState("uncertain", "result_contract_invalid");
  await expect(ready).toHaveText("Manual recovery required");
  await expect(progress).toBeHidden();
  await expect(reconcile).toBeVisible();
  await expect(retry).toBeHidden();

  await renderState("reconciliation-pending", "result_contract_invalid");
  await expect(ready).toHaveText("Recovery check queued");
  await expect(progress).toBeHidden();
  await expect(reconcile).toBeHidden();
  await expect(nextSteps).toContainText("checking that the server and credential state are unchanged");

  await renderState("reconciliation-claimed", "result_contract_invalid");
  await expect(ready).toHaveText("Checking safe recovery");
  await expect(progress).toBeHidden();
  await expect(nextSteps).toContainText("read-only recovery check runs");

  await renderState("awaiting-heartbeat");
  await expect(ready).toHaveText("Waiting for heartbeat");
  await expect(installStep).toHaveAttribute("data-state", "done");
  await expect(heartbeatStep).toHaveAttribute("data-state", "current");

  await renderState("heartbeat-observed");
  await expect(ready).toHaveText("Heartbeat verified");
  await expect(heartbeatStep).toHaveAttribute("data-state", "done");

  await renderState("future-state");
  await expect(ready).toHaveText("Manual recovery required");
  await expect(progress).toBeHidden();
  await expect(hostKey).toBeHidden();
  await expect(automatic).toBeHidden();
  await expect(recovery).toHaveJSProperty("open", true);

  const serverSideRecoveryStillPolls = await page.evaluate(() =>
    [
      "reconciliation-pending",
      "reconciliation-claimed",
      "retirement-pending",
      "retirement-claimed",
      "credential-retired",
    ].every(
      (state) =>
        !provisioningJobTerminal({
          state: "cleanup-needed",
          managed_identity: { state },
        }),
    ),
  );
  expect(serverSideRecoveryStillPolls).toBe(true);
});

test("provider cleanup recovers a lost response and refreshes fleet without replaying delete", async ({
  page,
}) => {
  const activeJob = {
    id: "setup-cleanup-recovery",
    provider: "hetzner-cloud",
    state: "cleanup-needed",
    updated_at: 1,
    host_name: "lab-01",
    provider_resources: [
      {
        provider: "hetzner-cloud",
        kind: "server",
        provider_id: "4253",
        name: "lab-01",
        location: "fsn1",
        state: "created",
      },
    ],
    handoff: {
      status: "provider-resource-created",
      summary: "Managed installation stopped safely.",
      next_steps: ["Review cleanup."],
    },
    managed_identity: {
      credential_ref: "sec_00000000000000000000",
      executor_owner: "csb1",
      state: "retry-required",
    },
    progress: [],
  };
  const deletedJob = {
    ...activeJob,
    state: "complete",
    updated_at: 2,
    terminal_outcome: "rolled-back",
    provider_resources: [
      {
        ...activeJob.provider_resources[0],
        state: "deleted",
      },
    ],
    handoff: {
      status: "provider-resource-deleted",
      summary: "The provider resource is deleted.",
      next_steps: [],
    },
    managed_identity: null,
  };
  let cleanupRequests = 0;
  let statusReads = 0;
  await page.route("**/setup/provisioning-jobs/**", async (route) => {
    const request = route.request();
    const path = new URL(request.url()).pathname;
    if (request.method() === "POST" && path.endsWith("/cleanup")) {
      cleanupRequests += 1;
      await route.fulfill({
        status: 502,
        contentType: "text/html",
        body: "<p>upstream response lost</p>",
      });
      return;
    }
    if (request.method() === "GET" && path.endsWith("/setup-cleanup-recovery")) {
      statusReads += 1;
      await route.fulfill({ status: 200, json: { job: deletedJob } });
      return;
    }
    await route.abort();
  });

  await page.goto("/");
  const result = await page.evaluate(async (job) => {
    const overlay = document.querySelector("[data-setup-assistant]");
    overlay.hidden = false;
    renderProvisioningJob(overlay, job);
    overlay.querySelector("[data-created-delete-confirm]").checked = true;
    const originalRefresh = refresh;
    globalThis.__cleanupFleetRefresh = null;
    refresh = async (reason, options) => {
      globalThis.__cleanupFleetRefresh = { reason, options };
      return true;
    };
    try {
      return await deleteTrackedProviderServer(
        overlay,
        overlay.querySelector("[data-created-delete]"),
      );
    } finally {
      refresh = originalRefresh;
    }
  }, activeJob);

  expect(result).toEqual({ state: "deleted", recovered: true });
  expect(cleanupRequests).toBe(1);
  expect(statusReads).toBe(1);
  await expect(page.locator("[data-created-ready-text]")).toHaveText("Removed");
  expect(await page.evaluate(() => globalThis.__cleanupFleetRefresh)).toEqual({
    reason: "provider-cleanup",
    options: { force: true, recovery: true },
  });
});

test("responsive layouts do not overflow and numbered guide circles stay centred", async ({
  page,
}, testInfo) => {
  await page.goto("/settings/providers/hetzner-cloud");
  await expect(page.locator("main")).toBeVisible();

  const horizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(horizontalOverflow).toBeLessThanOrEqual(1);

  const circles = page.locator(".provider-guide-progress i, .provider-help-number");
  const count = await circles.count();
  expect(count).toBeGreaterThan(0);
  for (let index = 0; index < count; index += 1) {
    const offset = await circles.nth(index).evaluate((element) => {
      const range = document.createRange();
      range.selectNodeContents(element);
      const circle = element.getBoundingClientRect();
      const text = range.getBoundingClientRect();
      return Math.abs(circle.top + circle.height / 2 - (text.top + text.height / 2));
    });
    expect(offset).toBeLessThanOrEqual(1.5);
  }

  if (testInfo.project.name.includes("mobile")) {
    const controls = page.locator("button:visible, a:visible, input:visible, select:visible");
    const controlCount = await controls.count();
    const viewport = page.viewportSize();
    expect(viewport).not.toBeNull();
    for (let index = 0; index < Math.min(controlCount, 40); index += 1) {
      const box = await controls.nth(index).boundingBox();
      if (box) expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
    }
  }
});

test("provider help visual stays within its reviewed baseline", async ({ page }) => {
  test.skip(process.platform !== "linux", "visual baseline uses the pinned Linux Chromium image");
  await page.goto("/settings/providers/hetzner-cloud");
  const help = page.locator(".provider-help");
  await expect(help).toBeVisible();
  await expect(help).toHaveScreenshot("provider-help.png", {
    animations: "disabled",
    caret: "hide",
    maxDiffPixelRatio: 0.005,
  });
});

test("managed service secrets stay value-free, accessible, and narrow-screen safe", async ({
  page,
}) => {
  const servicesResponse = await page.goto("/services");
  expect(servicesResponse?.status()).toBe(200);
  const service = page.locator(".managed-service-card").first();
  await expect(service).toBeVisible();
  await expect(service).toContainText("Needs setup");
  await service.click();

  await expect(page.getByRole("heading", { name: "Managed service canary" })).toBeVisible();
  await expect(page.getByText("Service secret", { exact: true })).toBeVisible();
  await expect(page.getByText("Reveal", { exact: true })).toBeVisible();
  await expect(page.getByText("Never", { exact: true })).toBeVisible();
  await expect(page.getByRole("button", { name: "Setup unavailable" })).toBeDisabled();
  await expect(page.getByRole("button", { name: /reveal|show|copy/i })).toHaveCount(0);
  await expect(page.getByRole("link", { name: /reveal|show|copy/i })).toHaveCount(0);

  const html = await page.content();
  for (const forbidden of [
    'name="secret_value"',
    'name="source"',
    'name="host_ref"',
    'name="service_ref"',
    'name="slot_ref"',
    "callback_url",
    "return_url",
  ]) {
    expect(html).not.toContain(forbidden);
  }

  const details = page.getByText("Technical details", { exact: true });
  await details.focus();
  await page.keyboard.press("Enter");
  await expect(page.getByText("Host reference", { exact: true })).toBeVisible();

  const results = await new AxeBuilder({ page }).analyze();
  expect(
    results.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);

  const overflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(overflow).toBeLessThanOrEqual(1);
});

test("removal dialog names credential retirement for an undeclared Janus-managed host", async ({
  page,
}) => {
  // The shared removal dialog is only rendered once the fleet has a host, so
  // onboard a throwaway one and hand it back at the end of the test.
  const host = "browser-remove-copy";
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v4",
      version: 4,
      name: host,
      role: "server",
      is_nix: false,
      heartbeat_interval_secs: 60,
      freshness: { applicable: false },
    },
  });
  expect(report.status()).toBe(204);

  await page.goto("/");
  await expect(page.locator("[data-host-action-overlay]")).toHaveCount(1);

  const scopeFor = async (dataset) =>
    page.evaluate((attributes) => {
      const root = document.createElement("span");
      root.setAttribute("data-host-actions", "");
      Object.assign(root.dataset, {
        host: "dsc0",
        backupLabel: "Not observed",
        kernelState: "current",
        ...attributes,
      });
      document.body.append(root);
      try {
        openHostActionDialog("remove", root);
        const overlay = document.querySelector("[data-host-action-overlay]");
        return {
          scope: overlay.querySelector('[data-host-action-fact="scope"]')?.textContent,
          infoTitle: overlay.querySelector("[data-host-action-info-title]")?.textContent,
          infoCopy: overlay.querySelector("[data-host-action-info-copy]")?.textContent,
        };
      } finally {
        root.remove();
      }
    }, dataset);

  // PHAROS-194: the case that used to be labelled registration-only and then
  // failed with a 409 must now state the credential retirement up front.
  const janusOnly = await scopeFor({ declared: "false", credentialRetirement: "true" });
  expect(janusOnly.scope).toBe("Pharos registration + Janus credential retirement");
  expect(janusOnly.infoTitle).toBe("Credential retirement required");
  expect(janusOnly.infoCopy).toContain("retired");

  const both = await scopeFor({ declared: "true", credentialRetirement: "true" });
  expect(both.scope).toBe(
    "Pharos registration + nixcfg review + Janus credential retirement",
  );

  const runtimeOnly = await scopeFor({ declared: "false", credentialRetirement: "false" });
  expect(runtimeOnly.scope).toBe("Pharos registration only");
  expect(runtimeOnly.infoTitle).toBe("Runtime-only removal");

  await page.evaluate(() => closeHostActionDialog());

  // Return the throwaway host; manifest fixture hosts may remain in the fleet.
  const removal = await page.request.post(
    `/host-actions/${host}/remove`,
    {
      headers: { "x-pharos-action": "1" },
      data: { confirmation: host, disposition: "unmanaged", successor: null },
    },
  );
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
  const hostsPayload = await page.request.get("/hosts.json").then((response) => response.json());
  expect(hostsPayload.hosts?.some((entry) => entry.name === host)).toBe(false);
});

test("stale side nixpkgs is visible as neutral context without host attention", async ({
  page,
}) => {
  const host = "browser-secondary-nixpkgs";
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v5",
      version: 5,
      name: host,
      role: "server",
      is_nix: true,
      heartbeat_interval_secs: 60,
      freshness: {
        applicable: true,
        flake_lock_age_days: 0,
        commits_behind: 0,
        nixpkgs_age_days: 0,
        nixpkgs_channel: "nixos-unstable",
        secondary_nixpkgs: {
          input: "nixpkgs-stable",
          age_days: 218,
          channel: "nixos-25.05",
        },
        deployment_evidence: {
          schema: "inspr.pharos.nix-deployment-evidence.v1",
          version: 1,
          source_revision: "1111111111111111111111111111111111111111",
          flake_lock_sha256:
            "2222222222222222222222222222222222222222222222222222222222222222",
          nixpkgs_revision: "3333333333333333333333333333333333333333",
          nixpkgs_last_modified: 1700000000,
          nixpkgs_channel: "nixos-unstable",
        },
        nixcfg_comparison: {
          upstream_revision: "1111111111111111111111111111111111111111",
          relation: "current",
          commits_behind: 0,
        },
        nixpkgs_comparison: {
          upstream_revision: "3333333333333333333333333333333333333333",
          relation: "current",
        },
      },
      backup_observations: [healthyBackupObservation()],
    },
  });
  expect(report.status()).toBe(204);

  await page.goto("/");
  const snapshot = await page.request.get("/hosts.json");
  expect(snapshot.ok()).toBe(true);
  expect(
    await page.evaluate((payload) => applyFleetSnapshot(payload), await snapshot.json()),
  ).toBe(true);
  const card = page
    .locator(`[data-host="${host}"][data-host-surface="runtime"]`)
    .first();
  await expect(card).toBeVisible();
  await expect(card.locator("[data-reason]")).toContainText("all clear");
  await expect(card.locator(".freshness-rail")).toHaveAttribute("hidden", "");
  await expect(
    card.locator(".freshness-rail .fresh-row-compact:not([hidden])"),
  ).toHaveCount(0);
  const secondary = page
    .locator(`tr[data-host="${host}"]`)
    .locator('[data-fresh-kind="secondary-nixpkgs"]');
  await expect(secondary).toContainText("Other root nixpkgs");
  await expect(secondary).toContainText("nixpkgs-stable");
  await expect(secondary).toContainText("nixos-25.05");
  await expect(secondary).toContainText("218d");
  await expect(secondary.locator("[data-fresh-value]")).toHaveClass("na");

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("legacy numeric freshness is unverified rather than up to date", async ({ page }) => {
  const host = "browser-unverified-nix";
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v4",
      version: 4,
      name: host,
      role: "server",
      is_nix: true,
      heartbeat_interval_secs: 60,
      freshness: {
        applicable: true,
        flake_lock_age_days: 0,
        commits_behind: 0,
        nixpkgs_age_days: 0,
        nixpkgs_channel: "nixos-unstable",
      },
    },
  });
  expect(report.status()).toBe(204);

  await page.goto("/");
  const snapshot = await page.request.get("/hosts.json");
  expect(snapshot.ok()).toBe(true);
  expect(
    await page.evaluate((payload) => applyFleetSnapshot(payload), await snapshot.json()),
  ).toBe(true);
  const card = page
    .locator(`[data-host="${host}"][data-host-surface="runtime"]`)
    .first();
  await expect(card.locator("[data-reason]")).toContainText("freshness unverified");
  await expect(card.locator(".freshness-rail")).not.toHaveAttribute(
    "hidden",
    "",
  );
  await expect(
    card.locator('[data-fresh-kind="freshness-unverified"]'),
  ).toBeVisible();
  await expect(
    card.locator('[data-fresh-kind="freshness-unverified"]'),
  ).toContainText("unverified");

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("fleet host cards do not overlap in grid or list view", async ({ page }) => {
  const hosts = ["browser-card-a", "browser-card-b", "browser-card-c"];
  for (const host of hosts) {
    const report = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v5",
        version: 5,
        name: host,
        role: "server",
        is_nix: true,
        heartbeat_interval_secs: 60,
        freshness: {
          applicable: true,
          flake_lock_age_days: 1,
          commits_behind: 0,
          nixpkgs_age_days: 2,
          nixpkgs_channel: "nixos-unstable",
          secondary_nixpkgs: null,
          deployment_evidence: {
            schema: "inspr.pharos.nix-deployment-evidence.v1",
            version: 1,
            source_revision: "a".repeat(40),
            flake_lock_sha256: "b".repeat(64),
            nixpkgs_revision: "c".repeat(40),
            nixpkgs_last_modified: 1700000000,
            nixpkgs_channel: "nixos-unstable",
          },
          nixcfg_comparison: {
            upstream_revision: "a".repeat(40),
            relation: "current",
            commits_behind: 0,
          },
          nixpkgs_comparison: {
            upstream_revision: "c".repeat(40),
            relation: "current",
          },
        },
      },
    });
    expect(report.status()).toBe(204);
  }

  await page.goto("/");
  await page.setViewportSize({ width: 1280, height: 1024 });
  await expect(page.locator("[data-grid]")).toBeVisible();

  const gridCards = page.locator(
    '[data-grid] article[data-host="browser-card-a"], [data-grid] article[data-host="browser-card-b"], [data-grid] article[data-host="browser-card-c"]',
  );
  await expect(gridCards).toHaveCount(3);

  const checkNoOverlap = async (locator) => {
    const boxes = await locator.evaluateAll((elements) =>
      elements.map((el) => {
        const rect = el.getBoundingClientRect();
        return { top: rect.top, bottom: rect.bottom, left: rect.left, right: rect.right };
      }),
    );

    for (let i = 0; i < boxes.length; i += 1) {
      for (let j = i + 1; j < boxes.length; j += 1) {
        const a = boxes[i];
        const b = boxes[j];
        const overlapX = a.left < b.right && a.right > b.left;
        const overlapY = a.top < b.bottom && a.bottom > b.top;
        const overlaps = overlapX && overlapY;
        expect(overlaps).toBe(false);
      }
    }
  };

  await checkNoOverlap(gridCards);

  for (const host of hosts) {
    const removal = await page.request.post(`/host-actions/${host}/remove`, {
      headers: { "x-pharos-action": "1" },
      data: { confirmation: host, disposition: "unmanaged", successor: null },
    });
    expect(removal.status()).toBe(202);
    const reonboard = await page.request.post(
      `/host-actions/${host}/allow-reonboarding`,
      { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
    );
    expect(reonboard.ok()).toBe(true);
  }
});

test("fleet host actions menu opens adjacent to its trigger", async ({ page }) => {
  const hosts = [
    "browser-actions-a",
    "browser-actions-b",
    "browser-actions-c",
    "browser-actions-d",
  ];
  for (const host of hosts) {
    const report = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v5",
        version: 5,
        name: host,
        role: "server",
        is_nix: true,
        heartbeat_interval_secs: 60,
        freshness: {
          applicable: true,
          flake_lock_age_days: 1,
          commits_behind: 0,
          nixpkgs_age_days: 2,
          nixpkgs_channel: "nixos-unstable",
          secondary_nixpkgs: null,
          deployment_evidence: {
            schema: "inspr.pharos.nix-deployment-evidence.v1",
            version: 1,
            source_revision: "a".repeat(40),
            flake_lock_sha256: "b".repeat(64),
            nixpkgs_revision: "c".repeat(40),
            nixpkgs_last_modified: 1700000000,
            nixpkgs_channel: "nixos-unstable",
          },
          nixcfg_comparison: {
            upstream_revision: "a".repeat(40),
            relation: "current",
            commits_behind: 0,
          },
          nixpkgs_comparison: {
            upstream_revision: "c".repeat(40),
            relation: "current",
          },
        },
      },
    });
    expect(report.status()).toBe(204);
  }

  await page.goto("/");
  await page.setViewportSize({ width: 1280, height: 1024 });

  const host = "browser-actions-b";
  const trigger = page.locator(
    `[data-grid] article[data-host="${host}"] [data-host-actions-trigger]`,
  );
  await trigger.click();

  const placement = await page.evaluate((hostName) => {
    const pad = 16;
    const card = document.querySelector(
      `[data-grid] article[data-host="${hostName}"]`,
    );
    const menuTrigger = card?.querySelector("[data-host-actions-trigger]");
    const menu = card?.querySelector("[data-host-actions-menu]");
    if (!menuTrigger || !menu || menu.hidden) {
      return { intersects: false, hostTitle: "", itemCount: 0 };
    }
    const triggerRect = menuTrigger.getBoundingClientRect();
    const menuRect = menu.getBoundingClientRect();
    const intersects =
      triggerRect.left - pad < menuRect.right &&
      triggerRect.right + pad > menuRect.left &&
      triggerRect.top - pad < menuRect.bottom &&
      triggerRect.bottom + pad > menuRect.top;
    return {
      intersects,
      hostTitle: menu.querySelector(".host-actions-title")?.textContent?.trim(),
      itemCount: menu.querySelectorAll('[role="menuitem"]:not([hidden])').length,
    };
  }, host);

  expect(placement.intersects).toBe(true);
  expect(placement.hostTitle).toBe(host);
  expect(placement.itemCount).toBeGreaterThan(0);
  await expect(
    page.locator(`[data-host-actions-menu]:not([hidden]) .host-action-item`, {
      hasText: "View technical details",
    }),
  ).toBeVisible();

  for (const cleanupHost of hosts) {
    const removal = await page.request.post(`/host-actions/${cleanupHost}/remove`, {
      headers: { "x-pharos-action": "1" },
      data: {
        confirmation: cleanupHost,
        disposition: "unmanaged",
        successor: null,
      },
    });
    expect(removal.status()).toBe(202);
    const reonboard = await page.request.post(
      `/host-actions/${cleanupHost}/allow-reonboarding`,
      { headers: { "x-pharos-action": "1" }, data: { confirmation: cleanupHost } },
    );
    expect(reonboard.ok()).toBe(true);
  }
});

function healthyBackupObservation() {
  return {
    id: "restic-main",
    label: "Restic main",
    engine: "restic",
    state: "healthy",
    configured: "enabled",
    summary: "last backup succeeded",
    target_label: "off-box repository",
    last_success_at: 1_700_000_000,
    last_attempt_at: 1_700_000_000,
    last_attempt_state: "succeeded",
  };
}

function failedBackupObservation() {
  return {
    id: "restic-main",
    label: "Restic main",
    engine: "restic",
    state: "failed",
    configured: "enabled",
    summary: "last backup failed",
    target_label: "off-box repository",
    last_attempt_at: 1_700_000_000,
    last_attempt_state: "failed",
  };
}

test("fleet card header keeps actions visible and backup shield only when not ok", async ({
  page,
}) => {
  const healthyHost = "header-actions-healthy";
  const failedHost = "header-actions-failed";
  const hosts = [healthyHost, failedHost];

  const reportBackup = async (host, observation) => {
    const report = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v5",
        version: 5,
        name: host,
        role: "server",
        is_nix: true,
        heartbeat_interval_secs: 60,
        freshness: {
          applicable: true,
          flake_lock_age_days: 1,
          commits_behind: 0,
          nixpkgs_age_days: 2,
          nixpkgs_channel: "nixos-unstable",
          deployment_evidence: {
            schema: "inspr.pharos.nix-deployment-evidence.v1",
            version: 1,
            source_revision: "a".repeat(40),
            flake_lock_sha256: "b".repeat(64),
            nixpkgs_revision: "c".repeat(40),
            nixpkgs_last_modified: 1_700_000_000,
            nixpkgs_channel: "nixos-unstable",
          },
          nixcfg_comparison: {
            upstream_revision: "a".repeat(40),
            relation: "current",
            commits_behind: 0,
          },
          nixpkgs_comparison: {
            upstream_revision: "c".repeat(40),
            relation: "current",
          },
        },
        backup_observations: [observation],
      },
    });
    expect(report.status()).toBe(204);
  };

  await reportBackup(healthyHost, healthyBackupObservation());
  await reportBackup(failedHost, failedBackupObservation());

  try {
    await page.goto("/");

    const healthyCard = page.locator(
      `[data-grid] article[data-host="${healthyHost}"]`,
    );
    const healthyRow = page.locator(`tr[data-host="${healthyHost}"]`);
    const failedCard = page.locator(
      `[data-grid] article[data-host="${failedHost}"]`,
    );
    const failedRow = page.locator(`tr[data-host="${failedHost}"]`);
    const healthyCardChip = healthyCard.locator(".backup-chip");
    const failedCardChip = failedCard.locator(".backup-chip");
    const healthyRail = healthyCard.locator(".freshness-rail");
    const failedRail = failedCard.locator(".freshness-rail");
    const failedRailBackup = failedRail.locator('[data-fresh-kind="backup-fault"]');

    await expect(healthyCardChip).toHaveCount(1);
    await expect(healthyCardChip).toHaveAttribute("hidden", "");
    await expect(healthyRail).toHaveAttribute("hidden", "");
    await expect(failedCardChip).toHaveCount(1);
    await expect(failedCardChip).not.toHaveAttribute("hidden", "");
    await expect(failedRail).not.toHaveAttribute("hidden", "");
    await expect(failedRailBackup).toBeVisible();
    await expect(failedRailBackup).toContainText("Backup failed");

    for (const width of [1440, 1024, 768, 390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      await expect(healthyCard.locator("[data-host-actions-trigger]")).toBeVisible();
      await expect(failedCard.locator("[data-host-actions-trigger]")).toBeVisible();
      await expect(failedCardChip).toBeVisible();

      const cardChrome = await failedCard.evaluate((card) => {
        const cardRect = card.getBoundingClientRect();
        const actions = card.querySelector("[data-host-actions-trigger]");
        const backup = card.querySelector(".backup-chip");
        const actionsRect = actions?.getBoundingClientRect();
        const backupRect = backup?.getBoundingClientRect();
        return {
          actionsInside:
            actionsRect != null &&
            actionsRect.left >= cardRect.left - 1 &&
            actionsRect.right <= cardRect.right + 1,
          backupInside:
            backupRect != null &&
            backupRect.left >= cardRect.left - 1 &&
            backupRect.right <= cardRect.right + 1,
        };
      });
      expect(cardChrome).toEqual({ actionsInside: true, backupInside: true });
    }

    const failedBackupChrome = await failedCardChip.evaluate((el) => {
      const style = getComputedStyle(el);
      return {
        borderColor: style.borderColor,
        backgroundColor: style.backgroundColor,
      };
    });
    expect(failedBackupChrome.borderColor).not.toBe("rgba(0, 0, 0, 0)");
    expect(failedBackupChrome.backgroundColor).not.toBe("rgba(0, 0, 0, 0)");

    const snapshotResponse = await page.request.get("/hosts.json");
    expect(snapshotResponse.ok()).toBe(true);
    const snapshot = await snapshotResponse.json();
    const applyBackupSnapshot = (observation) => {
      const payload = structuredClone(snapshot);
      const host = payload.hosts.find((candidate) => candidate.name === failedHost);
      expect(host).toBeDefined();
      host.backup_observations = [observation];
      return page.evaluate((body) => applyFleetSnapshot(body), payload);
    };

    await failedCardChip.focus();
    await expect(failedCardChip).toBeFocused();
    expect(await applyBackupSnapshot(healthyBackupObservation())).toBe(true);
    await expect(failedCardChip).toHaveAttribute("hidden", "");
    await expect(failedCardChip).toHaveAttribute("data-backup-state", "healthy");
    await expect(failedCard.locator("[data-host-actions-trigger]")).toBeFocused();
    await expect(failedRail).toHaveAttribute("hidden", "");
    await expect(failedRailBackup).toHaveAttribute("hidden", "");

    expect(await applyBackupSnapshot(failedBackupObservation())).toBe(true);
    await expect(failedCardChip).not.toHaveAttribute("hidden", "");
    await expect(failedCardChip).toHaveAttribute("data-backup-state", "failed");
    await expect(failedRail).not.toHaveAttribute("hidden", "");
    await expect(failedRailBackup).toBeVisible();

    await page.locator("[data-view-button='list']").click();
    await expect(page.locator("main")).toHaveAttribute("data-view", "list");
    await expect(healthyRow.locator(".backup-chip")).toHaveCount(1);
    await expect(healthyRow.locator(".backup-chip")).toHaveAttribute("hidden", "");
    await expect(failedRow.locator(".backup-chip")).toHaveCount(1);
    await expect(failedRow.locator(".backup-chip")).not.toHaveAttribute("hidden", "");
    for (const width of [1440, 1024, 768, 390, 320]) {
      await page.setViewportSize({ width, height: 900 });
      await expect(healthyRow.locator("[data-host-actions-trigger]")).toBeVisible();
      await expect(failedRow.locator("[data-host-actions-trigger]")).toBeVisible();
      await expect(failedRow.locator(".backup-chip")).toBeVisible();
    }
  } finally {
    for (const host of hosts) {
      const removal = await page.request.post(`/host-actions/${host}/remove`, {
        headers: { "x-pharos-action": "1" },
        data: { confirmation: host, disposition: "unmanaged", successor: null },
      });
      expect(removal.status()).toBe(202);
      const reonboard = await page.request.post(
        `/host-actions/${host}/allow-reonboarding`,
        { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
      );
      expect(reonboard.ok()).toBe(true);
    }
  }
});

test("fault rail uses full card width, stays one line, and keeps quiet hashes in technical details", async ({
  page,
}) => {
  const quietHost = "freshness-rail-quiet";
  const faultHost = "freshness-rail-fault";
  const hosts = [quietHost, faultHost];
  const currentFreshness = {
    applicable: true,
    flake_lock_age_days: 1,
    commits_behind: 0,
    nixpkgs_age_days: 2,
    nixpkgs_channel: "nixos-unstable",
    deployment_evidence: {
      schema: "inspr.pharos.nix-deployment-evidence.v1",
      version: 1,
      source_revision: "a".repeat(40),
      flake_lock_sha256: "b".repeat(64),
      nixpkgs_revision: "c".repeat(40),
      nixpkgs_last_modified: 1_700_000_000,
      nixpkgs_channel: "nixos-unstable",
    },
    nixcfg_comparison: {
      upstream_revision: "a".repeat(40),
      relation: "current",
      commits_behind: 0,
    },
    nixpkgs_comparison: {
      upstream_revision: "c".repeat(40),
      relation: "current",
    },
  };
  const reportHost = async (name, freshness, backup, kernel) => {
    const report = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v5",
        version: 5,
        name,
        role: "server",
        is_nix: true,
        heartbeat_interval_secs: 60,
        freshness,
        backup_observations: [backup],
        kernel: kernel
          ? {
              schema: "inspr.pharos.kernel-posture.v1",
              version: 1,
              ...kernel,
            }
          : undefined,
      },
    });
    expect(report.status()).toBe(204);
  };
  await reportHost(
    quietHost,
    currentFreshness,
    healthyBackupObservation(),
    {
      state: "current",
      running_version: "7.0.14",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    },
  );
  await reportHost(
    faultHost,
    {
      ...structuredClone(currentFreshness),
      commits_behind: 12,
      nixpkgs_channel: "nixos-25.05",
      deployment_evidence: {
        ...structuredClone(currentFreshness.deployment_evidence),
        nixpkgs_channel: "nixos-25.05",
      },
      nixcfg_comparison: {
        upstream_revision: "d".repeat(40),
        relation: "behind",
        commits_behind: 12,
      },
      nixpkgs_comparison: {
        upstream_revision: "e".repeat(40),
        relation: "different",
      },
    },
    failedBackupObservation(),
    {
      state: "reboot_required",
      running_version: "6.18.26",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    },
  );

  try {
    await page.goto("/");
    const quietCard = page.locator(`[data-grid] article[data-host="${quietHost}"]`);
    const faultCard = page.locator(`[data-grid] article[data-host="${faultHost}"]`);
    const quietRail = quietCard.locator(".freshness-rail");
    const faultRail = faultCard.locator(".freshness-rail");
    const visibleFaults = faultRail.locator(".fresh-row-compact:not([hidden])");

    await expect(quietRail).toHaveAttribute("hidden", "");
    await expect(quietRail.locator(".fresh-row-compact:not([hidden])")).toHaveCount(0);
    await expect(faultRail).toBeVisible();
    await expect(faultRail).toHaveAttribute("role", "group");
    await expect(visibleFaults).toHaveCount(5);
    await expect(faultRail.locator('[data-fresh-kind="nixpkgs-eol"]')).toBeVisible();
    await expect(faultRail.locator('[data-fresh-kind="nixpkgs-drift"]')).toBeVisible();
    await expect(faultRail.locator('[data-fresh-kind="nixcfg-drift"]')).toBeVisible();
    await expect(faultRail.locator('[data-fresh-kind="backup-fault"]')).toBeVisible();
    const failedBackupValue = faultRail.locator(
      '[data-fresh-kind="backup-fault"] [data-fresh-value]',
    );
    await expect(failedBackupValue).toHaveClass("down");
    const failedBackupColors = await failedBackupValue.evaluate((value) => {
      const probe = document.createElement("span");
      probe.style.color = "var(--down)";
      value.appendChild(probe);
      const expected = getComputedStyle(probe).color;
      probe.remove();
      return { actual: getComputedStyle(value).color, expected };
    });
    expect(failedBackupColors.actual).toBe(failedBackupColors.expected);
    await expect(faultRail.locator('[data-fresh-kind="kernel-restart"]')).toBeVisible();
    await expect(faultRail.locator('[data-fresh-kind="deployed-sha"]')).toHaveCount(0);
    await expect(faultRail.locator('[data-fresh-kind="nixcfg-sha"]')).toHaveCount(0);
    await expect(faultRail.locator('[data-fresh-kind="nixpkgs-sha"]')).toHaveCount(0);
    await expect(faultRail).not.toContainText("+N");

    for (const width of [1440, 1024, 900, 390, 320]) {
      await page.setViewportSize({ width, height: 1200 });
      const geometry = await faultRail.evaluate((rail) => {
        const card = rail.closest(".card");
        const scroller = rail.querySelector("[data-fresh-scroll-container]");
        const chips = Array.from(
          rail.querySelectorAll(".fresh-row-compact:not([hidden])"),
        );
        const cardRect = card.getBoundingClientRect();
        const railRect = rail.getBoundingClientRect();
        const scrollerRect = scroller.getBoundingClientRect();
        const style = getComputedStyle(card);
        const innerWidth =
          cardRect.width -
          Number.parseFloat(style.paddingLeft) -
          Number.parseFloat(style.paddingRight);
        const tops = chips.map((chip) => Math.round(chip.getBoundingClientRect().top));
        return {
          railInside:
            railRect.left >= cardRect.left - 1 &&
            railRect.right <= cardRect.right + 1,
          spansInnerWidth: Math.abs(railRect.width - innerWidth) <= 2,
          scrollerInside:
            scrollerRect.left >= railRect.left - 1 &&
            scrollerRect.right <= railRect.right + 1,
          oneLine: new Set(tops).size === 1,
          overflow: scroller.scrollWidth > scroller.clientWidth + 1,
          allChipsInside: chips.every((chip) => {
            const rect = chip.getBoundingClientRect();
            return rect.left >= scrollerRect.left - 1 && rect.right <= scrollerRect.right + 1;
          }),
        };
      });
      expect(geometry.railInside).toBe(true);
      expect(geometry.spansInnerWidth).toBe(true);
      expect(geometry.scrollerInside).toBe(true);
      expect(geometry.oneLine).toBe(true);
      if (width === 320) {
        expect(geometry.overflow).toBe(true);
        await expect(faultRail.locator(".fresh-chevron-right")).toHaveClass(/visible/);
        await expect(faultRail).toHaveAttribute("data-overflow-right", "true");
        const wheelBoundary = await faultRail.evaluate((rail) => {
          const scroller = rail.querySelector("[data-fresh-scroll-container]");
          scroller.style.scrollBehavior = "auto";
          scroller.scrollLeft = 0;
          const leavesPageScrollAtLeft = scroller.dispatchEvent(
            new WheelEvent("wheel", { deltaY: -120, cancelable: true }),
          );
          scroller.scrollLeft = scroller.scrollWidth - scroller.clientWidth;
          const leavesPageScrollAtRight = scroller.dispatchEvent(
            new WheelEvent("wheel", { deltaY: 120, cancelable: true }),
          );
          scroller.scrollLeft = 0;
          const consumesInwardScroll = !scroller.dispatchEvent(
            new WheelEvent("wheel", { deltaY: 120, cancelable: true }),
          );
          return { leavesPageScrollAtLeft, leavesPageScrollAtRight, consumesInwardScroll };
        });
        expect(wheelBoundary).toEqual({
          leavesPageScrollAtLeft: true,
          leavesPageScrollAtRight: true,
          consumesInwardScroll: true,
        });
        const rightChevron = faultRail.locator(".fresh-chevron-right");
        const leftChevron = faultRail.locator(".fresh-chevron-left");
        await rightChevron.focus();
        await expect(rightChevron).toBeFocused();
        await faultRail.evaluate((rail) => {
          const scroller = rail.querySelector("[data-fresh-scroll-container]");
          scroller.style.scrollBehavior = "auto";
          scroller.scrollLeft = scroller.scrollWidth - scroller.clientWidth;
          scroller.dispatchEvent(new Event("scroll"));
        });
        await expect(rightChevron).not.toHaveClass(/visible/);
        await expect(leftChevron).toBeFocused();
      }
    }

    const offscreenFault = visibleFaults.last();
    await offscreenFault.focus();
    await expect(offscreenFault).toBeFocused();
    await expect(page.locator('[data-fresh-popover][role="tooltip"]')).toBeVisible();

    const firstFault = visibleFaults.first();
    await expect(firstFault).not.toHaveAttribute("title", /.*/);
    await firstFault.focus();
    await expect(firstFault).toBeFocused();
    await expect(page.locator('[data-fresh-popover][role="tooltip"]')).toBeVisible();
    await expect(firstFault).toHaveAttribute(
      "aria-describedby",
      "freshness-fault-tooltip",
    );
    await expect(page.locator("[data-fresh-popover]")).toContainText(
      await firstFault.locator("[data-fresh-value]").textContent(),
    );
    await page.keyboard.press("Escape");
    await expect(page.locator("[data-fresh-popover]")).toBeHidden();
    await expect(firstFault).not.toHaveAttribute("aria-describedby", /.*/);

    await quietCard.locator("[data-host-actions-trigger]").click();
    await quietCard.locator('[data-host-action="technical"]').click();
    const technical = page.locator("[data-host-action-technical]");
    await expect(technical).toBeVisible();
    await expect(technical).toContainText("Deployed revision: " + "a".repeat(40));
    await expect(technical).toContainText("nixcfg revision: " + "a".repeat(40));
    await expect(technical).toContainText("nixpkgs revision: " + "c".repeat(40));
    await page.evaluate(() => closeHostActionDialog());

    const response = await page.request.get("/hosts.json");
    expect(response.ok()).toBe(true);
    const original = await response.json();
    const healed = structuredClone(original);
    const healedHost = healed.hosts.find((host) => host.name === faultHost);
    expect(healedHost).toBeDefined();
    healedHost.freshness = structuredClone(currentFreshness);
    healedHost.backup_observations = [healthyBackupObservation()];
    healedHost.kernel = {
      state: "current",
      running_version: "7.0.14",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    };
    await faultCard.locator("[data-host-actions]").evaluate((root) => root.remove());
    await expect(faultCard.locator("[data-host-actions]")).toHaveCount(0);
    await firstFault.focus();
    await expect(page.locator("[data-fresh-popover]")).toBeVisible();
    expect(await page.evaluate((body) => applyFleetSnapshot(body), healed)).toBe(true);
    await expect(faultRail).toHaveAttribute("hidden", "");
    await expect(visibleFaults).toHaveCount(0);
    await expect(page.locator("[data-fresh-popover]")).toBeHidden();
    await expect(faultCard).toBeFocused();

    expect(await page.evaluate((body) => applyFleetSnapshot(body), original)).toBe(true);
    await expect(faultRail).not.toHaveAttribute("hidden", "");
    await expect(visibleFaults).toHaveCount(5);
  } finally {
    for (const host of hosts) {
      const removal = await page.request.post(`/host-actions/${host}/remove`, {
        headers: { "x-pharos-action": "1" },
        data: { confirmation: host, disposition: "unmanaged", successor: null },
      });
      expect(removal.status()).toBe(202);
      const reonboard = await page.request.post(
        `/host-actions/${host}/allow-reonboarding`,
        { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
      );
      expect(reonboard.ok()).toBe(true);
    }
  }
});
async function reportRuntimeHost(page, name, extra = {}) {
  const isNix = extra.is_nix ?? false;
  const freshness =
    extra.freshness ??
    (isNix
      ? {
          applicable: true,
          flake_lock_age_days: 0,
          commits_behind: 0,
          nixpkgs_age_days: 0,
          nixpkgs_channel: "nixos-unstable",
          deployment_evidence: {
            schema: "inspr.pharos.nix-deployment-evidence.v1",
            version: 1,
            source_revision: "1111111111111111111111111111111111111111",
            flake_lock_sha256:
              "2222222222222222222222222222222222222222222222222222222222222222",
            nixpkgs_revision: "3333333333333333333333333333333333333333",
            nixpkgs_last_modified: 1_700_000_000,
            nixpkgs_channel: "nixos-unstable",
          },
          nixcfg_comparison: {
            upstream_revision: "1111111111111111111111111111111111111111",
            relation: "current",
            commits_behind: 0,
          },
          nixpkgs_comparison: {
            upstream_revision: "3333333333333333333333333333333333333333",
            relation: "current",
          },
        }
      : { applicable: false });
  const kernel =
    extra.kernel == null
      ? undefined
      : {
          schema: "inspr.pharos.kernel-posture.v1",
          version: 1,
          state: extra.kernel.state,
          running_version: extra.kernel.running_version,
          expected_version: extra.kernel.expected_version,
          observed_at: extra.kernel.observed_at,
        };
  const response = await page.request.post("/report", {
    data: {
      schema: isNix
        ? "inspr.pharos.host-report.v5"
        : "inspr.pharos.host-report.v4",
      version: isNix ? 5 : 4,
      name,
      role: "server",
      is_nix: isNix,
      heartbeat_interval_secs: 60,
      freshness,
      preferences: extra.preferences,
      kernel,
    },
  });
  expect(response.status()).toBe(204);
}

async function applyServerFleetSnapshot(page) {
  const snapshot = await page.request.get("/hosts.json");
  expect(snapshot.ok()).toBe(true);
  const payload = await snapshot.json();
  return page.evaluate((body) => applyFleetSnapshot(body), payload);
}

async function cancelUpdateRestartJob(page, jobId) {
  if (!jobId) return;
  try {
    await page.request.post(`/host-actions/jobs/${encodeURIComponent(jobId)}/cancel`, {
      headers: { "x-pharos-action": "1" },
      data: {},
    });
  } catch {
    /* best effort */
  }
}

async function clearRetirementIfPending(page, host) {
  try {
    await page.request.post(`/host-actions/${host}/allow-reonboarding`, {
      headers: { "x-pharos-action": "1" },
      data: { confirmation: host },
    });
  } catch {
    /* best effort */
  }
}

function resetDispatchAcceptFlag(acceptFlagPath) {
  if (!acceptFlagPath) return;
  try {
    fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
  } catch {
    /* best effort */
  }
}

async function cancelVisibleFleetUpdateRestarts(page) {
  const payload = await page.request.get("/hosts.json").then((response) => {
    return response.ok() ? response.json() : null;
  });
  if (!payload?.hosts) return;
  const cancelIds = new Set();
  for (const entry of payload.hosts) {
    if (entry.lifecycle?.slot === "update_restart" && entry.lifecycle.run_id) {
      cancelIds.add(entry.lifecycle.run_id);
    }
    if (entry.host_action?.workflow?.kind === "update_restart" && entry.host_action?.id) {
      cancelIds.add(entry.host_action.id);
    }
  }
  for (const id of cancelIds) {
    await cancelUpdateRestartJob(page, id);
  }
}

async function cleanupRemovalRestartFixture(page, host, options = {}) {
  const { acceptFlagPath, updateRunId } = options;
  await cancelUpdateRestartJob(page, updateRunId);
  await cancelVisibleFleetUpdateRestarts(page);
  await clearRetirementIfPending(page, host);
  resetDispatchAcceptFlag(acceptFlagPath);
}

async function expectInformationalWorkflowControlsHidden(dialog) {
  await expect(dialog.locator("[data-host-remove-disposition-field]")).toBeHidden();
  await expect(dialog.locator("[data-host-remove-successor]")).toBeHidden();
  await expect(dialog.locator("[data-host-remove-confirm]")).toBeHidden();
  await expect(dialog.locator("[data-host-attended-confirm]")).toBeHidden();
  await expect(dialog.locator("[data-host-workflow]")).toBeHidden();
  await expect(dialog.locator("[data-host-action-technical]")).toBeHidden();
  await expect(dialog.locator("[data-host-action-primary]")).toBeHidden();
}

test("fleet refresh consumes server-emitted lifecycle for failed settings", async ({
  page,
}) => {
  const host = "bl-server-failed-settings";
  await reportRuntimeHost(page, host, { is_nix: true });
  await page.goto("/");

  const agora = await page.request.post("/agora/requests/host-preferences.json", {
    data: { host, preferences: { accent: "#48b8a8" } },
  });
  expect(agora.status()).toBe(409);

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData?.lifecycle?.slot).toBe("settings_change");
  expect(hostData?.lifecycle?.label).not.toBe("Change requested");

  expect(await applyServerFleetSnapshot(page)).toBe(true);
  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toBeVisible();
  await expect(chip.locator("[data-host-lifecycle-chip-copy]")).toHaveText(
    hostData.lifecycle.label,
  );
  await expect(chip.locator("[data-host-lifecycle-chip-copy]")).not.toContainText(
    "Change requested",
  );
  if (hostData.lifecycle?.run_id) {
    await expect(chip).toHaveAttribute(
      "data-lifecycle-run-id",
      hostData.lifecycle.run_id,
    );
  }
  const continueBtn = card
    .locator("[data-host-actions]")
    .first()
    .locator("[data-host-action='lifecycle-continue']");
  await expect(continueBtn).toBeHidden();

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("fleet refresh applies server lifecycle when run_id differs from host_action", async ({
  page,
}) => {
  const host = "bl-server-lifecycle-diverge";
  await reportRuntimeHost(page, host, { is_nix: true });
  await page.goto("/");

  const agora = await page.request.post("/agora/requests/host-preferences.json", {
    data: { host, preferences: { accent: "#48b8a8" } },
  });
  expect(agora.status()).toBe(409);

  const manifest = requireFixtureManifest(
    test,
    "system update proposal fixture requires local harness manifest",
  );
  if (!manifest) return;
  fs.writeFileSync(manifest.acceptFlagPath, "true", { mode: 0o600 });

  const proposal = await page.request.post("/host-actions/system-update", {
    headers: { "x-pharos-action": "1" },
    data: { host },
  });
  expect(proposal.status()).toBe(202);

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData?.lifecycle?.slot).toBe("settings_change");
  expect(hostData?.lifecycle?.run_id).toBeTruthy();
  expect(hostData?.host_action?.id).toBeTruthy();
  expect(hostData.lifecycle.run_id).not.toBe(hostData.host_action.id);

  expect(await applyServerFleetSnapshot(page)).toBe(true);
  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "data-lifecycle-run-id",
    hostData.lifecycle.run_id,
  );

  const lifecycleRunId = hostData.lifecycle.run_id;
  const legacyJobId = hostData.host_action.id;
  const pollResponsePromise = page.waitForResponse(
    (response) =>
      response.url().includes(
        `/host-actions/jobs/${encodeURIComponent(lifecycleRunId)}`,
      ) && response.request().method() === "GET",
  );
  await card.locator("[data-host-lifecycle-chip]").click();
  const pollResponse = await pollResponsePromise;
  expect(pollResponse.ok()).toBe(true);
  const pollPayload = await pollResponse.json();
  expect(pollPayload.job.id).toBe(lifecycleRunId);
  expect(pollPayload.job.id).not.toBe(legacyJobId);
  expect(pollPayload.job.workflow?.kind).toBe("settings_change");
  await expect(page.locator("[data-host-action-overlay]")).toBeVisible();
  await page.evaluate(() => closeHostActionDialog());

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
  fs.writeFileSync(manifest.acceptFlagPath, "false", { mode: 0o600 });
});

test("lifecycle chip opens drift sheet without agora navigation or workflow steps", async ({
  page,
}) => {
  const host = "bl-lifecycle-drift-sheet";
  await reportRuntimeHost(page, host, {
    kernel: {
      state: "reboot_required",
      running_version: "6.18.26",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    },
  });
  await page.goto("/");

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toBeVisible();
  await expect(chip).toHaveAttribute("type", "button");
  await expect(chip).not.toHaveAttribute("href", /.*/);

  const jobPolls = [];
  page.on("request", (request) => {
    if (
      request.url().includes("/host-actions/jobs/") &&
      request.method() === "GET"
    ) {
      jobPolls.push(request.url());
    }
  });
  await chip.click();
  expect(jobPolls).toHaveLength(0);

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(page).toHaveURL("/");
  await expect(dialog.locator("[data-host-workflow]")).toBeHidden();
  await expect(dialog.locator("[data-host-action-fact-row='kernel']")).toBeVisible();
  await expect(dialog.locator("[data-host-action-fact='kernel']")).toContainText("6.18.26");
  await expect(dialog.locator("[data-host-action-fact='kernel']")).toContainText("7.0.14");
  await expect(dialog.locator("[data-host-action-info-copy]")).toContainText(
    "Pharos will not restart this host",
  );

  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("lifecycle chip opens persisted run sheet without agora navigation", async ({
  page,
}) => {
  const host = "bl-lifecycle-run-sheet";
  await reportRuntimeHost(page, host, { is_nix: true });
  await page.goto("/");

  const agora = await page.request.post("/agora/requests/host-preferences.json", {
    data: { host, preferences: { accent: "#48b8a8" } },
  });
  expect(agora.status()).toBe(409);

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toBeVisible();
  await expect(chip).toHaveAttribute("data-lifecycle-invoke", "workflow");

  const pollResponsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/host-actions/jobs/") &&
      response.request().method() === "GET",
  );
  await chip.click();
  const pollResponse = await pollResponsePromise;
  expect(pollResponse.ok()).toBe(true);

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(page).toHaveURL("/");
  await expect(dialog.locator("[data-host-workflow]")).not.toBeEmpty();
  await expect(dialog.locator("[data-host-action-fact-row='declared']")).toBeHidden();
  await expect(dialog.locator("[data-host-action-fact-row='observed']")).toBeHidden();

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("fleet refresh kernel chip follows server lifecycle transitions", async ({ page }) => {
  const host = "bl-kernel-lifecycle";
  await reportRuntimeHost(page, host, {
    kernel: {
      state: "reboot_required",
      running_version: "6.18.26",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    },
  });
  await page.goto("/");

  expect(await applyServerFleetSnapshot(page)).toBe(true);
  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toBeVisible();
  await expect(chip).toHaveAttribute("data-lifecycle-slot", "kernel_drift");
  await expect(chip.locator("[data-host-lifecycle-chip-copy]")).toContainText(
    "Restart required",
  );
  await expect(card.locator("[data-kernel-slot]")).toHaveCount(0);
  const continueBtn = card
    .locator("[data-host-actions]")
    .first()
    .locator("[data-host-action='lifecycle-continue']");
  await expect(continueBtn).toBeHidden();

  await reportRuntimeHost(page, host, {
    kernel: {
      state: "current",
      running_version: "7.0.14",
      expected_version: "7.0.14",
      observed_at: 1_700_000_100,
    },
  });
  expect(await applyServerFleetSnapshot(page)).toBe(true);
  await expect(card.locator("[data-host-lifecycle-chip-copy]")).toContainText("Up to date");

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("fleet refresh keeps workflow note inert without host actions root", async ({
  browser,
}) => {
  await waitForHarnessTokens();
  const host = "bl-readonly-lifecycle";
  const writeContext = await newAuthedContext(browser, "write");
  const writePage = await writeContext.newPage();
  await reportRuntimeHost(writePage, host, { is_nix: true });
  const agora = await writePage.request.post("/agora/requests/host-preferences.json", {
    data: { host, preferences: { accent: "#9868d0" } },
  });
  expect(agora.status()).toBe(409);
  await writeContext.close();

  const readContext = await newAuthedContext(browser, "read");
  const page = await readContext.newPage();
  await page.goto("/");

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData?.lifecycle?.invoke).toBe("workflow");

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const row = page.locator(`tr[data-host="${host}"][data-host-surface="runtime"]`).first();
  await expect(card.locator("[data-host-actions]")).toHaveCount(0);
  await expect(row.locator("[data-host-actions]")).toHaveCount(0);
  await expect(card.locator("[data-host-lifecycle-chip]")).toHaveCount(1);
  await expect(row.locator("[data-host-lifecycle-chip]")).toHaveCount(1);
  await expect(card.locator("[data-host-lifecycle-chip]")).toBeVisible();
  await expect(card.locator("[data-host-lifecycle-chip]")).toBeDisabled();
  await expect(row.locator("[data-host-lifecycle-chip]")).toBeDisabled();
  await expect(row.locator("[data-host-lifecycle-chip]")).not.toBeVisible();
  await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "aria-disabled",
    "true",
  );
  await expect(row.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "aria-disabled",
    "true",
  );

  expect(await applyServerFleetSnapshot(page)).toBe(true);
  await expect(card.locator("[data-host-lifecycle-chip]")).toBeVisible();
  await expect(card.locator("[data-host-lifecycle-chip]")).toBeDisabled();
  await expect(row.locator("[data-host-lifecycle-chip]")).toHaveCount(1);
  await expect(row.locator("[data-host-lifecycle-chip]")).toBeDisabled();
  await expect(row.locator("[data-host-lifecycle-chip]")).not.toBeVisible();
  await expect(card.locator("[data-host-lifecycle-chip]")).not.toBeFocused();

  await page.locator("[data-view-button='list']").click();
  await expect(page.locator("main")).toHaveAttribute("data-view", "list");
  await expect(row.locator("[data-host-lifecycle-chip]")).toBeVisible();
  await expect(row.locator("[data-host-lifecycle-chip]")).toBeDisabled();
  await readContext.close();

  const cleanupContext = await newAuthedContext(browser, "write");
  const cleanupPage = await cleanupContext.newPage();
  const removal = await cleanupPage.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await cleanupPage.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
  await cleanupContext.close();
});

test("fleet refresh keeps sequential settings surfaces aligned on card and row", async ({
  page,
}) => {
  const host = "bl-settings-sequential";
  const settingsTitle = openHostSettingsTitle(host);
  await reportRuntimeHost(page, host, {
    preferences: { accent: "#111111" },
  });
  await page.goto("/");

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const row = page.locator(`tr[data-host="${host}"][data-host-surface="runtime"]`).first();

  expect(await applyServerFleetSnapshot(page)).toBe(true);
  await expectSettingsSurfaces(card, {
    state: "applied",
    title: settingsTitle,
    chipCopy: "Up to date",
  });
  await page.locator("[data-view-button='list']").click();
  await expect(page.locator("main")).toHaveAttribute("data-view", "list");
  await expectSettingsSurfaces(row, {
    state: "applied",
    title: settingsTitle,
    chipCopy: "Up to date",
  });
  await page.locator("[data-view-button='grid']").click();

  const agora = await page.request.post("/agora/requests/host-preferences.json", {
    data: { host, preferences: { accent: "#48b8a8" } },
  });
  expect(agora.status()).toBe(200);
  expect(await applyServerFleetSnapshot(page)).toBe(true);
  const cardWithdraw = card.locator('[data-host-action="withdraw-settings"]');
  await expect(cardWithdraw).not.toHaveAttribute("hidden", "");
  await expect(cardWithdraw.locator("svg")).toHaveCount(1);
  await expectSettingsSurfaces(card, {
    state: "request_pending",
    title: settingsTitle,
    chipCopy: "change waiting",
    requestedIconVisible: false,
  });
  await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "data-lifecycle-level",
    "warning",
  );
  const cardChipChrome = await card.evaluate((surface) => {
    const chip = surface.querySelector(".host-lifecycle-chip");
    const chipStyle = getComputedStyle(chip);
    return {
      fontFamily: chipStyle.fontFamily,
      surfaceFontFamily: getComputedStyle(surface).fontFamily,
      color: chipStyle.color,
      borderTopWidth: chipStyle.borderTopWidth,
      borderRightWidth: chipStyle.borderRightWidth,
      borderBottomWidth: chipStyle.borderBottomWidth,
      borderLeftWidth: chipStyle.borderLeftWidth,
      backgroundColor: chipStyle.backgroundColor,
      paddingTop: chipStyle.paddingTop,
      paddingRight: chipStyle.paddingRight,
      paddingBottom: chipStyle.paddingBottom,
      paddingLeft: chipStyle.paddingLeft,
    };
  });
  expect(cardChipChrome.fontFamily).toBe(cardChipChrome.surfaceFontFamily);
  expect(parseFloat(cardChipChrome.borderTopWidth)).toBeGreaterThan(0);
  expect(parseFloat(cardChipChrome.borderRightWidth)).toBeGreaterThan(0);
  expect(parseFloat(cardChipChrome.borderBottomWidth)).toBeGreaterThan(0);
  expect(parseFloat(cardChipChrome.borderLeftWidth)).toBeGreaterThan(0);
  expect(cardChipChrome.backgroundColor).not.toBe("rgba(0, 0, 0, 0)");
  expect(cardChipChrome.backgroundColor).not.toBe("transparent");
  expect(parseFloat(cardChipChrome.paddingRight)).toBeGreaterThan(0);
  expect(parseFloat(cardChipChrome.paddingLeft)).toBeGreaterThan(0);
  await page.locator("[data-view-button='list']").click();
  const rowWithdraw = row.locator('[data-host-action="withdraw-settings"]');
  await expect(rowWithdraw).not.toHaveAttribute("hidden", "");
  await expect(rowWithdraw.locator("svg")).toHaveCount(1);
  await expectSettingsSurfaces(row, {
    state: "request_pending",
    title: settingsTitle,
    chipCopy: "change waiting",
    requestedIconVisible: false,
  });
  await expect(row.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "data-lifecycle-level",
    "warning",
  );
  const listChipChrome = await row.evaluate((surface) => {
    const chip = surface.querySelector(".host-lifecycle-chip");
    const attention = surface.querySelector(".list-attention") ?? surface;
    const chipStyle = getComputedStyle(chip);
    return {
      color: chipStyle.color,
      borderTopWidth: chipStyle.borderTopWidth,
      borderRightWidth: chipStyle.borderRightWidth,
      borderBottomWidth: chipStyle.borderBottomWidth,
      borderLeftWidth: chipStyle.borderLeftWidth,
      borderTopStyle: chipStyle.borderTopStyle,
      borderRightStyle: chipStyle.borderRightStyle,
      borderBottomStyle: chipStyle.borderBottomStyle,
      borderLeftStyle: chipStyle.borderLeftStyle,
      backgroundColor: chipStyle.backgroundColor,
      paddingTop: chipStyle.paddingTop,
      paddingRight: chipStyle.paddingRight,
      paddingBottom: chipStyle.paddingBottom,
      paddingLeft: chipStyle.paddingLeft,
      fontFamily: chipStyle.fontFamily,
      attentionFontFamily: getComputedStyle(attention).fontFamily,
      rowFontFamily: getComputedStyle(surface).fontFamily,
    };
  });
  expect(listChipChrome.borderTopWidth).toBe("0px");
  expect(listChipChrome.borderRightWidth).toBe("0px");
  expect(listChipChrome.borderBottomWidth).toBe("0px");
  expect(listChipChrome.borderLeftWidth).toBe("0px");
  expect(listChipChrome.borderTopStyle).toBe("none");
  expect(listChipChrome.borderRightStyle).toBe("none");
  expect(listChipChrome.borderBottomStyle).toBe("none");
  expect(listChipChrome.borderLeftStyle).toBe("none");
  expect(listChipChrome.backgroundColor).toBe("rgba(0, 0, 0, 0)");
  expect(listChipChrome.paddingTop).toBe("0px");
  expect(listChipChrome.paddingRight).toBe("0px");
  expect(listChipChrome.paddingBottom).toBe("0px");
  expect(listChipChrome.paddingLeft).toBe("0px");
  expect([
    listChipChrome.attentionFontFamily,
    listChipChrome.rowFontFamily,
  ]).toContain(listChipChrome.fontFamily);
  expect(cardChipChrome.color).toBe(listChipChrome.color);
  expect(cardChipChrome.color).toBe("rgb(139, 87, 0)");
  await page.locator("[data-view-button='grid']").click();

  await reportRuntimeHost(page, host, {
    preferences: { accent: "#48b8a8" },
  });
  expect(await applyServerFleetSnapshot(page)).toBe(true);
  await expectSettingsSurfaces(card, {
    state: "applied",
    title: settingsTitle,
    chipCopy: "Up to date",
  });
  await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "data-lifecycle-level",
    "clear",
  );
  await page.locator("[data-view-button='list']").click();
  await expectSettingsSurfaces(row, {
    state: "applied",
    title: settingsTitle,
    chipCopy: "Up to date",
  });
  await expect(row.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "data-lifecycle-level",
    "clear",
  );
  const cardQuietColor = await card.evaluate((surface) =>
    getComputedStyle(surface.querySelector(".host-lifecycle-chip")).color,
  );
  const listQuietColor = await row.evaluate((surface) =>
    getComputedStyle(surface.querySelector(".host-lifecycle-chip")).color,
  );
  expect(cardQuietColor).toBe(listQuietColor);
  expect(cardQuietColor).toBe("rgb(124, 142, 160)");

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("settings naming applies only to settings surfaces, not generic host actions", async ({
  page,
}) => {
  const host = "bl-settings-accessibility";
  const settingsTitle = openHostSettingsTitle(host);
  await reportRuntimeHost(page, host, { preferences: { accent: "#224466" } });
  await page.goto("/");

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const hostActions = card.locator("[data-host-actions]").first();
  await expect(hostActions).toHaveAttribute("data-settings-state", "applied");
  await expect(hostActions).not.toHaveAttribute("title", settingsTitle);
  await expect(hostActions).not.toHaveAttribute("aria-label", settingsTitle);

  const settingsLink = card.locator("a[data-settings-state]").first();
  await expect(settingsLink).toHaveAttribute("title", settingsTitle);
  await expect(settingsLink).toHaveAttribute("aria-label", settingsTitle);

  const results = await new AxeBuilder({ page })
    .include(`[data-host="${host}"][data-host-surface="runtime"].card`)
    .analyze();
  const serious = results.violations.filter(({ impact }) =>
    ["serious", "critical"].includes(impact),
  );
  expect(serious).toEqual([]);

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("fleet refresh shows workflow chip when UpdateRestart lifecycle wins", async ({
  page,
}, testInfo) => {
  test.skip(
    testInfo.project.name !== "chromium-mobile",
    "covered once in the final mobile lifecycle regression",
  );
  const host = `bl-kernel-vs-restart-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, {
    is_nix: true,
    kernel: {
      state: "reboot_required",
      running_version: "6.18.26",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    },
  });

  const review = await page.request.post(`/host-actions/${host}/update-restart/review`, {
    headers: { "x-pharos-action": "1" },
    data: {},
  });
  expect(review.status()).toBe(202);

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData?.kernel?.state).toBe("reboot_required");
  expect(hostData?.lifecycle?.slot).toBe("update_restart");
  const runId = hostData?.lifecycle?.run_id;
  expect(runId).toBeTruthy();

  await page.goto("/");
  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const expectKernelDriftChipAbsent = async () => {
    await expect(card.locator("[data-kernel-slot]")).toHaveCount(0);
    await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
      "data-lifecycle-invoke",
      "update_restart",
    );
  };
  await expectKernelDriftChipAbsent();
  expect(await applyServerFleetSnapshot(page)).toBe(true);
  await expectKernelDriftChipAbsent();
  await expect(card.locator("[data-host-lifecycle-chip]")).toBeVisible();

  const cancel = await page.request.post(
    `/host-actions/jobs/${encodeURIComponent(runId)}/cancel`,
    { headers: { "x-pharos-action": "1" }, data: {} },
  );
  expect(cancel.status()).toBe(200);
});

test("fleet refresh hides generic update-restart when removal masks host_action", async ({
  page,
}, testInfo) => {
  const manifest = requireFixtureManifest(
    test,
    "declared host removal fixture requires local harness manifest",
  );
  if (!manifest) return;

  const host = `bl-removal-vs-restart-${testInfo.project.name}`;
  let updateRunId;
  try {
    await cleanupRemovalRestartFixture(page, host, {
      acceptFlagPath: manifest.acceptFlagPath,
    });
    fs.writeFileSync(manifest.acceptFlagPath, "true", { mode: 0o600 });

    await reportRuntimeHost(page, host, {
      is_nix: true,
      kernel: {
        state: "reboot_required",
        running_version: "6.18.26",
        expected_version: "7.0.14",
        observed_at: 1_700_000_000,
      },
    });

    const removal = await page.request.post(`/host-actions/${host}/remove`, {
      headers: { "x-pharos-action": "1" },
      data: { confirmation: host, disposition: "unmanaged", successor: null },
    });
    expect(removal.status()).toBe(202);

    const review = await page.request.post(`/host-actions/${host}/update-restart/review`, {
      headers: { "x-pharos-action": "1" },
      data: {},
    });
    expect(review.status()).toBe(202);
    const reviewBody = await review.json();
    updateRunId = reviewBody.job?.id;
    expect(updateRunId).toBeTruthy();

    const payload = await page.request.get("/hosts.json").then((response) => {
      expect(response.ok()).toBe(true);
      return response.json();
    });
    const hostData = payload.hosts.find((entry) => entry.name === host);
    expect(hostData?.host_action?.workflow?.kind).toBe("remove_host");
    expect(hostData?.lifecycle?.slot).toBe("remove_host");
    expect(hostData?.update_restart_active).toBe(true);
    const removalRunId = hostData?.lifecycle?.run_id;
    expect(removalRunId).toBeTruthy();
    expect(removalRunId).not.toBe(updateRunId);

    await page.goto("/");
    const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
    const actionsRoot = card.locator("[data-host-actions]").first();
    await expect(actionsRoot).toHaveAttribute("data-update-restart-active", "true");
    await expect(actionsRoot.locator("[data-host-action='update-restart'][hidden]")).toHaveCount(1);
    await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
      "data-lifecycle-invoke",
      "workflow",
    );
    await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
      "data-lifecycle-run-id",
      removalRunId,
    );

    expect(await applyServerFleetSnapshot(page)).toBe(true);
    await expect(actionsRoot).toHaveAttribute("data-update-restart-active", "true");
    await expect(actionsRoot.locator("[data-host-action='update-restart'][hidden]")).toHaveCount(1);
    await expect(card.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
      "data-lifecycle-run-id",
      removalRunId,
    );
  } finally {
    await cleanupRemovalRestartFixture(page, host, {
      acceptFlagPath: manifest.acceptFlagPath,
      updateRunId,
    });
  }
});

test("saved update-restart stays read-only until the exact job renders", async ({
  page,
}, testInfo) => {
  const host = `bl-saved-restart-loading-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, {
    is_nix: true,
    kernel: {
      state: "reboot_required",
      running_version: "6.18.26",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    },
  });
  const review = await page.request.post(`/host-actions/${host}/update-restart/review`, {
    headers: { "x-pharos-action": "1" },
    data: {},
  });
  expect(review.status()).toBe(202);
  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  const runId = hostData?.lifecycle?.run_id;
  expect(hostData?.lifecycle?.slot).toBe("update_restart");
  expect(runId).toBeTruthy();

  const pauseFleetRefresh = async () => {
    await page.evaluate(() => {
      clearRefreshTimer();
      abandonRefresh();
    });
  };

  await page.goto("/");
  await page.locator("[data-view-button='grid']").click();
  await expect(page.locator("main")).toHaveAttribute("data-view", "grid");
  await pauseFleetRefresh();

  const renderedPayload = await page.request.get("/hosts.json").then((response) => {
    expect(response.ok()).toBe(true);
    return response.json();
  });
  const renderedHostData = renderedPayload.hosts.find((entry) => entry.name === host);
  expect(renderedHostData?.lifecycle?.run_id).toBe(runId);
  expect(renderedHostData?.lifecycle?.primary_action).toBeFalsy();

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toHaveAttribute("data-lifecycle-invoke", "update_restart");
  await expect(chip).toHaveAttribute("data-lifecycle-run-id", runId);

  const actionsRoot = card.locator("[data-host-actions]").first();
  const restartItem = actionsRoot.locator("[data-host-action='update-restart']");
  const continueItem = actionsRoot.locator("[data-host-action='lifecycle-continue']");
  await expect(actionsRoot.locator("[data-host-action='update-restart'][hidden]")).toHaveCount(
    1,
  );
  await expect(actionsRoot.locator("[data-host-action='lifecycle-continue'][hidden]")).toHaveCount(
    1,
  );

  const continueSnapshot = structuredClone(renderedPayload);
  const continueHost = continueSnapshot.hosts.find((entry) => entry.name === host);
  continueHost.lifecycle.primary_action = {
    kind: "recover",
    label: "Resume guarded update",
  };
  await pauseFleetRefresh();
  expect(
    await page.evaluate((body) => applyFleetSnapshot(body), continueSnapshot),
  ).toBe(true);
  await expect(actionsRoot.locator("[data-host-action='update-restart'][hidden]")).toHaveCount(
    1,
  );
  await expect(
    actionsRoot.locator("[data-host-action='lifecycle-continue']:not([hidden])"),
  ).toHaveCount(1);
  await expect(actionsRoot.locator("[data-host-action='lifecycle-continue'] strong")).toHaveText(
    "Continue: Resume guarded update",
  );
  await expect(actionsRoot.locator("[data-host-action='lifecycle-continue']")).toHaveAttribute(
    "data-lifecycle-run-id",
    runId,
  );
  await expect(
    actionsRoot.locator(".host-action-item:not([hidden])").filter({ hasText: /^Continue:/ }),
  ).toHaveCount(1);

  await card.scrollIntoViewIfNeeded();
  await card.locator("[data-host-actions-trigger]").click();
  await expect(card.locator("[data-host-actions-menu]:not([hidden])")).toBeVisible();
  await expect(restartItem).toBeHidden();
  await expect(continueItem).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(card.locator("[data-host-actions-menu]")).toBeHidden();

  await pauseFleetRefresh();
  expect(await page.evaluate((body) => applyFleetSnapshot(body), renderedPayload)).toBe(true);

  const jobPath = `/host-actions/jobs/${encodeURIComponent(runId)}`;
  const isExactJobGet = (url, method) => {
    if (method !== "GET") return false;
    try {
      return new URL(url).pathname === jobPath;
    } catch {
      return false;
    }
  };
  const prefetchedJob = await page.request.get(jobPath);
  expect(prefetchedJob.ok()).toBe(true);
  const prefetchedPayload = await prefetchedJob.json();
  const reviewPosts = [];
  const jobGets = [];
  page.on("request", (request) => {
    if (
      request.method() === "POST" &&
      request.url().includes(`/host-actions/${host}/update-restart/review`)
    ) {
      reviewPosts.push(request.url());
    }
    if (isExactJobGet(request.url(), request.method())) {
      jobGets.push(request.url());
    }
  });
  let releaseJobGet = () => {};
  const holdJobGet = new Promise((resolve) => {
    releaseJobGet = resolve;
  });
  await page.route("**/host-actions/jobs/**", async (route) => {
    const request = route.request();
    if (!isExactJobGet(request.url(), request.method())) {
      await route.continue();
      return;
    }
    await holdJobGet;
    await route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify(prefetchedPayload),
    });
  });

  await chip.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  const primary = dialog.locator("[data-host-action-primary]");
  await expect(primary).toBeHidden();
  await expect(primary).toBeDisabled();
  await expect(dialog.locator("[data-host-action-copy]")).toContainText(
    "Loading the saved execution checklist",
  );
  await expect(
    dialog.getByRole("button", { name: "Prepare guarded review" }),
  ).toHaveCount(0);
  await expect.poll(() => jobGets.length).toBeGreaterThan(0);
  await page.evaluate(() => submitHostAction());
  expect(reviewPosts).toEqual([]);

  const pollResponsePromise = page.waitForResponse(
    (response) =>
      isExactJobGet(response.url(), response.request().method()) &&
      response.ok(),
  );
  releaseJobGet();
  const pollResponse = await pollResponsePromise;
  expect(pollResponse.ok()).toBe(true);
  await expect(dialog.locator("[data-host-workflow]")).not.toBeEmpty();
  await expect(primary).toBeHidden();
  expect(reviewPosts).toEqual([]);
  await page.unroute("**/host-actions/jobs/**");
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  const cancel = await page.request.post(
    `/host-actions/jobs/${encodeURIComponent(runId)}/cancel`,
    { headers: { "x-pharos-action": "1" }, data: {} },
  );
  expect(cancel.status()).toBe(200);
});

test("system update uncertainty dialog acknowledges and retries once", async ({
  page,
}, testInfo) => {
  test.setTimeout(60_000);
  const manifest = requireFixtureManifest(
    test,
    "system update uncertainty fixture requires local harness manifest",
  );
  if (!manifest) return;
  const { acceptFlagPath, dispatchMockBase } = manifest;
  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });

  const host = `browser-uncertain-${testInfo.project.name}`;
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v4",
      version: 4,
      name: host,
      role: "server",
      is_nix: true,
      heartbeat_interval_secs: 60,
      freshness: { applicable: true },
    },
  });
  expect(report.status()).toBe(204);

  const readDispatchAttempts = async () => {
    const response = await fetch(`${dispatchMockBase}/test/dispatch-attempts`);
    expect(response.ok).toBe(true);
    const text = await response.text();
    return Number(text);
  };
  const readDispatchAccepted = async () => {
    const response = await fetch(`${dispatchMockBase}/test/dispatch-accepted`);
    expect(response.ok).toBe(true);
    const text = await response.text();
    return Number(text);
  };
  const attemptsAtStart = await readDispatchAttempts();
  const acceptedAtStart = await readDispatchAccepted();
  expect(Number.isNaN(attemptsAtStart)).toBe(false);
  expect(Number.isNaN(acceptedAtStart)).toBe(false);

  const uncertain = await page.request.post("/host-actions/system-update", {
    headers: { "X-Pharos-Action": "1" },
    data: { host },
  });
  expect(uncertain.status()).toBe(409);
  const uncertainPayload = await uncertain.json();
  expect(uncertainPayload.job.state).toBe("failed");
  expect(uncertainPayload.job.workflow.status_label).toBe(
    "dispatch outcome uncertain",
  );
  expect(uncertainPayload.job.workflow.evidence).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        label: "Repository dispatch",
        value: "outcome uncertain",
      }),
    ]),
  );
  expect(uncertainPayload.workflow_html).toContain("outcome uncertain");
  expect(uncertainPayload.workflow_html).toContain("not confirmed");
  const priorJobId = uncertainPayload.job.id;
  expect(await readDispatchAttempts()).toBe(attemptsAtStart + 1);
  expect(await readDispatchAccepted()).toBe(acceptedAtStart);

  const blocked = await page.request.post("/host-actions/system-update", {
    headers: { "X-Pharos-Action": "1" },
    data: { host },
  });
  expect(blocked.status()).toBe(409);
  expect(await readDispatchAttempts()).toBe(attemptsAtStart + 1);
  expect(await readDispatchAccepted()).toBe(acceptedAtStart);

  const invalidAck = await page.request.post("/host-actions/system-update", {
    headers: {
      "X-Pharos-Action": "1",
      "X-Pharos-Acknowledge-Uncertainty": "not-a-valid-job-id!!!",
    },
    data: { host },
  });
  expect(invalidAck.status()).toBe(400);
  expect(await readDispatchAttempts()).toBe(attemptsAtStart + 1);
  expect(await readDispatchAccepted()).toBe(acceptedAtStart);

  await page.goto("/");
  const card = page.locator(`article.card[data-host="${host}"]`);
  await expect(card).toBeVisible();

  const useKeyboard = testInfo.project.name.includes("mobile");

  if (useKeyboard) {
    const widths = await page.evaluate(() => ({
      innerWidth: window.innerWidth,
      clientWidth: document.documentElement.clientWidth,
      scrollWidth: document.documentElement.scrollWidth,
    }));
    expect(widths.innerWidth).toBe(412);
    expect(widths.clientWidth).toBe(412);
    expect(widths.scrollWidth).toBe(412);
  }

  const dialog = () =>
    page.getByRole("dialog", { name: "Review system updates" });
  const retryButton = () =>
    dialog().getByRole("button", {
      name: "I verified nixcfg — request again",
    });
  const closeButton = () =>
    dialog().getByRole("button", { name: "Close", exact: true });

  const openDialog = async () => {
    const jobPoll = page.waitForResponse(
      (response) =>
        response.url().includes("/host-actions/jobs/") &&
        response.request().method() === "GET",
    );
    await card.locator("[data-host-lifecycle-chip]").click();
    await jobPoll;
  };

  await openDialog();
  await expect(dialog()).toBeVisible();
  await expect(retryButton()).toBeVisible();
  await expect(retryButton()).toBeEnabled();
  await expect(dialog().locator("[data-host-action-copy]")).toContainText(
    "Verify nixcfg",
  );
  const statusLine = dialog().locator("[data-host-action-status]");
  await expect(statusLine).toBeVisible();
  await expect(statusLine).toHaveAttribute("aria-live", "polite");
  await expect(statusLine).not.toBeEmpty();

  const axeWithDialog = await new AxeBuilder({ page }).analyze();
  expect(
    axeWithDialog.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);

  await closeButton().click();
  await expect(dialog()).toBeHidden();

  await openDialog();
  await expect(dialog()).toBeVisible();
  await expect(retryButton()).toBeVisible();
  await expect(retryButton()).toBeEnabled();

  fs.writeFileSync(acceptFlagPath, "true", { mode: 0o600 });

  const retryPost = page.waitForResponse(
    (response) =>
      response.url().includes("/host-actions/system-update") &&
      response.request().method() === "POST",
  );
  if (useKeyboard) {
    await retryButton().focus();
    await page.keyboard.press("Enter");
  } else {
    await retryButton().click();
  }
  const retryResponse = await retryPost;
  expect(retryResponse.status()).toBe(202);
  const replacementPayload = await retryResponse.json();
  const replacementJobId = replacementPayload.job.id;
  expect(replacementJobId).not.toBe(priorJobId);
  expect(replacementPayload.job.state).toBe("succeeded");
  await expect(dialog().locator("[data-host-workflow]")).toContainText(
    "continues in nixcfg",
  );
  await expect(retryButton()).toBeHidden();
  const axeAfterHandoff = await new AxeBuilder({ page }).analyze();
  expect(
    axeAfterHandoff.violations.filter(({ impact }) =>
      ["serious", "critical"].includes(impact),
    ),
  ).toEqual([]);
  expect(await readDispatchAttempts()).toBe(attemptsAtStart + 2);
  expect(await readDispatchAccepted()).toBe(acceptedAtStart + 1);

  const replay = await page.request.post("/host-actions/system-update", {
    headers: {
      "X-Pharos-Action": "1",
      "X-Pharos-Acknowledge-Uncertainty": priorJobId,
    },
    data: { host },
  });
  expect(replay.status()).toBe(202);
  const replayPayload = await replay.json();
  expect(replayPayload.job.id).toBe(replacementJobId);
  expect(await readDispatchAttempts()).toBe(attemptsAtStart + 2);
  expect(await readDispatchAccepted()).toBe(acceptedAtStart + 1);

  const priorJob = await page.request.get(
    `/host-actions/jobs/${encodeURIComponent(priorJobId)}`,
  );
  expect(priorJob.ok()).toBe(true);
  const priorPayload = await priorJob.json();
  expect(priorPayload.job.id).toBe(priorJobId);
  expect(priorPayload.job.state).toBe("failed");
  expect(
    priorPayload.job.workflow.events.some((event) =>
      String(event.label).toLowerCase().includes("uncertainty acknowledged"),
    ),
  ).toBe(true);
  expect(priorPayload.job.workflow.evidence).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        label: "Repository dispatch",
        value: "outcome uncertain",
      }),
    ]),
  );

  expect(replacementPayload.job.workflow.status_label).toBe(
    "review handed to nixcfg",
  );
  expect(replacementPayload.job.workflow.evidence).toEqual(
    expect.arrayContaining([
      expect.objectContaining({
        label: "Repository dispatch",
        value: "accepted",
      }),
    ]),
  );
  expect(replacementPayload.workflow_html).toContain(
    "Repository dispatch</dt><dd>accepted</dd>",
  );

  await page.keyboard.press("Escape");
  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
});

test("settings no-run-on-single-field keeps color and host type as drafts", async ({
  page,
}, testInfo) => {
  const host = `settings-draft-field-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, { preferences: { accent: "#224466" } });
  let requestPosts = 0;
  page.on("request", (request) => {
    if (
      request.url().includes("/agora/requests/host-preferences.json") &&
      request.method() === "POST"
    ) {
      requestPosts += 1;
    }
  });

  await page.goto(`/agora?host=${encodeURIComponent(host)}`);
  await page.locator("[data-color]").evaluate((input) => {
    input.value = "#48b8a8";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await expect(page.locator("[data-settings-status]")).toHaveText(
    "Draft only — no request sent.",
  );
  await expect(page.locator("[data-review-settings]")).toBeEnabled();
  let snapshot = await page.request.get("/hosts.json").then((response) => response.json());
  let hostData = snapshot.hosts.find((entry) => entry.name === host);
  expect(hostData.requested_preferences).toBeNull();
  expect(hostData.lifecycle.run_id).toBeNull();
  expect(requestPosts).toBe(0);

  await page.locator("[data-discard-settings]").click();
  await page.locator("[data-advanced]").evaluate((details) => {
    details.open = true;
  });
  await page.locator("[data-host-kind]").selectOption("workstation");
  await expect(page.locator("[data-settings-status]")).toHaveText(
    "Draft only — no request sent.",
  );
  snapshot = await page.request.get("/hosts.json").then((response) => response.json());
  hostData = snapshot.hosts.find((entry) => entry.name === host);
  expect(hostData.requested_preferences).toBeNull();
  expect(hostData.lifecycle.run_id).toBeNull();
  expect(requestPosts).toBe(0);
});

test("settings discard-is-clean closes review without a request", async ({
  page,
}, testInfo) => {
  const host = `settings-draft-discard-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, { preferences: { accent: "#224466" } });
  let requestPosts = 0;
  page.on("request", (request) => {
    if (
      request.url().includes("/agora/requests/host-preferences.json") &&
      request.method() === "POST"
    ) {
      requestPosts += 1;
    }
  });

  await page.goto(`/agora?host=${encodeURIComponent(host)}`);
  await page.locator("[data-color]").evaluate((input) => {
    input.value = "#48b8a8";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await page.locator("[data-review-settings]").click();
  const dialog = page.getByRole("dialog", { name: `Confirm changes for ${host}` });
  await expect(dialog).toBeVisible();
  await dialog.getByRole("button", { name: "Discard draft" }).click();
  await expect(dialog).toBeHidden();
  await expect(page.locator("[data-color]")).toHaveValue("#224466");
  await expect(page.locator("[data-review-settings]")).toBeDisabled();
  const snapshot = await page.request.get("/hosts.json").then((response) => response.json());
  const hostData = snapshot.hosts.find((entry) => entry.name === host);
  expect(hostData.requested_preferences).toBeNull();
  expect(hostData.lifecycle.run_id).toBeNull();
  expect(requestPosts).toBe(0);
});

test("settings confirm-creates-one-run and opens the workflow sheet", async ({
  page,
}, testInfo) => {
  const host = `settings-draft-confirm-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, { preferences: { accent: "#224466" } });
  const settingsResponses = [];
  page.on("response", async (response) => {
    if (
      response.url().includes("/agora/requests/host-preferences.json") &&
      response.request().method() === "POST"
    ) {
      settingsResponses.push(response);
    }
  });

  await page.goto(`/agora?host=${encodeURIComponent(host)}`);
  await page.locator("[data-color]").evaluate((input) => {
    input.value = "#48b8a8";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await page.locator("[data-review-settings]").click();
  const dialog = page.getByRole("dialog", { name: `Confirm changes for ${host}` });
  await expect(dialog).toContainText("Host color: #224466 → #48b8a8");
  await expect(dialog).toContainText(`Pharos pending preferences for ${host}`);
  await expect(dialog).toContainText(
    "Pharos will not close or merge a nixcfg proposal.",
  );
  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/agora/requests/host-preferences.json") &&
      response.request().method() === "POST",
  );
  await dialog.getByRole("button", { name: "Confirm change request" }).click();
  const response = await responsePromise;
  expect(response.ok()).toBe(true);
  const payload = await response.json();
  await expect(page.getByRole("dialog", { name: `Change ${host} settings` })).toBeVisible();
  await expect(page.locator("[data-host-workflow]")).toContainText("Wait for the host");
  expect(settingsResponses).toHaveLength(1);
  const snapshot = await page.request.get("/hosts.json").then((result) => result.json());
  const hostData = snapshot.hosts.find((entry) => entry.name === host);
  expect(hostData.requested_preferences.accent).toBe("#48b8a8");
  expect(hostData.lifecycle.run_id).toBe(payload.job.id);
});

test("legacy settings receipt gap pauses polling and continues through one explicit action", async ({
  page,
}, testInfo) => {
  const host = `settings-legacy-continue-${testInfo.project.name}`;
  const runId = `action-settings-change-${host}-1700000200-1`;
  await reportRuntimeHost(page, host, {
    is_nix: true,
    preferences: { accent: "#224466" },
  });

  const workflowHtml = `
    <section data-host-workflow>
      <div data-ladder-key="requested" data-ladder-state="current">
        Saved settings have no durable repository receipt
      </div>
    </section>`;
  const continuedWorkflowHtml = `
    <section data-host-workflow>
      <button type="button" data-host-action-refresh>Check host now</button>
    </section>`;
  const legacyJob = {
    id: runId,
    host,
    kind: "system_update_proposal",
    state: "proposal_requested",
    updated_at: 1_700_000_201,
    workflow: {
      kind: "settings_change",
      title: `Change ${host} settings`,
      guidance:
        "Pharos has the exact saved settings, but no durable repository receipt. Continuing may resend the same values to the reviewed nixcfg workflow.",
      status_label: "request needs continuation",
      primary_action: { kind: "continue", label: "Continue request" },
      can_cancel: false,
    },
  };
  const continuedJob = {
    ...legacyJob,
    updated_at: 1_700_000_202,
    workflow: {
      ...legacyJob.workflow,
      guidance:
        "The repository handoff is accepted. Finish the nixcfg review, merge, and deployment, then check host evidence.",
      status_label: "change waiting",
      primary_action: { kind: "refresh", label: "Check host now" },
    },
  };
  const jobPath = `/host-actions/jobs/${encodeURIComponent(runId)}`;
  const continuePath = `${jobPath}/continue-settings-dispatch`;
  const jobGets = [];
  const continuationPosts = [];
  await page.route("**/host-actions/jobs/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === "GET" && pathname === jobPath) {
      jobGets.push(pathname);
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({
          job: legacyJob,
          message: "The saved request needs an explicit continuation.",
          workflow_html: workflowHtml,
        }),
      });
      return;
    }
    if (request.method() === "POST" && pathname === continuePath) {
      continuationPosts.push({
        headers: request.headers(),
        body: request.postDataJSON(),
      });
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          job: continuedJob,
          message:
            "The recovered settings were sent to the reviewed nixcfg workflow.",
          workflow_html: continuedWorkflowHtml,
        }),
      });
      return;
    }
    await route.continue();
  });

  await page.goto(`/?host=${encodeURIComponent(host)}&workflow=${encodeURIComponent(runId)}`);
  const dialog = page.getByRole("dialog", { name: `Change ${host} settings` });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-copy]")).toContainText(
    "may resend the same values",
  );
  await expect(dialog.locator("[data-host-action-safe-note]")).toHaveText(
    "Ready to continue the saved request",
  );
  await expect(dialog.locator("[data-host-action-safe-note]")).toHaveAttribute(
    "data-workflow-live",
    "false",
  );
  const continueRequest = dialog.getByRole("button", { name: "Continue request" });
  await expect(continueRequest).toBeVisible();
  expect(jobGets).toHaveLength(1);
  await page.waitForTimeout(2_500);
  expect(jobGets).toHaveLength(1);

  await continueRequest.click();
  await expect.poll(() => continuationPosts.length).toBe(1);
  expect(continuationPosts[0].headers["x-pharos-action"]).toBe("1");
  expect(continuationPosts[0].body).toEqual({});
  await expect(dialog.getByRole("button", { name: "Check host now" })).toBeVisible();
  await expect(continueRequest).toBeHidden();
  await expect(dialog.locator("[data-host-action-status]")).toContainText(
    "sent to the reviewed nixcfg workflow",
  );
});

test("settings sheet live wait advances only from host evidence and stops terminal polling", async ({
  page,
}, testInfo) => {
  test.setTimeout(30_000);
  const manifest = requireFixtureManifest(
    test,
    "settings host-check fixture requires local dispatch manifest",
  );
  if (!manifest) return;
  fs.writeFileSync(manifest.acceptFlagPath, "true", { mode: 0o600 });
  const host = `settings-live-wait-${testInfo.project.name}`;
  const desired = {
    accent: "#48b8a8",
    kind: "server",
    alerts: {
      suppress_down: false,
      suppress_backup: false,
      suppress_nix_freshness: false,
    },
  };
  await reportRuntimeHost(page, host, {
    is_nix: true,
    preferences: { accent: "#224466" },
  });
  const requestedUrls = [];
  page.on("request", (request) => requestedUrls.push(request.url()));

  await page.goto(`/agora?host=${encodeURIComponent(host)}`);
  await page.locator("[data-color]").evaluate((input) => {
    input.value = "#48b8a8";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await page.locator("[data-review-settings]").click();
  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/agora/requests/host-preferences.json") &&
      response.request().method() === "POST",
  );
  await page.getByRole("button", { name: "Confirm change request" }).click();
  const requestPayload = await (await responsePromise).json();
  const runId = requestPayload.job.id;
  const dialog = page.getByRole("dialog", { name: `Change ${host} settings` });
  const exactGuidance = `The repository handoff is accepted, but no matching host report is recorded. Finish the nixcfg review, merge, and deployment first. Then ${host} must report the requested values; Pharos will not mark this run complete without that matching host evidence.`;
  await expect(dialog.locator("[data-host-action-copy]")).toHaveText(exactGuidance);
  await expect(dialog.locator('[data-step-state="waiting"]')).toContainText(
    "The nixcfg review, merge, and deployment must finish first",
  );
  const checkHost = dialog.getByRole("button", { name: "Check host now" });
  await expect(dialog.locator("[data-host-action-refresh]")).toHaveCount(1);
  await expect(dialog.locator("[data-host-action-primary]")).toBeHidden();
  await expect(checkHost).toBeVisible();
  await expect(dialog.locator("[data-host-action-safe-note]")).toHaveAttribute(
    "data-workflow-live",
    "true",
  );
  await expect(dialog.locator('[data-step-state="waiting"]')).toHaveAttribute(
    "data-waiting-for-evidence",
    "true",
  );
  await expect(dialog.locator('[data-step-state="waiting"]')).toHaveAttribute(
    "aria-busy",
    "true",
  );
  await expect(dialog.locator('[data-ladder-key="verified"]')).not.toHaveAttribute(
    "data-ladder-state",
    "complete",
  );

  const jobPath = `/host-actions/jobs/${encodeURIComponent(runId)}`;
  const exactJobRequests = [];
  const manualCheckRequests = [];
  let recordingManualCheck = false;
  page.on("request", (request) => {
    if (recordingManualCheck) {
      manualCheckRequests.push({
        method: request.method(),
        path: new URL(request.url()).pathname,
      });
    }
    if (new URL(request.url()).pathname === jobPath) {
      exactJobRequests.push(request.method());
    }
  });
  const checkResponsePromise = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === jobPath &&
      response.request().method() === "GET",
  );
  recordingManualCheck = true;
  await checkHost.click();
  expect((await checkResponsePromise).ok()).toBe(true);
  recordingManualCheck = false;
  expect(exactJobRequests.length).toBeGreaterThan(0);
  expect(exactJobRequests.every((method) => method === "GET")).toBe(true);
  expect(manualCheckRequests.some((request) => request.path === jobPath)).toBe(true);
  expect(manualCheckRequests.filter((request) => request.method === "POST")).toEqual([]);
  await expect(dialog.locator("[data-host-action-copy]")).toHaveText(exactGuidance);
  await expect(checkHost).toBeEnabled();

  const secondCheckResponsePromise = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === jobPath &&
      response.request().method() === "GET",
  );
  recordingManualCheck = true;
  await checkHost.click();
  expect((await secondCheckResponsePromise).ok()).toBe(true);
  recordingManualCheck = false;
  await expect(checkHost).toBeEnabled();
  expect(manualCheckRequests.filter((request) => request.method === "POST")).toEqual([]);

  const readsAfterManualChecks = exactJobRequests.length;
  await expect
    .poll(() => exactJobRequests.length, { timeout: 3_500 })
    .toBe(readsAfterManualChecks + 1);
  await page.waitForTimeout(500);
  expect(exactJobRequests).toHaveLength(readsAfterManualChecks + 1);

  const resumedResponsePromise = page.waitForResponse(
    (response) =>
      new URL(response.url()).pathname === jobPath &&
      response.request().method() === "GET",
  );
  await page.goto(`/?host=${encodeURIComponent(host)}&workflow=${encodeURIComponent(runId)}`);
  const resumedPayload = await (await resumedResponsePromise).json();
  expect(resumedPayload.job.id).toBe(runId);
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-copy]")).toHaveText(exactGuidance);
  await expect(dialog.getByRole("button", { name: "Check host now" })).toBeVisible();
  await expect(dialog.locator(".host-workflow-meta")).toContainText("Started");

  await reportRuntimeHost(page, host, { is_nix: true, preferences: desired });
  await expect(dialog.locator('[data-ladder-key="executed"]')).toHaveAttribute(
    "data-ladder-state",
    "complete",
    { timeout: 8_000 },
  );
  await expect(dialog.locator('[data-ladder-key="verified"]')).toHaveAttribute(
    "data-ladder-state",
    "complete",
  );
  await expect(dialog.locator("[data-host-action-safe-note]")).toHaveAttribute(
    "data-workflow-live",
    "false",
  );
  await expect(dialog.getByRole("button", { name: "Check host now" })).toBeHidden();
  await expect(dialog.locator("[data-host-action-copy]")).toHaveText(
    "The host reported the requested settings. The saved workflow is complete.",
  );
  await dialog.locator(".host-workflow-advanced summary").click();
  await expect(dialog.locator(".host-workflow-advanced")).toContainText("Last update");
  await expect(dialog.locator(".host-workflow-advanced")).toContainText(
    "Host reported the requested settings",
  );
  const terminalPollCount = requestedUrls.filter((url) => url.includes(jobPath)).length;
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await page.waitForTimeout(2_500);
  expect(requestedUrls.filter((url) => url.includes(jobPath))).toHaveLength(
    terminalPollCount,
  );
  expect(requestedUrls.some((url) => url.includes("fleet.barta.cm"))).toBe(false);
  resetDispatchAcceptFlag(manifest.acceptFlagPath);
});

test("settings dispatch uncertainty stays recoverable after page reload", async ({
  page,
}, testInfo) => {
  test.setTimeout(60_000);
  const manifest = requireFixtureManifest(
    test,
    "settings uncertainty fixture requires local harness manifest",
  );
  if (!manifest) return;
  const { acceptFlagPath } = manifest;
  const settingsUncertainFlagPath = acceptFlagPath.replace(
    /dispatch-accept$/,
    "dispatch-settings-uncertain",
  );
  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
  fs.writeFileSync(settingsUncertainFlagPath, "true", { mode: 0o600 });

  const host = `browser-settings-uncertain-${testInfo.project.name}`;
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v4",
      version: 4,
      name: host,
      role: "server",
      is_nix: true,
      heartbeat_interval_secs: 60,
      freshness: { applicable: true },
    },
  });
  expect(report.status()).toBe(204);

  const preferences = {
    accent: "#48b8a8",
    kind: "server",
    alerts: {
      suppress_down: false,
      suppress_backup: false,
      suppress_nix_freshness: false,
    },
  };
  const uncertain = await page.request.post(
    "/agora/requests/host-preferences.json",
    { data: { host, preferences } },
  );
  expect(uncertain.status()).toBe(409);
  const uncertainPayload = await uncertain.json();
  expect(uncertainPayload.job.workflow.status_label).toBe(
    "dispatch outcome uncertain",
  );
  const uncertainJobId = uncertainPayload.job.id;

  await page.goto(`/agora?host=${encodeURIComponent(host)}`);
  await page.locator("[data-color]").evaluate((input) => {
    input.value = "#d45d5d";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  const review = page.locator("[data-review-settings]");
  await expect(review).toBeEnabled();
  await review.click();
  const confirm = page.getByRole("button", { name: "Confirm change request" });
  await expect(confirm).toBeVisible();
  const activeConflict = page.waitForResponse(
    (response) =>
      response.url().includes("/agora/requests/host-preferences.json") &&
      response.request().method() === "POST",
  );
  await confirm.click();
  const conflictResponse = await activeConflict;
  expect(conflictResponse.status()).toBe(409);
  const conflictPayload = await conflictResponse.json();
  expect(conflictPayload.job.id).toBe(uncertainJobId);
  expect(conflictPayload.workflow_html).toContain("outcome uncertain");

  const dialog = page.getByRole("dialog", {
    name: `Change ${host} settings`,
  });
  const acknowledge = dialog.getByRole("button", {
    name: "I verified nixcfg — allow a new request",
  });
  await expect(dialog).toBeVisible();
  await expect(acknowledge).toBeVisible();
  await expect(acknowledge).toBeEnabled();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();

  await page.goto("/");
  const card = page.locator(`article.card[data-host="${host}"]`);
  await expect(card).toBeVisible();
  const jobPoll = page.waitForResponse(
    (response) =>
      response.url().includes(`/host-actions/jobs/${uncertainJobId}`) &&
      response.request().method() === "GET",
  );
  await card.locator("[data-host-lifecycle-chip]").click();
  await jobPoll;
  await expect(dialog).toBeVisible();
  await expect(acknowledge).toBeVisible();
  await expect(acknowledge).toBeEnabled();

  const acknowledgePost = page.waitForResponse(
    (response) =>
      response.url().includes(
        `/host-actions/jobs/${uncertainJobId}/acknowledge-dispatch-uncertainty`,
      ) && response.request().method() === "POST",
  );
  await acknowledge.click();
  const acknowledgeResponse = await acknowledgePost;
  expect(acknowledgeResponse.status()).toBe(200);
  const acknowledgedPayload = await acknowledgeResponse.json();
  expect(acknowledgedPayload.job.workflow.status_label).toBe(
    "uncertainty acknowledged",
  );
  await expect(acknowledge).toBeHidden();

  fs.writeFileSync(acceptFlagPath, "true", { mode: 0o600 });
  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
});

test("cross-host system update uncertainty recovery posts workflow host", async ({
  page,
}, testInfo) => {
  test.setTimeout(60_000);
  const manifest = requireFixtureManifest(
    test,
    "cross-host uncertainty fixture requires local harness manifest",
  );
  if (!manifest) return;
  const { acceptFlagPath } = manifest;
  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });

  const hostA = `browser-cross-a-${testInfo.project.name}`;
  const hostB = `browser-cross-b-${testInfo.project.name}`;

  for (const host of [hostA, hostB]) {
    const report = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v4",
        version: 4,
        name: host,
        role: "server",
        is_nix: true,
        heartbeat_interval_secs: 60,
        freshness: { applicable: true },
      },
    });
    expect(report.status()).toBe(204);
  }

  const uncertain = await page.request.post("/host-actions/system-update", {
    headers: { "X-Pharos-Action": "1" },
    data: { host: hostA },
  });
  expect(uncertain.status()).toBe(409);
  const uncertainPayload = await uncertain.json();
  const priorJobId = uncertainPayload.job.id;
  expect(uncertainPayload.job.host).toBe(hostA);

  await page.goto("/");
  const cardB = page.locator(`article.card[data-host="${hostB}"]`);
  await expect(cardB).toBeVisible();

  // Model the stale-card race explicitly: B rendered the action before A's
  // uncertain workflow reached the next fleet refresh. The server must return
  // A's persisted conflict and the client must bind all recovery to A.
  await page.evaluate((host) => {
    const card = document.querySelector(`article.card[data-host="${host}"]`);
    const root = card?.querySelector("[data-host-actions]");
    const item = root?.querySelector("[data-host-action='system-update']");
    if (!root || !item) throw new Error("system update action fixture missing");
    item.hidden = false;
    openHostActionDialog("system-update", root, item);
  }, hostB);

  // The accessible name changes from the action prompt to the persisted
  // workflow title after the 409 payload is rendered, so anchor on the stable
  // dialog element across that transition.
  const dialog = page.locator("[data-host-action-dialog]");
  await expect(dialog).toBeVisible();

  const createReview = dialog.getByRole("button", {
    name: "Create update review",
  });
  await expect(createReview).toBeVisible();
  const conflictPost = page.waitForResponse(
    (response) =>
      response.url().includes("/host-actions/system-update") &&
      response.request().method() === "POST",
  );
  await createReview.click();
  const conflictResponse = await conflictPost;
  expect(conflictResponse.status()).toBe(409);
  const conflictPayload = await conflictResponse.json();
  expect(conflictPayload.job.host).toBe(hostA);

  const retryButton = dialog.getByRole("button", {
    name: "I verified nixcfg — request again",
  });
  await expect(retryButton).toBeVisible();
  await expect(retryButton).toBeEnabled();

  fs.writeFileSync(acceptFlagPath, "true", { mode: 0o600 });

  const retryPost = page.waitForRequest(
    (request) =>
      request.url().includes("/host-actions/system-update") &&
      request.method() === "POST",
  );
  const retryResponsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/host-actions/system-update") &&
      response.request().method() === "POST" &&
      response !== conflictResponse,
  );
  await retryButton.click();
  const retryRequest = await retryPost;
  const retryBody = JSON.parse(retryRequest.postData() || "{}");
  expect(retryBody.host).toBe(hostA);
  expect(retryRequest.headers()["x-pharos-acknowledge-uncertainty"]).toBe(
    priorJobId,
  );

  const retryResponse = await retryResponsePromise;
  expect(retryResponse.status()).toBe(202);
  const retryPayload = await retryResponse.json();
  expect(retryPayload.job.host).toBe(hostA);
  expect(retryPayload.job.id).not.toBe(priorJobId);

  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
});

test("preference drift host_report resolver uses blocked_by without active run", async ({
  page,
}) => {
  const host = "bl-prefs-host-report-drift";
  await reportRuntimeHost(page, host, { preferences: { accent: "#111111" } });
  await page.goto("/");

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const entry = payload.hosts.find((row) => row.name === host);
  expect(entry).toBeTruthy();
  entry.preferences_state = "request_pending";
  entry.requested_preferences = {
    accent: "#48b8a8",
    kind: "server",
    alerts: {
      suppress_down: false,
      suppress_backup: false,
      suppress_nix_freshness: false,
    },
  };
  entry.lifecycle = {
    schema: "inspr.pharos.host-lifecycle.v1",
    version: 1,
    slot: "prefs_drift",
    label: "Change requested",
    level: "warning",
    invoke: "host_settings",
    run_id: null,
    detail: "Requested preferences have not yet been observed by the host.",
    blocked_by: ["host_report"],
  };
  expect(await page.evaluate((body) => applyFleetSnapshot(body), payload)).toBe(true);

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toHaveCount(1);
  await expect(chip).toHaveAttribute("data-lifecycle-slot", "prefs_drift");
  await expect(chip).toHaveAttribute("data-lifecycle-blocked-by", "host_report");
  await expect(chip.locator("[data-host-lifecycle-chip-copy]")).toHaveText(
    "Change requested",
  );
  await expect(chip).toHaveAttribute(
    "data-lifecycle-declared-summary",
    "accent #48b8a8",
  );
  await expect(chip).toHaveAttribute("data-lifecycle-observed-summary", "accent #111111");

  expect(await page.evaluate((body) => applyFleetSnapshot(body), payload)).toBe(true);
  await expect(chip).toHaveAttribute(
    "data-lifecycle-declared-summary",
    "accent #48b8a8",
  );
  await expect(chip).toHaveAttribute("data-lifecycle-observed-summary", "accent #111111");

  const jobPolls = [];
  page.on("request", (request) => {
    if (
      request.url().includes("/host-actions/jobs/") &&
      request.method() === "GET"
    ) {
      jobPolls.push(request.url());
    }
  });
  await chip.click();
  expect(jobPolls).toHaveLength(0);

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-workflow]")).toBeHidden();
  await expect(dialog.locator("[data-host-action-info-title]")).toContainText(
    "Resolved when the host reports",
  );
  await expect(dialog.locator("[data-host-action-fact='declared']")).toContainText(
    "#48b8a8",
  );
  await expect(dialog.locator("[data-host-action-fact='observed']")).toContainText(
    "#111111",
  );
  await dialog.getByRole("button", { name: "Close", exact: true }).click();

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("settings run offers one-click guarded apply for a loaded declaration", async ({
  page,
}) => {
  const manifest = requireFixtureManifest(
    test,
    "loaded declaration settings run requires local dispatch fixture",
  );
  if (!manifest) return;
  fs.writeFileSync(manifest.acceptFlagPath, "true", { mode: 0o600 });

  const host = "bl-prefs-declared-drift";
  const desired = {
    accent: "#48b8a8",
    kind: "server",
    alerts: {
      suppress_down: false,
      suppress_backup: false,
      suppress_nix_freshness: false,
    },
  };
  await reportRuntimeHost(page, host, {
    is_nix: true,
    preferences: { accent: "#111111" },
  });
  const response = await page.request.post(
    "/agora/requests/host-preferences.json",
    { data: { host, preferences: desired } },
  );
  expect(response.ok()).toBe(true);
  const requested = await response.json();

  await page.goto(
    `/?host=${encodeURIComponent(host)}&workflow=${encodeURIComponent(requested.job.id)}`,
  );
  const dialog = page.getByRole("dialog", { name: `Change ${host} settings` });
  await expect(dialog).toBeVisible();
  await expect(dialog.locator('[data-ladder-key="declared"]')).toHaveAttribute(
    "data-ladder-state",
    "complete",
  );
  await expect(dialog.locator('[data-ladder-key="executed"]')).not.toHaveAttribute(
    "data-ladder-state",
    "complete",
  );
  await expect(dialog.locator("[data-host-action-copy]")).toContainText(
    `Apply it on ${host}`,
  );
  await expect(
    dialog.getByRole("button", { name: `Apply on ${host}`, exact: true }),
  ).toBeEnabled();
  await dialog.locator(".host-workflow-advanced summary").click();
  await expect(dialog.locator(".host-workflow-advanced")).toContainText(
    "Repository request",
  );

  await reportRuntimeHost(page, host, { is_nix: true, preferences: desired });
  await page.evaluate(() => window.dispatchEvent(new Event("focus")));
  await expect(dialog.locator('[data-ladder-key="verified"]')).toHaveAttribute(
    "data-ladder-state",
    "complete",
    { timeout: 8_000 },
  );
  resetDispatchAcceptFlag(manifest.acceptFlagPath);
});

test("settings guarded apply retains its parent run through linked confirmation and exact host evidence", async ({
  page,
}, testInfo) => {
  const host = `settings-linked-apply-${testInfo.project.name}`;
  const parentId = `action-settings-change-${host}-1700000400-1`;
  const childId = `action-update-restart-${host}-1700000401-1`;
  const desired = {
    accent: "#48b8a8",
    kind: "server",
    alerts: {
      suppress_down: false,
      suppress_backup: false,
      suppress_nix_freshness: false,
    },
  };
  await reportRuntimeHost(page, host, {
    is_nix: true,
    preferences: { ...desired, accent: "#111111" },
  });

  const workflowHtml = ({ applyState = "action_required", verified = false } = {}) => `
    <section data-host-workflow>
      <div data-ladder-key="requested" data-ladder-state="complete">Requested</div>
      <div data-ladder-key="declared" data-ladder-state="complete">Declared</div>
      <div data-ladder-key="executed" data-ladder-state="${verified ? "complete" : applyState}">Executed</div>
      <div data-ladder-key="verified" data-ladder-state="${verified ? "complete" : "queued"}">Verified</div>
      ${applyState === "waiting" ? '<button type="button" data-host-action-refresh>Check host now</button>' : ""}
    </section>`;
  const parentJob = ({
    state = "proposal_requested",
    updatedAt,
    linkedState = null,
    linkedUpdatedAt = null,
    primaryAction = null,
    guidance,
  }) => ({
    id: parentId,
    host,
    kind: "system_update_proposal",
    state,
    updated_at: updatedAt,
    workflow: {
      kind: "settings_change",
      title: `Change ${host} settings`,
      guidance,
      status_label: state === "succeeded" ? "change complete" : "change waiting",
      primary_action: primaryAction,
      can_cancel: false,
      linked_run_id: linkedState ? childId : null,
      linked_run_state: linkedState,
      linked_run_updated_at: linkedUpdatedAt,
    },
  });
  const readyJob = parentJob({
    updatedAt: 1_700_000_400,
    primaryAction: { kind: "apply_declared", label: `Apply on ${host}` },
    guidance: `The accepted nixcfg declaration is ready. Apply it on ${host} through the guarded workflow.`,
  });
  const confirmationJob = parentJob({
    updatedAt: 1_700_000_400,
    linkedState: "awaiting_confirmation",
    linkedUpdatedAt: 1_700_000_402,
    primaryAction: {
      kind: "confirm",
      label: `Confirm apply on ${host}`,
      target_run_id: childId,
    },
    guidance: `The guarded plan is ready. Confirm the attended apply for ${host}.`,
  });
  const waitingForEvidenceJob = parentJob({
    updatedAt: 1_700_000_400,
    linkedState: "succeeded",
    linkedUpdatedAt: 1_700_000_403,
    primaryAction: { kind: "refresh", label: "Check host now" },
    guidance: `The guarded deployment completed on ${host}, but this request is not complete until the host reports the exact requested values.`,
  });
  const completedJob = parentJob({
    state: "succeeded",
    updatedAt: 1_700_000_404,
    linkedState: "succeeded",
    linkedUpdatedAt: 1_700_000_403,
    guidance: "The host reported the requested settings. The saved workflow is complete.",
  });
  const childJob = {
    id: childId,
    host,
    kind: "update_restart",
    intent: "apply_declared",
    state: "queued_apply",
    updated_at: 1_700_000_403,
    settings_change_id: parentId,
    workflow: {
      kind: "update_restart",
      title: `Apply declared configuration to ${host}`,
      guidance: "Attended confirmation recorded.",
      status_label: "confirmed",
      primary_action: null,
      can_cancel: false,
    },
  };

  let phase = "ready";
  const parentGets = [];
  const applyPosts = [];
  const confirmPosts = [];
  const parentPath = `/host-actions/jobs/${encodeURIComponent(parentId)}`;
  const applyPath = `${parentPath}/apply-declared`;
  const confirmPath = `/host-actions/jobs/${encodeURIComponent(childId)}/confirm`;
  await page.route("**/host-actions/jobs/**", async (route) => {
    const request = route.request();
    const pathname = new URL(request.url()).pathname;
    if (request.method() === "GET" && pathname === parentPath) {
      parentGets.push(pathname);
      const [job, html] = phase === "complete"
        ? [completedJob, workflowHtml({ applyState: "complete", verified: true })]
        : phase === "waiting_for_evidence"
          ? [waitingForEvidenceJob, workflowHtml({ applyState: "waiting" })]
          : [readyJob, workflowHtml()];
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify({ job, message: job.workflow.guidance, workflow_html: html }),
      });
      return;
    }
    if (request.method() === "POST" && pathname === applyPath) {
      applyPosts.push({ headers: request.headers(), body: request.postDataJSON() });
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          job: confirmationJob,
          message: confirmationJob.workflow.guidance,
          workflow_html: workflowHtml(),
        }),
      });
      return;
    }
    if (request.method() === "POST" && pathname === confirmPath) {
      confirmPosts.push({ headers: request.headers(), body: request.postDataJSON() });
      phase = "waiting_for_evidence";
      await route.fulfill({
        status: 202,
        contentType: "application/json",
        body: JSON.stringify({
          job: childJob,
          message: "Attended confirmation recorded.",
          workflow_html: "<section data-host-workflow>Confirmed child run</section>",
        }),
      });
      return;
    }
    await route.continue();
  });

  await page.goto(
    `/?host=${encodeURIComponent(host)}&workflow=${encodeURIComponent(parentId)}`,
  );
  const dialog = page.getByRole("dialog", { name: `Change ${host} settings` });
  const hostActions = page
    .locator(`[data-host="${host}"][data-host-surface="runtime"]`)
    .first()
    .locator("[data-host-actions]");
  await expect(dialog).toBeVisible();
  await expect(hostActions).toHaveAttribute("data-action-job-id", parentId);

  const apply = dialog.getByRole("button", { name: `Apply on ${host}`, exact: true });
  await expect(apply).toBeEnabled();
  await apply.click();
  await expect.poll(() => applyPosts.length).toBe(1);
  expect(applyPosts[0].headers["x-pharos-action"]).toBe("1");
  expect(applyPosts[0].body).toEqual({});
  await expect(hostActions).toHaveAttribute("data-action-job-id", parentId);

  const confirm = dialog.getByRole("button", {
    name: `Confirm apply on ${host}`,
    exact: true,
  });
  const confirmationInput = dialog.locator("[data-host-remove-input]");
  const attended = dialog.locator("[data-host-attended-input]");
  await expect(confirm).toBeDisabled();
  await confirmationInput.fill(host);
  await expect(confirm).toBeDisabled();
  await attended.check();
  await expect(confirm).toBeEnabled();
  await confirm.click();

  await expect.poll(() => confirmPosts.length).toBe(1);
  expect(confirmPosts[0].headers["x-pharos-action"]).toBe("1");
  expect(confirmPosts[0].body).toEqual({ confirmation: host, attended: true });
  await expect(hostActions).toHaveAttribute("data-action-job-id", parentId);
  await expect(dialog.locator("[data-host-action-copy]")).toContainText(
    "not complete until the host reports the exact requested values",
  );
  await expect(dialog.locator('[data-ladder-key="verified"]')).not.toHaveAttribute(
    "data-ladder-state",
    "complete",
  );
  expect(applyPosts).toHaveLength(1);
  expect(parentGets.length).toBeGreaterThanOrEqual(2);

  await reportRuntimeHost(page, host, { is_nix: true, preferences: desired });
  phase = "complete";
  await dialog.getByRole("button", { name: "Check host now", exact: true }).click();
  await expect(dialog.locator('[data-ladder-key="verified"]')).toHaveAttribute(
    "data-ladder-state",
    "complete",
  );
  await expect(dialog.locator("[data-host-action-copy]")).toHaveText(
    "The host reported the requested settings. The saved workflow is complete.",
  );
  await expect(hostActions).toHaveAttribute("data-action-job-id", parentId);
  expect(applyPosts).toHaveLength(1);
});

test("Agora keeps guarded settings apply read-only without fleet operator access", async ({
  page,
}, testInfo) => {
  const host = `settings-viewer-apply-${testInfo.project.name}`;
  const parentId = `action-settings-change-${host}-1700000450-1`;
  await reportRuntimeHost(page, host, {
    is_nix: true,
    preferences: { accent: "#111111" },
  });
  const applyPosts = [];
  await page.route("**/agora/requests/host-preferences.json", async (route) => {
    if (route.request().method() !== "POST") return route.continue();
    await route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        status: "requested",
        job: {
          id: parentId,
          host,
          kind: "system_update_proposal",
          state: "proposal_requested",
          updated_at: 1_700_000_451,
          workflow: {
            kind: "settings_change",
            title: `Change ${host} settings`,
            guidance: `The declaration is ready for guarded apply on ${host}.`,
            status_label: "ready to apply",
            primary_action: { kind: "apply_declared", label: `Apply on ${host}` },
            can_cancel: false,
          },
        },
        message: "The declaration is ready.",
        workflow_html: "<section data-host-workflow>Ready for guarded apply</section>",
      }),
    });
  });
  await page.route("**/host-actions/jobs/*/apply-declared", async (route) => {
    applyPosts.push(route.request().url());
    await route.fulfill({ status: 403, contentType: "application/json", body: '{"error":"forbidden"}' });
  });

  await page.goto(`/agora?host=${encodeURIComponent(host)}`);
  await page.locator(".settings-main").evaluate((main) => {
    main.dataset.canManageFleet = "false";
  });
  await page.locator("[data-color]").evaluate((input) => {
    input.value = "#48b8a8";
    input.dispatchEvent(new Event("input", { bubbles: true }));
  });
  await page.locator("[data-review-settings]").click();
  await page.getByRole("button", { name: "Confirm change request" }).click();

  const dialog = page.getByRole("dialog", { name: `Change ${host} settings` });
  const apply = dialog.getByRole("button", { name: `Apply on ${host}`, exact: true });
  await expect(page.locator(".settings-main")).toHaveAttribute(
    "data-can-manage-fleet",
    "false",
  );
  await expect(apply).toBeVisible();
  await expect(apply).toBeDisabled();
  await expect(dialog.locator("[data-host-action-safe-note]")).toContainText(
    "Fleet operator access is required",
  );
  await apply.evaluate((button) => button.click());
  expect(applyPosts).toHaveLength(0);
});

test("preference drift declared_not_applied sheet resolves in host settings", async ({
  page,
}) => {
  const host = "bl-prefs-declared-drift";
  await reportRuntimeHost(page, host, { preferences: { accent: "#111111" } });
  await page.goto("/");

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toHaveCount(1);
  await expect(chip).toHaveAttribute("data-lifecycle-slot", "prefs_drift");
  await expect(chip).toHaveAttribute(
    "data-lifecycle-declared-summary",
    "accent #48b8a8",
  );
  await expect(chip).toHaveAttribute("data-lifecycle-observed-summary", "accent #111111");
  await expect(chip.locator("[data-host-lifecycle-chip-copy]")).toHaveText(
    "Ready to apply",
  );
  await expect(chip).toHaveAttribute("data-lifecycle-level", "info");

  expect(await applyServerFleetSnapshot(page)).toBe(true);
  await expect(chip).toHaveAttribute(
    "data-lifecycle-declared-summary",
    "accent #48b8a8",
  );
  await expect(chip).toHaveAttribute("data-lifecycle-observed-summary", "accent #111111");
  const cardInfoColor = await card.evaluate((surface) =>
    getComputedStyle(surface.querySelector(".host-lifecycle-chip")).color,
  );
  await page.locator("[data-view-button='list']").click();
  await expect(page.locator("main")).toHaveAttribute("data-view", "list");
  const row = page.locator(`tr[data-host="${host}"][data-host-surface="runtime"]`).first();
  await expect(row.locator("[data-host-lifecycle-chip]")).toHaveAttribute(
    "data-lifecycle-level",
    "info",
  );
  const listInfoColor = await row.evaluate((surface) =>
    getComputedStyle(surface.querySelector(".host-lifecycle-chip")).color,
  );
  expect(cardInfoColor).toBe(listInfoColor);
  expect(cardInfoColor).toBe("rgb(23, 106, 152)");
  await page.locator("[data-view-button='grid']").click();

  await chip.click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-info-title]")).toContainText(
    "Resolved in host settings",
  );
  await expect(dialog.locator("[data-host-action-fact='declared']")).toContainText(
    "#48b8a8",
  );
  await expect(dialog.locator("[data-host-action-fact='observed']")).toContainText(
    "#111111",
  );
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
});

test("ready-to-apply lifecycle starts one typed guarded run from the drift sheet", async ({
  page,
}) => {
  const host = "bl-declared-apply";
  await reportRuntimeHost(page, host, { preferences: { accent: "#111111" } });
  await page.goto("/");

  const response = await page.request.get("/hosts.json");
  const payload = await response.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData).toBeTruthy();
  hostData.preferences_state = "declared_not_applied";
  hostData.declared_preferences = { accent: "#48b8a8" };
  hostData.lifecycle = {
    schema: "inspr.pharos.host-lifecycle.v1",
    version: 1,
    slot: "prefs_drift",
    label: "Ready to apply",
    level: "info",
    invoke: "update_restart",
    run_id: null,
    update_restart_intent: "apply_declared",
    detail:
      "Declared preferences differ from the host. Start a guarded apply with the normal backup and confirmation gates.",
    blocked_by: [],
  };
  expect(await page.evaluate((body) => applyFleetSnapshot(body), payload)).toBe(true);

  let submitted = null;
  await page.route(`**/host-actions/${host}/update-restart/review`, async (route) => {
    submitted = route.request().postDataJSON();
    await route.fulfill({
      status: 202,
      contentType: "application/json",
      body: JSON.stringify({
        message: "Declared apply review queued.",
        workflow_html: '<p data-test-declared-apply-run>Saved guarded run</p>',
        job: {
          id: "action-update-restart-bl-declared-apply-1",
          host,
          kind: "update_restart",
          intent: "apply_declared",
          state: "queued_review",
          updated_at: 1,
          workflow: {
            kind: "update_restart",
            title: `Apply declared configuration to ${host}`,
            guidance: "The request is saved. No live change has started.",
            status_label: "review queued",
            primary_action: null,
            can_cancel: true,
          },
        },
      }),
    });
  });

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toHaveAttribute("data-lifecycle-invoke", "update_restart");
  await expect(chip).toHaveAttribute(
    "data-lifecycle-update-restart-intent",
    "apply_declared",
  );
  await chip.click();

  const dialog = page.getByRole("dialog");
  const primary = dialog.locator("[data-host-action-primary]");
  await expect(primary).toHaveText("Prepare guarded apply");
  await expect(primary).toBeVisible();
  await primary.click();

  expect(submitted).toEqual({ intent: "apply_declared" });
  await expect(dialog.locator("[data-host-workflow]")).toBeVisible();
  await expect(dialog.locator("[data-test-declared-apply-run]")).toHaveText(
    "Saved guarded run",
  );
  await expect(dialog.locator("[data-host-action-title]")).toHaveText(
    `Apply declared configuration to ${host}`,
  );
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await page.unroute(`**/host-actions/${host}/update-restart/review`);

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("quiet lifecycle chip opens sheet without job polling or workflow steps", async ({
  page,
}) => {
  const host = "bl-quiet-lifecycle-sheet";
  await reportRuntimeHost(page, host, { preferences: { accent: "#224466" } });
  await page.goto("/");

  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  const chip = card.locator("[data-host-lifecycle-chip]");
  await expect(chip).toHaveCount(1);
  await expect(chip).toHaveAttribute("data-lifecycle-slot", "quiet");

  const jobPolls = [];
  page.on("request", (request) => {
    if (
      request.url().includes("/host-actions/jobs/") &&
      request.method() === "GET"
    ) {
      jobPolls.push(request.url());
    }
  });
  await chip.click();
  expect(jobPolls).toHaveLength(0);

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-workflow]")).toBeHidden();
  await expect(dialog.locator("[data-host-action-info-title]")).toContainText("No drift");
  await dialog.getByRole("button", { name: "Close", exact: true }).click();

  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("lifecycle continue menu opens saved run at lifecycle.run_id", async ({
  page,
}, testInfo) => {
  const manifest = requireFixtureManifest(
    test,
    "lifecycle continue fixture requires local harness manifest",
  );
  if (!manifest) return;
  const { acceptFlagPath } = manifest;
  const settingsUncertainFlagPath = acceptFlagPath.replace(
    /dispatch-accept$/,
    "dispatch-settings-uncertain",
  );
  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
  fs.writeFileSync(settingsUncertainFlagPath, "true", { mode: 0o600 });

  const host = `bl-lifecycle-continue-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, { is_nix: true });
  const uncertain = await page.request.post("/agora/requests/host-preferences.json", {
    data: {
      host,
      preferences: {
        accent: "#48b8a8",
        kind: "server",
        alerts: {
          suppress_down: false,
          suppress_backup: false,
          suppress_nix_freshness: false,
        },
      },
    },
  });
  expect(uncertain.status()).toBe(409);
  const uncertainPayload = await uncertain.json();
  const lifecycleRunId = uncertainPayload.job.id;

  fs.writeFileSync(acceptFlagPath, "true", { mode: 0o600 });
  const proposal = await page.request.post("/host-actions/system-update", {
    headers: { "x-pharos-action": "1" },
    data: { host },
  });
  expect(proposal.status()).toBe(202);

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData?.lifecycle?.run_id).toBe(lifecycleRunId);
  expect(hostData?.host_action?.id).toBeTruthy();
  expect(hostData.lifecycle.run_id).not.toBe(hostData.host_action.id);
  expect(hostData?.lifecycle?.primary_action?.label).toBe(
    "I verified nixcfg — allow a new request",
  );

  await page.goto("/");
  const card = page.locator(`[data-host="${host}"][data-host-surface="runtime"].card`).first();
  await card.scrollIntoViewIfNeeded();
  const continueBtn = card
    .locator("[data-host-actions]")
    .first()
    .locator("[data-host-action='lifecycle-continue']");
  expect(await applyServerFleetSnapshot(page)).toBe(true);
  await card.locator("[data-host-actions-trigger]").click();
  await expect(card.locator("[data-host-actions-menu]:not([hidden])")).toBeVisible();
  await expect(continueBtn).toBeVisible();
  await expect(continueBtn).toContainText(
    "Continue: I verified nixcfg — allow a new request",
  );
  await expect(continueBtn).toHaveAttribute(
    "data-lifecycle-run-id",
    lifecycleRunId,
  );

  const pollResponsePromise = page.waitForResponse(
    (response) =>
      response
        .url()
        .includes(`/host-actions/jobs/${encodeURIComponent(lifecycleRunId)}`) &&
      response.request().method() === "GET",
  );
  await page.evaluate((hostName) => {
    const surface = document.querySelector(
      `article.card[data-host="${hostName}"][data-host-surface="runtime"]`,
    );
    const root = surface?.querySelector("[data-host-actions]");
    if (!root) throw new Error("missing host actions root");
    openHostActions(root);
    const btn = root.querySelector("[data-host-action='lifecycle-continue']");
    if (!btn || btn.hidden) throw new Error("lifecycle continue menu item hidden");
    btn.click();
  }, host);
  const pollResponse = await pollResponsePromise;
  expect(pollResponse.ok()).toBe(true);
  const pollPayload = await pollResponse.json();
  expect(pollPayload.job.id).toBe(lifecycleRunId);
  expect(pollPayload.job.id).not.toBe(hostData.host_action.id);

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(page).toHaveURL("/");
  await expect(dialog.locator("[data-host-workflow]")).not.toBeEmpty();
  await expect(
    dialog.getByRole("button", { name: "I verified nixcfg — allow a new request" }),
  ).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();

  const failedHost = `bl-lifecycle-continue-hidden-${testInfo.project.name}`;
  await reportRuntimeHost(page, failedHost, { is_nix: true });
  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
  fs.writeFileSync(settingsUncertainFlagPath, "false", { mode: 0o600 });
  const failed = await page.request.post("/agora/requests/host-preferences.json", {
    data: { host: failedHost, preferences: { accent: "#9868d0" } },
  });
  expect(failed.status()).toBe(409);
  const failedPayload = await failed.json();
  const failedRunId = failedPayload.job.id;

  await page.goto("/");
  const failedCard = page
    .locator(`[data-host="${failedHost}"][data-host-surface="runtime"].card`)
    .first();
  const failedContinue = failedCard
    .locator("[data-host-actions]")
    .first()
    .locator("[data-host-action='lifecycle-continue']");

  const hiddenPayload = await page.request.get("/hosts.json").then((r) => r.json());
  const hiddenEntry = hiddenPayload.hosts.find((entry) => entry.name === failedHost);
  delete hiddenEntry.lifecycle.primary_action;
  expect(await page.evaluate((body) => applyFleetSnapshot(body), hiddenPayload)).toBe(
    true,
  );
  await failedCard.locator("[data-host-actions-trigger]").click();
  await expect(failedContinue).toBeHidden();
  await page.keyboard.press("Escape");

  const visiblePayload = await page.request.get("/hosts.json").then((r) => r.json());
  const visibleEntry = visiblePayload.hosts.find((entry) => entry.name === failedHost);
  visibleEntry.lifecycle.primary_action = {
    kind: "recover",
    label: "Run recovery checks",
  };
  expect(await page.evaluate((body) => applyFleetSnapshot(body), visiblePayload)).toBe(
    true,
  );
  await failedCard.locator("[data-host-actions-trigger]").click();
  await expect(failedContinue).toBeVisible();
  await expect(failedContinue).toContainText("Continue: Run recovery checks");
  await expect(failedContinue).toHaveAttribute("data-lifecycle-run-id", failedRunId);

  fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });
  fs.writeFileSync(settingsUncertainFlagPath, "false", { mode: 0o600 });
  const removal = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(removal.status()).toBe(202);
  const reonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(reonboard.ok()).toBe(true);
});

test("activity workflow query polls the requested job id", async ({ page }, testInfo) => {
  const manifest = requireFixtureManifest(
    test,
    "activity workflow fixture requires local harness manifest",
  );
  if (!manifest) return;
  fs.writeFileSync(manifest.acceptFlagPath, "false", { mode: 0o600 });

  const host = `bl-activity-workflow-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, { is_nix: true });
  const settings = await page.request.post("/agora/requests/host-preferences.json", {
    data: { host, preferences: { accent: "#48b8a8" } },
  });
  expect(settings.status()).toBe(409);
  const requestedJobId = (await settings.json()).job.id;
  expect(requestedJobId).toMatch(/^[A-Za-z0-9_-]{8,128}$/);

  fs.writeFileSync(manifest.acceptFlagPath, "true", { mode: 0o600 });
  const proposal = await page.request.post("/host-actions/system-update", {
    headers: { "x-pharos-action": "1" },
    data: { host },
  });
  expect(proposal.status()).toBe(202);

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData?.lifecycle?.run_id).toBe(requestedJobId);
  expect(hostData?.host_action?.id).toBeTruthy();
  expect(hostData.lifecycle.run_id).not.toBe(hostData.host_action.id);
  const legacyJobId = hostData.host_action.id;

  const jobGets = [];
  page.on("request", (request) => {
    if (
      request.url().includes("/host-actions/jobs/") &&
      request.method() === "GET"
    ) {
      jobGets.push(request.url());
    }
  });
  const pollResponsePromise = page.waitForResponse(
    (response) =>
      response
        .url()
        .includes(`/host-actions/jobs/${encodeURIComponent(requestedJobId)}`) &&
      response.request().method() === "GET",
  );
  await page.goto(`/?host=${host}&workflow=${encodeURIComponent(requestedJobId)}`);
  const pollResponse = await pollResponsePromise;
  expect(pollResponse.ok()).toBe(true);
  const pollPayload = await pollResponse.json();
  expect(pollPayload.job.id).toBe(requestedJobId);
  expect(pollPayload.job.id).not.toBe(legacyJobId);
  expect(
    jobGets.some((url) =>
      url.includes(`/host-actions/jobs/${encodeURIComponent(legacyJobId)}`),
    ),
  ).toBe(false);

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-workflow]")).not.toBeEmpty();
  await expect(dialog.locator("[data-host-action-copy]")).not.toHaveText(
    "Loading the saved execution checklist...",
  );
  await expect(page).toHaveURL(new RegExp(`[?&]host=${host}`));
  await expect(page).not.toHaveURL(/\/agora/);

  fs.writeFileSync(manifest.acceptFlagPath, "false", { mode: 0o600 });
  const cleanup = await page.request.post(`/host-actions/${host}/remove`, {
    headers: { "x-pharos-action": "1" },
    data: { confirmation: host, disposition: "unmanaged", successor: null },
  });
  expect(cleanup.status()).toBe(202);
  const cleanupReonboard = await page.request.post(
    `/host-actions/${host}/allow-reonboarding`,
    { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
  );
  expect(cleanupReonboard.ok()).toBe(true);
});

test("settings run shows five-state truth and withdraw clears only the Pharos request", async ({
  page,
}, testInfo) => {
  const manifest = requireFixtureManifest(
    test,
    "settings withdrawal requires local dispatch fixture",
  );
  if (!manifest) return;
  fs.writeFileSync(manifest.acceptFlagPath, "true", { mode: 0o600 });

  const host = `bl-settings-withdraw-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, {
    is_nix: true,
    preferences: { accent: "#224466" },
  });
  const request = await page.request.post(
    "/agora/requests/host-preferences.json",
    { data: { host, preferences: { accent: "#48b8a8" } } },
  );
  expect(request.ok()).toBe(true);
  const requested = await request.json();
  const runId = requested.job.id;

  await page.goto("/");
  const card = page
    .locator(`[data-host="${host}"][data-host-surface="runtime"].card`)
    .first();
  await card.locator("[data-host-lifecycle-chip]").click();
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  const ladder = dialog.locator(".host-workflow-ladder li");
  await expect(ladder).toHaveCount(5);
  await expect(ladder.locator("strong")).toHaveText([
    "Observed",
    "Declared",
    "Requested",
    "Executed",
    "Verified",
  ]);
  await expect(dialog.locator(".host-workflow-next")).toContainText("Next");
  await expect(dialog.locator(".host-workflow-next")).toContainText("Where");
  await expect(dialog.locator(".host-workflow-next")).toContainText("Will not");
  await expect(dialog.locator("[data-host-action-cancel]")).toBeHidden();

  let withdrawPosts = 0;
  let withdrawalResponseSeen = false;
  let staleWithdrawalJobGets = 0;
  page.on("request", (outgoing) => {
    if (
      outgoing.url().includes(`/host-actions/jobs/${encodeURIComponent(runId)}/withdraw`) &&
      outgoing.method() === "POST"
    ) {
      withdrawPosts += 1;
    }
    if (
      outgoing.url().includes(`/host-actions/jobs/${encodeURIComponent(runId)}`) &&
      outgoing.method() === "GET" &&
      !withdrawalResponseSeen
    ) {
      staleWithdrawalJobGets += 1;
    }
  });
  page.on("response", (incoming) => {
    if (
      incoming.url().includes(`/host-actions/jobs/${encodeURIComponent(runId)}/withdraw`) &&
      incoming.request().method() === "POST"
    ) {
      withdrawalResponseSeen = true;
    }
  });
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();
  expect(withdrawPosts).toBe(0);

  const stableSnapshotResponse = await page.request.get("/hosts.json");
  expect(stableSnapshotResponse.ok()).toBe(true);
  const stableSnapshot = await stableSnapshotResponse.json();
  const pointerReorderedSnapshot = structuredClone(stableSnapshot);
  const pointerReorderedHost = pointerReorderedSnapshot.hosts.find(
    (entry) => entry.name === host,
  );
  expect(pointerReorderedHost).toBeTruthy();
  pointerReorderedHost.attention = {
    ...(pointerReorderedHost.attention ?? {}),
    label: pointerReorderedHost.attention?.label ?? "settings change waiting",
    level: pointerReorderedHost.attention?.level ?? "warn",
    rank: -1,
  };
  const actionsTrigger = card.locator("[data-host-actions-trigger]");
  await actionsTrigger.hover();
  await page.mouse.down();
  const stableRefreshMoves = await card.evaluate((surface, snapshot) => {
    const grid = surface.parentElement;
    if (!grid) return -1;
    const observer = new MutationObserver(() => {});
    observer.observe(grid, { childList: true });
    window.applyFleetSnapshot(snapshot);
    const moves = observer
      .takeRecords()
      .filter(
        (record) =>
          [...record.addedNodes, ...record.removedNodes].includes(surface),
      ).length;
    observer.disconnect();
    return moves;
  }, pointerReorderedSnapshot);
  expect(stableRefreshMoves).toBe(0);
  await page.mouse.up();

  const withdraw = card.locator('[data-host-action="withdraw-settings"]');
  await expect(withdraw).toBeVisible();
  await page.keyboard.press("Escape");
  await expect(withdraw).toBeHidden();
  await expect(actionsTrigger).toBeFocused();
  await expect(
    page.locator('[data-grid] > .card[data-host-surface="runtime"]').first(),
  ).toHaveAttribute("data-host", host);

  const blurResetSnapshot = structuredClone(stableSnapshot);
  const blurResetHost = blurResetSnapshot.hosts.find(
    (entry) => entry.name === host,
  );
  expect(blurResetHost).toBeTruthy();
  blurResetHost.attention = {
    ...(blurResetHost.attention ?? {}),
    label: blurResetHost.attention?.label ?? "settings change waiting",
    level: blurResetHost.attention?.level ?? "warn",
    rank: 99,
  };
  await actionsTrigger.hover();
  await page.mouse.down();
  await page.evaluate(() => window.dispatchEvent(new Event("blur")));
  await card.evaluate((_, snapshot) => {
    window.applyFleetSnapshot(snapshot);
  }, blurResetSnapshot);
  await expect(
    page.locator('[data-grid] > .card[data-host-surface="runtime"]').last(),
  ).toHaveAttribute("data-host", host);
  await page.mouse.move(0, 0);
  await page.mouse.up();

  await actionsTrigger.hover();
  await page.mouse.down({ button: "middle" });
  const nonPrimarySnapshot = structuredClone(stableSnapshot);
  const nonPrimaryHost = nonPrimarySnapshot.hosts.find(
    (entry) => entry.name === host,
  );
  expect(nonPrimaryHost).toBeTruthy();
  nonPrimaryHost.attention = {
    ...(nonPrimaryHost.attention ?? {}),
    label: nonPrimaryHost.attention?.label ?? "settings change waiting",
    level: nonPrimaryHost.attention?.level ?? "warn",
    rank: -1,
  };
  await card.evaluate((_, snapshot) => {
    window.applyFleetSnapshot(snapshot);
  }, nonPrimarySnapshot);
  await expect(
    page.locator('[data-grid] > .card[data-host-surface="runtime"]').first(),
  ).toHaveAttribute("data-host", host);
  await page.mouse.up({ button: "middle" });

  const reorderedSnapshot = structuredClone(stableSnapshot);
  const reorderedHost = reorderedSnapshot.hosts.find(
    (entry) => entry.name === host,
  );
  expect(reorderedHost).toBeTruthy();
  reorderedHost.attention = {
    ...(reorderedHost.attention ?? {}),
    label: reorderedHost.attention?.label ?? "settings change waiting",
    level: reorderedHost.attention?.level ?? "warn",
    rank: 99,
  };
  await page.keyboard.down("Space");
  const keyboardRefreshMoves = await card.evaluate((surface, snapshot) => {
    const grid = surface.parentElement;
    if (!grid) return -1;
    const observer = new MutationObserver(() => {});
    observer.observe(grid, { childList: true });
    window.applyFleetSnapshot(snapshot);
    const moves = observer
      .takeRecords()
      .filter(
        (record) =>
          [...record.addedNodes, ...record.removedNodes].includes(surface),
      ).length;
    observer.disconnect();
    return moves;
  }, reorderedSnapshot);
  expect(keyboardRefreshMoves).toBe(0);
  await page.keyboard.up("Space");
  await expect(withdraw).toBeVisible();
  const focusedMenuItem = card
    .locator('[data-host-actions-menu] [role="menuitem"]:visible')
    .first();
  await expect(focusedMenuItem).toBeFocused();
  const menuBox = await card
    .locator("[data-host-actions-menu]")
    .boundingBox();
  const viewport = page.viewportSize();
  expect(menuBox).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(menuBox.x).toBeGreaterThanOrEqual(0);
  expect(menuBox.y).toBeGreaterThanOrEqual(0);
  expect(menuBox.x + menuBox.width).toBeLessThanOrEqual(viewport.width);
  expect(menuBox.y + menuBox.height).toBeLessThanOrEqual(viewport.height);
  await expect(withdraw).toContainText("Withdraw change request");
  await expect(withdraw).toContainText(
    "Clears the pending request. An open nixcfg proposal stays open there.",
  );
  const withdrawalResponse = page.waitForResponse(
    (response) =>
      response.url().includes(`/host-actions/jobs/${encodeURIComponent(runId)}/withdraw`) &&
      response.request().method() === "POST",
  );
  staleWithdrawalJobGets = 0;
  withdrawalResponseSeen = false;
  await withdraw.evaluate((button) => button.click());
  expect((await withdrawalResponse).status()).toBe(200);
  await expect(
    page.locator('[data-grid] > .card[data-host-surface="runtime"]').last(),
  ).toHaveAttribute("data-host", host);
  expect(withdrawPosts).toBe(1);
  expect(staleWithdrawalJobGets).toBe(0);
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-copy]")).toContainText(
    "pending request was cleared",
  );
  await expect(dialog.locator(".host-workflow-next")).toContainText(
    "An open nixcfg proposal stays open there.",
  );

  const snapshot = await page.request.get("/hosts.json");
  const payload = await snapshot.json();
  const hostData = payload.hosts.find((entry) => entry.name === host);
  expect(hostData.requested_preferences).toBeNull();
  expect(hostData.lifecycle.label).toBe("settings change cancelled");
  expect(hostData.lifecycle.label).not.toBe("Change requested");

  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(card.locator("[data-host-actions-trigger]")).toBeFocused();
  fs.writeFileSync(manifest.acceptFlagPath, "false", { mode: 0o600 });
});

test("delayed withdrawal cannot repaint a newly opened host action", async ({
  page,
}, testInfo) => {
  const manifest = requireFixtureManifest(
    test,
    "delayed settings withdrawal requires local dispatch fixture",
  );
  if (!manifest) return;
  fs.writeFileSync(manifest.acceptFlagPath, "true", { mode: 0o600 });

  const host = `bl-withdraw-delay-${testInfo.project.name}`;
  const otherHost = `bl-withdraw-other-${testInfo.project.name}`;
  await reportRuntimeHost(page, host, { is_nix: true });
  await reportRuntimeHost(page, otherHost);
  const request = await page.request.post(
    "/agora/requests/host-preferences.json",
    { data: { host, preferences: { accent: "#48b8a8" } } },
  );
  expect(request.ok()).toBe(true);
  const runId = (await request.json()).job.id;

  await page.goto("/");
  await page.evaluate((withdrawRunId) => {
    const originalFetch = window.fetch.bind(window);
    window.__releaseWithdrawal = () => {};
    window.fetch = (input, init) => {
      const url = String(input);
      if (url.endsWith(`/host-actions/jobs/${withdrawRunId}/withdraw`)) {
        return new Promise((resolve, reject) => {
          window.__releaseWithdrawal = () => {
            originalFetch(input, init).then(resolve, reject);
          };
        });
      }
      return originalFetch(input, init);
    };
  }, runId);
  const card = page
    .locator(`[data-host="${host}"][data-host-surface="runtime"].card`)
    .first();
  await card.locator("[data-host-actions-trigger]").click();
  await card
    .locator('[data-host-action="withdraw-settings"]')
    .evaluate((button) => button.click());
  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-status]")).toContainText(
    "Clearing the pending request",
  );
  await dialog.getByRole("button", { name: "Close", exact: true }).click();

  const otherCard = page
    .locator(`[data-host="${otherHost}"][data-host-surface="runtime"].card`)
    .first();
  await otherCard.locator("[data-host-actions-trigger]").click();
  await otherCard
    .locator('[data-host-action="technical"]')
    .evaluate((button) => button.click());
  await expect(dialog.locator("[data-host-action-title]")).toHaveText(
    `${otherHost} technical details`,
  );

  const delayedResponse = page.waitForResponse(
    (response) =>
      response.url().includes(`/host-actions/jobs/${encodeURIComponent(runId)}/withdraw`) &&
      response.request().method() === "POST",
  );
  await page.evaluate(() => window.__releaseWithdrawal());
  expect((await delayedResponse).status()).toBe(200);
  await expect(dialog.locator("[data-host-action-title]")).toHaveText(
    `${otherHost} technical details`,
  );
  await expect(dialog.locator("[data-host-action-technical]")).toContainText(
    `Host: ${otherHost}`,
  );
  fs.writeFileSync(manifest.acceptFlagPath, "false", { mode: 0o600 });
});

test("informational lifecycle sheets hide leftover workflow controls", async ({
  page,
}) => {
  const quietHost = "bl-sheet-reuse-quiet";
  const kernelHost = "bl-sheet-reuse-kernel";
  const prefsHost = "bl-prefs-declared-drift";
  await reportRuntimeHost(page, quietHost, { preferences: { accent: "#224466" } });
  await reportRuntimeHost(page, kernelHost, {
    kernel: {
      state: "reboot_required",
      running_version: "6.18.26",
      expected_version: "7.0.14",
      observed_at: 1_700_000_000,
    },
  });
  await reportRuntimeHost(page, prefsHost, { preferences: { accent: "#111111" } });
  await page.goto("/");

  const quietCard = page
    .locator(`[data-host="${quietHost}"][data-host-surface="runtime"].card`)
    .first();
  await page.evaluate((hostName) => {
    const surface = document.querySelector(
      `article.card[data-host="${hostName}"][data-host-surface="runtime"]`,
    );
    const root = surface?.querySelector("[data-host-actions]");
    if (!root) throw new Error("missing host actions root");
    openHostActionDialog("remove", root);
  }, quietHost);

  const dialog = page.getByRole("dialog");
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-remove-disposition-field]")).toBeVisible();
  await expect(dialog.locator("[data-host-remove-confirm]")).toBeVisible();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();

  await page.evaluate(() => {
    const overlay = document.querySelector("[data-host-action-overlay]");
    overlay
      ?.querySelector("[data-host-remove-disposition-field]")
      ?.removeAttribute("hidden");
    overlay?.querySelector("[data-host-remove-successor]")?.removeAttribute("hidden");
    overlay?.querySelector("[data-host-remove-confirm]")?.removeAttribute("hidden");
    overlay?.querySelector("[data-host-attended-confirm]")?.removeAttribute("hidden");
  });

  await quietCard.locator("[data-host-lifecycle-chip]").click();
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-info-title]")).toContainText("No drift");
  await expectInformationalWorkflowControlsHidden(dialog);
  await expect(dialog.locator("[data-host-action-close]").first()).toBeFocused();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();

  const kernelCard = page
    .locator(`[data-host="${kernelHost}"][data-host-surface="runtime"].card`)
    .first();
  await kernelCard.locator("[data-host-lifecycle-chip]").click();
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-info-copy]")).toContainText(
    "Pharos will not restart this host",
  );
  await expectInformationalWorkflowControlsHidden(dialog);
  await expect(dialog.locator("[data-host-action-close]").first()).toBeFocused();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();
  await expect(dialog).toBeHidden();

  const prefsCard = page
    .locator(`[data-host="${prefsHost}"][data-host-surface="runtime"].card`)
    .first();
  const prefsChip = prefsCard.locator("[data-host-lifecycle-chip]");
  await expect(prefsChip).toHaveAttribute("data-lifecycle-slot", "prefs_drift");
  await prefsChip.click();
  await expect(dialog).toBeVisible();
  await expect(dialog.locator("[data-host-action-info-title]")).toContainText(
    "Resolved in host settings",
  );
  await expectInformationalWorkflowControlsHidden(dialog);
  await expect(dialog.locator("[data-host-action-close]").first()).toBeFocused();
  await dialog.getByRole("button", { name: "Close", exact: true }).click();

  for (const host of [quietHost, kernelHost]) {
    const removal = await page.request.post(`/host-actions/${host}/remove`, {
      headers: { "x-pharos-action": "1" },
      data: { confirmation: host, disposition: "unmanaged", successor: null },
    });
    expect(removal.status()).toBe(202);
    const reonboard = await page.request.post(
      `/host-actions/${host}/allow-reonboarding`,
      { headers: { "x-pharos-action": "1" }, data: { confirmation: host } },
    );
    expect(reonboard.ok()).toBe(true);
  }
});
