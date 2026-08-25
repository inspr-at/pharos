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
  await expect(card.locator('[data-fresh-kind="flake-lock-age"]')).toContainText(
    "exact",
  );
  await expect(card.locator('[data-fresh-kind="commits-behind"]')).toContainText(
    "exact",
  );
  await expect(card.locator('[data-fresh-kind="deployed-sha"]')).toContainText(
    "111111111111",
  );
  const secondary = card.locator('[data-fresh-kind="secondary-nixpkgs"]');
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
  await expect(card.locator('[data-fresh-kind="deployed-sha"]')).toContainText(
    "n/a",
  );
  await expect(card.locator('[data-fresh-kind="commits-behind"]')).toContainText(
    "unknown",
  );

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

test("chip row does not overflow card boundary or paint into neighbors", async ({ page }) => {
  const host = "browser-chip-overflow";
  const report = await page.request.post("/report", {
    data: {
      schema: "inspr.pharos.host-report.v5",
      version: 5,
      name: host,
      role: "test server",
      is_nix: true,
      heartbeat_interval_secs: 60,
      freshness: {
        applicable: true,
        flake_lock_age_days: 0,
        commits_behind: 0,
        nixpkgs_age_days: 36,
        nixpkgs_channel: "nixos-24.05",
        deployment_evidence: {
          schema: "inspr.pharos.nix-deployment-evidence.v1",
          version: 1,
          source_revision: "1111111111111111111111111111111111111111",
          flake_lock_sha256:
            "2222222222222222222222222222222222222222222222222222222222222222",
          nixpkgs_revision: "3333333333333333333333333333333333333333",
          nixpkgs_last_modified: 1700000000,
          nixpkgs_channel: "nixos-24.05",
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
    },
  });
  expect(report.status()).toBe(204);

  await page.goto("/");
  await page.setViewportSize({ width: 1280, height: 1024 });

  const card = page
    .locator(`[data-host="${host}"][data-host-surface="runtime"]`)
    .first();
  await expect(card).toBeVisible();

  const chipRow = card.locator('.fresh[data-fresh]');
  await expect(chipRow).toBeVisible();

  const chips = chipRow.locator('.fresh-row-compact');
  const chipCount = await chips.count();
  expect(chipCount).toBeGreaterThan(0);

  const cardBox = await card.boundingBox();
  expect(cardBox).not.toBeNull();

  const visibleChips = await chips.evaluateAll((elements, parentBox) => {
    return elements.map((el) => {
      const rect = el.getBoundingClientRect();
      return {
        left: rect.left,
        right: rect.right,
        width: rect.width,
        overflows: rect.right > parentBox.left + parentBox.width,
      };
    });
  }, cardBox);

  visibleChips.forEach((chip, index) => {
    expect(chip.overflows).toBe(false);
  });

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
  const save = page.locator("[data-save-color]");
  await expect(save).toBeVisible();
  const activeConflict = page.waitForResponse(
    (response) =>
      response.url().includes("/agora/requests/host-preferences.json") &&
      response.request().method() === "POST",
  );
  await save.click();
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
  await dialog.getByRole("button", { name: "Cancel", exact: true }).click();
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
