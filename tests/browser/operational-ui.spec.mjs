import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

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
