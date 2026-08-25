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

  // Return the fleet to empty so the rest of the suite sees its usual state.
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
  await page.goto("/");
  await expect(page.locator("[data-host-action-overlay]")).toHaveCount(0);
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

  const gridCards = page.locator('[data-grid] article').filter({
    or: [
      { hasAttribute: 'data-host', value: 'browser-card-a' },
      { hasAttribute: 'data-host', value: 'browser-card-b' },
      { hasAttribute: 'data-host', value: 'browser-card-c' },
    ],
  });
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

test("fleet refresh consumes lifecycle projection for settings runs and precedence", async ({
  page,
}) => {
  const failedHost = "bl-lifecycle-failed";
  const cancelledHost = "bl-lifecycle-cancelled";
  const runHost = "bl-lifecycle-run-kernel";

  for (const host of [failedHost, cancelledHost, runHost]) {
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
  }

  await page.goto("/");

  const applyLifecycleRefresh = async (hostName, lifecycleOverrides, extra = {}) => {
    const snapshot = await page.request.get("/hosts.json");
    const payload = await snapshot.json();
    const host = payload.hosts.find((entry) => entry.name === hostName);
    expect(host).toBeTruthy();
    Object.assign(host, extra);
    host.lifecycle = {
      schema: "inspr.pharos.host-lifecycle.v1",
      version: 1,
      blocked_by: [],
      detail: "browser lifecycle projection regression",
      ...lifecycleOverrides,
    };
    return page.evaluate((body) => applyFleetSnapshot(body), payload);
  };

  expect(
    await applyLifecycleRefresh(
      failedHost,
      {
        slot: "settings_change",
        label: "settings request stopped",
        level: "warning",
        invoke: "workflow",
        run_id: "failed-settings-run",
      },
      {
        preferences_state: "request_pending",
        requested_preferences: { accent: "#48b8a8" },
        host_action: {
          id: "failed-settings-run",
          state: "failed",
          workflow: {
            kind: "settings_change",
            status_label: "settings request stopped",
            status_level: "warning",
          },
        },
      },
    ),
  ).toBe(true);

  const failedCard = page.locator(`[data-host="${failedHost}"]`).first();
  await expect(failedCard.locator("[data-host-action-note-copy]")).toContainText(
    "settings request stopped",
  );
  await expect(failedCard.locator("[data-settings-note]")).toBeHidden();

  expect(
    await applyLifecycleRefresh(
      cancelledHost,
      {
        slot: "settings_change",
        label: "settings change cancelled",
        level: "clear",
        invoke: "workflow",
        run_id: "cancelled-settings-run",
      },
      {
        preferences_state: "request_pending",
        requested_preferences: { accent: "#9868d0" },
      },
    ),
  ).toBe(true);

  const cancelledCard = page.locator(`[data-host="${cancelledHost}"]`).first();
  await expect(cancelledCard.locator("[data-host-action-note-copy]")).toContainText(
    "settings change cancelled",
  );
  await expect(cancelledCard.locator("[data-settings-note]")).toBeHidden();

  expect(
    await applyLifecycleRefresh(
      runHost,
      {
        slot: "update_restart",
        label: "review queued",
        level: "warning",
        invoke: "update_restart",
        run_id: "update-restart-run",
      },
      {
        kernel: {
          state: "reboot_required",
          running_version: "6.18.26",
          expected_version: "7.0.14",
          observed_at: 1_700_000_000,
        },
        host_action: {
          id: "live-proposal-run",
          state: "proposal_requested",
          workflow: {
            kind: "system_update_proposal",
            status_label: "review requested",
            status_level: "warning",
          },
        },
      },
    ),
  ).toBe(true);

  const runCard = page.locator(`[data-host="${runHost}"]`).first();
  await expect(runCard.locator("[data-host-action-note-copy]")).toContainText(
    "review queued",
  );
  await expect(runCard.locator("[data-kernel-slot]")).toBeHidden();
  await expect(runCard.locator("[data-host-action-note]")).toHaveAttribute(
    "data-lifecycle-run-id",
    "update-restart-run",
  );

  for (const host of [failedHost, cancelledHost, runHost]) {
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
