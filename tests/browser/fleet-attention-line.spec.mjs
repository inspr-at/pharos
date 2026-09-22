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

test("attention lines stay equal to the server text after load", async ({ page }, testInfo) => {
  const workstation = `attention-workstation-${testInfo.project.name}`;
  const onboarding = `attention-onboarding-${testInfo.project.name}`;
  const now = Math.floor(Date.now() / 1000);
  const report = async (name, preferences, backup) => {
    const response = await page.request.post("/report", {
      data: {
        schema: "inspr.pharos.host-report.v5",
        version: 5,
        name,
        role: "production",
        is_nix: false,
        heartbeat_interval_secs: 60,
        freshness: { applicable: false },
        preferences,
        backup_observations: backup,
      },
    });
    expect(response.status(), await response.text()).toBe(204);
  };
  await report(workstation, { kind: "workstation" }, [{
    id: "restic-main",
    label: "Restic main",
    engine: "restic",
    state: "healthy",
    configured: "enabled",
    summary: "last backup succeeded",
    schedule: "daily",
    last_success_at: now - 120,
    last_attempt_at: now - 120,
    last_attempt_state: "succeeded",
    restore_validation: {
      level: "restore-sample",
      state: "passed",
      checked_at: now - 86400,
    },
  }]);
  await report(onboarding, { kind: "server" }, []);
  const job = await page.request.post("/setup/provisioning-jobs", {
    data: {
      provider: "existing-host",
      template: "manual-deferred",
      apply: true,
      host_name: onboarding,
      role: "server",
      is_nix: false,
      backup_intent: "required",
    },
  });
  const createdBody = await job.text();
  expect(job.ok(), createdBody).toBe(true);
  const created = JSON.parse(createdBody);
  const jobId = created.job.id;
  try {
    const html = await (await page.request.get("/")).text();
    const server = await page.evaluate(({ html, hosts }) => {
      const doc = new DOMParser().parseFromString(html, "text/html");
      const text = (selector) =>
        (doc.querySelector(selector)?.textContent || "").replace(/\s+/g, " ").trim();
      return Object.fromEntries(hosts.map((host) => [host, {
        card: text(`article.card[data-host="${host}"] .attention-line`),
        row: text(`tr.harbor-host[data-host="${host}"] .attention-line`),
      }]));
    }, { html, hosts: [workstation, onboarding] });
    expect(server[workstation].card).toContain("No action needed");
    expect(server[workstation].card).toContain("down alerts off for workstation");
    expect(server[workstation].card.match(/down alerts off for workstation/g)).toHaveLength(1);
    expect(server[onboarding].card).toMatch(/First backup (pending|overdue)/);
    expect(server[onboarding].row).toBe(server[onboarding].card);

    await page.goto("/");
    const live = await page.evaluate((hosts) => {
      const text = (selector) =>
        (document.querySelector(selector)?.textContent || "").replace(/\s+/g, " ").trim();
      return Object.fromEntries(hosts.map((host) => [host, {
        card: text(`article.card[data-host="${host}"] .attention-line`),
        row: text(`tr.harbor-host[data-host="${host}"] .attention-line`),
      }]));
    }, [workstation, onboarding]);
    expect(live[workstation]).toEqual(server[workstation]);
    expect(live[onboarding]).toEqual(server[onboarding]);
  } finally {
    try {
      // The required-backup job stays on the fleet as a setup card once the
      // runtime host is gone. A backup observation completes it first.
      await report(onboarding, { kind: "server" }, [{
        id: "restic-main",
        label: "Restic main",
        engine: "restic",
        state: "healthy",
        configured: "enabled",
        summary: "last backup succeeded",
        schedule: "daily",
        last_success_at: now - 120,
        last_attempt_at: now - 120,
        last_attempt_state: "succeeded",
        restore_validation: {
          level: "restore-sample",
          state: "passed",
          checked_at: now - 86400,
        },
      }]);
      const settled = await page.request.get(`/setup/provisioning-jobs/${encodeURIComponent(jobId)}`);
      const payload = await settled.json();
      expect(settled.ok(), JSON.stringify(payload)).toBe(true);
      expect(payload.job.state).toBe("complete");
    } finally {
      for (const host of [workstation, onboarding]) {
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
      const home = await (await page.request.get("/")).text();
      expect(home).not.toContain(`class="card setup-card" data-host="${onboarding}"`);
    }
  }
});
