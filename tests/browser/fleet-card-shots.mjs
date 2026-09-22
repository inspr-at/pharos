import fs from "node:fs";
import path from "node:path";
import { chromium } from "@playwright/test";
import { newAuthedContext, waitForHarnessTokens } from "./harness.mjs";

const outDir = "/private/tmp/claude-501/-Users-markus-Code-pharos/0fea778f-cfc3-4e64-856c-5ac4218c2e27/scratchpad/shots-slice1";
const listDir = "/private/tmp/claude-501/-Users-markus-Code-pharos/0fea778f-cfc3-4e64-856c-5ac4218c2e27/scratchpad/shots-slice2";
const slice3Dir = "/private/tmp/claude-501/-Users-markus-Code-pharos/0fea778f-cfc3-4e64-856c-5ac4218c2e27/scratchpad/shots-slice3";
const widths = [390, 768, 1280, 1440, 1920, 2560];

const hosts = [
  { name: "relay-03", role: "edge", backup: "failed", age: 1080 },
  { name: "beacon-02", role: "staging", backup: "overdue", age: 96 },
  { name: "dune-05", role: "production", backup: "healthy", age: 20 },
  { name: "nova-04", role: "lab", backup: "none", age: null },
  { name: "atlas-01", role: "production", backup: "healthy", age: 12 },
  { name: "grove-06", role: "production", backup: "healthy", age: 54 },
];

function backupObservation(kind, now) {
  if (kind === "none") return [];
  const failed = kind === "failed";
  const overdue = kind === "overdue";
  const observation = {
    id: "restic-main",
    label: "Restic main",
    engine: "restic",
    state: failed ? "failed" : "healthy",
    configured: "enabled",
    summary: failed ? "last backup failed" : "last backup succeeded",
    schedule: "daily",
    target_label: "off-box repository",
    last_success_at: failed ? null : now - 2 * 3600,
    last_attempt_at: now - 3600,
    last_attempt_state: failed ? "failed" : "succeeded",
  };
  if (!failed) {
    observation.restore_validation = {
      level: "restore-sample",
      state: "passed",
      checked_at: now - (overdue ? 45 : 6) * 86400,
      summary: "one file restored",
    };
  }
  return [observation];
}

async function main() {
  await waitForHarnessTokens();
  fs.mkdirSync(outDir, { recursive: true });
  fs.mkdirSync(listDir, { recursive: true });
  fs.mkdirSync(slice3Dir, { recursive: true });
  const browser = await chromium.launch({ headless: true });
  const context = await newAuthedContext(browser, "write");
  const page = await context.newPage();
  try {
    const now = Math.floor(Date.now() / 1000);
    for (const host of hosts) {
      const report = await page.request.post("/report", {
        data: {
          schema: "inspr.pharos.host-report.v5",
          version: 5,
          name: host.name,
          role: host.role,
          is_nix: false,
          heartbeat_interval_secs: 60,
          freshness: { applicable: false },
          preferences: { kind: "server" },
          backup_observations: backupObservation(host.backup, now),
        },
      });
      if (report.status() !== 204) {
        throw new Error(`${host.name} report ${report.status()}: ${await report.text()}`);
      }
    }
    await page.setViewportSize({ width: 1440, height: 1200 });
    const snapshot = page.waitForResponse(
      (res) => res.url().includes("/hosts.json") && res.ok(),
      { timeout: 12000 },
    );
    await page.goto("/");
    await page.locator("article.card").first().waitFor();
    await snapshot.catch(() => {});
    const paintSamples = () => page.evaluate((samples) => {
      const now = Date.now() / 1000;
      for (const sample of samples) {
        const seenText = sample.age == null
          ? "never"
          : sample.age < 60
            ? `${sample.age}s ago`
            : `${Math.floor(sample.age / 60)}m ago`;
        document.querySelectorAll(`[data-host="${sample.name}"] [data-seen-compact]`).forEach((seen) => {
          seen.textContent = seenText;
        });
        document.querySelectorAll(`[data-host="${sample.name}"] .beat`).forEach((beat) => {
          if (sample.age == null) {
            delete beat.dataset.last;
            beat.dataset.beat = "waiting";
          } else {
            beat.dataset.last = String(now - sample.age);
            const stamps = [];
            for (let step = 20; step >= 0; step -= 1) stamps.push(now - sample.age - step * 30);
            if (typeof window.setBeatHistory === "function") window.setBeatHistory(beat, stamps, 60, now, 15);
          }
          window.updateBeatClock(beat, now);
        });
      }
    }, hosts);
    await paintSamples();

    for (const width of widths) {
      await page.setViewportSize({ width, height: width < 800 ? 1400 : 1200 });
      await page.screenshot({ path: path.join(outDir, `cards-${width}.png`) });
    }

    await page.setViewportSize({ width: 1440, height: 900 });
    const single = page.locator('article.card[data-host="atlas-01"]');
    await single.scrollIntoViewIfNeeded();
    await single.screenshot({ path: path.join(outDir, "card-single.png") });
    await single.hover();
    await page.waitForTimeout(250);
    await page.screenshot({ path: path.join(outDir, "cards-hover.png") });

    await page.locator('[data-view-button="list"]').click();
    await page.locator("table.list tbody tr").first().waitFor();
    await paintSamples();
    for (const width of [1440, 1920, 768, 390]) {
      await page.setViewportSize({ width, height: width < 800 ? 1400 : 1100 });
      await page.screenshot({ path: path.join(listDir, `list-${width}.png`), fullPage: true });
    }
    await page.setViewportSize({ width: 768, height: 1100 });
    await page.screenshot({ path: path.join(slice3Dir, "list-768.png"), fullPage: true });

    await page.locator('[data-view-button="grid"]').click();
    await page.locator("article.card").first().waitFor();
    await page.screenshot({ path: path.join(slice3Dir, "cards-768.png"), fullPage: true });

    await page.setViewportSize({ width: 1440, height: 1000 });
    await paintSamples();
    const preview = page.locator('article.card[data-host="beacon-02"] [data-host-drawer-trigger]');
    await preview.scrollIntoViewIfNeeded();
    await preview.click();
    await page.locator("#host-quick-drawer").waitFor();
    await page.waitForTimeout(350);
    await page.screenshot({ path: path.join(slice3Dir, "drawer-1440.png") });
    await page.setViewportSize({ width: 390, height: 844 });
    await page.waitForTimeout(350);
    await page.screenshot({ path: path.join(slice3Dir, "drawer-390.png") });
    await page.keyboard.press("Escape");

    const actions = page.locator('article.card[data-host="relay-03"] [data-host-actions-trigger]');
    await actions.scrollIntoViewIfNeeded();
    await actions.click();
    await page.locator("[data-host-actions-menu]:not([hidden])").waitFor();
    await page.waitForTimeout(200);
    await page.screenshot({ path: path.join(slice3Dir, "mobile-actions-menu.png") });
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
