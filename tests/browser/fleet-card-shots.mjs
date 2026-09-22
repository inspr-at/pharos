import fs from "node:fs";
import path from "node:path";
import { chromium } from "@playwright/test";
import { newAuthedContext, waitForHarnessTokens } from "./harness.mjs";

const outDir = "/private/tmp/claude-501/-Users-markus-Code-pharos/0fea778f-cfc3-4e64-856c-5ac4218c2e27/scratchpad/shots-slice1";
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
    await page.goto("/");
    await page.locator("article.card").first().waitFor();
    await page.evaluate((samples) => {
      const now = Date.now() / 1000;
      for (const sample of samples) {
        const beat = document.querySelector(`article.card[data-host="${sample.name}"] .beat`);
        if (!beat) continue;
        if (sample.age == null) {
          delete beat.dataset.last;
          beat.dataset.beat = "waiting";
        } else {
          beat.dataset.last = String(now - sample.age);
        }
        window.updateBeatClock(beat, now);
      }
    }, hosts);

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
  } finally {
    await context.close();
    await browser.close();
  }
}

main().catch((error) => {
  console.error(error);
  process.exitCode = 1;
});
