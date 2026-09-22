// Synthetic Chromium proof only. No live app, identity, or credential is used.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { chromium } from "@playwright/test";
import { FAMILY_VIEWPORTS } from "../scripts/live-ui-apps.mjs";
import { browserContextOptions, takeAuthenticatedShot, openGuardedBrowser, shutdownLiveSession } from "../scripts/live-ui-guard.mjs";
import { installGuard, readProbe } from "../scripts/live-ui.mjs";

const dir = fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "family-browser-proof-")));
fs.chmodSync(dir, 0o700);
const secret = "SYNTHETIC_SCREENSHOT_CANARY_308";
const secrets = ["synthetic", secret];
const opened = await openGuardedBrowser((options) => chromium.launch(options));
let sessions = [];
try {
  const context = await opened.browser.newContext(browserContextOptions());
  const policy = { familyApp: "janus", secrets, gate: opened.gate };
  const pageRef = { page: null };
  const guard = await installGuard(context, policy, [], pageRef);
  sessions = guard.sessions;
  const page = await context.newPage();
  pageRef.page = page;
  await guard.armPage(page);
  assert.equal(Boolean(opened.gate.compromised()), false);
  await page.setContent("<main><h1>Ordinary vault</h1><form action='/janus/logout'><button>Sign out</button></form></main>");
  assert.equal((await readProbe(page, policy)).familyShell, false);
  await page.setContent("<main data-inspr-flow-reviewer><h1>Restricted Flow review</h1><form action='/janus/logout'><button>Sign out</button></form></main>");
  assert.equal((await readProbe(page, policy)).familyShell, true);
  for (const [name, viewport] of Object.entries(FAMILY_VIEWPORTS)) {
    await page.setViewportSize(viewport);
    await page.setContent("<main><h1>Synthetic app surface</h1><p>No live identity is used.</p></main>");
    const output = path.join(dir, `${name}.png`);
    assert.equal(await takeAuthenticatedShot(page, { permitted: true, password: secret, options: { path: output, fullPage: false } }), true);
    fs.chmodSync(output, 0o600);
    const png = fs.readFileSync(output);
    assert.equal(png.readUInt32BE(16), viewport.width);
    assert.equal(png.readUInt32BE(20), viewport.height);
    await page.setContent(`<main><input type="hidden" value="${secret}"></main>`);
    assert.equal(await takeAuthenticatedShot(page, { permitted: true, password: secret, options: { path: path.join(dir, `${name}-forbidden.png`) } }), false);
    assert.equal(fs.existsSync(path.join(dir, `${name}-forbidden.png`)), false);
  }
  process.stdout.write("Synthetic guarded Chromium: desktop/mobile dimensions and hidden-input screenshot refusal passed.\n");
} finally {
  await shutdownLiveSession({
    close: async () => { opened.gate.beginShutdown(); await opened.browser.close(); },
    sessions, detach: () => opened.gate.close(), secrets,
  });
}
