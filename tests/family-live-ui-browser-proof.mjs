// Synthetic Chromium proof only. No live app, identity, or credential is used.
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { chromium } from "@playwright/test";
import { FAMILY_ORIGIN, FAMILY_VIEWPORTS, classifyFamilyObservation } from "../scripts/live-ui-apps.mjs";
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
  const paimosPolicy = { ...policy, familyApp: "paimos" };
  for (const shell of [
    "<div class='layout'><button class='logout-btn' title='Log out'>Sign out</button></div>",
    "<div class='p6-shell habitat-shell' data-shell='v6'><button type='button' aria-label='Log out'>Sign out</button></div>",
  ]) {
    await page.setContent(shell);
    const probe = await readProbe(page, paimosPolicy);
    assert.equal(probe.familyShell, true);
    const observed = { app: "paimos", location: { origin: FAMILY_ORIGIN, pathname: "/paimos/" }, status: 200, probe, callbackConfirmed: true };
    assert.equal(classifyFamilyObservation(observed), "authenticated");
    assert.equal(classifyFamilyObservation({ ...observed, callbackConfirmed: false }), "broken-ui");
    await page.setContent(`${shell}<form><input type='password' name='password'></form>`);
    assert.equal(classifyFamilyObservation({ ...observed, probe: await readProbe(page, paimosPolicy) }), "auth-required");
  }
  for (const lookalike of [
    "<button type='button' aria-label='Log out'>Sign out</button>",
    "<div class='p6-shell habitat-shell'><button type='button' aria-label='Log out'>Sign out</button></div>",
    "<div class='p6-shell habitat-shell' data-shell='v6'><button type='button'>Sign out</button></div>",
    "<div class='layout'><span class='logout-btn'>Sign out</span></div>",
  ]) {
    await page.setContent(lookalike);
    const probe = await readProbe(page, paimosPolicy);
    assert.equal(probe.familyShell, false);
    assert.equal(classifyFamilyObservation({ app: "paimos", location: { origin: FAMILY_ORIGIN, pathname: "/paimos/" }, status: 200, probe, callbackConfirmed: true }), "broken-ui");
  }
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
  process.stdout.write("Synthetic guarded Chromium: Paimos V6/legacy shells, lookalike/auth refusal, desktop/mobile dimensions and hidden-input screenshot refusal passed.\n");
} finally {
  await shutdownLiveSession({
    close: async () => { opened.gate.beginShutdown(); await opened.browser.close(); },
    sessions, detach: () => opened.gate.close(), secrets,
  });
}
