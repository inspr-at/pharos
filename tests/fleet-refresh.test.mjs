import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";
import { pharosPublicPathSource } from "./fixtures/pharos-public-path.mjs";

const fleetRuntimeSource = readFileSync(
  new URL("../crates/pharosd/assets/ui/foot.html", import.meta.url),
  "utf8",
);
const appUrlStart = fleetRuntimeSource.indexOf("function appUrl(path)");
const appUrlEnd = fleetRuntimeSource.indexOf("}", appUrlStart) + 1;
const lifecycleStart = fleetRuntimeSource.indexOf("const REFRESH_MS=10000;");
const lifecycleEnd = fleetRuntimeSource.indexOf(
  "document.addEventListener('visibilitychange'",
  lifecycleStart,
);

assert.notEqual(appUrlStart, -1, "appUrl helper must exist in foot.html");
assert.notEqual(appUrlEnd, 0, "appUrl helper must exist in foot.html");
assert.notEqual(lifecycleStart, -1, "Fleet refresh lifecycle start must exist");
assert.notEqual(lifecycleEnd, -1, "Fleet refresh lifecycle end must exist");

const appUrlSource = fleetRuntimeSource.slice(appUrlStart, appUrlEnd);
const lifecycleSource = fleetRuntimeSource.slice(lifecycleStart, lifecycleEnd);
const fleetRuntimeSourcePrefix = `${appUrlSource}\n${lifecycleSource}`;
const exposeTestApi = `
globalThis.__fleetTest = {
  refresh,
  recoverFleet,
  suspendFleet,
  fleetSnapshotFresh,
  updateFleetSummary,
  replaceApplyFleetSnapshot(replacement) { applyFleetSnapshot = replacement; },
  state() {
    return {
      generation: refreshGeneration,
      refreshActive: refreshPromise !== null,
      recoveryActive: recoveryPromise !== null,
      lastSuccessfulRefreshAt,
    };
  },
};
`;

function jsonResponse(data, overrides = {}) {
  return {
    ok: true,
    redirected: false,
    headers: { get: () => "application/json; charset=utf-8" },
    json: async () => data,
    ...overrides,
  };
}

function snapshot(asOf = 1_700_000_000) {
  return {
    as_of: asOf,
    hosts: [
      { name: "alpha", liveness: "live" },
      { name: "beta", liveness: "stale" },
      { name: "gamma", liveness: "down" },
      { name: "delta", liveness: "awaiting_first_heartbeat" },
    ],
  };
}

function deferredFetchQueue() {
  const pending = [];
  const fetch = (_url, options = {}) =>
    new Promise((resolve, reject) => {
      const entry = { resolve, reject, signal: options.signal };
      pending.push(entry);
      options.signal?.addEventListener(
        "abort",
        () => reject(Object.assign(new Error("aborted"), { name: "AbortError" })),
        { once: true },
      );
    });
  return { fetch, pending };
}

function harness(fetch, { publicBasePath = "" } = {}) {
  const summary = new Map(
    ["all", "live", "stale", "down"].map((key) => [key, { textContent: "" }]),
  );
  const asOf = {
    dataset: { snapshotLabel: "as of 12:00:00" },
    textContent: "as of 12:00:00",
  };
  const main = {
    dataset: { fleetSyncState: "current" },
    querySelector: (selector) => (selector === "[data-as-of]" ? asOf : null),
  };
  const events = [];
  let timerId = 0;
  const activeTimers = new Set();
  const publicBaseMeta = publicBasePath
    ? { content: publicBasePath, getAttribute: (name) => (name === "content" ? publicBasePath : null) }
    : null;
  const beats = [];
  const document = {
    hidden: false,
    body: { dataset: {} },
    hasFocus: () => true,
    querySelector(selector) {
      if (selector === 'meta[name="pharos-public-base-path"]') return publicBaseMeta;
      if (selector === "main[data-fleet-sync-state]") return main;
      const match = selector.match(/^\[data-summary-count="(all|live|stale|down)"\]$/);
      return match ? summary.get(match[1]) : null;
    },
    querySelectorAll(selector) {
      if (selector === ".beat") return beats;
      return [];
    },
  };
  const window = { location: { reload: () => events.push("reload") } };
  const context = vm.createContext({
    AbortController,
    console,
    document,
    fetch,
    window,
    clock: (value) => String(value),
    stopBeatClock: () => events.push("stop"),
    resumeBeatClock: () => events.push("resume"),
    setTimeout: () => {
      const id = ++timerId;
      activeTimers.add(id);
      return id;
    },
    clearTimeout: (id) => activeTimers.delete(id),
  });
  if (publicBasePath) {
    vm.runInContext(pharosPublicPathSource, context);
  }
  vm.runInContext(fleetRuntimeSourcePrefix + exposeTestApi, context);
  return {
    api: context.__fleetTest,
    activeTimers,
    asOf,
    document,
    beats,
    events,
    main,
    summary,
  };
}

test("foreground recovery applies a fresh snapshot before clocks resume", async () => {
  const queue = deferredFetchQueue();
  const page = harness(queue.fetch);
  page.api.replaceApplyFleetSnapshot((data) => {
    page.events.push(`apply:${data.as_of}`);
    return true;
  });

  const recovery = page.api.recoverFleet("focus");
  assert.equal(page.main.dataset.fleetSyncState, "syncing");
  assert.deepEqual(page.events, ["stop"]);

  queue.pending[0].resolve(jsonResponse(snapshot(42)));
  assert.equal(await recovery, true);

  assert.deepEqual(page.events, ["stop", "apply:42", "resume"]);
  assert.equal(page.main.dataset.fleetSyncState, "current");
  assert.equal(page.asOf.dataset.refreshState, "current");
});

test("rapid suspend and focus cannot let an older request replace recovery", async () => {
  const queue = deferredFetchQueue();
  const page = harness(queue.fetch);
  const applied = [];
  page.api.replaceApplyFleetSnapshot((data) => {
    applied.push(data.as_of);
    return true;
  });

  const oldRecovery = page.api.recoverFleet("focus");
  page.api.suspendFleet();
  const currentRecovery = page.api.recoverFleet("focus-again");
  const duplicateRecovery = page.api.recoverFleet("duplicate-focus");

  assert.equal(queue.pending.length, 2);
  assert.equal(currentRecovery, duplicateRecovery);
  queue.pending[1].resolve(jsonResponse(snapshot(200)));

  assert.equal(await oldRecovery, false);
  assert.equal(await currentRecovery, true);
  assert.deepEqual(applied, [200]);
  assert.equal(page.main.dataset.fleetSyncState, "current");
});

test("failed foreground synchronization preserves state and reports stale data", async () => {
  const queue = deferredFetchQueue();
  const page = harness(queue.fetch);
  page.api.replaceApplyFleetSnapshot(() => {
    throw new Error("must not apply an invalid response");
  });

  const beat = { dataset: { beatLive: "true" } };
  page.beats.push(beat);
  const recovery = page.api.recoverFleet("visible");
  queue.pending[0].resolve(
    jsonResponse({}, {
      redirected: true,
      headers: { get: () => "text/html" },
    }),
  );

  assert.equal(await recovery, false);
  assert.equal(page.main.dataset.fleetSyncState, "stale");
  assert.equal(beat.dataset.beatLive, "false");
  assert.match(page.asOf.textContent, /^Data out of date/);
  assert.deepEqual(page.events, ["stop"]);
});

test("summary counters reconcile from the same host snapshot", () => {
  const page = harness(async () => jsonResponse(snapshot()));
  page.api.updateFleetSummary(snapshot().hosts);

  assert.equal(page.summary.get("all").textContent, "4");
  assert.equal(page.summary.get("live").textContent, "1");
  assert.equal(page.summary.get("stale").textContent, "1");
  assert.equal(page.summary.get("down").textContent, "1");
});

test("fleet refresh requests hosts.json through appUrl at root and prefixed mounts", async () => {
  const rootUrls = [];
  const rootPage = harness(async (url) => {
    rootUrls.push(url);
    return jsonResponse(snapshot());
  });
  rootPage.api.replaceApplyFleetSnapshot(() => true);
  assert.equal(await rootPage.api.refresh("manual"), true);
  assert.equal(rootUrls.length, 1);
  assert.match(rootUrls[0], /^\/hosts\.json\?refresh=\d+$/);

  const prefixedUrls = [];
  const prefixedPage = harness(
    async (url) => {
      prefixedUrls.push(url);
      return jsonResponse(snapshot());
    },
    { publicBasePath: "/pharos" },
  );
  prefixedPage.api.replaceApplyFleetSnapshot(() => true);
  assert.equal(await prefixedPage.api.refresh("manual"), true);
  assert.equal(prefixedUrls.length, 1);
  assert.match(prefixedUrls[0], /^\/pharos\/hosts\.json\?refresh=\d+$/);
});

test("suspension cancels polling instead of trusting background timers", async () => {
  const queue = deferredFetchQueue();
  const page = harness(queue.fetch);

  const refresh = page.api.refresh("timer");
  assert.equal(page.api.state().refreshActive, true);
  page.document.hidden = true;
  page.api.suspendFleet();

  assert.equal(await refresh, false);
  assert.equal(page.api.state().refreshActive, false);
  assert.equal(page.activeTimers.size, 0);
  assert.equal(page.events.at(-1), "stop");
});

const pureStart = fleetRuntimeSource.indexOf("const HISTORY_DOTS=12;");
const pureEnd = fleetRuntimeSource.indexOf("/* TIMELINE_PURE_END */");
const clockStart = fleetRuntimeSource.indexOf("let beatClockTimer=null;");
const clockEnd = fleetRuntimeSource.indexOf("/* TIMELINE_CLOCK_END */");
const listenerEnd = fleetRuntimeSource.indexOf("/* FLEET_LISTENERS_END */");

assert.notEqual(pureStart, -1, "timeline pure block must exist");
assert.notEqual(pureEnd, -1, "timeline pure block must end");
assert.notEqual(clockStart, -1, "beat clock block must exist");
assert.notEqual(clockEnd, -1, "beat clock block must end");
assert.notEqual(listenerEnd, -1, "fleet listener block must end");

function legacyHeartbeatX(age, interval) {
  if (age <= interval) return (age / interval) * 64;
  if (age <= interval * 2) return 64 + ((age - interval) / interval) * (82 - 64);
  if (age <= interval * 5) return 82 + ((age - interval * 2) / (interval * 3)) * (100 - 82);
  return 100;
}

function loadPure() {
  const source = `${fleetRuntimeSource.slice(pureStart, pureEnd)}
globalThis.__pure = {
  heartbeatTiming,
  heartbeatTimelineX,
  resolveHeartbeatGrace,
  projectDailyBackup,
  projectRestoreStatus,
  projectHealth,
  arrivalPresentation,
  dedupeHeartbeats,
  aggregateHistory,
  historyInfo,
  signalInfo,
};
`;
  const context = vm.createContext({ console });
  vm.runInContext(source, context);
  return context.__pure;
}

function vmPlain(value) {
  return JSON.parse(JSON.stringify(value));
}

test("grace, restore, and history projections follow the shared contracts", () => {
  const api = loadPure();
  const now = 2_000_000_000;
  const windowDef = { key: "10m", label: "10m", secs: 600 };

  assert.equal(api.heartbeatTiming(75, 60, 15), "on-time");
  assert.equal(api.heartbeatTiming(76, 60, 15), "late");
  assert.equal(api.heartbeatTiming(20, 10, 15), "on-time");
  assert.equal(api.heartbeatTiming(21, 10, 15), "stale");
  assert.equal(api.heartbeatTiming(51, 10, 15), "down");
  for (const age of [0, 30, 60, 61, 90, 120, 121, 200, 300, 301]) {
    assert.equal(api.heartbeatTimelineX(age, 60, 0), legacyHeartbeatX(age, 60));
  }

  assert.deepEqual(vmPlain(api.resolveHeartbeatGrace({}, undefined)), { secs: 15, source: "default", lateAfter: null });
  const hostGrace = api.resolveHeartbeatGrace({
    heartbeat_grace: { effective_secs: 0, source: "host", late_after_secs: 60 },
  }, 15);
  assert.equal(hostGrace.secs, 0);
  assert.equal(hostGrace.source, "host");
  assert.equal(api.resolveHeartbeatGrace({}, 40).source, "fleet");
  assert.equal(api.resolveHeartbeatGrace({ preferences: { alerts: { heartbeat_grace_secs: 0 } } }, 40).secs, 0);

  const current = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 2_592_000, restored_files: 1 },
  }], now);
  assert.equal(current.state, "passed");
  assert.equal(current.tone, "good");
  assert.equal(current.overdue, false);

  const overdue = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 2_592_001, restored_files: 1 },
  }], now);
  assert.equal(overdue.state, "overdue");
  assert.equal(overdue.tone, "amber");
  assert.equal(overdue.overdue, true);

  const checkOnly = api.projectRestoreStatus([{
    restore_validation: { level: "repository-check", state: "passed", checked_at: now - 10 },
  }], now);
  assert.equal(checkOnly.state, "unknown");
  assert.notEqual(checkOnly.tone, "good");

  const countedOut = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, restored_files: 0 },
  }], now);
  assert.equal(countedOut.state, "unknown");
  assert.notEqual(countedOut.tone, "good");

  const failed = api.projectRestoreStatus([
    { restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 100, restored_files: 1 } },
    { restore_validation: { level: "restore-sample", state: "failed", checked_at: now - 10 } },
  ], now);
  assert.equal(failed.state, "failed");
  assert.equal(failed.tone, "bad");
  assert.match(failed.detail, /last successful selective restore/);

  const legacyWithoutEvidence = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10 },
  }], now);
  assert.equal(legacyWithoutEvidence.state, "unknown");
  assert.equal(legacyWithoutEvidence.label, "Not observed");
  assert.match(legacyWithoutEvidence.detail, /No restored-file evidence/);

  const retainedAfterFailure = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "failed", checked_at: now - 10, last_success_at: now - 5 * 86_400, restored_files: 2 },
  }], now);
  assert.equal(retainedAfterFailure.state, "failed");
  assert.equal(retainedAfterFailure.at, now - 5 * 86_400);
  assert.match(retainedAfterFailure.detail, /last successful selective restore 5d ago/);

  const retainedBoundary = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "stale", checked_at: now - 10, last_success_at: now - 2_592_000, restored_files: 1 },
  }], now);
  assert.equal(retainedBoundary.overdue, false);
  assert.equal(retainedBoundary.at, now - 2_592_000);
  const retainedOverdue = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "stale", checked_at: now - 10, last_success_at: now - 2_592_001, restored_files: 1 },
  }], now);
  assert.equal(retainedOverdue.state, "overdue");
  assert.equal(retainedOverdue.overdue, true);

  const daily = api.projectDailyBackup([{
    state: "healthy", schedule: "daily", last_success_at: now - 50,
  }], now);
  assert.equal(daily.label, "Daily OK");
  assert.equal(daily.tone, "good");
  assert.equal(daily.state, "ok");
  const hourly = api.projectDailyBackup([{
    state: "healthy", schedule: "hourly", last_success_at: now - 50,
  }], now);
  assert.equal(hourly.label, "Successful");
  assert.equal(hourly.tone, "good");
  const disabled = api.projectDailyBackup([{ configured: "disabled", state: "unknown" }], now);
  assert.equal(disabled.state, "disabled");
  assert.equal(disabled.tone, "amber");
  assert.equal(disabled.label, "Disabled");
  assert.match(disabled.detail, /not an exemption/);
  assert.notEqual(api.projectRestoreStatus([{ configured: "disabled", state: "unknown" }], now).state, "not-required");
  const disabledFailed = api.projectDailyBackup([{
    configured: "disabled", state: "failed", last_success_at: now - 10,
  }], now);
  assert.equal(disabledFailed.state, "failed");
  assert.equal(disabledFailed.label, "Failed");
  assert.equal(disabledFailed.tone, "bad");
  assert.equal(api.projectDailyBackup([{ state: "healthy", schedule: "daily" }], now).label, "Success time unknown");
  const exactFresh = api.projectDailyBackup([{
    state: "healthy", schedule: "daily", last_success_at: now - 129600,
  }], now);
  assert.equal(exactFresh.label, "Daily OK");
  assert.equal(exactFresh.tone, "good");
  const justStale = api.projectDailyBackup([{
    state: "healthy", schedule: "daily", last_success_at: now - 129601,
  }], now);
  assert.equal(justStale.state, "stale");
  assert.equal(justStale.tone, "amber");
  assert.equal(justStale.label, "Stale");
  const future = api.projectDailyBackup([{
    state: "healthy", schedule: "daily", last_success_at: now + 3,
  }], now);
  assert.notEqual(future.tone, "good");
  assert.equal(future.state, "stale");
  assert.equal(future.label, "Stale");
  const staleDaily = api.projectDailyBackup([{
    state: "healthy", schedule: "daily", last_success_at: now - 3 * 24 * 60 * 60,
  }], now);
  assert.equal(staleDaily.state, "stale");
  assert.equal(staleDaily.tone, "amber");
  assert.equal(staleDaily.label, "Stale");
  assert.notEqual(staleDaily.label, "Daily OK");
  const recentRestore = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10 * 24 * 60 * 60, restored_files: 1 },
  }], now);
  assert.equal(recentRestore.tone, "good");
  assert.equal(recentRestore.state, "passed");
  assert.equal(recentRestore.overdue, false);
  const sameHostJobs = [
    { repository_id: "repo-a", state: "failed", schedule: "daily", last_success_at: now - 3 * 24 * 60 * 60 },
    { repository_id: "repo-b", state: "healthy", schedule: "daily", last_success_at: now - 10, restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, files_restored: 1, restored_files: 1 } },
  ];
  const sameHostRestore = api.projectRestoreStatus(sameHostJobs, now);
  assert.equal(sameHostRestore.state, "passed");
  assert.equal(sameHostRestore.tone, "good");
  assert.equal(sameHostRestore.overdue, false);
  const sameHostDaily = api.projectDailyBackup(sameHostJobs, now);
  assert.equal(sameHostDaily.label, "Failed");
  assert.equal(sameHostDaily.tone, "bad");
  const noCrossHost = api.projectRestoreStatus([sameHostJobs[0]], now);
  assert.equal(noCrossHost.state, "unknown");
  assert.notEqual(noCrossHost.tone, "good");
  const zeroFromOtherJob = api.projectRestoreStatus([
    { repository_id: "repo-a", state: "failed", schedule: "daily", last_success_at: now - 100 },
    { repository_id: "repo-b", state: "healthy", schedule: "daily", restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, restored_files: 0 } },
  ], now);
  assert.equal(zeroFromOtherJob.state, "unknown");
  assert.notEqual(zeroFromOtherJob.tone, "good");
  const ownedRestore = api.projectRestoreStatus([
    { repository_id: "repo-a", state: "healthy", schedule: "daily", last_success_at: now - 50, restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, restored_files: 1 } },
  ], now);
  assert.equal(ownedRestore.tone, "good");
  assert.equal(ownedRestore.state, "passed");
  const borrowedDaily = api.projectDailyBackup([
    { repository_id: "repo-a", state: "failed", schedule: "daily", last_success_at: now - 3 * 24 * 60 * 60 },
    { repository_id: "repo-b", state: "healthy", schedule: "daily", last_success_at: now - 10, restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, restored_files: 1 } },
  ], now);
  assert.equal(borrowedDaily.label, "Failed");
  assert.equal(borrowedDaily.tone, "bad");
  const mixed = api.projectHealth({
    liveness: "live",
    backup: staleDaily,
    restore: recentRestore,
    check: null,
    services: [],
    kernelRestart: false,
    freshness: null,
  });
  assert.equal(mixed.tone, "amber");
  assert.equal(mixed.summary, "Backup Stale");
  assert.equal(mixed.count, 1);
  assert.ok(mixed.reasons.every((reason) => reason.tone !== "good"));
  assert.ok(mixed.reasons.some((reason) => reason.label === "Backup Stale"));
  assert.equal(mixed.reasons.some((reason) => reason.label === "Passed"), false);
  const arrival = api.arrivalPresentation(now - 10, 60, 15, now);
  assert.equal(arrival.state, "on-time");
  assert.equal(arrival.label, "On time");
  assert.doesNotMatch(`${arrival.label} ${arrival.detail}`, /%|Arrival scale|time axis|empty is not healthy/);

  const health = api.projectHealth({
    liveness: "live",
    backup: daily,
    restore: overdue,
    check: null,
    services: [],
    kernelRestart: false,
    freshness: null,
  });
  assert.equal(health.tone, "amber");
  assert.equal(health.summary, "Restore Overdue");
  assert.equal(health.reasons.some((reason) => reason.tone === "good"), false);
  assert.ok(health.reasons.some((reason) => reason.label === "Restore Overdue"));
  const suppressed = api.projectHealth({
    liveness: "down",
    expectedOffline: false,
    backup: daily,
    restore: recentRestore,
    check: null,
    services: [],
    kernelRestart: false,
    freshness: null,
  });
  assert.equal(suppressed.tone, "bad");
  assert.equal(suppressed.label, "Not reporting");
  assert.equal(suppressed.summary, "Not reporting");
  assert.equal(suppressed.reasons.some((reason) => reason.label === "Offline as expected"), false);
  assert.equal(suppressed.reasons.some((reason) => reason.tone === "good"), false);

  assert.deepEqual(vmPlain(api.dedupeHeartbeats([5, 5.4, 5.9, 6.5])), [5, 6.5]);
  const start = now - 600;
  const gapped = api.aggregateHistory([start + 10, start + 400], windowDef, now, 60, 15);
  assert.equal(gapped.marks.some((mark) => mark.level === "ok"), false);
  assert.equal(gapped.marks.some((mark) => mark.level === "unknown"), false);
  const downMark = gapped.marks.find((mark) => mark.level === "down");
  assert.ok(downMark);
  assert.ok(Math.abs(downMark.x - (400 / 600) * 100) < 0.2);
  assert.equal(api.historyInfo([now + 30], 0, 60, 15, now).level, "unknown");
  const first = api.aggregateHistory([now - 10], windowDef, now, 60, 15);
  const futureOnly = api.aggregateHistory([now + 30], windowDef, now, 60, 15);
  const empty = api.aggregateHistory([], windowDef, now, 60, 15);
  assert.deepEqual(vmPlain(first.marks), []);
  assert.deepEqual(vmPlain(futureOnly.marks), []);
  assert.deepEqual(vmPlain(empty.marks), []);
  for (const view of [first, futureOnly, empty, gapped]) {
    assert.equal(view.axisNowX, 100);
    assert.equal(view.axisStartX, 100);
  }
});

test("shared history fixture keeps the worst bucket event in both projections", () => {
  const api = loadPure();
  const fixture = JSON.parse(readFileSync(new URL("./fixtures/history-worst-bucket.json", import.meta.url), "utf8"));
  assert.ok(fixture.cases.find((item) => item.name === "worst-in-bucket").samples.length > 12);
  for (const item of fixture.cases) {
    const view = api.aggregateHistory(item.samples, { secs: item.windowSecs }, item.now, item.interval, item.grace);
    assert.equal(view.axisNowX, 100, item.name);
    assert.equal(view.axisStartX, 100, item.name);
    assert.equal(view.partial, item.expect.partial, item.name);
    assert.deepEqual(vmPlain(view.marks).map((mark) => ({
      stamp: mark.stamp,
      level: mark.level,
      label: mark.label,
    })), item.expect.marks.map((mark) => ({
      stamp: mark.stamp,
      level: mark.level,
      label: mark.label,
    })), item.name);
    for (const mark of view.marks) {
      assert.equal(mark.key, `sample:${mark.stamp}`, item.name);
      assert.match(mark.detail, /after previous/, item.name);
      assert.ok(mark.label && mark.detail, item.name);
      const expected = item.expect.marks.find((candidate) => candidate.stamp === mark.stamp);
      assert.ok(Math.abs(mark.x - expected.x) < 0.06, `${item.name} ${mark.stamp}`);
      if (item.expect.minX != null) assert.ok(mark.x >= item.expect.minX, item.name);
    }
    for (const hidden of item.expect.hiddenStamps || []) {
      assert.equal(view.marks.some((mark) => mark.stamp === hidden), false, `${item.name} ${hidden}`);
    }
    if (item.arrival) {
      const arrival = api.arrivalPresentation(item.arrival.last, item.interval, item.grace, item.now);
      assert.equal(arrival.state, item.arrival.state, item.name);
      assert.equal(view.marks.some((mark) => mark.stamp === item.now), false, item.name);
    }
  }
});

function historyMarkDom() {
  function linkChildren(parent) {
    parent.childNodes.forEach((node, index) => {
      node.parentNode = parent;
      node.nextSibling = parent.childNodes[index + 1] || null;
    });
  }
  const document = {
    body: null,
    activeElement: null,
    getElementById() { return null; },
    createElement: null,
  };
  function element(tag) {
    return {
      tag,
      className: "",
      dataset: {},
      attributes: {},
      title: "",
      tabIndex: 0,
      childNodes: [],
      parentNode: null,
      nextSibling: null,
      inserts: [],
      get firstChild() {
        return this.childNodes[0] || null;
      },
      style: {
        props: {},
        setProperty(name, value) { this.props[name] = String(value); },
      },
      setAttribute(name, value) { this.attributes[name] = String(value); },
      getAttribute(name) { return this.attributes[name]; },
      removeAttribute(name) { delete this.attributes[name]; },
      focus() { document.activeElement = this; },
      blur() {
        if (document.activeElement === this) document.activeElement = document.body;
      },
      remove() {
        if (!this.parentNode) return;
        const parent = this.parentNode;
        parent.childNodes = parent.childNodes.filter((node) => node !== this);
        linkChildren(parent);
        this.parentNode = null;
        this.nextSibling = null;
      },
      insertBefore(child, ref) {
        const movingFocused = !!(child.parentNode && document.activeElement === child);
        if (child.parentNode) {
          child.parentNode.childNodes = child.parentNode.childNodes.filter((node) => node !== child);
          linkChildren(child.parentNode);
        }
        const at = ref == null ? this.childNodes.length : this.childNodes.indexOf(ref);
        this.childNodes.splice(at, 0, child);
        linkChildren(this);
        this.inserts.push(child);
        if (movingFocused) child.blur();
        return child;
      },
      querySelectorAll(selector) {
        if (selector !== ".beat-mark") return [];
        return this.childNodes.filter((node) => String(node.className).split(/\s+/).includes("beat-mark"));
      },
    };
  }
  document.body = element("body");
  document.createElement = element;
  return { document, element };
}

function loadHistoryReconcile(document) {
  const sourceStart = fleetRuntimeSource.indexOf("let activeHistoryMark=null;");
  const sourceEnd = fleetRuntimeSource.indexOf("function updateHistoryEvents");
  const context = vm.createContext({ console, document });
  vm.runInContext(`const CLOCK_SKEW_SECS=2;
${fleetRuntimeSource.slice(sourceStart, sourceEnd)}
globalThis.__history = {
  reconcileHistoryMarks,
  hover(mark){ activeHistoryMark=mark; historyPin=null; },
  pin(mark, mode){ activeHistoryMark=mark; historyPin=mode; },
  clear(){ activeHistoryMark=null; historyPin=null; },
};
`, context);
  return context.__history;
}

test("history refresh leaves an ordered mark attached", () => {
  const sourceEnd = fleetRuntimeSource.indexOf("function updateHistoryEvents");
  const reconcileBody = fleetRuntimeSource.slice(
    fleetRuntimeSource.indexOf("function reconcileHistoryMarks"),
    sourceEnd,
  );
  assert.equal(reconcileBody.includes("appendChild"), false);
  assert.match(reconcileBody, /insertBefore/);
  assert.match(fleetRuntimeSource, /marks\.dataset\.historyStart=String\(view\.start\)/);
  assert.match(fleetRuntimeSource, /marks\.dataset\.historyEnd=String\(view\.end\)/);

  const { document, element } = historyMarkDom();
  const history = loadHistoryReconcile(document);
  const container = element("span");
  const kept = element("span");
  kept.className = "beat-mark";
  kept.dataset.historyKey = "sample:50";
  container.insertBefore(kept, null);
  container.inserts = [];
  document.activeElement = kept;
  history.reconcileHistoryMarks(container, [{
    key: "sample:50",
    x: 40,
    stamp: 50,
    level: "late",
    label: "late heartbeat",
    detail: "90s after previous · 08:00",
  }]);
  assert.equal(container.inserts.length, 0);
  assert.equal(document.activeElement, kept);
  assert.equal(kept.parentNode, container);
  assert.equal(kept.dataset.historyLabel, "late heartbeat");
  assert.match(kept.getAttribute("aria-label"), /after previous/);

  history.reconcileHistoryMarks(container, [
    {
      key: "sample:50",
      x: 40,
      stamp: 50,
      level: "late",
      label: "late heartbeat",
      detail: "90s after previous · 08:00",
    },
    {
      key: "sample:80",
      x: 70,
      stamp: 80,
      level: "ok",
      label: "on cadence",
      detail: "30s after previous · 08:01",
    },
  ]);
  assert.equal(document.activeElement, kept);
  assert.equal(container.inserts.length, 1);
  assert.equal(container.inserts[0], container.childNodes[1]);
  assert.notEqual(container.inserts[0], kept);
  assert.equal(container.childNodes[0], kept);

  history.reconcileHistoryMarks(container, [{
    key: "sample:80",
    x: 70,
    stamp: 80,
    level: "ok",
    label: "on cadence",
    detail: "30s after previous · 08:01",
  }]);
  assert.equal(kept.parentNode, null);
  assert.equal(document.activeElement, document.body);
  assert.equal(container.childNodes.some((node) => node.dataset.historyKey === "sample:50"), false);

  const reorder = [
    { key: "sample:10", x: 10, stamp: 10, level: "ok", label: "on cadence", detail: "20s after previous · 08:00" },
    { key: "sample:20", x: 20, stamp: 20, level: "late", label: "late heartbeat", detail: "90s after previous · 08:01" },
    { key: "sample:30", x: 30, stamp: 30, level: "ok", label: "on cadence", detail: "20s after previous · 08:02" },
  ];
  history.reconcileHistoryMarks(container, [reorder[0], reorder[2], reorder[1]]);
  const moved = container.childNodes[2];
  assert.equal(moved.dataset.historyKey, "sample:20");
  document.activeElement = moved;
  history.reconcileHistoryMarks(container, reorder);
  assert.equal(document.activeElement, moved);
  assert.equal(container.childNodes.map((node) => node.dataset.historyKey).join(","), "sample:10,sample:20,sample:30");
  assert.equal(container.childNodes[1], moved);
});

test("daily and restore projections follow the shared evidence contract", () => {
  const api = loadPure();
  const now = 1_700_000_000;
  const day = 24 * 60 * 60;
  const fresh = { state: "healthy", schedule: "daily", last_success_at: now - 60 };
  const stale = { state: "healthy", schedule: "daily", last_success_at: now - 129601 };
  for (const jobs of [[fresh, stale], [stale, fresh]]) {
    const daily = api.projectDailyBackup(jobs, now);
    assert.equal(daily.state, "stale");
    assert.equal(daily.tone, "amber");
    assert.equal(daily.label, "Stale");
    assert.equal(daily.at, now - 129601);
    assert.notEqual(daily.label, "Daily OK");
  }
  const missingTime = { state: "healthy", schedule: "daily" };
  for (const jobs of [[fresh, missingTime], [missingTime, fresh]]) {
    const daily = api.projectDailyBackup(jobs, now);
    assert.notEqual(daily.tone, "good");
    assert.equal(daily.state, "unknown");
    assert.equal(daily.label, "Success time unknown");
    assert.equal(daily.at, null);
  }
  const disabled = { configured: "disabled", state: "unknown" };
  for (const jobs of [[fresh, disabled], [disabled, fresh]]) {
    const daily = api.projectDailyBackup(jobs, now);
    assert.notEqual(daily.tone, "good");
    assert.equal(daily.state, "disabled");
    assert.equal(daily.tone, "amber");
    assert.equal(daily.label, "Disabled");
  }
  const missing = api.projectDailyBackup([
    fresh,
    { state: "missing", last_success_at: now - 10 },
  ], now);
  assert.equal(missing.state, "missing");
  assert.equal(missing.tone, "bad");
  const failed = api.projectDailyBackup([
    { state: "not-required", summary: "No backup is required" },
    { state: "failed", last_success_at: now - 10 },
  ], now);
  assert.equal(failed.state, "failed");
  assert.equal(failed.tone, "bad");
  assert.equal(api.projectDailyBackup([
    { state: "not-required", summary: "No backup is required" },
  ], now).state, "not-required");

  // Every matrix record carries restored-file evidence; the evidence gate has its own cases above.
  const restore = (records) => api.projectRestoreStatus(records.map((record) => ({
    restore_validation: { level: "restore-sample", restored_files: 1, ...record },
  })), now);
  const futureOnly = restore([{ state: "passed", checked_at: now + 86400 }]);
  assert.equal(futureOnly.state, "unknown");
  assert.notEqual(futureOnly.tone, "good");
  assert.notEqual(futureOnly.state, "passed");
  for (const records of [
    [{ state: "passed", checked_at: now - 10 }, { state: "passed", checked_at: now + 86400 }],
    [{ state: "passed", checked_at: now + 86400 }, { state: "passed", checked_at: now - 10 }],
  ]) {
    const kept = restore(records);
    assert.equal(kept.state, "passed");
    assert.equal(kept.tone, "good");
    assert.equal(kept.at, now - 10);
    assert.equal(kept.overdue, false);
  }
  for (const adverse of ["stale", "unknown"]) {
    for (const records of [
      [{ state: "passed", checked_at: now - 100 }, { state: adverse, checked_at: now - 10 }],
      [{ state: adverse, checked_at: now - 10 }, { state: "passed", checked_at: now - 100 }],
    ]) {
      const newer = restore(records);
      assert.equal(newer.state, "unknown", adverse);
      assert.equal(newer.tone, "neutral", adverse);
      assert.equal(newer.label, "Unknown", adverse);
      assert.equal(newer.at, now - 100, adverse);
      assert.equal(newer.overdue, false, adverse);
      assert.match(newer.detail, /last successful selective restore/);
      assert.notEqual(newer.tone, "good");
    }
  }
  for (const records of [
    [{ state: "passed", checked_at: now - 100 }, { state: "failed", checked_at: now - 10 }],
    [{ state: "failed", checked_at: now - 10 }, { state: "passed", checked_at: now - 100 }],
  ]) {
    const newerFailed = restore(records);
    assert.equal(newerFailed.state, "failed");
    assert.equal(newerFailed.tone, "bad");
    assert.equal(newerFailed.at, now - 100);
    assert.match(newerFailed.detail, /last successful selective restore/);
  }
  const exact = restore([{ state: "passed", checked_at: now - 30 * day }]);
  assert.equal(exact.state, "passed");
  assert.equal(exact.tone, "good");
  assert.equal(exact.at, now - 30 * day);
  assert.equal(exact.overdue, false);
  const overdue = restore([{ state: "passed", checked_at: now - 30 * day - 1 }]);
  assert.equal(overdue.state, "overdue");
  assert.equal(overdue.tone, "amber");
  assert.equal(overdue.at, now - 30 * day - 1);
  assert.equal(overdue.overdue, true);
  const agedStale = restore([
    { state: "passed", checked_at: now - 30 * day - 1 },
    { state: "stale", checked_at: now - 10 },
  ]);
  assert.equal(agedStale.state, "overdue");
  assert.equal(agedStale.tone, "amber");
  assert.equal(agedStale.at, now - 30 * day - 1);
  const agedFailed = restore([
    { state: "stale", checked_at: now - 10 },
    { state: "passed", checked_at: now - 30 * day - 1 },
    { state: "failed", checked_at: now - 10 },
  ]);
  assert.equal(agedFailed.state, "failed");
  assert.equal(agedFailed.tone, "bad");
  assert.equal(agedFailed.at, now - 30 * day - 1);
  for (const checked_at of [0, -1, null, undefined, "", 1.5, Number.NaN, now + 3, "9223372036854775807", 253402300800]) {
    const absent = restore([{ state: "passed", checked_at }]);
    assert.notEqual(absent.state, "passed", String(checked_at));
    assert.notEqual(absent.tone, "good", String(checked_at));
    assert.equal(absent.at, null, String(checked_at));
  }
  assert.equal(restore([{ state: "passed", checked_at: now + 2 }]).state, "passed");
  const futureFailed = restore([
    { state: "failed", checked_at: now + 86400 },
    { state: "passed", checked_at: now - 10 },
  ]);
  assert.equal(futureFailed.state, "passed");
  assert.equal(futureFailed.tone, "good");
  assert.equal(futureFailed.at, now - 10);
  for (const adverse of ["failed", "stale", "unknown"]) {
    for (const states of [["passed", adverse], [adverse, "passed"]]) {
      const tied = restore(states.map((state) => ({ state, checked_at: now - 50 })));
      assert.notEqual(tied.tone, "good", states.join(","));
      assert.notEqual(tied.state, "passed", states.join(","));
      assert.equal(tied.state, "unknown", states.join(","));
      assert.equal(tied.tone, "neutral", states.join(","));
      assert.equal(tied.label, "Unknown", states.join(","));
      assert.equal(tied.at, now - 50, states.join(","));
    }
  }
});

test("advancing history buckets keep the engaged mark until interaction ends", () => {
  const api = loadPure();
  const now = 1_700_000_000;
  const windowDef = { key: "10m", label: "10m", secs: 600 };
  const samples = [];
  for (let stamp = now - 600; stamp <= now; stamp += 20) samples.push(stamp);
  const before = api.aggregateHistory(samples, windowDef, now, 60, 15);
  const after = api.aggregateHistory(samples, windowDef, now + 10, 60, 15);
  const afterKeys = new Set(after.marks.map((mark) => mark.key));
  const dropped = before.marks.filter((mark) => !afterKeys.has(mark.key));
  assert.equal(before.marks.length, 12);
  assert.equal(after.marks.length, 12);
  assert.equal(dropped.length, 5);
  for (const mark of dropped) {
    assert.ok(mark.stamp >= after.start && mark.stamp <= after.end + 2, String(mark.stamp));
  }

  const { document } = historyMarkDom();
  const history = loadHistoryReconcile(document);
  const container = document.createElement("span");
  function publish(view) {
    container.dataset.historyStart = String(view.start);
    container.dataset.historyEnd = String(view.end);
    history.reconcileHistoryMarks(container, view.marks);
  }
  function markFor(spec) {
    return container.childNodes.find((node) => node.dataset.historyKey === spec.key);
  }
  function geometry(node, view) {
    const stamp = Number(node.dataset.historyStamp);
    const expected = ((stamp - view.start) / (view.end - view.start)) * 100;
    return Math.abs(parseFloat(node.style.props["--mark-x"]) - Number(expected.toFixed(1))) < 0.001;
  }

  publish(before);
  const focusedSpec = dropped[0];
  const focused = markFor(focusedSpec);
  const focusedDetail = focused.getAttribute("aria-label");
  assert.match(focusedDetail, /after previous/);
  document.activeElement = focused;
  publish(after);
  assert.equal(focused.parentNode, container);
  assert.equal(document.activeElement, focused);
  assert.equal(focused.getAttribute("aria-label"), focusedDetail);
  assert.equal(focused.dataset.historyDetail, focusedSpec.detail);
  assert.equal(geometry(focused, after), true);
  assert.equal(container.childNodes.length, after.marks.length + 1);
  assert.equal(container.childNodes.filter((node) => node.dataset.historyKey === focusedSpec.key).length, 1);
  for (const spec of dropped.slice(1)) {
    assert.equal(container.childNodes.some((node) => node.dataset.historyKey === spec.key), false);
  }
  for (const spec of after.marks) {
    assert.equal(container.childNodes.some((node) => node.dataset.historyKey === spec.key), true);
  }
  document.activeElement = document.body;
  history.clear();
  publish(after);
  assert.equal(focused.parentNode, null);
  assert.equal(document.activeElement, document.body);
  assert.equal(container.childNodes.length, after.marks.length);
  assert.equal(container.childNodes.some((node) => node.dataset.historyKey === focusedSpec.key), false);

  publish(before);
  const hoveredSpec = dropped[1];
  const hovered = markFor(hoveredSpec);
  const hoveredDetail = hovered.getAttribute("aria-label");
  document.activeElement = document.body;
  history.hover(hovered);
  publish(after);
  assert.equal(hovered.parentNode, container);
  assert.equal(document.activeElement, document.body);
  assert.equal(hovered.getAttribute("aria-label"), hoveredDetail);
  assert.equal(geometry(hovered, after), true);
  assert.equal(container.childNodes.length, after.marks.length + 1);
  history.clear();
  publish(after);
  assert.equal(hovered.parentNode, null);
  assert.equal(container.childNodes.length, after.marks.length);

  publish(before);
  const pinnedSpec = dropped[2];
  const pinned = markFor(pinnedSpec);
  const pinnedDetail = pinned.getAttribute("aria-label");
  document.activeElement = document.body;
  history.pin(pinned, "touch");
  publish(after);
  assert.equal(pinned.parentNode, container);
  assert.equal(pinned.getAttribute("aria-label"), pinnedDetail);
  assert.equal(pinned.dataset.historyLabel, pinnedSpec.label);
  assert.equal(container.childNodes.length, after.marks.length + 1);
  history.clear();
  publish(after);
  assert.equal(pinned.parentNode, null);
  assert.equal(container.childNodes.some((node) => node.dataset.historyKey === pinnedSpec.key), false);

  publish(before);
  const aged = markFor(dropped[3]);
  document.activeElement = aged;
  container.dataset.historyStart = String(Number(aged.dataset.historyStamp) + 10);
  container.dataset.historyEnd = String(Number(aged.dataset.historyStamp) + 610);
  history.reconcileHistoryMarks(container, after.marks);
  assert.equal(aged.parentNode, null);
  assert.equal(document.activeElement, document.body);
  assert.ok(container.childNodes.length <= 12);
});

test("down-alert suppression and exact times follow the scan contract", () => {
  const attentionStart = fleetRuntimeSource.indexOf("function expectedOfflineHost");
  const attentionEnd = fleetRuntimeSource.indexOf("const BACKUP_RANK=");
  const attentionContext = vm.createContext({ console });
  vm.runInContext(`
function freshnessAttention(){return null}
${fleetRuntimeSource.slice(attentionStart, attentionEnd)}
globalThis.__attention = { expectedOfflineHost, attentionFor };
`, attentionContext);
  const attention = attentionContext.__attention;
  const suppressed = { kind: "server", alerts: { suppress_down: true } };
  assert.equal(attention.expectedOfflineHost({ preferences: suppressed, service_observations: [] }), false);
  assert.equal(attention.attentionFor("down", null, suppressed, 1).label, "silent heartbeat");
  assert.equal(attention.attentionFor("down", null, suppressed, 1).level, "down");
  assert.equal(attention.expectedOfflineHost({ preferences: { kind: "workstation" }, service_observations: [] }), true);
  assert.equal(attention.attentionFor("down", null, { kind: "workstation" }, 1).label, "offline as expected");
  assert.equal(attention.expectedOfflineHost({
    preferences: { kind: "server" },
    service_observations: [{ id: "appliance-convergence", summary: "powered off as expected" }],
  }), true);

  const factStart = fleetRuntimeSource.indexOf("function setFactText");
  const factEnd = fleetRuntimeSource.indexOf("function updateHealthProjection");
  function factNode() {
    return {
      hidden: false,
      dataset: {},
      childNodes: [],
      attributes: {},
      className: "",
      textContent: "",
      parentElement: null,
      setAttribute(name, value) { this.attributes[name] = String(value); },
      appendChild(child) {
        child.parentElement = this;
        this.childNodes.push(child);
        return child;
      },
      remove() {
        if (!this.parentElement) return;
        this.parentElement.childNodes = this.parentElement.childNodes.filter((child) => child !== this);
        this.parentElement = null;
      },
      querySelector(selector) {
        const wanted = selector.startsWith("[") ? selector.slice(1, -1) : "";
        const visit = (node) => {
          for (const child of node.childNodes) {
            if (wanted && Object.prototype.hasOwnProperty.call(child.attributes, wanted)) return child;
            const nested = visit(child);
            if (nested) return nested;
          }
          return null;
        };
        return visit(this);
      },
      querySelectorAll(selector) {
        const found = [];
        const visit = (node) => {
          for (const child of node.childNodes) {
            if (selector === ".fact-exact" && String(child.className).split(/\s+/).includes("fact-exact")) found.push(child);
            visit(child);
          }
        };
        visit(this);
        return found;
      },
    };
  }
  const created = [];
  const document = {
    createElement() {
      const node = factNode();
      created.push(node);
      return node;
    },
  };
  const factContext = vm.createContext({ console, document });
  vm.runInContext(`
function appUrl(path){return path}
const SELECTIVE_RESTORE_OVERDUE_SECS=2592000;
${fleetRuntimeSource.slice(factStart, factEnd)}
globalThis.__facts = { updateBackupStatus, listRestoreValue, utcObservedStamp, recordedUnix };
`, factContext);
  const daily = factNode();
  daily.dataset.host = "alpha";
  const label = factNode();
  label.attributes["data-daily-backup-label"] = "";
  const note = factNode();
  note.attributes["data-daily-backup-note"] = "";
  const time = factNode();
  time.attributes["data-daily-backup-date"] = "";
  const duplicate = factNode();
  duplicate.className = "fact-exact";
  note.appendChild(duplicate);
  daily.appendChild(label);
  daily.appendChild(note);
  daily.appendChild(time);
  const surface = {
    dataset: { host: "alpha" },
    querySelector(selector) {
      if (selector === "[data-daily-backup]") return daily;
      return null;
    },
  };
  const protection = {
    daily: { state: "ok", tone: "good", label: "Daily OK", detail: "last success 50s ago", at: 1_700_000_000 },
    restore: null,
    check: null,
  };
  factContext.__facts.updateBackupStatus(surface, protection);
  factContext.__facts.updateBackupStatus(surface, protection);
  const times = daily.childNodes.filter((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-daily-backup-date"));
  assert.equal(times.length, 1);
  assert.equal(times[0], time);
  assert.equal(times[0].attributes.datetime, "2023-11-14T22:13:20Z");
  assert.equal(times[0].textContent, "2023-11-14 22:13:20 UTC");
  assert.equal(note.childNodes.some((child) => String(child.className).includes("fact-exact")), false);
  assert.equal(created.filter((node) => Object.prototype.hasOwnProperty.call(node.attributes, "data-daily-backup-date")).length, 0);
  const passedRestore = { state: "passed", at: Math.floor(Date.now() / 1000) - 6 * 86400 };
  assert.match(factContext.__facts.listRestoreValue(passedRestore), /^Passed · \d+d$/);
  assert.equal(factContext.__facts.utcObservedStamp(1_700_000_000).iso, "2023-11-14T22:13:20Z");
  assert.equal(factContext.__facts.utcObservedStamp(1_700_000_000).visible, "2023-11-14 22:13:20 UTC");
  for (const missing of [null, undefined, "", 0, "0"]) {
    assert.equal(factContext.__facts.recordedUnix(missing), null);
    assert.equal(factContext.__facts.utcObservedStamp(missing), null);
  }
  for (const invalid of [1.5, Infinity, Number.NaN, true, "9223372036854775807", 1_700_000_000_000, 253402300800]) {
    assert.doesNotThrow(() => factContext.__facts.utcObservedStamp(invalid));
    assert.equal(factContext.__facts.recordedUnix(invalid), null);
    assert.equal(factContext.__facts.utcObservedStamp(invalid), null);
  }
  assert.equal(factContext.__facts.utcObservedStamp(253402300799).iso, "9999-12-31T23:59:59Z");
  assert.equal(factContext.__facts.utcObservedStamp(253402300799).visible, "9999-12-31 23:59:59 UTC");

  protection.daily.at = "9223372036854775807";
  assert.doesNotThrow(() => factContext.__facts.updateBackupStatus(surface, protection));
  assert.equal(daily.childNodes.some((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-daily-backup-date")), false);
  assert.equal(daily.dataset.dailyBackupAt, undefined);
  assert.equal(String(daily.textContent).includes("1970"), false);
  assert.equal(String(daily.textContent).includes("+"), false);

  protection.daily.at = 1_700_000_000;
  factContext.__facts.updateBackupStatus(surface, protection);
  protection.daily.at = 1_700_000_000_000;
  factContext.__facts.updateBackupStatus(surface, protection);
  assert.equal(daily.childNodes.some((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-daily-backup-date")), false);
  assert.equal(String(daily.textContent).includes("055840"), false);

  protection.daily.at = null;
  factContext.__facts.updateBackupStatus(surface, protection);
  const cleared = daily.childNodes.filter((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-daily-backup-date"));
  assert.equal(cleared.length, 0);
  assert.equal(daily.dataset.dailyBackupAt, undefined);
  assert.equal(created.some((node) => String(node.textContent).includes("1970")), false);
  assert.equal(String(daily.textContent).includes("1970"), false);

  const evidence = factNode();
  evidence.querySelector = factNode().querySelector;
  const evidenceSurface = {
    dataset: { host: "alpha" },
    querySelector(selector) {
      if (selector === "[data-daily-backup]") return daily;
      if (selector === "[data-protection-evidence]") return evidence;
      return null;
    },
  };
  protection.daily.at = 1_700_000_000;
  factContext.__facts.updateBackupStatus(evidenceSurface, protection);
  const disclosed = evidence.childNodes.filter((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-daily-backup-instant"));
  assert.equal(disclosed.length, 1);
  const disclosedTime = disclosed[0].querySelector("[data-daily-backup-date]");
  const disclosedLabel = disclosed[0].querySelector("[data-daily-backup-instant-label]");
  assert.equal(disclosedTime.attributes.datetime, "2023-11-14T22:13:20Z");
  assert.equal(disclosedTime.textContent, "2023-11-14 22:13:20 UTC");
  assert.equal(disclosedLabel.textContent, "Backup last success ");
  assert.equal(`${disclosedLabel.textContent}${disclosedTime.textContent}`, "Backup last success 2023-11-14 22:13:20 UTC");
  assert.equal(evidence.hidden, false);
  protection.restore = {
    state: "passed",
    tone: "good",
    label: "Passed",
    detail: "selective restore 1d ago",
    at: 1_699_136_000,
    overdue: false,
    producer: "passed",
  };
  const restore = factNode();
  evidenceSurface.querySelector = (selector) => {
    if (selector === "[data-daily-backup]") return daily;
    if (selector === "[data-restore]") return restore;
    if (selector === "[data-protection-evidence]") return evidence;
    return null;
  };
  factContext.__facts.updateBackupStatus(evidenceSurface, protection);
  const restoreInstant = evidence.childNodes.find((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-restore-instant"));
  assert.ok(restoreInstant);
  assert.equal(restoreInstant.querySelector("[data-restore-instant-label]").textContent, "Selective restore last success ");
  assert.equal(restoreInstant.querySelector("[data-restore-date]").attributes.datetime, "2023-11-04T22:13:20Z");
  assert.equal(evidence.querySelector("[data-due-instant]"), null);
  protection.daily.at = null;
  factContext.__facts.updateBackupStatus(evidenceSurface, protection);
  assert.equal(evidence.childNodes.some((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-daily-backup-instant")), false);
  assert.equal(evidence.querySelector("[data-daily-backup-instant-label]"), null);
  assert.equal(evidence.hidden, false);
  protection.restore.at = "9223372036854775807";
  factContext.__facts.updateBackupStatus(evidenceSurface, protection);
  assert.equal(evidence.childNodes.some((child) => Object.prototype.hasOwnProperty.call(child.attributes, "data-restore-instant")), false);
  assert.equal(evidence.querySelector("[data-restore-instant-label]"), null);
  assert.equal(evidence.hidden, true);
  assert.equal(created.some((node) => String(node.textContent).includes("1970")), false);
  assert.equal(created.some((node) => String(node.textContent).includes("Due")), false);
});

function controllableClock() {
  let now = 0;
  let seq = 0;
  const timers = new Map();
  function setTimeout(fn, ms) {
    const id = ++seq;
    timers.set(id, { fn, at: now + Number(ms || 0) });
    return id;
  }
  function clearTimeout(id) {
    timers.delete(id);
  }
  function advance(ms) {
    const end = now + ms;
    while (true) {
      let nextAt = null;
      let nextId = null;
      for (const [id, timer] of timers) {
        if (timer.at <= end && (nextAt == null || timer.at < nextAt || (timer.at === nextAt && id < nextId))) {
          nextAt = timer.at;
          nextId = id;
        }
      }
      if (nextId == null) {
        now = end;
        return;
      }
      now = nextAt;
      const timer = timers.get(nextId);
      timers.delete(nextId);
      timer.fn();
    }
  }
  return { setTimeout, clearTimeout, advance, timers };
}

function elementMatches(node, selector) {
  if (!node?.dataset) return false;
  if (selector === "[data-fleet-recovery]") return Object.hasOwn(node.dataset, "fleetRecovery");
  if (selector === "[data-fleet-retry]") return Object.hasOwn(node.dataset, "fleetRetry");
  if (selector === "[data-fleet-sign-in]") return Object.hasOwn(node.dataset, "fleetSignIn");
  return false;
}

function findElement(node, selector) {
  if (!node) return null;
  if (elementMatches(node, selector)) return node;
  for (const child of node.childNodes || []) {
    const found = findElement(child, selector);
    if (found) return found;
  }
  return null;
}

function createTimelineElement(tag) {
  return {
    tag,
    hidden: false,
    textContent: "",
    className: "",
    type: "",
    href: "",
    dataset: {},
    style: {},
    childNodes: [],
    setAttribute(name, value) {
      if (name === "href") this.href = value;
    },
    append(...kids) {
      this.childNodes.push(...kids);
    },
    addEventListener() {},
    querySelector(selector) {
      return findElement(this, selector);
    },
  };
}

function eventTarget() {
  const map = new Map();
  return {
    addEventListener(type, fn) {
      const list = map.get(type) || [];
      list.push(fn);
      map.set(type, list);
    },
    removeEventListener() {},
    dispatch(type, event = {}) {
      for (const fn of map.get(type) || []) fn(event);
    },
  };
}

function timelineHarness(fetch) {
  const clock = controllableClock();
  const created = [];
  const asOf = {
    dataset: { snapshotLabel: "as of 12:00:00" },
    textContent: "as of 12:00:00",
    insertAdjacentElement() {},
  };
  const main = {
    dataset: { fleetSyncState: "current" },
    querySelector: (selector) => (selector === "[data-as-of]" ? asOf : null),
  };
  const documentEvents = eventTarget();
  const windowEvents = eventTarget();
  const document = {
    ...documentEvents,
    hidden: false,
    visibilityState: "visible",
    hasFocus: () => false,
    body: { dataset: {}, appendChild() {} },
    documentElement: { dataset: {} },
    createElement(tag) {
      const node = createTimelineElement(tag);
      created.push(node);
      return node;
    },
    querySelector(selector) {
      if (selector === "main[data-fleet-sync-state]") return main;
      if (selector === "[data-fleet-recovery]") {
        return created.find((node) => elementMatches(node, selector)) || null;
      }
      return null;
    },
    querySelectorAll(selector) {
      const matches = [];
      const visit = (node) => {
        if (!node) return;
        const classes = String(node.className || "").split(/\s+/);
        if (selector.startsWith(".") && classes.includes(selector.slice(1))) matches.push(node);
        for (const child of node.childNodes || []) visit(child);
      };
      for (const node of created) visit(node);
      visit(this.body);
      return matches;
    },
  };
  const window = {
    ...windowEvents,
    location: { pathname: "/fleet", search: "?view=cards", reload() {} },
  };
  const source = `${appUrlSource}
${fleetRuntimeSource.slice(pureStart, pureEnd)}
function updateBeatClock(){}
${fleetRuntimeSource.slice(clockStart, clockEnd)}
${fleetRuntimeSource.slice(lifecycleStart, listenerEnd)}
globalThis.__timeline = {
  resumeBeatClock,
  scheduleRefresh,
  suspendFleet,
  recoverFleet,
  armFleetWatchdog,
  pageFrozen,
  fleetRecoveryModel,
  replaceApply(fn) { applyFleetSnapshot = fn; },
  timers() { return { beat: beatClockTimer, refresh: refreshTimer }; },
};
`;
  const context = vm.createContext({
    AbortController,
    console,
    document,
    fetch,
    navigator: { onLine: true },
    window,
    setTimeout: clock.setTimeout,
    clearTimeout: clock.clearTimeout,
  });
  vm.runInContext(source, context);
  return { api: context.__timeline, asOf, clock, document, main, window };
}

test("a visible unfocused page keeps one clock and one poll", () => {
  const queue = deferredFetchQueue();
  const page = timelineHarness(queue.fetch);
  page.api.resumeBeatClock();
  page.api.scheduleRefresh(10_000);
  const armed = page.api.timers();
  assert.ok(armed.beat != null);
  assert.ok(armed.refresh != null);
  page.clock.advance(1000);
  assert.notEqual(page.api.timers().beat, armed.beat);
  assert.equal(page.api.timers().refresh, armed.refresh);
  assert.equal(queue.pending.length, 0);

  page.window.dispatch("blur");
  assert.notEqual(page.api.timers().beat, null);
  assert.equal(page.api.timers().refresh, armed.refresh);
  assert.equal(queue.pending.length, 0);

  page.document.hidden = true;
  page.document.visibilityState = "hidden";
  page.document.dispatch("visibilitychange");
  assert.equal(page.api.timers().beat, null);
  assert.equal(page.api.timers().refresh, null);
  assert.equal(queue.pending.length, 0);
});

test("returning from hidden performs one recovery and focus does not fetch again", async () => {
  const queue = deferredFetchQueue();
  const page = timelineHarness(queue.fetch);
  page.api.replaceApply(() => true);
  page.document.hidden = true;
  page.document.visibilityState = "hidden";
  page.document.dispatch("visibilitychange");
  page.document.hidden = false;
  page.document.visibilityState = "visible";
  page.document.dispatch("visibilitychange");
  assert.equal(queue.pending.length, 1);
  const recovery = page.api.recoverFleet("visible");
  queue.pending[0].resolve(jsonResponse(snapshot(88)));
  assert.equal(await recovery, true);
  assert.ok(page.api.timers().beat != null);
  assert.ok(page.api.timers().refresh != null);
  page.window.dispatch("focus");
  assert.equal(queue.pending.length, 1);
});

test("auth HTML stops the clock and offers sign-in", async () => {
  const queue = deferredFetchQueue();
  const page = timelineHarness(queue.fetch);
  const recovery = page.api.recoverFleet("visible");
  queue.pending[0].resolve(jsonResponse({}, {
    redirected: true,
    status: 200,
    headers: { get: () => "text/html" },
  }));
  assert.equal(await recovery, false);
  assert.equal(page.main.dataset.fleetSyncState, "stale");
  assert.match(page.asOf.textContent, /^Data out of date/);
  assert.equal(page.api.timers().beat, null);
  assert.equal(page.api.fleetRecoveryModel("auth").action, "sign-in");
  const box = page.document.querySelector("[data-fleet-recovery]");
  const signIn = box.querySelector("[data-fleet-sign-in]");
  const retry = box.querySelector("[data-fleet-retry]");
  assert.equal(box.hidden, false);
  assert.equal(signIn.hidden, false);
  assert.equal(retry.hidden, true);
  assert.match(signIn.href, /\/auth\/login\?return_to=/);
});

test("the visible-page watchdog restarts a stranded page without waiting for focus", () => {
  const queue = deferredFetchQueue();
  const page = timelineHarness(queue.fetch);
  page.api.replaceApply(() => true);
  page.api.armFleetWatchdog();
  page.clock.advance(5000);
  assert.equal(queue.pending.length, 1);
  page.clock.advance(5000);
  assert.equal(queue.pending.length, 1);
});

test("delivery coverage qualifies a partial window without changing the percent", () => {
  const api = loadPure();
  const windowDef = { key: "10m", label: "10m", secs: 600 };
  const first = api.signalInfo([1000], null, 60, 1000, windowDef);
  assert.equal(first.text, "100%");
  assert.equal(first.level, "good");
  assert.equal(first.coverage, "partial");
  assert.match(first.title, /Partial retention/);
  assert.match(first.title, /1 of 1 expected reports/);

  const covered = [];
  for (let stamp = 400; stamp <= 1000; stamp += 60) covered.push(stamp);
  const full = api.signalInfo(covered, null, 60, 1000, windowDef);
  assert.equal(full.text, "100%");
  assert.equal(full.coverage, "full");
  assert.doesNotMatch(full.title, /Partial retention/);

  const empty = api.signalInfo([0, -1], 0, 60, 1000, windowDef);
  assert.equal(empty.text, "—");
  assert.equal(empty.coverage, "none");
});

test("fleet return marker stores only the fleet pathname", () => {
  const start = fleetRuntimeSource.indexOf("/* FLEET_MARKER_START */");
  const end = fleetRuntimeSource.indexOf("/* FLEET_MARKER_END */");
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  assert.match(fleetRuntimeSource, /initControls\(\);\s*markFleetEntry\(\);/);
  assert.match(fleetRuntimeSource, /function writeAssistantUrl[\s\S]*?replaceDocumentUrl\(/);

  function loadMarker({ fleet, pathname, search, prior, input = "qa-return-diagnostic" }) {
    const updates = [];
    const history = {
      state: prior,
      url: "",
      replaceState(state, _title, url) {
        this.state = state;
        this.url = url;
      },
    };
    const navigation = {
      currentEntry: {
        getState() {
          return history.state;
        },
      },
      updateCurrentEntry(update) {
        updates.push(update);
        history.state = update.state;
      },
    };
    const main = fleet ? { dataset: { view: "list", fleetSyncState: "current" } } : null;
    const searchInput = { value: input };
    const document = {
      querySelector(selector) {
        if (selector === "main[data-fleet-sync-state]") return main;
        if (selector === "main") return main;
        if (selector === "[data-sort]") return { value: "name" };
        if (selector === "input[data-search]") return searchInput;
        return null;
      },
    };
    const location = { pathname, search };
    const context = vm.createContext({
      console,
      document,
      location,
      history,
      navigation,
      URLSearchParams,
    });
    vm.runInContext(`
let activeLiveFilter='all';
let signalWindow={key:'10m'};
${fleetRuntimeSource.slice(start, end)}
globalThis.__marker = { updateUrlState, markFleetEntry, withFleetMarker, replaceDocumentUrl, fleetSearchText };
`, context);
    return { context, history, updates };
  }

  const fleet = loadMarker({
    fleet: true,
    pathname: "/",
    search: "?view=list&q=qa-return-diagnostic&sort=name",
    prior: { scroll: 1 },
  });
  assert.equal(fleet.context.__marker.markFleetEntry(), true);
  assert.deepEqual(vmPlain(fleet.history.state), { scroll: 1, pharosFleet: { path: "/" } });
  assert.equal(fleet.updates.at(-1).state.pharosFleet.path, "/");
  assert.deepEqual(vmPlain(Object.keys(fleet.updates.at(-1).state.pharosFleet)), ["path"]);

  assert.equal(fleet.context.__marker.fleetSearchText(), null);
  fleet.context.__marker.updateUrlState();
  assert.equal(fleet.history.state.pharosFleet.path, "/");
  assert.deepEqual(Object.keys(fleet.history.state.pharosFleet), ["path"]);
  assert.equal(fleet.history.state.pharosSearch, "qa-return-diagnostic");
  assert.equal(fleet.context.__marker.fleetSearchText(), "qa-return-diagnostic");
  assert.equal(fleet.history.state.scroll, 1);
  assert.match(fleet.history.url, /view=list/);
  assert.match(fleet.history.url, /sort=name/);
  assert.doesNotMatch(fleet.history.url, /(?:^|[?&])q=/);
  assert.equal(JSON.stringify(fleet.history.state.pharosFleet).includes("qa-return-diagnostic"), false);
  assert.equal(JSON.stringify(fleet.history.state).includes("view"), false);
  assert.equal(fleet.context.__marker.markFleetEntry(), true);
  assert.equal(fleet.history.state.pharosSearch, "qa-return-diagnostic");
  fleet.context.__marker.replaceDocumentUrl("/?view=list&sort=name&filter=all&signal=10m");
  assert.equal(fleet.history.state.pharosSearch, "qa-return-diagnostic");
  assert.equal(fleet.history.state.pharosFleet.path, "/");
  assert.doesNotMatch(fleet.history.url, /(?:^|[?&])q=/);

  const cleared = loadMarker({
    fleet: true,
    pathname: "/",
    search: "?view=list&q=secret-host&sort=name",
    prior: { scroll: 1, pharosSearch: "secret-host", pharosFleet: { path: "/" } },
    input: "",
  });
  cleared.context.__marker.updateUrlState();
  assert.equal(cleared.history.state.pharosSearch, undefined);
  assert.equal(cleared.context.__marker.fleetSearchText(), null);
  assert.doesNotMatch(cleared.history.url, /(?:^|[?&])q=/);
  assert.equal(cleared.history.state.scroll, 1);
  assert.equal(JSON.stringify(cleared.history.state).includes("secret-host"), false);

  const elsewhere = loadMarker({
    fleet: false,
    pathname: "/backups",
    search: "",
    prior: { scroll: 1 },
  });
  assert.equal(elsewhere.context.__marker.markFleetEntry(), false);
  assert.equal(elsewhere.updates.length, 0);
  elsewhere.context.__marker.replaceDocumentUrl("/backups?host=alpha");
  assert.equal(elsewhere.history.state, null);
  assert.equal(elsewhere.updates.length, 0);
  assert.equal(elsewhere.history.url, "/backups?host=alpha");
});

test("an open workflow keeps its parent job across a refresh that has no action or only the child", () => {
  const start = fleetRuntimeSource.indexOf("function activeHostActionJobId");
  const end = fleetRuntimeSource.indexOf("function initHostActions");
  assert.notEqual(start, -1);
  assert.notEqual(end, -1);
  const document = { body: { dataset: { hostActionDialogOpen: "true" } } };
  const context = vm.createContext({ console, document });
  vm.runInContext(`
let hostActionContext=null;
let openHostActionsRoot=null;
function positionHostActions(){}
${fleetRuntimeSource.slice(start, end)}
globalThis.__actions = { updateHostActionState, setContext(value){ hostActionContext=value; } };
`, context);

  function actionNode() {
    return { hidden: true, dataset: {}, querySelector() { return null; } };
  }
  function rootFor(host) {
    const nodes = {
      'system-update': actionNode(),
      'update-restart': actionNode(),
      remove: actionNode(),
      'withdraw-settings': actionNode(),
      'lifecycle-continue': actionNode(),
    };
    return {
      dataset: {
        host,
        canManage: "true",
        isNix: "true",
        janusReady: "true",
        systemUpdateAvailable: "true",
        actionJobId: "parent-run",
        actionKind: "settings_change",
        actionState: "proposal_requested",
      },
      querySelector(selector) {
        const match = selector.match(/data-host-action="([^"]+)"/);
        return match ? nodes[match[1]] || null : null;
      },
    };
  }
  const root = rootFor("qa-harbor");
  const surface = { querySelector() { return root; } };
  context.__actions.setContext({ root, jobId: "parent-run" });

  context.__actions.updateHostActionState(surface, { preferences_state: "applied" }, null);
  assert.equal(root.dataset.actionJobId, "parent-run");
  assert.equal(root.dataset.actionKind, "settings_change");
  assert.equal(root.dataset.actionState, "proposal_requested");

  context.__actions.updateHostActionState(surface, {
    preferences_state: "applied",
    host_action: {
      id: "child-run",
      settings_change_id: "parent-run",
      state: "queued_apply",
      workflow: { kind: "update_restart" },
    },
  }, null);
  assert.equal(root.dataset.actionJobId, "parent-run");
  assert.equal(root.dataset.actionKind, "settings_change");
  assert.equal(root.dataset.actionState, "proposal_requested");

  document.body.dataset.hostActionDialogOpen = "false";
  context.__actions.updateHostActionState(surface, { preferences_state: "applied" }, null);
  assert.equal(root.dataset.actionJobId, undefined);
  assert.equal(root.dataset.actionKind, undefined);
  assert.equal(root.dataset.actionState, undefined);
});

test("review update and restart follows a proven nixcfg gap or reboot, not a channel difference", () => {
  const start = fleetRuntimeSource.indexOf("function activeHostActionJobId");
  const end = fleetRuntimeSource.indexOf("function initHostActions");
  const document = { body: { dataset: {} } };
  const context = vm.createContext({ console, document });
  vm.runInContext(`
let hostActionContext=null;
let openHostActionsRoot=null;
function positionHostActions(){}
${fleetRuntimeSource.slice(start, end)}
globalThis.__actions = { updateHostActionState };
`, context);

  function project(host, { manage = true, janus = true } = {}) {
    const restart = { hidden: false, dataset: {}, querySelector() { return { textContent: "" }; } };
    const update = { hidden: false, dataset: {}, querySelector() { return null; } };
    const root = {
      dataset: {
        host: "qa-harbor",
        canManage: manage ? "true" : "false",
        isNix: "true",
        janusReady: janus ? "true" : "false",
        systemUpdateAvailable: "true",
      },
      querySelector(selector) {
        if (selector === '[data-host-action="update-restart"]') return restart;
        if (selector === '[data-host-action="system-update"]') return update;
        return null;
      },
    };
    context.__actions.updateHostActionState({ querySelector() { return root; } }, host, null);
    return { restart, update, root };
  }
  const channelOnly = project({
    kernel: { state: "current" },
    freshness: {
      nixcfg_comparison: { relation: "current", commits_behind: 0 },
      nixpkgs_comparison: { relation: "different" },
    },
  });
  assert.equal(channelOnly.root.dataset.updatePending, "false");
  assert.equal(channelOnly.restart.hidden, true);
  assert.equal(channelOnly.update.hidden, false);

  for (const commits of [undefined, null, 0, "0"]) {
    const unknown = project({
      kernel: { state: "current" },
      freshness: { nixcfg_comparison: { relation: "behind", commits_behind: commits } },
    });
    assert.equal(unknown.root.dataset.updatePending, "false");
    assert.equal(unknown.restart.hidden, true);
  }

  const behind = project({
    kernel: { state: "current" },
    freshness: { nixcfg_comparison: { relation: "behind", commits_behind: 4 } },
  });
  assert.equal(behind.root.dataset.updatePending, "true");
  assert.equal(behind.restart.hidden, false);
  assert.equal(behind.update.hidden, false);

  const reboot = project({
    kernel: { state: "reboot_required" },
    freshness: { nixcfg_comparison: { relation: "current", commits_behind: 0 } },
  });
  assert.equal(reboot.root.dataset.updatePending, "true");
  assert.equal(reboot.restart.hidden, false);

  const viewer = project({
    kernel: { state: "reboot_required" },
    freshness: { nixcfg_comparison: { relation: "behind", commits_behind: 4 } },
  }, { manage: false });
  assert.equal(viewer.root.dataset.updatePending, "true");
  assert.equal(viewer.restart.hidden, true);
  assert.equal(viewer.update.hidden, true);
});

test("the first fleet refresh keeps the dialog interval while a host action is open", () => {
  const callStart = fleetRuntimeSource.lastIndexOf("scheduleRefresh(");
  const call = fleetRuntimeSource.slice(callStart, fleetRuntimeSource.indexOf(";", callStart) + 1);
  assert.match(call, /hostActionDialogOpen/);
  assert.match(call, /DIALOG_REFRESH_MS/);
  assert.equal(call.includes("scheduleRefresh(3000)"), false);

  const delays = [];
  const document = { body: { dataset: { hostActionDialogOpen: "true" } } };
  const context = vm.createContext({
    document,
    DIALOG_REFRESH_MS: 60000,
    scheduleRefresh(delay) { delays.push(delay); },
  });
  vm.runInContext(call, context);
  document.body.dataset.hostActionDialogOpen = "false";
  vm.runInContext(call, context);
  assert.deepEqual(delays, [60000, 3000]);
});

test("a hidden page does not keep the watchdog looping", () => {
  const queue = deferredFetchQueue();
  const page = timelineHarness(queue.fetch);
  page.api.armFleetWatchdog();
  page.api.scheduleRefresh(10_000);
  page.api.resumeBeatClock();
  page.document.hidden = true;
  page.document.visibilityState = "hidden";
  page.document.dispatch("visibilitychange");
  page.clock.advance(20_000);
  assert.equal(queue.pending.length, 0);
  assert.equal(page.api.timers().beat, null);
  assert.equal(page.api.timers().refresh, null);
});

test("simulated document freeze suspends fleet work and document resume schedules recovery", async () => {
  // Simulated DOM delivery of the production listener block only. freeze and
  // resume are non-bubbling and are dispatched here on separate document and
  // window targets. This does not observe a trusted browser Page Lifecycle event.
  const queue = deferredFetchQueue();
  const page = timelineHarness(queue.fetch);
  let applied = null;
  page.api.replaceApply((data) => {
    applied = data.as_of;
    return true;
  });
  page.api.resumeBeatClock();
  page.api.scheduleRefresh(10_000);
  page.api.armFleetWatchdog();
  const armed = page.api.timers();
  assert.notEqual(armed.beat, null);
  assert.notEqual(armed.refresh, null);
  assert.equal(page.document.hidden, false);
  assert.equal(page.document.visibilityState, "visible");
  assert.equal(page.api.pageFrozen(), false);

  page.window.dispatch("freeze");
  page.window.dispatch("resume");
  assert.equal(page.document.body.dataset.fleetLifecycleFrozen, undefined);
  assert.equal(page.api.pageFrozen(), false);
  assert.equal(page.api.timers().beat, armed.beat);
  assert.equal(page.api.timers().refresh, armed.refresh);
  assert.equal(page.main.dataset.fleetSyncState, "current");
  assert.equal(queue.pending.length, 0);

  page.document.dispatch("freeze");
  assert.equal(page.document.body.dataset.fleetLifecycleFrozen, "true");
  assert.equal(page.document.hidden, false);
  assert.equal(page.document.visibilityState, "visible");
  assert.equal(page.api.pageFrozen(), true);
  assert.equal(page.api.timers().beat, null);
  assert.equal(page.api.timers().refresh, null);
  assert.equal(page.main.dataset.fleetSyncState, "current");
  page.clock.advance(20_000);
  assert.equal(queue.pending.length, 0);
  assert.equal(page.api.timers().beat, null);
  assert.equal(page.api.timers().refresh, null);

  page.window.dispatch("resume");
  assert.equal(page.document.body.dataset.fleetLifecycleFrozen, "true");
  assert.equal(page.api.pageFrozen(), true);
  assert.equal(queue.pending.length, 0);
  assert.equal(page.main.dataset.fleetSyncState, "current");

  page.document.dispatch("resume");
  assert.equal(page.document.body.dataset.fleetLifecycleFrozen, undefined);
  assert.equal(page.api.pageFrozen(), false);
  assert.equal(page.main.dataset.fleetSyncState, "syncing");
  assert.equal(queue.pending.length, 1);
  assert.equal(page.api.timers().beat, null);

  queue.pending[0].resolve(jsonResponse(snapshot(91)));
  assert.equal(await page.api.recoverFleet("resume"), true);
  assert.equal(applied, 91);
  assert.equal(page.main.dataset.fleetSyncState, "current");
  assert.equal(page.api.pageFrozen(), false);
  assert.notEqual(page.api.timers().beat, null);
  assert.notEqual(page.api.timers().refresh, null);
  assert.equal(queue.pending.length, 1);

  page.window.dispatch("freeze");
  assert.equal(page.document.body.dataset.fleetLifecycleFrozen, undefined);
  assert.equal(page.api.pageFrozen(), false);
  assert.notEqual(page.api.timers().beat, null);
  assert.notEqual(page.api.timers().refresh, null);
  assert.equal(queue.pending.length, 1);
});

test("drawer fallback uses the card summary before a snapshot and drops the previous host", () => {
  const pureStart = fleetRuntimeSource.indexOf("const HISTORY_DOTS=12;");
  const pureEnd = fleetRuntimeSource.indexOf("/* TIMELINE_PURE_END */");
  const drawerStart = fleetRuntimeSource.indexOf("function hostSurfaces");
  const drawerEnd = fleetRuntimeSource.indexOf("function hostDrawerFocusables");
  const assuranceStart = fleetRuntimeSource.indexOf("function kernelNeedsRestart");
  const assuranceEnd = fleetRuntimeSource.indexOf("function attentionFor");
  const stampStart = fleetRuntimeSource.indexOf("const UTC_STAMP_EXCLUSIVE_END");
  const stampEnd = fleetRuntimeSource.indexOf("function evidenceCaption");
  const shortStart = fleetRuntimeSource.indexOf("function shortRevision");
  const shortEnd = fleetRuntimeSource.indexOf("function updateConfigEvidence");
  assert.ok(pureStart >= 0 && assuranceStart >= 0 && drawerStart >= 0 && stampStart >= 0 && shortStart >= 0);

  function makeNode(spec = {}) {
    const element = {
      dataset: { ...(spec.dataset || {}) },
      attributes: { ...(spec.attributes || {}) },
      childNodes: [],
      className: spec.className || "",
      textContent: spec.text || "",
      innerHTML: spec.html || "",
      href: "",
      value: "",
      disabled: false,
      checked: false,
      setAttribute(name, value) {
        this.attributes[name] = String(value);
        if (name === "href") this.href = String(value);
      },
      getAttribute(name) {
        return Object.prototype.hasOwnProperty.call(this.attributes, name) ? this.attributes[name] : null;
      },
      appendChild(child) {
        this.childNodes.push(child);
        return child;
      },
      replaceChildren() {
        this.childNodes = [];
      },
      querySelector(selector) {
        return queryNodes(this, selector)[0] || null;
      },
      querySelectorAll(selector) {
        return queryNodes(this, selector);
      },
    };
    return element;
  }
  function selectorMatches(element, selector) {
    if (selector.startsWith(".")) return element.className.split(/\s+/).includes(selector.slice(1));
    if (!selector.startsWith("[") || !selector.endsWith("]")) return false;
    const body = selector.slice(1, -1);
    if (!body.includes("=")) return Object.prototype.hasOwnProperty.call(element.attributes, body);
    const eq = body.indexOf("=");
    const name = body.slice(0, eq);
    const wanted = body.slice(eq + 1).replace(/^"|"$/g, "");
    return element.attributes[name] === wanted;
  }
  function queryNodes(root, selector) {
    const found = [];
    for (const child of root.childNodes) {
      if (selectorMatches(child, selector)) found.push(child);
      found.push(...queryNodes(child, selector));
    }
    return found;
  }
  function labeled(attr, text, extra) {
    return makeNode({ attributes: { [attr]: "" }, text, ...extra });
  }

  const panel = makeNode({ attributes: { "data-host-drawer": "" } });
  panel.dataset.canManage = "false";
  const fields = {};
  for (const name of ["title", "role", "mark", "state", "attention", "guidance", "owner", "next", "settings-state", "health", "backup", "restore", "reasons", "workspace", "check", "config", "deployed", "nixcfg", "nixpkgs", "backup-clock", "restore-clock", "color", "kind", "draft-status", "discard", "review"]) {
    const child = labeled(`data-host-drawer-${name}`, "");
    if (name === "mark") child.innerHTML = "<svg>server</svg>";
    panel.appendChild(child);
    fields[name] = child;
  }
  fields.attention.textContent = "freshness unverified";
  fields.health.textContent = "Previous host";
  fields.backup.textContent = "Old backup";
  fields.restore.textContent = "Old restore";

  const reasonTime = labeled("data-health-date", "2026-08-18 12:46:51 UTC");
  const reason = labeled("data-health-reason", "Restore Overdue2026-08-18 12:46:51 UTC", {
    dataset: { healthAt: "1787050011" },
  });
  reason.appendChild(reasonTime);
  const icon = makeNode({ className: "os-badge-icon", html: "<svg>nix</svg>" });
  const badge = makeNode({ attributes: { "data-health-badge": "" }, dataset: { healthTone: "amber" } });
  badge.appendChild(icon);
  const beacon = makeNode({
    attributes: { "data-host-surface": "runtime" },
    dataset: { host: "beacon", live: "live", drawerWorkspaceHref: "/hosts/beacon" },
  });
  for (const child of [
    makeNode({ className: "role", text: "server" }),
    labeled("data-health-summary", "Restore Overdue"),
    labeled("data-daily-backup-label", "Daily OK"),
    labeled("data-daily-backup-note", "last success 12h ago"),
    labeled("data-daily-backup-date", "2026-09-22 00:46:51 UTC"),
    labeled("data-restore-label", "Overdue"),
    labeled("data-restore-note", "last successful selective restore 35d ago"),
    labeled("data-restore-date", "2026-08-18 12:46:51 UTC"),
    reason,
    badge,
  ]) beacon.appendChild(child);

  const harbor = makeNode({
    attributes: { "data-host-surface": "runtime" },
    dataset: { host: "harbor", live: "live" },
  });
  harbor.appendChild(makeNode({ className: "role", text: "server" }));
  harbor.appendChild(labeled("data-health-summary", "No action needed"));

  const surfaces = [beacon, harbor];
  const document = {
    createElement() { return makeNode(); },
    querySelector(selector) {
      return selector === "[data-host-drawer]" ? panel : null;
    },
    querySelectorAll(selector) {
      return selector === '[data-host-surface="runtime"]' ? surfaces : [];
    },
  };
  const context = vm.createContext({
    Array,
    Date,
    JSON,
    Map,
    console,
    document,
    encodeURIComponent,
  });
  vm.runInContext(`
function appUrl(path){return path}
let fleetHostsByName=new Map();
${fleetRuntimeSource.slice(pureStart, pureEnd)}
${fleetRuntimeSource.slice(assuranceStart, assuranceEnd)}
${fleetRuntimeSource.slice(stampStart, stampEnd)}
${fleetRuntimeSource.slice(shortStart, shortEnd)}
${fleetRuntimeSource.slice(drawerStart, drawerEnd)}
globalThis.__drawer={
  populateHostDrawer,
  updateOpenHostDrawer,
  projectHostAssurance,
  setHosts(entries){fleetHostsByName=new Map(entries);}
};
`, context);

  context.__drawer.populateHostDrawer(beacon);
  assert.equal(fields.attention.textContent, "Restore Overdue");
  assert.equal(fields.health.textContent, "Restore Overdue");
  assert.match(fields.backup.textContent, /^Daily OK · /);
  assert.match(fields.restore.textContent, /^Overdue · /);
  assert.equal(fields.reasons.childNodes.length, 1);
  assert.match(fields.reasons.childNodes[0].textContent, /^Restore Overdue · 2026-08-18 12:46:51 UTC$/);
  assert.equal(fields.mark.dataset.healthTone, "amber");
  assert.match(fields.mark.innerHTML, /nix/);
  assert.equal(fields["backup-clock"].textContent, "2026-09-22 00:46:51 UTC");

  context.__drawer.populateHostDrawer(harbor);
  assert.equal(fields.attention.textContent, "No action needed");
  assert.equal(fields.health.textContent, "No action needed");
  assert.equal(fields.backup.textContent, "Not recorded");
  assert.equal(fields.restore.textContent, "Not recorded");
  assert.equal(fields.mark.dataset.healthTone, undefined);
  assert.match(fields.mark.innerHTML, /server/);
  assert.doesNotMatch(fields.reasons.childNodes[0].textContent, /Restore Overdue/);

  const now = 1_700_000_000;
  const liveHost = {
    name: "beacon",
    liveness: "live",
    attention: { label: "freshness unverified" },
    freshness: { applicable: true },
    backup_observations: [{
      state: "healthy",
      schedule: "daily",
      last_success_at: now - 3600,
      restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 40 * 86400, restored_files: 1 },
    }],
  };
  context.__drawer.populateHostDrawer(beacon);
  context.__drawer.setHosts([["beacon", liveHost]]);
  const projected = context.__drawer.projectHostAssurance(liveHost, now);
  assert.equal(projected.health.summary, "Restore Overdue");
  assert.notEqual(projected.health.summary, "freshness unverified");
  context.__drawer.updateOpenHostDrawer(liveHost, now);
  assert.equal(fields.attention.textContent, "Restore Overdue");
  assert.equal(fields.health.textContent, "Restore Overdue");
  assert.match(fields.backup.textContent, /^Daily OK · /);
  assert.match(fields.restore.textContent, /^Overdue · /);
  assert.match(fields.reasons.childNodes.map((item) => item.textContent).join("\n"), /Restore Overdue · \d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/);
  assert.doesNotMatch(fields.attention.textContent, /freshness unverified/);
});
