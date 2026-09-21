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

  const recovery = page.api.recoverFleet("visible");
  queue.pending[0].resolve(
    jsonResponse({}, {
      redirected: true,
      headers: { get: () => "text/html" },
    }),
  );

  assert.equal(await recovery, false);
  assert.equal(page.main.dataset.fleetSyncState, "stale");
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
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 2_592_000 },
  }], now);
  assert.equal(current.state, "passed");
  assert.equal(current.tone, "good");
  assert.equal(current.overdue, false);

  const overdue = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 2_592_001 },
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
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, files_restored: 0 },
  }], now);
  assert.equal(countedOut.state, "unknown");
  assert.notEqual(countedOut.tone, "good");

  const failed = api.projectRestoreStatus([
    { restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 100 } },
    { restore_validation: { level: "restore-sample", state: "failed", checked_at: now - 10 } },
  ], now);
  assert.equal(failed.state, "failed");
  assert.equal(failed.tone, "bad");
  assert.match(failed.detail, /last successful selective restore/);

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
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10 * 24 * 60 * 60 },
  }], now);
  assert.equal(recentRestore.tone, "good");
  assert.equal(recentRestore.state, "passed");
  assert.equal(recentRestore.overdue, false);
  const sameHostJobs = [
    { repository_id: "repo-a", state: "failed", schedule: "daily", last_success_at: now - 3 * 24 * 60 * 60 },
    { repository_id: "repo-b", state: "healthy", schedule: "daily", last_success_at: now - 10, restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, files_restored: 1 } },
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
    { repository_id: "repo-b", state: "healthy", schedule: "daily", restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10, files_restored: 0 } },
  ], now);
  assert.equal(zeroFromOtherJob.state, "unknown");
  assert.notEqual(zeroFromOtherJob.tone, "good");
  const ownedRestore = api.projectRestoreStatus([
    { repository_id: "repo-a", state: "healthy", schedule: "daily", last_success_at: now - 50, restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10 } },
  ], now);
  assert.equal(ownedRestore.tone, "good");
  assert.equal(ownedRestore.state, "passed");
  const borrowedDaily = api.projectDailyBackup([
    { repository_id: "repo-a", state: "failed", schedule: "daily", last_success_at: now - 3 * 24 * 60 * 60 },
    { repository_id: "repo-b", state: "healthy", schedule: "daily", last_success_at: now - 10, restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10 } },
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

test("history refresh leaves an ordered mark attached", () => {
  const sourceStart = fleetRuntimeSource.indexOf("let activeHistoryMark=null;");
  const sourceEnd = fleetRuntimeSource.indexOf("function updateHistoryEvents");
  const reconcileBody = fleetRuntimeSource.slice(
    fleetRuntimeSource.indexOf("function reconcileHistoryMarks"),
    sourceEnd,
  );
  assert.equal(reconcileBody.includes("appendChild"), false);
  assert.match(reconcileBody, /insertBefore/);

  function linkChildren(parent) {
    parent.childNodes.forEach((node, index) => {
      node.parentNode = parent;
      node.nextSibling = parent.childNodes[index + 1] || null;
    });
  }
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
      style: { setProperty() {} },
      setAttribute(name, value) { this.attributes[name] = String(value); },
      getAttribute(name) { return this.attributes[name]; },
      removeAttribute(name) { delete this.attributes[name]; },
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
        if (child.parentNode) {
          child.parentNode.childNodes = child.parentNode.childNodes.filter((node) => node !== child);
          linkChildren(child.parentNode);
        }
        const at = ref == null ? this.childNodes.length : this.childNodes.indexOf(ref);
        this.childNodes.splice(at, 0, child);
        linkChildren(this);
        this.inserts.push(child);
        return child;
      },
      querySelectorAll(selector) {
        if (selector !== ".beat-mark") return [];
        return this.childNodes.filter((node) => String(node.className).split(/\s+/).includes("beat-mark"));
      },
    };
  }
  const document = {
    body: element("body"),
    activeElement: null,
    getElementById() { return null; },
    createElement: element,
  };
  const context = vm.createContext({ console, document });
  vm.runInContext(`${fleetRuntimeSource.slice(sourceStart, sourceEnd)}
globalThis.__history = { reconcileHistoryMarks };
`, context);
  const container = element("span");
  const kept = element("span");
  kept.className = "beat-mark";
  kept.dataset.historyKey = "sample:50";
  container.insertBefore(kept, null);
  container.inserts = [];
  document.activeElement = kept;
  context.__history.reconcileHistoryMarks(container, [{
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

  const added = element("span");
  context.__history.reconcileHistoryMarks(container, [
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

  context.__history.reconcileHistoryMarks(container, [{
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
globalThis.__facts = { updateBackupStatus };
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
