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
  assert.equal(current.state, "current");
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
  assert.match(failed.detail, /Last successful selective restore/);

  const daily = api.projectDailyBackup([{
    state: "healthy", schedule: "daily", last_success_at: now - 50,
  }], now);
  assert.equal(daily.label, "Daily OK");
  assert.equal(daily.tone, "good");
  const hourly = api.projectDailyBackup([{
    state: "healthy", schedule: "hourly", last_success_at: now - 50,
  }], now);
  assert.equal(hourly.label, "Successful");
  assert.equal(hourly.tone, "good");
  assert.equal(api.projectDailyBackup([{ configured: "disabled", state: "unknown" }], now).state, "not-required");
  assert.equal(api.projectDailyBackup([{ state: "healthy", schedule: "daily" }], now).label, "Success time unknown");
  const staleDaily = api.projectDailyBackup([{
    state: "healthy", schedule: "daily", last_success_at: now - 3 * 24 * 60 * 60,
  }], now);
  assert.equal(staleDaily.state, "stale");
  assert.equal(staleDaily.tone, "amber");
  assert.notEqual(staleDaily.label, "Daily OK");
  const recentRestore = api.projectRestoreStatus([{
    restore_validation: { level: "restore-sample", state: "passed", checked_at: now - 10 * 24 * 60 * 60 },
  }], now);
  assert.equal(recentRestore.tone, "good");
  assert.equal(recentRestore.overdue, false);
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
  assert.ok(mixed.reasons.some((reason) => reason.label === "Backup stale"));
  assert.ok(mixed.reasons.some((reason) => reason.tone === "good" && reason.label === "Passed"));
  const arrival = api.arrivalPresentation(now - 10, 60, 15, now);
  assert.equal(arrival.state, "on-time");
  assert.doesNotMatch(`${arrival.label} ${arrival.detail}`, /%|Arrival scale|time axis/);
  assert.match(arrival.detail, /Late after/);

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
  assert.ok(health.reasons.some((reason) => reason.tone === "good" && reason.label === "Daily OK"));
  assert.ok(health.reasons.some((reason) => reason.label === "Selective restore overdue"));

  assert.deepEqual(vmPlain(api.dedupeHeartbeats([5, 5.4, 5.9, 6.5])), [5, 6.5]);
  const start = now - 600;
  const gapped = api.aggregateHistory([start + 10, start + 400], windowDef, now, 60, 15);
  assert.equal(gapped.marks.some((mark) => mark.level === "ok"), false);
  assert.equal(gapped.marks.some((mark) => mark.level === "down"), true);
  assert.equal(api.historyInfo([now + 30], 0, 60, 15, now).level, "unknown");
  assert.equal(api.aggregateHistory([now + 30], windowDef, now, 60, 15).marks.some((mark) => mark.level === "ok"), false);
  assert.deepEqual(vmPlain(api.aggregateHistory([], windowDef, now, 60, 15).marks), []);
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
