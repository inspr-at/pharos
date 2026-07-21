import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import vm from "node:vm";

const fleetRuntimeSource = readFileSync(
  new URL("../crates/pharosd/assets/ui/foot.html", import.meta.url),
  "utf8",
);
const lifecycleStart = fleetRuntimeSource.indexOf("const REFRESH_MS=10000;");
const lifecycleEnd = fleetRuntimeSource.indexOf(
  "document.addEventListener('visibilitychange'",
  lifecycleStart,
);

assert.notEqual(lifecycleStart, -1, "Fleet refresh lifecycle start must exist");
assert.notEqual(lifecycleEnd, -1, "Fleet refresh lifecycle end must exist");

const lifecycleSource = fleetRuntimeSource.slice(lifecycleStart, lifecycleEnd);
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

function harness(fetch) {
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
  const document = {
    hidden: false,
    body: { dataset: {} },
    hasFocus: () => true,
    querySelector(selector) {
      if (selector === "main[data-fleet-sync-state]") return main;
      const match = selector.match(/^\[data-summary-count="(all|live|stale|down)"\]$/);
      return match ? summary.get(match[1]) : null;
    },
  };
  const context = vm.createContext({
    AbortController,
    console,
    document,
    fetch,
    window: { location: { reload: () => events.push("reload") } },
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
  vm.runInContext(lifecycleSource + exposeTestApi, context);
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
