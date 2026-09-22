import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { fileURLToPath } from "node:url";
import {
  CLICK_ALLOWLIST,
  DOM_ALLOWLIST,
  FOCUS_METHOD,
  INSPECTION_SELECTORS,
  POLL_WAIT_MS,
  RETURN_WAIT_MS,
  allowlistedArrival,
  allowlistedChipCopy,
  allowlistedVersion,
  alternateGraceSeconds,
  arrivalPercent,
  boxUnchanged,
  clickPermitted,
  domChangePermitted,
  hostLinkMatches,
  inspectAuthenticatedClient,
  inspectionRouteAllowed,
  inspectionSkipped,
  plannedInspectionRoutes,
  publicPathFromUrl,
  representativeHostPath,
  sealInspection,
  searchQueryPresent,
  settleLiveInspection,
} from "../scripts/live-ui-inspect.mjs";
import {
  EXIT_CODES,
  LiveUiError,
  SCREENSHOT_FILES,
  SERVER_MUTATION_ALLOWLIST,
  loadDraftFile,
  planInventory,
  publicPath,
  screenshotName,
} from "../scripts/live-ui-guard.mjs";

const REPO_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");

test("live query mapping keeps list and host sections and drops search text", () => {
  assert.equal(publicPath("/pharos/?view=list&sort=name&filter=all&signal=10m&q=hidden-host"), "/pharos/?view=list");
  assert.equal(publicPath("/pharos?view=list"), "/pharos/?view=list");
  assert.equal(publicPath("/pharos/?view=grid"), "/pharos/");
  assert.equal(publicPath("/pharos/map?view=list"), "/pharos/map");
  assert.equal(publicPath("/pharos/?section=settings"), "/pharos/");
  assert.equal(publicPath("/pharos/hosts/legacy-host?section=backups&q=hidden-host"), "/pharos/hosts/legacy-host?section=backups");
  assert.equal(publicPath("/pharos/hosts/legacy-host?section=activity"), "/pharos/hosts/legacy-host?section=activity");
  assert.equal(publicPath("/pharos/hosts/legacy-host?section=settings"), "/pharos/hosts/legacy-host?section=settings");
  assert.equal(publicPath("/pharos/hosts/legacy-host?section=overview"), "/pharos/hosts/legacy-host");
  assert.equal(publicPath("/pharos/hosts/legacy-host?section=settings&section=backups"), "/pharos/hosts/legacy-host");
  assert.equal(publicPath("/pharos/?view=list&q=s3cr", ["s3cr"]), "path-category");
  assert.equal(publicPathFromUrl("https://pharos.barta.cm/pharos/?view=list&q=hidden-host"), "/pharos/?view=list");
  assert.equal(searchQueryPresent("https://pharos.barta.cm/pharos/?view=list&q=hidden-host"), true);
  assert.equal(searchQueryPresent("/pharos/?view=list"), false);
  assert.equal(JSON.stringify(publicPathFromUrl("https://user:secret@pharos.barta.cm/pharos/?view=list")).includes("secret"), false);
});

test("inspection screenshot names stay value-free and distinct", () => {
  assert.equal(screenshotName("/pharos/?view=list&sort=name"), "01-home-list.png");
  assert.equal(screenshotName("/pharos/"), "01-home.png");
  assert.notEqual(screenshotName("/pharos/?view=list"), screenshotName("/pharos/"));
  assert.equal(screenshotName("/pharos/hosts/legacy-host?section=backups", 3), "host-03-backups.png");
  assert.equal(screenshotName("/pharos/hosts/legacy-host?section=activity", 3), "host-03-activity.png");
  assert.equal(screenshotName("/pharos/hosts/legacy-host?section=settings", 3), "host-03-settings.png");
  assert.equal(screenshotName("/pharos/hosts/legacy-host", 3), "host-03.png");
  assert.equal(screenshotName("/pharos/hosts/legacy-host?section=settings", 3, "settings-draft"), "host-03-settings-draft.png");
  assert.equal(screenshotName("/pharos/", 1, "settings-draft"), "");
  assert.equal(screenshotName("/pharos/settings/providers", 1, "fleet-freshness"), "10-fleet-freshness.png");
  assert.equal(screenshotName("/pharos/", 1, "card-exact-times"), "11-card-exact-times.png");
  assert.equal(screenshotName("/pharos/", 1, "quick-preview"), "12-quick-preview.png");
  assert.equal(screenshotName("/pharos/", 1, "actions-menu"), "13-actions-menu.png");
  assert.equal(screenshotName("/pharos/", 1, "history-hint"), "14-history-hint.png");
  assert.equal(screenshotName("/pharos/", 1, "custom-script"), "");
  assert.equal(screenshotName("/pharos/", 1, "../escape"), "");
  for (const name of [
    screenshotName("/pharos/?view=list"),
    screenshotName("/pharos/hosts/legacy-host?section=backups", 3),
    screenshotName("/pharos/settings/providers", 1, "fleet-freshness"),
  ]) {
    assert.equal(name.includes("legacy-host"), false);
    assert.equal(Object.values(SCREENSHOT_FILES).includes(name), false);
  }
});

test("inventory keeps every host and adds list plus one host's sections", () => {
  const planned = planInventory({
    hostNames: ["legacy-host", "declared-only"],
    hrefs: ["/pharos/settings/providers/hetzner-cloud"],
  });
  assert.equal(planned.includes("/pharos/?view=list"), true);
  assert.equal(planned.includes("/pharos/hosts/declared-only"), true);
  assert.equal(planned.includes("/pharos/hosts/declared-only?section=settings"), true);
  assert.equal(planned.includes("/pharos/hosts/declared-only?section=backups"), true);
  assert.equal(planned.includes("/pharos/hosts/declared-only?section=activity"), true);
  assert.equal(planned.includes("/pharos/hosts/legacy-host"), true);
  assert.equal(planned.includes("/pharos/hosts/legacy-host?section=settings"), true);
  assert.equal(planned.includes("/pharos/hosts/legacy-host?section=backups"), false);
  assert.equal(planned.filter((route) => route === "/pharos/?view=list").length, 1);
});

test("settings draft paths map through the owned draft file", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-live-inspect-"));
  const dir = path.join(root, "private");
  fs.mkdirSync(dir, { mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, "draft.json");
  try {
    fs.writeFileSync(
      file,
      `${JSON.stringify({
        path: "/pharos/hosts/legacy-host?section=settings",
        fields: [{ selector: "input[data-grace-seconds]", value: "16" }],
      })}\n`,
      { mode: 0o600 },
    );
    fs.chmodSync(file, 0o600);
    const draft = loadDraftFile(file, REPO_ROOT);
    assert.equal(draft.path, "/pharos/hosts/legacy-host?section=settings");
    assert.equal(draft.dispatch, "dom-only");
    assert.deepEqual(draft.serverRequests, []);
    fs.writeFileSync(
      file,
      JSON.stringify({
        path: "/pharos/hosts/legacy-host?section=backups",
        fields: [{ selector: "input[data-grace-seconds]", value: "16" }],
      }),
      { mode: 0o600 },
    );
    fs.chmodSync(file, 0o600);
    assert.throws(() => loadDraftFile(file, REPO_ROOT), (error) => error instanceof LiveUiError && error.code === "draft-path");
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("inspection routes and clicks stay on the fixed allowlist", () => {
  assert.equal(SERVER_MUTATION_ALLOWLIST.length, 0);
  assert.equal(representativeHostPath(["/pharos/", "/pharos/hosts/legacy-host?section=settings"]), "/pharos/hosts/legacy-host");
  const routes = plannedInspectionRoutes("/pharos/hosts/legacy-host?section=settings");
  assert.deepEqual(routes, [
    "/pharos/",
    "/pharos/?view=list",
    "/pharos/settings/providers",
    "/pharos/hosts/legacy-host",
    "/pharos/hosts/legacy-host?section=backups",
    "/pharos/hosts/legacy-host?section=activity",
    "/pharos/hosts/legacy-host?section=settings",
  ]);
  assert.equal(inspectionRouteAllowed("/pharos/hosts/legacy-host", "/pharos/?view=list"), true);
  assert.equal(inspectionRouteAllowed("/pharos/hosts/legacy-host", "/pharos/auth/login"), false);
  assert.equal(inspectionRouteAllowed("/pharos/hosts/legacy-host", "/pharos/host-actions/legacy-host/remove"), false);
  assert.equal(inspectionRouteAllowed("/pharos/hosts/legacy-host", "/pharos/hosts/other-host"), false);
  assert.equal(hostLinkMatches("/pharos/hosts/legacy-host", "/pharos/hosts/legacy-host?section=settings"), true);
  assert.equal(clickPermitted("preview"), true);
  assert.equal(clickPermitted("actions-trigger"), true);
  assert.equal(clickPermitted("grace-reset"), true);
  for (const action of ["review", "confirm", "apply", "save", "logout", "update-restart", "menuitem", "add-server"]) {
    assert.equal(clickPermitted(action), false);
    assert.equal(CLICK_ALLOWLIST.includes(action), false);
  }
  assert.equal(domChangePermitted("grace-seconds"), true);
  assert.equal(domChangePermitted("grace-source"), true);
  assert.equal(DOM_ALLOWLIST.includes("review-settings"), false);
  assert.equal(alternateGraceSeconds("15"), "16");
  assert.equal(alternateGraceSeconds("3600"), "3599");
  assert.equal(alternateGraceSeconds("nope"), "");
  assert.equal(allowlistedChipCopy("No pending changes"), "No pending changes");
  assert.equal(allowlistedChipCopy("Up to date"), "Up to date");
  assert.equal(allowlistedChipCopy("Review update and restart"), "");
  assert.equal(allowlistedArrival("On time"), "On time");
  assert.equal(allowlistedArrival("user@example"), "");
  assert.equal(allowlistedVersion("260921221314.0.0"), "260921221314.0.0");
  assert.equal(allowlistedVersion("v260921221314.0.0"), "");
  assert.equal(arrivalPercent("--arrival-x:12.20%"), "12.20");
  assert.equal(boxUnchanged({ width: 10.2, height: 4 }, { x: 3, width: 10, height: 4.2 }), true);
  assert.equal(boxUnchanged({ width: 10, height: 4 }, { width: 12, height: 4 }), false);
  assert.equal(FOCUS_METHOD, "synthetic-visible-unfocused");
  assert.equal(POLL_WAIT_MS >= 10_000 && POLL_WAIT_MS <= 15_000, true);
  assert.equal(RETURN_WAIT_MS > 0 && RETURN_WAIT_MS < 5_000, true);
});

test("sealed inspection output keeps only allowlisted evidence", () => {
  const sealed = sealInspection({
    role: "manager",
    productionWindowSwitchReproduced: true,
    representativeHost: "https://auth.inspr.at/ui/login?password=secret",
    searchQueryRetained: false,
    screenshots: ["10-fleet-freshness.png", "../secret.png", "01-home.png", "host-03-backups.png"],
    checks: {
      shell: { status: "observed", linkCount: 7, sevenLinks: true, version: "260921221314.0.0", account: "person@example" },
      lifecycle: { status: "observed", chip: "No pending changes" },
      preview: { status: "observed", reviewPresent: true, reviewActivated: true },
      actions: { status: "observed", reviewUpdatePresent: true, channelOnly: "observed", reviewUpdateActivated: true },
      fleetFreshness: { status: "observed", nixpkgsDays: "30", heartbeatGrace: "15", heartbeatSupported: true, saveClicked: true },
      focus: {
        status: "observed",
        productionWindowSwitchReproduced: true,
        method: "physical-chrome",
        before: "On time",
        during: "Late",
        after: "On time",
        beforePercent: "4.50",
        duringPercent: "12.20",
        afterPercent: "13.06",
        visibleUnfocused: true,
        hostsJsonGet: true,
        clockAdvanced: true,
      },
      notes: "<html>password=secret</html>",
    },
    rawError: "https://auth.inspr.at/ui/login?code=secret",
  });
  const encoded = JSON.stringify(sealed);
  assert.equal(encoded.includes("secret"), false);
  assert.equal(encoded.includes("auth.inspr.at"), false);
  assert.equal(encoded.includes("<html>"), false);
  assert.equal(encoded.includes("person@example"), false);
  assert.equal(encoded.includes("physical-chrome"), false);
  assert.equal(sealed.role, "manager");
  assert.equal(sealed.focusMethod, FOCUS_METHOD);
  assert.equal(sealed.productionWindowSwitchReproduced, false);
  assert.equal(sealed.mapBasemap, "harness-denied-foreign-origin");
  assert.equal(sealed.representativeHost, "");
  assert.deepEqual(sealed.screenshots, ["10-fleet-freshness.png", "host-03-backups.png"]);
  assert.equal(sealed.checks.preview.reviewActivated, false);
  assert.equal(sealed.checks.actions.reviewUpdateActivated, false);
  assert.equal(sealed.checks.actions.channelOnly, "unobservable");
  assert.equal(sealed.checks.fleetFreshness.saveClicked, false);
  assert.equal(sealed.checks.fleetFreshness.nixpkgsDays, "30");
  assert.equal(sealed.checks.lifecycle.chip, "No pending changes");
  assert.equal(sealed.checks.focus.productionWindowSwitchReproduced, false);
  assert.equal(sealed.checks.focus.method, FOCUS_METHOD);
  assert.equal(sealed.checks.focus.beforePercent, "4.50");
  assert.equal(sealed.checks.notes, undefined);
  assert.equal(sealed.rawError, undefined);
  const skipped = inspectionSkipped("not-manager");
  assert.equal(skipped.role, "not-manager");
  assert.equal(skipped.checks.cards.status, "not-supported");
  assert.equal(skipped.checks.draft.status, "not-supported");
  assert.equal(skipped.productionWindowSwitchReproduced, false);
});

test("a non-manager inspection does not touch the page", async () => {
  const page = {
    locator() {
      throw new Error("page used");
    },
  };
  const result = await inspectAuthenticatedClient({
    managerShell: false,
    page,
    openRoute() {
      throw new Error("navigation used");
    },
  });
  assert.equal(result.halt, "");
  assert.equal(result.evidence.role, "not-manager");
  assert.equal(result.evidence.checks.actions.reviewUpdateActivated, false);
});

test("inspection source stays bounded to fixed local actions", () => {
  const source = fs.readFileSync(new URL("../scripts/live-ui-inspect.mjs", import.meta.url), "utf8");
  assert.equal((source.match(/\.click\(/g) || []).length, 1);
  assert.equal((source.match(/\.hover\(/g) || []).length, 1);
  assert.equal((source.match(/\.fill\(/g) || []).length, 1);
  assert.equal((source.match(/\.selectOption\(/g) || []).length, 1);
  assert.equal((source.match(/\.press\(/g) || []).length, 1);
  assert.equal(source.includes('.press("Escape")'), true);
  assert.equal(source.includes(".goto("), false);
  assert.equal(source.includes("newPage"), false);
  assert.equal(source.includes(".screenshot("), false);
  assert.equal(source.includes("fetch("), false);
  assert.equal(source.includes(".post("), false);
  assert.equal(source.includes("storageState"), false);
  assert.equal(source.includes("launchPersistentContext"), false);
  const runner = fs.readFileSync(new URL("../scripts/live-ui.mjs", import.meta.url), "utf8");
  assert.equal(runner.includes("inspectAuthenticatedClient"), true);
  assert.equal(runner.includes("context.on(\"response\""), false);
  assert.equal(runner.includes("settleLiveInspection({ inventoryClass: \"authenticated\", error })"), true);
  assert.equal(runner.includes("settleLiveInspection({ inventoryClass: overall, halt: inspectionHalt })"), true);
  const order = ["step:fleet", "step:cards", "step:history", "step:exact-times", "step:preview", "step:actions", "step:focus", "step:list", "step:tabs", "step:draft", "step:freshness"];
  let cursor = -1;
  for (const step of order) {
    const next = source.indexOf(step, cursor + 1);
    assert.equal(next > cursor, true, step);
    cursor = next;
  }
});

function emptyLocator() {
  const loc = {
    count: async () => 0,
    first() { return loc; },
    nth() { return loc; },
    locator() { return loc; },
    isVisible: async () => false,
    isDisabled: async () => true,
    getAttribute: async () => null,
    inputValue: async () => "",
    innerText: async () => "",
    click: async () => {},
    fill: async () => {},
    selectOption: async () => { throw new Error("not a select"); },
    hover: async () => {},
    evaluate: async () => false,
    boundingBox: async () => null,
    scrollIntoViewIfNeeded: async () => {},
  };
  return loc;
}

test("inspection navigation failures override an authenticated inventory", async () => {
  const guarded = await inspectAuthenticatedClient({
    page: { locator: () => emptyLocator() },
    managerShell: true,
    hostPaths: ["/pharos/hosts/legacy-host"],
    openRoute() {
      throw new LiveUiError("network-guard");
    },
  });
  assert.equal(guarded.halt, "network-guard");
  const guardedClass = settleLiveInspection({
    inventoryClass: "authenticated",
    halt: guarded.halt,
  });
  assert.equal(guardedClass, "network-guard");
  assert.equal(EXIT_CODES[guardedClass] ?? 1, 1);

  const broken = await inspectAuthenticatedClient({
    page: { locator: () => emptyLocator() },
    managerShell: true,
    hostPaths: ["/pharos/hosts/legacy-host"],
    openRoute: async () => ({ class: "broken-ui" }),
  });
  assert.equal(broken.halt, "broken-ui");
  assert.equal(settleLiveInspection({
    inventoryClass: "authenticated",
    halt: broken.halt,
  }), "broken-ui");
  assert.equal(EXIT_CODES["broken-ui"] ?? 1, 1);
  assert.equal(EXIT_CODES.authenticated, 0);

  const thrown = new Error("inspection crashed");
  assert.equal(settleLiveInspection({
    inventoryClass: "authenticated",
    error: new LiveUiError("network-guard"),
  }), "network-guard");
  assert.equal(settleLiveInspection({
    inventoryClass: "authenticated",
    error: thrown,
  }), "broken-ui");
  assert.equal(settleLiveInspection({
    inventoryClass: "authenticated",
    halt: "",
  }), "authenticated");
  assert.equal(settleLiveInspection({
    inventoryClass: "policy-denied",
    halt: "",
  }), "policy-denied");
});

test("missing old-release controls stay not-supported without failing the run", async () => {
  const result = await inspectAuthenticatedClient({
    page: {
      locator: () => emptyLocator(),
      url: () => "https://pharos.example/pharos/?view=list",
    },
    managerShell: true,
    hostPaths: ["/pharos/hosts/legacy-host"],
    openRoute: async () => ({ class: "authenticated" }),
  });
  assert.equal(result.halt, "");
  assert.equal(result.evidence.checks.cards.status, "not-supported");
  assert.equal(result.evidence.checks.draft.status, "not-supported");
  assert.equal(result.evidence.checks.fleetFreshness.status, "not-supported");
  assert.equal(settleLiveInspection({
    inventoryClass: "authenticated",
    halt: result.halt,
  }), "authenticated");
});

test("fleet-default grace edits the settings select and resets locally", async () => {
  const saved = { source: "fleet", seconds: "15", reviewEnabled: false };
  const draft = { source: "fleet", seconds: "15", disabled: true, reviewEnabled: false };
  const trace = [];
  let broadSelects = 0;
  let route = "/pharos/";

  const control = (spec) => {
    const loc = {
      count: async () => 1,
      first() { return loc; },
      nth() { return loc; },
      locator() { return emptyLocator(); },
      isVisible: async () => spec.visible !== false,
      isDisabled: async () => spec.disabled(),
      getAttribute: async (name) => spec.attrs?.[name] ?? null,
      inputValue: async () => spec.value(),
      innerText: async () => spec.text || "",
      click: async () => { if (spec.onClick) spec.onClick(); },
      fill: async (value) => { if (spec.onFill) spec.onFill(value); },
      selectOption: async (value) => { if (spec.onSelect) spec.onSelect(value); },
      hover: async () => {},
      evaluate: async () => false,
      boundingBox: async () => null,
      scrollIntoViewIfNeeded: async () => {},
    };
    return loc;
  };

  const page = {
    url: () => `https://pharos.example${route}`,
    locator(selector) {
      if (selector === "[data-grace-source]") {
        return control({
          disabled: () => false,
          value: () => "section",
          onSelect() {
            broadSelects += 1;
            throw new Error("section precedes the select");
          },
        });
      }
      if (selector === INSPECTION_SELECTORS.fleetMain) {
        return control({
          disabled: () => false,
          value: () => "",
          attrs: { "data-view": "list" },
          text: "",
        });
      }
      if (selector === INSPECTION_SELECTORS.breadcrumb) {
        return control({ disabled: () => false, value: () => "", text: "Fleet" });
      }
      if (selector === INSPECTION_SELECTORS.tabCurrent) {
        const section = route.includes("section=backups")
          ? "backups"
          : route.includes("section=activity")
            ? "activity"
            : route.includes("section=settings")
              ? "settings"
              : "overview";
        return control({
          disabled: () => false,
          value: () => "",
          attrs: { "data-section": section },
        });
      }
      if (selector === INSPECTION_SELECTORS.graceSeconds) {
        return control({
          disabled: () => draft.disabled,
          value: () => draft.seconds,
          onFill(value) {
            if (draft.disabled) throw new Error("seconds stay disabled");
            trace.push({ action: "fill", value });
            draft.seconds = value;
            draft.reviewEnabled = true;
          },
        });
      }
      if (selector === INSPECTION_SELECTORS.graceSource) {
        return control({
          disabled: () => false,
          value: () => draft.source,
          attrs: { "data-fleet-grace-seconds": saved.seconds },
          onSelect(value) {
            trace.push({ action: "select", value });
            draft.source = value;
            draft.disabled = value !== "host";
            if (value !== "host") draft.seconds = saved.seconds;
          },
        });
      }
      if (selector === INSPECTION_SELECTORS.graceReset) {
        return control({
          disabled: () => false,
          value: () => "",
          onClick() {
            trace.push({ action: "reset", from: draft.seconds });
            draft.source = "fleet";
            draft.seconds = saved.seconds;
            draft.disabled = true;
            draft.reviewEnabled = false;
          },
        });
      }
      if (selector === INSPECTION_SELECTORS.reviewSettings) {
        return control({
          disabled: () => !draft.reviewEnabled,
          value: () => "",
        });
      }
      return emptyLocator();
    },
  };

  const result = await inspectAuthenticatedClient({
    page,
    managerShell: true,
    hostPaths: ["/pharos/hosts/legacy-host"],
    openRoute: async (routePath) => {
      route = routePath;
      if (routePath.includes("section=settings")) {
        draft.source = saved.source;
        draft.seconds = saved.seconds;
        draft.disabled = saved.source !== "host";
        draft.reviewEnabled = saved.reviewEnabled;
      }
      return { class: "authenticated" };
    },
  });

  assert.equal(INSPECTION_SELECTORS.graceSource, "select[data-grace-source]");
  assert.equal(broadSelects, 0);
  assert.deepEqual(trace, [
    { action: "select", value: "host" },
    { action: "fill", value: "16" },
    { action: "reset", from: "16" },
  ]);
  assert.equal(result.halt, "");
  assert.equal(result.evidence.checks.draft.status, "observed");
  assert.equal(result.evidence.checks.draft.persistedUnchanged, true);
  assert.equal(result.evidence.checks.draft.resetPresent, true);
  assert.equal(result.evidence.checks.draft.reviewEnabled, true);
  assert.equal(result.evidence.checks.draft.confirmSheets, 0);
  assert.equal(result.evidence.checks.fleetFreshness.status, "not-supported");
  assert.equal(settleLiveInspection({
    inventoryClass: "authenticated",
    halt: result.halt,
  }), "authenticated");
});
