import {
  LiveUiError,
  PERSONAL_APP_ORIGINS,
  SERVER_MUTATION_ALLOWLIST,
  isHostPath,
  publicPath,
} from "./live-ui-guard.mjs";

// Fixed client inspections for one authenticated manager session.
// Clicks, fills, and routes are an allowlist. Application writes stay denied
// by the request guard; this module does not open a browser or a new page.

export const FOCUS_METHOD = "synthetic-visible-unfocused";
export const POLL_WAIT_MS = 12_000;
export const RETURN_WAIT_MS = 1_500;
export const CLICK_ALLOWLIST = Object.freeze([
  "exact-times",
  "preview",
  "drawer-close",
  "grace-reset",
  "actions-trigger",
]);
export const DOM_ALLOWLIST = Object.freeze(["grace-seconds", "grace-source"]);
export const INSPECTION_SELECTORS = Object.freeze({
  runtimeCard: "article.card[data-host-surface='runtime']",
  runtimeRow: "tr[data-host-surface='runtime']",
  nameLink: "a.host-name",
  previewButton: "button.preview-button",
  osBadge: "[data-health-badge]",
  protection: "[data-protection]",
  factLabel: ".fact-label",
  factValue: ".fact-value",
  exactTimes: "[data-protection-evidence]",
  exactSummary: "[data-protection-evidence] > summary",
  backupInstant: "[data-daily-backup-instant-label]",
  restoreInstant: "[data-restore-instant-label]",
  historyMark: ".beat-mark",
  historyHint: "#history-hint",
  fleetMain: "main[data-fleet-sync-state]",
  settingsChip: "a.settings-card",
  drawer: "#host-quick-drawer",
  drawerLayer: "[data-host-drawer-layer]",
  drawerClose: "[data-host-drawer-close]",
  drawerReview: "[data-host-drawer-review]",
  hostTab: "a[data-host-tab]",
  currentTab: "a[data-host-tab][aria-current='page']",
  breadcrumb: "a[data-fleet-return]",
  graceSeconds: "[data-grace-seconds]",
  graceReset: "[data-grace-reset]",
  graceSource: "select[data-grace-source]",
  discardDraft: "[data-discard-settings]",
  reviewSettings: "[data-review-settings]",
  colorInput: "input[data-color]",
  alertDown: "[data-alert-down]",
  freshnessTitle: "#fleet-freshness-title",
  nixpkgsDays: "input[name='nixpkgs_warn_after_days']",
  heartbeatGrace: "input[name='heartbeat_grace_secs']",
  lifecycleCopy: "[data-host-lifecycle-chip-copy]",
  actionsTrigger: "[data-host-actions-trigger]",
  actionsMenu: "[data-host-actions-menu]",
  updateRestart: "[data-host-action='update-restart']",
  sideLink: "a.side-link",
  lighthouse: ".side-mark",
  account: ".side-user",
  version: "[data-calendar-display]",
});
const CHIP_COPY = new Set(["No pending changes", "Up to date"]);
const ARRIVAL_LABELS = new Set(["On time", "Late", "Stale", "Down", "No heartbeat yet"]);
const SHOT_NAME =
  /^(?:01-home-list|10-fleet-freshness|11-card-exact-times|12-quick-preview|13-actions-menu|14-history-hint)\.png$|^host-\d{2}(?:-settings|-backups|-activity|-settings-draft)?\.png$/;
const FAILURE_HALTS = new Set([
  "broken-ui",
  "network-guard",
  "mfa-required",
  "auth-required",
  "account-setup-required",
  "policy-denied",
]);

export function inspectionFailureClass(error) {
  const code = error instanceof LiveUiError ? error.code : "";
  return code === "network-guard" ? "network-guard" : "broken-ui";
}

export function settleLiveInspection({ inventoryClass, halt = "", error = null } = {}) {
  if (error) return inspectionFailureClass(error);
  if (FAILURE_HALTS.has(halt)) return halt;
  return inventoryClass;
}

export function clickPermitted(action) {
  return CLICK_ALLOWLIST.includes(action);
}

export function domChangePermitted(action) {
  return DOM_ALLOWLIST.includes(action);
}

export function allowlistedChipCopy(text) {
  const value = String(text ?? "").replace(/\s+/g, " ").trim();
  return CHIP_COPY.has(value) ? value : "";
}

export function allowlistedArrival(text) {
  const value = String(text ?? "").replace(/\s+/g, " ").trim();
  return ARRIVAL_LABELS.has(value) ? value : "";
}

export function arrivalPercent(style) {
  const match = String(style ?? "").match(/--(?:arrival-x|cadence-x):\s*(\d{1,3}(?:\.\d{1,2})?)%/);
  if (!match) return "";
  const number = Number(match[1]);
  if (!Number.isFinite(number) || number < 0 || number > 100) return "";
  return match[1];
}

export function allowlistedVersion(text) {
  const value = String(text ?? "").trim();
  return /^\d{12}\.\d+\.\d+$/.test(value) ? value : "";
}

export function allowlistedSeconds(text, max = 3600) {
  if (!/^\d{1,4}$/.test(String(text ?? ""))) return "";
  const number = Number(text);
  if (!Number.isInteger(number) || number < 0 || number > max) return "";
  return String(number);
}

export function alternateGraceSeconds(saved) {
  const current = allowlistedSeconds(saved, 3600);
  if (!current) return "";
  const value = Number(current);
  return String(value === 3600 ? 3599 : value + 1);
}

export function boxSize(box) {
  if (!box || typeof box !== "object") return null;
  const width = Math.round(Number(box.width));
  const height = Math.round(Number(box.height));
  if (!Number.isInteger(width) || !Number.isInteger(height)) return null;
  if (width < 0 || height < 0 || width > 4000 || height > 4000) return null;
  return { width, height };
}

export function boxUnchanged(before, after) {
  const left = boxSize(before);
  const right = boxSize(after);
  if (!left || !right) return false;
  return left.width === right.width && left.height === right.height;
}

export function searchQueryPresent(rawUrl) {
  const raw = String(rawUrl ?? "");
  if (raw.length < 1 || raw.length > 500) return false;
  try {
    return new URL(raw, `${PERSONAL_APP_ORIGINS[0]}/`).searchParams.has("q");
  } catch {
    return false;
  }
}

export function publicPathFromUrl(rawUrl) {
  const raw = String(rawUrl ?? "");
  if (raw.length < 1 || raw.length > 500) return "";
  try {
    const url = new URL(raw, `${PERSONAL_APP_ORIGINS[0]}/`);
    return publicPath(`${url.pathname}${url.search}`, []);
  } catch {
    return "";
  }
}

export function representativeHostPath(paths) {
  if (!Array.isArray(paths)) return "";
  for (const candidate of paths.slice(0, 64)) {
    const bare = publicPath(String(candidate ?? ""), []).split("?")[0];
    if (isHostPath(bare)) return bare;
  }
  return "";
}

export function hostLinkMatches(hostPath, hrefPath) {
  const host = representativeHostPath([hostPath]);
  const href = publicPath(String(hrefPath ?? ""), []).split("?")[0];
  return host !== "" && href === host;
}

export function plannedInspectionRoutes(hostPath) {
  const host = representativeHostPath([hostPath]);
  const routes = ["/pharos/", "/pharos/?view=list", "/pharos/settings/providers"];
  if (host) {
    routes.push(host, `${host}?section=backups`, `${host}?section=activity`, `${host}?section=settings`);
  }
  return routes;
}

export function inspectionRouteAllowed(hostPath, routePath) {
  const path = publicPath(String(routePath ?? ""), []);
  return plannedInspectionRoutes(hostPath).includes(path);
}

export function countVisibleConfirmSheets() {
  const document = globalThis.document;
  if (!document || typeof document.querySelectorAll !== "function") return 0;
  const nodes = document.querySelectorAll("[data-host-action-overlay], [data-host-remove-confirm]");
  let count = 0;
  for (const node of nodes) {
    if (node.hidden) continue;
    if (typeof node.getClientRects === "function" && node.getClientRects().length === 0) continue;
    count += 1;
  }
  return Math.min(count, 8);
}

export function applyFleetFocus(action) {
  if (action === "blur") window.dispatchEvent(new Event("blur"));
  else if (action === "focus") window.dispatchEvent(new Event("focus"));
  const document = globalThis.document;
  const label = document?.querySelector?.("[data-arrival-label]");
  const beat = document?.querySelector?.(".beat");
  const cadence = String(beat?.style?.getPropertyValue?.("--cadence-x") || "").trim();
  const fill = document?.querySelector?.("[data-arrival-fill]");
  const focus = String(document?.documentElement?.dataset?.fleetFocus || "");
  return {
    label: String(label?.textContent || "").slice(0, 48),
    style: String(cadence ? `--cadence-x:${cadence}` : fill?.getAttribute?.("style") || "").slice(0, 80),
    hidden: document?.hidden === true,
    focus: focus === "focused" || focus === "unfocused" ? focus : "",
  };
}

function checkStatus(value) {
  if (value === "observed" || value === "not-supported" || value === "unobservable" || value === "partial") {
    return value;
  }
  return "partial";
}

function flag(value) {
  return value === true;
}

function smallCount(value, max = 32) {
  const number = Number(value);
  if (!Number.isInteger(number) || number < 0 || number > max) return 0;
  return number;
}

function shotName(value) {
  return typeof value === "string" && SHOT_NAME.test(value) ? value : "";
}

function unsupportedChecks() {
  const absent = { status: "not-supported" };
  return {
    shell: { ...absent, linkCount: 0, sevenLinks: false, lighthouse: false, accountPresent: false, version: "" },
    cards: {
      ...absent,
      nameLink: false,
      quickPreview: false,
      osBadge: false,
      protectionPair: false,
      exactTimesClosed: false,
      backupLastSuccess: false,
      selectiveRestoreLastSuccess: false,
    },
    history: { ...absent, hintVisible: false, boxUnchanged: false, restored: false },
    list: {
      ...absent,
      viewRetained: false,
      viewAttribute: false,
      nameLink: false,
      quickPreview: false,
      settingsChip: false,
      protectionPair: false,
      rowHeight: 0,
    },
    preview: {
      ...absent,
      drawerVisible: false,
      focusInside: false,
      reviewPresent: false,
      reviewActivated: false,
      escapeClosed: false,
      focusReturned: false,
    },
    actions: {
      ...absent,
      menuOpen: false,
      reviewUpdatePresent: false,
      reviewUpdateActivated: false,
      channelOnly: "unobservable",
    },
    lifecycle: { ...absent, chip: "" },
    tabs: {
      ...absent,
      overview: false,
      backups: false,
      activity: false,
      settings: false,
      breadcrumbFleet: false,
      color: false,
      alerts: false,
      grace: false,
      discard: false,
      review: false,
    },
    draft: {
      ...absent,
      reviewEnabled: false,
      confirmSheets: 0,
      resetPresent: false,
      persistedUnchanged: false,
    },
    fleetFreshness: {
      ...absent,
      titleVisible: false,
      nixpkgsDays: "",
      heartbeatGrace: "",
      heartbeatSupported: false,
      saveClicked: false,
    },
    focus: {
      ...absent,
      method: FOCUS_METHOD,
      productionWindowSwitchReproduced: false,
      documentHidden: false,
      visibleUnfocused: false,
      before: "",
      during: "",
      after: "",
      beforePercent: "",
      duringPercent: "",
      afterPercent: "",
      hostsJsonGet: false,
      hostsJsonGetWhileUnfocused: false,
      hostsJsonGetAfterReturn: false,
      clockAdvanced: false,
    },
  };
}

export function sealInspection(raw = {}) {
  const base = unsupportedChecks();
  const checks = raw?.checks && typeof raw.checks === "object" ? raw.checks : {};
  const merge = (key, fields) => {
    const source = checks[key] && typeof checks[key] === "object" ? checks[key] : {};
    const next = { ...base[key], ...fields(source) };
    next.status = checkStatus(source.status || base[key].status);
    return next;
  };
  const host = representativeHostPath([raw?.representativeHost]);
  const screenshots = [];
  if (Array.isArray(raw?.screenshots)) {
    for (const name of raw.screenshots) {
      const shot = shotName(name);
      if (shot && !screenshots.includes(shot)) screenshots.push(shot);
      if (screenshots.length >= 12) break;
    }
  }
  return {
    schema: "inspr.pharos.live-ui-inspection.v1",
    role: raw?.role === "manager" ? "manager" : "not-manager",
    focusMethod: FOCUS_METHOD,
    productionWindowSwitchReproduced: false,
    mapBasemap: "harness-denied-foreign-origin",
    searchQueryRetained: flag(raw?.searchQueryRetained),
    representativeHost: host,
    screenshots,
    checks: {
      shell: merge("shell", (source) => ({
        linkCount: smallCount(source.linkCount, 16),
        sevenLinks: flag(source.sevenLinks),
        lighthouse: flag(source.lighthouse),
        accountPresent: flag(source.accountPresent),
        version: allowlistedVersion(source.version),
      })),
      cards: merge("cards", (source) => ({
        nameLink: flag(source.nameLink),
        quickPreview: flag(source.quickPreview),
        osBadge: flag(source.osBadge),
        protectionPair: flag(source.protectionPair),
        exactTimesClosed: flag(source.exactTimesClosed),
        backupLastSuccess: flag(source.backupLastSuccess),
        selectiveRestoreLastSuccess: flag(source.selectiveRestoreLastSuccess),
      })),
      history: merge("history", (source) => ({
        hintVisible: flag(source.hintVisible),
        boxUnchanged: flag(source.boxUnchanged),
        restored: flag(source.restored),
      })),
      list: merge("list", (source) => ({
        viewRetained: flag(source.viewRetained),
        viewAttribute: flag(source.viewAttribute),
        nameLink: flag(source.nameLink),
        quickPreview: flag(source.quickPreview),
        settingsChip: flag(source.settingsChip),
        protectionPair: flag(source.protectionPair),
        rowHeight: smallCount(source.rowHeight, 4000),
      })),
      preview: merge("preview", (source) => ({
        drawerVisible: flag(source.drawerVisible),
        focusInside: flag(source.focusInside),
        reviewPresent: flag(source.reviewPresent),
        reviewActivated: false,
        escapeClosed: flag(source.escapeClosed),
        focusReturned: flag(source.focusReturned),
      })),
      actions: merge("actions", (source) => ({
        menuOpen: flag(source.menuOpen),
        reviewUpdatePresent: flag(source.reviewUpdatePresent),
        reviewUpdateActivated: false,
        channelOnly: "unobservable",
      })),
      lifecycle: merge("lifecycle", (source) => ({
        chip: allowlistedChipCopy(source.chip),
      })),
      tabs: merge("tabs", (source) => ({
        overview: flag(source.overview),
        backups: flag(source.backups),
        activity: flag(source.activity),
        settings: flag(source.settings),
        breadcrumbFleet: flag(source.breadcrumbFleet),
        color: flag(source.color),
        alerts: flag(source.alerts),
        grace: flag(source.grace),
        discard: flag(source.discard),
        review: flag(source.review),
      })),
      draft: merge("draft", (source) => ({
        reviewEnabled: flag(source.reviewEnabled),
        confirmSheets: smallCount(source.confirmSheets, 8),
        resetPresent: flag(source.resetPresent),
        persistedUnchanged: flag(source.persistedUnchanged),
      })),
      fleetFreshness: merge("fleetFreshness", (source) => ({
        titleVisible: flag(source.titleVisible),
        nixpkgsDays: allowlistedSeconds(source.nixpkgsDays, 3650),
        heartbeatGrace: allowlistedSeconds(source.heartbeatGrace, 3600),
        heartbeatSupported: flag(source.heartbeatSupported),
        saveClicked: false,
      })),
      focus: merge("focus", (source) => ({
        method: FOCUS_METHOD,
        productionWindowSwitchReproduced: false,
        documentHidden: flag(source.documentHidden),
        visibleUnfocused: flag(source.visibleUnfocused),
        before: allowlistedArrival(source.before),
        during: allowlistedArrival(source.during),
        after: allowlistedArrival(source.after),
        beforePercent: arrivalPercent(`--arrival-x:${source.beforePercent}%`),
        duringPercent: arrivalPercent(`--arrival-x:${source.duringPercent}%`),
        afterPercent: arrivalPercent(`--arrival-x:${source.afterPercent}%`),
        hostsJsonGet: flag(source.hostsJsonGet),
        hostsJsonGetWhileUnfocused: flag(source.hostsJsonGetWhileUnfocused),
        hostsJsonGetAfterReturn: flag(source.hostsJsonGetAfterReturn),
        clockAdvanced: flag(source.clockAdvanced),
      })),
    },
  };
}

export function inspectionSkipped(reason) {
  const manager = reason !== "not-manager";
  const checks = unsupportedChecks();
  const status = manager ? "partial" : "not-supported";
  for (const check of Object.values(checks)) check.status = status;
  return sealInspection({ role: manager ? "manager" : "not-manager", checks });
}

async function isShown(locator) {
  try {
    return await locator.first().isVisible({ timeout: 1500 });
  } catch {
    return false;
  }
}

async function attr(locator, name) {
  try {
    if ((await locator.count()) < 1) return "";
    const value = await locator.first().getAttribute(name, { timeout: 1500 });
    return typeof value === "string" ? value.slice(0, 80) : "";
  } catch {
    return "";
  }
}

async function linkedPath(locator) {
  const href = await attr(locator, "href");
  if (!href) return "";
  return publicPathFromUrl(href);
}

async function matchingSurface(page, selector, host) {
  const nodes = page.locator(selector);
  let total = 0;
  try {
    total = await nodes.count();
  } catch {
    return null;
  }
  const cap = Math.min(total, 32);
  for (let index = 0; index < cap; index += 1) {
    const node = nodes.nth(index);
    const linked = await linkedPath(node.locator(INSPECTION_SELECTORS.nameLink));
    if (hostLinkMatches(host, linked)) return node;
  }
  return null;
}

async function clickAllowed(locator, action) {
  if (!clickPermitted(action)) return false;
  try {
    await locator.click({ timeout: 2000 });
    return true;
  } catch {
    return false;
  }
}

async function pressEscape(page) {
  try {
    await page.keyboard.press("Escape");
    return true;
  } catch {
    return false;
  }
}

async function markedHidden(locator) {
  try {
    if ((await locator.count()) < 1) return true;
    return await locator.first().evaluate((element) => element.hasAttribute("hidden"));
  } catch {
    return true;
  }
}

async function recordedStamp(locator) {
  try {
    if ((await locator.count()) < 1) return false;
    const text = await locator.first().innerText({ timeout: 1500 });
    return /\d{4}-\d{2}-\d{2} \d{2}:\d{2}:\d{2} UTC/.test(String(text));
  } catch {
    return false;
  }
}

async function exactText(locator, expected) {
  try {
    if ((await locator.count()) < 1) return false;
    const text = await locator.first().innerText({ timeout: 1500 });
    return String(text).replace(/\s+/g, " ").trim() === expected;
  } catch {
    return false;
  }
}

async function numericInput(locator, max) {
  try {
    if ((await locator.count()) < 1) return "";
    return allowlistedSeconds(await locator.first().inputValue({ timeout: 1500 }), max);
  } catch {
    return "";
  }
}

async function elementDisabled(locator) {
  try {
    if ((await locator.count()) < 1) return true;
    return await locator.first().isDisabled({ timeout: 1500 });
  } catch {
    return true;
  }
}

async function confirmSheets(page) {
  try {
    return smallCount(await page.evaluate(countVisibleConfirmSheets), 8);
  } catch {
    return 0;
  }
}

async function simulateVisibleUnfocused(page) {
  if (typeof page?.on !== "function" || typeof page?.waitForTimeout !== "function" || typeof page?.evaluate !== "function") {
    return { status: "partial" };
  }
  let phase = "during";
  let duringGet = false;
  let afterGet = false;
  const onRequest = (request) => {
    let method = "";
    let pathname = "";
    try {
      method = typeof request?.method === "function" ? request.method() : "";
      pathname = new URL(String(request.url())).pathname;
    } catch {
      return;
    }
    if (method !== "GET" || pathname !== "/pharos/hosts.json") return;
    if (phase === "during") duringGet = true;
    else afterGet = true;
  };
  page.on("request", onRequest);
  try {
    const beforeSample = await page.evaluate(applyFleetFocus, "read");
    const blurred = await page.evaluate(applyFleetFocus, "blur");
    await page.waitForTimeout(POLL_WAIT_MS);
    const duringSample = await page.evaluate(applyFleetFocus, "read");
    phase = "after";
    await page.evaluate(applyFleetFocus, "focus");
    await page.waitForTimeout(RETURN_WAIT_MS);
    const afterSample = await page.evaluate(applyFleetFocus, "read");
    const beforePercent = arrivalPercent(beforeSample?.style);
    const duringPercent = arrivalPercent(duringSample?.style);
    const afterPercent = arrivalPercent(afterSample?.style);
    const before = allowlistedArrival(beforeSample?.label);
    const during = allowlistedArrival(duringSample?.label);
    const after = allowlistedArrival(afterSample?.label);
    return {
      status: duringGet || afterGet ? "observed" : "partial",
      documentHidden: blurred?.hidden === true,
      visibleUnfocused: blurred?.hidden !== true && blurred?.focus === "unfocused",
      before,
      during,
      after,
      beforePercent,
      duringPercent,
      afterPercent,
      hostsJsonGet: duringGet || afterGet,
      hostsJsonGetWhileUnfocused: duringGet,
      hostsJsonGetAfterReturn: afterGet,
      clockAdvanced:
        (beforePercent !== "" && duringPercent !== "" && beforePercent !== duringPercent) ||
        (before !== "" && during !== "" && before !== during),
    };
  } catch {
    return { status: "partial" };
  } finally {
    if (typeof page.off === "function") page.off("request", onRequest);
  }
}

export async function inspectAuthenticatedClient(options = {}) {
  if (options.managerShell !== true || SERVER_MUTATION_ALLOWLIST.length !== 0) {
    return {
      evidence: inspectionSkipped(options.managerShell === true ? "partial" : "not-manager"),
      halt: "",
    };
  }
  const page = options.page;
  const openRoute = options.openRoute;
  const shoot = options.shoot;
  if (!page || typeof page.locator !== "function" || typeof openRoute !== "function") {
    return { evidence: inspectionSkipped("partial"), halt: "" };
  }
  const host = representativeHostPath(options.hostPaths);
  const checks = unsupportedChecks();
  const screenshots = [];
  let halt = "";
  let searchQueryRetained = false;

  const finish = () => ({
    evidence: sealInspection({
      role: "manager",
      representativeHost: host,
      searchQueryRetained,
      screenshots,
      checks,
    }),
    halt: FAILURE_HALTS.has(halt) ? halt : "",
  });

  const go = async (routePath) => {
    if (halt) return false;
    if (!inspectionRouteAllowed(host, routePath)) {
      halt = "broken-ui";
      return false;
    }
    try {
      const viewed = await openRoute(routePath);
      if (!viewed || viewed.class !== "authenticated") {
        halt = FAILURE_HALTS.has(viewed?.class) ? viewed.class : "broken-ui";
        return false;
      }
      return true;
    } catch (error) {
      halt = inspectionFailureClass(error);
      return false;
    }
  };

  const capture = async (routePath, substep = "") => {
    if (typeof shoot !== "function") return;
    try {
      const name = await shoot(routePath, substep);
      const shot = shotName(name);
      if (shot && !screenshots.includes(shot)) screenshots.push(shot);
    } catch {
      // A refused shot stays absent.
    }
  };

  // step:fleet
  if (!(await go("/pharos/"))) {
    if (halt) checks.shell.status = "partial";
    return finish();
  }
  const fleet = page.locator(INSPECTION_SELECTORS.fleetMain);
  checks.shell = {
    status: (await isShown(fleet)) ? "observed" : "partial",
    linkCount: smallCount(await page.locator(INSPECTION_SELECTORS.sideLink).count().catch(() => 0), 16),
    sevenLinks: false,
    lighthouse: await isShown(page.locator(INSPECTION_SELECTORS.lighthouse)),
    accountPresent: await isShown(page.locator(INSPECTION_SELECTORS.account)),
    version: allowlistedVersion(await attr(page.locator(INSPECTION_SELECTORS.version), "data-canonical")),
  };
  checks.shell.sevenLinks = checks.shell.linkCount === 7;

  const card = host ? await matchingSurface(page, INSPECTION_SELECTORS.runtimeCard, host) : null;
  // step:cards
  if (!card) {
    checks.cards.status = "not-supported";
  } else {
    try {
      await card.scrollIntoViewIfNeeded({ timeout: 2000 });
    } catch {
      // A card below the fold can still be read.
    }
    const nameLinked = hostLinkMatches(host, await linkedPath(card.locator(INSPECTION_SELECTORS.nameLink)));
    const protection = card.locator(INSPECTION_SELECTORS.protection);
    const exact = card.locator(INSPECTION_SELECTORS.exactTimes);
    const exactHidden = await markedHidden(exact);
    let exactClosed = exactHidden;
    try {
      if (!exactHidden) exactClosed = (await exact.evaluate((element) => element.open === true)) === false;
    } catch {
      exactClosed = false;
    }
    checks.cards = {
      status: "observed",
      nameLink: nameLinked,
      quickPreview: await isShown(card.locator(INSPECTION_SELECTORS.previewButton)),
      osBadge: await isShown(card.locator(INSPECTION_SELECTORS.osBadge)),
      protectionPair:
        (await isShown(protection)) &&
        (await isShown(protection.locator(INSPECTION_SELECTORS.factLabel))) &&
        (await isShown(protection.locator(INSPECTION_SELECTORS.factValue))),
      exactTimesClosed: exactClosed,
      backupLastSuccess: false,
      selectiveRestoreLastSuccess: false,
    };
    // step:history
    const mark = card.locator(INSPECTION_SELECTORS.historyMark).first();
    const beforeBox = boxSize(await card.boundingBox({ timeout: 1500 }).catch(() => null));
    if (await isShown(mark)) {
      try {
        await mark.hover({ timeout: 2000 });
        const hint = page.locator(INSPECTION_SELECTORS.historyHint);
        const hintVisible = await isShown(hint);
        const afterBox = boxSize(await card.boundingBox({ timeout: 1500 }).catch(() => null));
        await capture("/pharos/", "history-hint");
        if (typeof page.mouse?.move === "function") await page.mouse.move(1, 1);
        const restored = (await isShown(hint)) === false;
        checks.history = {
          status: "observed",
          hintVisible,
          boxUnchanged: boxUnchanged(beforeBox, afterBox),
          restored,
        };
      } catch {
        checks.history.status = "partial";
      }
    } else {
      checks.history.status = "not-supported";
    }
    // step:exact-times
    if (!exactHidden) {
      const opened = await clickAllowed(exact.locator("summary"), "exact-times");
      let isOpen = false;
      try {
        isOpen = await exact.evaluate((element) => element.open === true);
      } catch {
        isOpen = false;
      }
      checks.cards.backupLastSuccess = await exactText(exact.locator(INSPECTION_SELECTORS.backupInstant), "Backup last success");
      checks.cards.selectiveRestoreLastSuccess = await exactText(
        exact.locator(INSPECTION_SELECTORS.restoreInstant),
        "Selective restore last success",
      );
      if (opened && isOpen) await capture("/pharos/", "card-exact-times");
    }
    // step:preview
    const trigger = card.locator(INSPECTION_SELECTORS.previewButton);
    if (await isShown(trigger)) {
      const opened = await clickAllowed(trigger, "preview");
      const drawer = page.locator(INSPECTION_SELECTORS.drawer);
      const drawerVisible = await isShown(drawer);
      let focusInside = false;
      try {
        focusInside = await drawer.evaluate((element) => element.contains(document.activeElement));
      } catch {
        focusInside = false;
      }
      const reviewPresent = await isShown(page.locator(INSPECTION_SELECTORS.drawerReview));
      if (drawerVisible) {
        await capture("/pharos/", "quick-preview");
        const backupClock = await recordedStamp(drawer.locator("[data-host-drawer-backup-clock]"));
        const restoreClock = await recordedStamp(drawer.locator("[data-host-drawer-restore-clock]"));
        checks.cards.backupLastSuccess =
          (await exactText(drawer.locator(INSPECTION_SELECTORS.backupInstant), "Backup last success")) && backupClock;
        checks.cards.selectiveRestoreLastSuccess =
          (await exactText(drawer.locator(INSPECTION_SELECTORS.restoreInstant), "Selective restore last success")) &&
          restoreClock;
      }
      const escaped = await pressEscape(page);
      let escapeClosed = (await isShown(page.locator(INSPECTION_SELECTORS.drawerLayer))) === false;
      if (!escapeClosed) {
        await clickAllowed(page.locator(`${INSPECTION_SELECTORS.drawer} ${INSPECTION_SELECTORS.drawerClose}`), "drawer-close");
        escapeClosed = (await isShown(page.locator(INSPECTION_SELECTORS.drawerLayer))) === false;
      }
      let focusReturned = false;
      try {
        focusReturned = await trigger.evaluate((element) => element === document.activeElement);
      } catch {
        focusReturned = false;
      }
      checks.preview = {
        status: opened && drawerVisible ? "observed" : "partial",
        drawerVisible,
        focusInside,
        reviewPresent,
        reviewActivated: false,
        escapeClosed: escaped && escapeClosed,
        focusReturned,
      };
    } else {
      checks.preview.status = "not-supported";
    }
    // step:actions
    const actions = card.locator(INSPECTION_SELECTORS.actionsTrigger);
    const chipText = await card
      .locator(INSPECTION_SELECTORS.lifecycleCopy)
      .innerText({ timeout: 1500 })
      .catch(() => "");
    checks.lifecycle = {
      status: (await card.locator(INSPECTION_SELECTORS.lifecycleCopy).count().catch(() => 0)) > 0 ? "observed" : "not-supported",
      chip: allowlistedChipCopy(chipText),
    };
    if (await isShown(actions)) {
      const opened = await clickAllowed(actions, "actions-trigger");
      const menu = card.locator(INSPECTION_SELECTORS.actionsMenu);
      const menuOpen = (await attr(actions, "aria-expanded")) === "true" && (await isShown(menu));
      const reviewItem = menu.locator(INSPECTION_SELECTORS.updateRestart);
      const reviewUpdatePresent = (await reviewItem.count().catch(() => 0)) > 0 && (await isShown(reviewItem));
      if (menuOpen) await capture("/pharos/", "actions-menu");
      await pressEscape(page);
      if ((await attr(actions, "aria-expanded")) === "true") await clickAllowed(actions, "actions-trigger");
      checks.actions = {
        status: opened ? "observed" : "partial",
        menuOpen,
        reviewUpdatePresent,
        reviewUpdateActivated: false,
        channelOnly: "unobservable",
      };
    } else {
      checks.actions.status = "not-supported";
    }
  }

  // step:focus
  if (!halt) checks.focus = { ...checks.focus, ...(await simulateVisibleUnfocused(page)) };

  // step:list
  if (await go("/pharos/?view=list")) {
    let rawUrl = "";
    try {
      rawUrl = typeof page.url === "function" ? page.url() : "";
    } catch {
      rawUrl = "";
    }
    searchQueryRetained = searchQueryPresent(rawUrl);
    const viewRetained = publicPathFromUrl(rawUrl) === "/pharos/?view=list";
    const viewAttribute = (await attr(page.locator(INSPECTION_SELECTORS.fleetMain), "data-view")) === "list";
    const row = host ? await matchingSurface(page, INSPECTION_SELECTORS.runtimeRow, host) : null;
    let rowHeight = 0;
    if (row) {
      const size = boxSize(await row.boundingBox({ timeout: 1500 }).catch(() => null));
      rowHeight = size ? size.height : 0;
    }
    checks.list = {
      status: viewRetained && viewAttribute ? "observed" : "partial",
      viewRetained,
      viewAttribute,
      nameLink: row ? hostLinkMatches(host, await linkedPath(row.locator(INSPECTION_SELECTORS.nameLink))) : false,
      quickPreview: row ? await isShown(row.locator(INSPECTION_SELECTORS.previewButton)) : false,
      settingsChip: row ? hostLinkMatches(host, await linkedPath(row.locator(INSPECTION_SELECTORS.settingsChip))) : false,
      protectionPair: row ? await isShown(row.locator(INSPECTION_SELECTORS.protection)) : false,
      rowHeight,
    };
    if (viewRetained) await capture("/pharos/?view=list");
  }

  // step:tabs
  if (host && !halt) {
    const sections = [
      ["overview", host],
      ["backups", `${host}?section=backups`],
      ["activity", `${host}?section=activity`],
      ["settings", `${host}?section=settings`],
    ];
    const tabResult = {
      status: "partial",
      overview: false,
      backups: false,
      activity: false,
      settings: false,
      breadcrumbFleet: false,
      color: false,
      alerts: false,
      grace: false,
      discard: false,
      review: false,
    };
    for (const [section, routePath] of sections) {
      if (!(await go(routePath))) break;
      const current = await attr(page.locator(INSPECTION_SELECTORS.currentTab), "data-section");
      tabResult[section] = current === section;
      tabResult.breadcrumbFleet = await exactText(page.locator(INSPECTION_SELECTORS.breadcrumb), "Fleet");
      await capture(routePath);
      if (section === "settings") {
        tabResult.color = await isShown(page.locator(INSPECTION_SELECTORS.colorInput));
        tabResult.alerts = await isShown(page.locator(INSPECTION_SELECTORS.alertDown));
        tabResult.grace = (await page.locator(INSPECTION_SELECTORS.graceSeconds).count().catch(() => 0)) > 0;
        tabResult.discard = await isShown(page.locator(INSPECTION_SELECTORS.discardDraft));
        tabResult.review = await isShown(page.locator(INSPECTION_SELECTORS.reviewSettings));
      }
    }
    const seen = ["overview", "backups", "activity", "settings"].filter((section) => tabResult[section]).length;
    tabResult.status = seen === 4 ? "observed" : seen === 0 ? "not-supported" : "partial";
    checks.tabs = tabResult;

    // step:draft
    const settingsPath = `${host}?section=settings`;
    if (!halt && (await page.locator(INSPECTION_SELECTORS.graceSeconds).count().catch(() => 0)) > 0) {
      const seconds = page.locator(INSPECTION_SELECTORS.graceSeconds).first();
      const source = page.locator(INSPECTION_SELECTORS.graceSource).first();
      const reset = page.locator(INSPECTION_SELECTORS.graceReset).first();
      const before = await numericInput(seconds, 3600);
      const resetPresent = await isShown(reset);
      let edited = false;
      if (before && domChangePermitted("grace-seconds")) {
        if (await elementDisabled(seconds)) {
          if ((await source.count().catch(() => 0)) > 0 && domChangePermitted("grace-source")) {
            try {
              await source.selectOption("host", { timeout: 2000 });
              edited = true;
            } catch {
              edited = false;
            }
          }
        }
        const next = alternateGraceSeconds(before);
        if (next && !(await elementDisabled(seconds))) {
          try {
            await seconds.fill(next, { timeout: 2000 });
            edited = true;
          } catch {
            edited = false;
          }
        }
      }
      const reviewEnabled = (await isShown(page.locator(INSPECTION_SELECTORS.reviewSettings))) &&
        (await elementDisabled(page.locator(INSPECTION_SELECTORS.reviewSettings))) === false;
      const sheets = await confirmSheets(page);
      if (resetPresent && !(await elementDisabled(reset))) await clickAllowed(reset, "grace-reset");
      const sheetsAfter = Math.max(sheets, await confirmSheets(page));
      let persistedUnchanged = false;
      if (await go(settingsPath)) {
        const after = await numericInput(page.locator(INSPECTION_SELECTORS.graceSeconds).first(), 3600);
        persistedUnchanged = before !== "" && after === before;
      }
      checks.draft = {
        status: before ? (edited ? "observed" : "partial") : "not-supported",
        reviewEnabled,
        confirmSheets: sheetsAfter,
        resetPresent,
        persistedUnchanged,
      };
    } else if (!halt) {
      checks.draft.status = "not-supported";
    }
  }

  // step:freshness
  if (await go("/pharos/settings/providers")) {
    const title = page.locator(INSPECTION_SELECTORS.freshnessTitle);
    if ((await title.count().catch(() => 0)) < 1) {
      checks.fleetFreshness.status = "not-supported";
    } else {
      try {
        await title.scrollIntoViewIfNeeded({ timeout: 2000 });
      } catch {
        // Visibility is recorded from the box either way.
      }
      const titleBox = boxSize(await title.boundingBox({ timeout: 1500 }).catch(() => null));
      const days = page.locator(INSPECTION_SELECTORS.nixpkgsDays);
      const grace = page.locator(INSPECTION_SELECTORS.heartbeatGrace);
      const heartbeatSupported = (await grace.count().catch(() => 0)) > 0;
      checks.fleetFreshness = {
        status: (await days.count().catch(() => 0)) > 0 ? "observed" : "partial",
        titleVisible: Boolean(titleBox && titleBox.height > 0),
        nixpkgsDays: await numericInput(days, 3650),
        heartbeatGrace: heartbeatSupported ? await numericInput(grace, 3600) : "",
        heartbeatSupported,
        saveClicked: false,
      };
      await capture("/pharos/settings/providers", "fleet-freshness");
    }
  }

  return finish();
}
