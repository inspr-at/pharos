import { test as base, expect } from "@playwright/test";
import { newAuthedContext, waitForHarnessTokens } from "./harness.mjs";

const test = base.extend({
  page: async ({ browser }, use) => {
    await waitForHarnessTokens();
    const context = await newAuthedContext(browser, "read");
    const page = await context.newPage();
    await use(page);
    await context.close();
  },
});

const tileOrigin = "https://tiles.openfreemap.org";
const hosts = ["map-alpha", "map-bravo"].map((name, index) => ({
  name, lat: 47.1, lon: 15.4, live: "live", status: "Live",
  search: name, settings_href: `/hosts/${name}/settings`,
  site_id: "synthetic-site", site_label: "Synthetic site", region: "Europe",
  location_source: "declared", location_state: "observed", location_stale: false,
  inbound_label: "12 ms", inbound_title: "Synthetic inbound", inbound_level: "good",
  outbound_label: "15 ms", outbound_title: "Synthetic outbound", outbound_level: "good",
  outbound_policy: "expected", attention: "Healthy", is_pharos: index === 0,
}));

// Real vendored renderers and worker, deterministic synthetic geography. Never
// use a public tile service for automated pan/zoom tests or require its uptime.
const style = {
  version: 8,
  sources: { land: { type: "geojson", data: `${tileOrigin}/pharos-test-land.geojson` } },
  layers: [
    { id: "water", type: "background", paint: { "background-color": "#dae5ea" } },
    { id: "land", type: "fill", source: "land", paint: { "fill-color": "#f4f5f1" } },
    { id: "border", type: "line", source: "land", paint: { "line-color": "#b8c0c4" } },
  ],
};

async function mapFixture(page, failTiles = false) {
  const pageErrors = [];
  const tileRequests = [];
  const workerResponses = [];
  page.on("pageerror", error => pageErrors.push(error.message));
  page.on("response", response => {
    if (response.url().endsWith("/maplibre-gl-csp-worker.js")) workerResponses.push(response);
  });
  await page.addInitScript(() => {
    window.__mapCspViolations = [];
    document.addEventListener("securitypolicyviolation", event => {
      window.__mapCspViolations.push(event.effectiveDirective);
    });
  });
  await page.route("**/map/data.json?*", route => route.fulfill({ json: { hosts } }));
  await page.route(`${tileOrigin}/**`, async route => {
    const request = route.request();
    const headers = await request.allHeaders();
    tileRequests.push({ url: request.url(), auth: Boolean(headers.authorization), referrer: Boolean(headers.referer), cookie: Boolean(headers.cookie) });
    if (failTiles) return route.fulfill({ status: 503, body: "Unavailable" });
    if (request.url() === `${tileOrigin}/styles/positron`) return route.fulfill({ json: style });
    if (request.url() === `${tileOrigin}/pharos-test-land.geojson`) {
      return route.fulfill({ json: {
        type: "Feature", properties: {}, geometry: {
          type: "Polygon", coordinates: [[[5, 40], [25, 40], [25, 55], [5, 55], [5, 40]]],
        },
      } });
    }
    throw new Error("Unexpected basemap request in fixture");
  });
  return { pageErrors, tileRequests, workerResponses };
}

async function expectLabels(page) {
  await expect(page.locator("#map-panel")).toHaveAttribute("data-map-state", "ready");
  await expect(page.locator(".map-node:visible")).toHaveCount(2);
  await expect(page.locator(".map-leaders line")).toHaveCount(2);
  await expect(page.locator(".map-links .map-link")).toHaveCount(1);
  await expect.poll(async () => {
    const [a, b] = await page.locator(".map-node").evaluateAll(nodes => nodes.map(node => {
      const r = node.getBoundingClientRect();
      return { left: r.left, right: r.right, top: r.top, bottom: r.bottom };
    }));
    return a.right <= b.left || b.right <= a.left || a.bottom <= b.top || b.bottom <= a.top;
  }).toBe(true);
}

async function panVisibleMap(page, testInfo) {
  const map = page.locator("#fleet-map");
  await map.scrollIntoViewIfNeeded();
  const area = await map.boundingBox();
  const viewport = page.viewportSize();
  expect(area).not.toBeNull();
  expect(viewport).not.toBeNull();
  expect(area.y).toBeGreaterThanOrEqual(0);
  expect(area.y).toBeLessThan(viewport.height);
  const start = { x: area.x + area.width * 0.6, y: area.y + Math.min(area.height * 0.7, viewport.height * 0.55) };
  const end = { x: start.x + Math.min(60, area.width * 0.15), y: start.y + 30 };
  if (testInfo.project.name.includes("mobile")) {
    const cdp = await page.context().newCDPSession(page);
    await cdp.send("Input.dispatchTouchEvent", { type: "touchStart", touchPoints: [{ ...start, id: 1 }] });
    for (let step = 1; step <= 8; step += 1) {
      await cdp.send("Input.dispatchTouchEvent", {
        type: "touchMove",
        touchPoints: [{
          x: start.x + (end.x - start.x) * step / 8,
          y: start.y + (end.y - start.y) * step / 8,
          id: 1,
        }],
      });
    }
    await cdp.send("Input.dispatchTouchEvent", { type: "touchEnd", touchPoints: [] });
    await cdp.detach();
    return;
  }
  await page.mouse.move(start.x, start.y);
  await page.mouse.down();
  await page.mouse.move(end.x, end.y, { steps: 8 });
  await page.mouse.up();
}

test("key-free vector basemap preserves labels, navigation, filters and viewport", async ({ page }, testInfo) => {
  const evidence = await mapFixture(page);
  const origin = process.env.PHAROS_BROWSER_ORIGIN;
  await page.context().addCookies([
    { name: "pharos_sort", value: "name", url: origin },
    { name: "pharos_view", value: "list", url: origin },
    { name: "pharos_search", value: "legacy", url: origin },
    { name: "pharos_live_filter", value: "down", url: origin },
    { name: "pharos_signal_window", value: "24h", url: origin },
    { name: "pharos_auth_state_fixture", value: "preserve", url: origin },
  ]);
  await page.goto("/map");
  await expectLabels(page);
  await expect(page.locator("#fleet-map")).toHaveAttribute("data-basemap-state", "blocked");
  await expect(page.locator("[data-basemap-consent]")).toBeVisible();
  expect(evidence.tileRequests).toEqual([]);
  expect(evidence.workerResponses).toEqual([]);
  expect(await page.evaluate(() => Object.keys(localStorage).filter(key => key.startsWith("pharos")))).toEqual([]);
  const cookies = await page.context().cookies(origin);
  expect(cookies.find(cookie => cookie.name === "pharos_auth_state_fixture")?.value).toBe("preserve");
  expect(cookies.filter(cookie => [
    "pharos_sort", "pharos_view", "pharos_search", "pharos_live_filter", "pharos_signal_window",
  ].includes(cookie.name))).toEqual([]);
  await page.getByRole("button", { name: "Load external basemap", exact: true }).click();
  await expect(page.locator("#fleet-map")).toHaveAttribute("data-basemap-state", "ready");
  await expect(page.locator("canvas.maplibregl-canvas")).toBeVisible();
  for (const name of ["OpenFreeMap", "OpenMapTiles", "OpenStreetMap"]) {
    await expect(page.locator(".leaflet-control-attribution").getByRole("link", { name, exact: true })).toBeVisible();
  }
  expect(evidence.workerResponses.length).toBeGreaterThan(0);
  expect(evidence.workerResponses[0].headers()["content-security-policy"]).toContain(`connect-src ${tileOrigin}`);
  expect(evidence.tileRequests.some(request => request.url.endsWith(".geojson"))).toBe(true);
  expect(evidence.tileRequests.every(request => !request.auth && !request.referrer && !request.cookie)).toBe(true);

  const before = await page.locator(".map-leaders line").first().getAttribute("x1");
  await panVisibleMap(page, testInfo);
  await expect.poll(() => page.locator(".map-leaders line").first().getAttribute("x1")).not.toBe(before);
  await page.locator(".leaflet-control-zoom-in").click();
  await page.getByRole("button", { name: "Maximize to window", exact: true }).click();
  await expect(page.locator("#map-panel")).toHaveAttribute("data-mode", "maximized");
  await page.getByRole("button", { name: "Compact server labels", exact: true }).click();
  await expect(page.locator("#map-panel")).toHaveAttribute("data-label-density", "compact");
  await expectLabels(page);

  const preferences = await page.evaluate(() => [
    "pharos.map.viewport.v1", "pharos.map.mode.v1", "pharos.map.labelDensity.v1",
  ].map(key => [key, JSON.parse(localStorage.getItem(key))]));
  const expiryFloor = Date.now() + 179 * 24 * 60 * 60 * 1000;
  const expiryCeiling = Date.now() + 181 * 24 * 60 * 60 * 1000;
  for (const [key, record] of preferences) {
    expect(record.version, key).toBe(1);
    expect(record.expiresAt, key).toBeGreaterThan(expiryFloor);
    expect(record.expiresAt, key).toBeLessThan(expiryCeiling);
  }

  await page.locator("input[data-search]").fill("map-alpha");
  await expect(page.locator(".map-node:visible")).toHaveCount(1);
  await page.locator("input[data-search]").fill("");
  await expectLabels(page);
  const viewport = await page.evaluate(() => localStorage.getItem("pharos.map.viewport.v1"));
  await page.reload();
  await expectLabels(page);
  await expect(page.locator("#fleet-map")).toHaveAttribute("data-basemap-state", "blocked");
  await expect(page.locator("[data-basemap-consent]")).toBeVisible();
  expect(await page.evaluate(() => localStorage.getItem("pharos.map.viewport.v1"))).toBe(viewport);
  await expect(page.locator("#map-panel")).toHaveAttribute("data-mode", "maximized");
  await expect(page.locator("#map-panel")).toHaveAttribute("data-label-density", "compact");
  await page.getByRole("button", { name: "Load external basemap", exact: true }).click();
  await expect(page.locator("#fleet-map")).toHaveAttribute("data-basemap-state", "ready");
  await page.screenshot({ path: testInfo.outputPath("keyfree-map.png") });
  expect(evidence.pageErrors).toEqual([]);
  expect(await page.evaluate(() => window.__mapCspViolations)).toEqual([]);
  await expect(page.locator('.map-node[data-host="map-alpha"]')).toHaveAttribute("href", "/hosts/map-alpha/settings");
});

test("expired, corrupt or unavailable preference storage fails closed", async ({ page }) => {
  await mapFixture(page);
  await page.goto("/map");
  await expectLabels(page);
  await page.evaluate(() => {
    localStorage.setItem("pharos.map.viewport.v1", JSON.stringify({ version: 1, value: "{}", expiresAt: 1 }));
    localStorage.setItem("pharos.map.mode.v1", "corrupt");
    localStorage.setItem("pharos.map.labelDensity.v1", JSON.stringify({ version: 1, value: "compact", expiresAt: 1 }));
  });
  await page.reload();
  await expectLabels(page);
  await expect(page.locator("#map-panel")).toHaveAttribute("data-mode", "standard");
  await expect(page.locator("#map-panel")).toHaveAttribute("data-label-density", "normal");
  expect(await page.evaluate(() => [
    localStorage.getItem("pharos.map.viewport.v1"),
    localStorage.getItem("pharos.map.mode.v1"),
    localStorage.getItem("pharos.map.labelDensity.v1"),
  ])).toEqual([null, null, null]);

  await page.addInitScript(() => {
    for (const method of ["getItem", "setItem", "removeItem"]) {
      Object.defineProperty(Storage.prototype, method, {
        configurable: true,
        value() { throw new DOMException("storage disabled", "SecurityError"); },
      });
    }
  });
  await page.reload();
  await expectLabels(page);
  await page.getByRole("button", { name: "Maximize to window", exact: true }).click();
  await expect(page.locator("#map-panel")).toHaveAttribute("data-mode", "maximized");
  await page.getByRole("button", { name: "Compact server labels", exact: true }).click();
  await expect(page.locator("#map-panel")).toHaveAttribute("data-label-density", "compact");
});

for (const failure of ["tiles", "library", "webgl"]) {
  test(`basemap ${failure} failure keeps host labels and controls usable`, async ({ page }) => {
    const evidence = await mapFixture(page, failure === "tiles");
    if (failure === "library") {
      await page.route("**/maplibre-gl-csp.js", route => route.abort());
    }
    if (failure === "webgl") {
      await page.addInitScript(() => {
        const getContext = HTMLCanvasElement.prototype.getContext;
        HTMLCanvasElement.prototype.getContext = function (kind, ...args) {
          return kind.startsWith("webgl") ? null : getContext.call(this, kind, ...args);
        };
      });
    }
    await page.goto("/map");
    await expectLabels(page);
    await page.getByRole("button", { name: "Load external basemap", exact: true }).click();
    await expect(page.locator("#fleet-map")).toHaveAttribute("data-basemap-state", "unavailable");
    await expect(page.locator("[data-map-note]")).toContainText("Host labels and map controls remain available");
    await page.locator(".leaflet-control-zoom-in").click();
    await page.getByRole("button", { name: "Maximize to window", exact: true }).click();
    await expectLabels(page);
    expect(evidence.pageErrors).toEqual([]);
  });
}
