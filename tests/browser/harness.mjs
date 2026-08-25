import fs from "node:fs";
import path from "node:path";
import { expect } from "@playwright/test";
import { readValidatedHarnessSessionFile } from "./harness-path.mjs";

const MACHINE_ROUTE_PATHS = new Set(["/report", "/register"]);

function syncHarnessSession() {
  if (process.env.PHAROS_BROWSER_RUN_DIR && process.env.PHAROS_BROWSER_ORIGIN) {
    return;
  }
  const envFile = process.env.PHAROS_BROWSER_HARNESS_ENV_FILE;
  if (!envFile) {
    return;
  }
  const approvedOrigin = process.env.PHAROS_BROWSER_ORIGIN;
  if (!approvedOrigin) {
    return;
  }
  const session = readValidatedHarnessSessionFile(envFile, approvedOrigin);
  if (!session) {
    return;
  }
  process.env.PHAROS_BROWSER_RUN_DIR = session.runDir;
}

function requireRunDir() {
  syncHarnessSession();
  const runDir = process.env.PHAROS_BROWSER_RUN_DIR;
  if (!runDir) {
    throw new Error("PHAROS_BROWSER_RUN_DIR is not set");
  }
  return runDir;
}

function pharosOrigin() {
  syncHarnessSession();
  return process.env.PHAROS_BROWSER_ORIGIN ?? null;
}

export function tokenPath(kind) {
  return path.join(requireRunDir(), `${kind}-token`);
}

export async function waitForHarnessTokens(timeoutMs = 30_000) {
  const deadline = Date.now() + timeoutMs;
  while (Date.now() < deadline) {
    syncHarnessSession();
    const runDir = process.env.PHAROS_BROWSER_RUN_DIR;
    if (
      runDir &&
      fs.existsSync(path.join(runDir, "write-token")) &&
      fs.existsSync(path.join(runDir, "read-token"))
    ) {
      return;
    }
    await new Promise((resolve) => setTimeout(resolve, 50));
  }
  throw new Error("browser harness tokens were not ready");
}

export function readHarnessToken(kind = "write") {
  return fs.readFileSync(tokenPath(kind), "utf8").trim();
}

function resolveRequestUrl(url) {
  const origin = pharosOrigin();
  if (!origin) {
    return null;
  }
  try {
    return new URL(url, origin);
  } catch {
    return null;
  }
}

function machineRoutePath(url) {
  const resolved = resolveRequestUrl(url);
  return resolved?.pathname ?? null;
}

export function isMachineRoute(url) {
  const pathname = machineRoutePath(url);
  return pathname != null && MACHINE_ROUTE_PATHS.has(pathname);
}

export function isPharosOriginUrl(url) {
  const resolved = resolveRequestUrl(url);
  const origin = pharosOrigin();
  return resolved != null && origin != null && resolved.origin === origin;
}

export function shouldAttachFleetAuth(url) {
  if (process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH === "1") {
    return false;
  }
  return isPharosOriginUrl(url) && !isMachineRoute(url);
}

function fleetAuthHeaders(kind = "write") {
  return { Authorization: `Bearer ${readHarnessToken(kind)}` };
}

export function withoutFleetAuth(headers = {}) {
  const next = { ...headers };
  delete next.Authorization;
  delete next.authorization;
  return next;
}

export function mergeFleetAuthHeaders(url, headers, authHeader) {
  if (!shouldAttachFleetAuth(url)) {
    return withoutFleetAuth(headers);
  }
  return { ...authHeader, ...headers };
}

export function withFleetRequestOptions(url, options = {}, authHeader) {
  const headers = mergeFleetAuthHeaders(url, options.headers, authHeader);
  return {
    ...options,
    headers,
    maxRedirects: 0,
  };
}

function wrapFleetRequest(request, authHeader) {
  const original = {
    get: request.get.bind(request),
    post: request.post.bind(request),
    put: request.put.bind(request),
    patch: request.patch.bind(request),
    delete: request.delete.bind(request),
    fetch: request.fetch.bind(request),
  };

  request.get = async (url, options = {}) =>
    original.get(url, withFleetRequestOptions(url, options, authHeader));
  request.post = async (url, options = {}) =>
    original.post(url, withFleetRequestOptions(url, options, authHeader));
  request.put = async (url, options = {}) =>
    original.put(url, withFleetRequestOptions(url, options, authHeader));
  request.patch = async (url, options = {}) =>
    original.patch(url, withFleetRequestOptions(url, options, authHeader));
  request.delete = async (url, options = {}) =>
    original.delete(url, withFleetRequestOptions(url, options, authHeader));
  request.fetch = async (url, options = {}) =>
    original.fetch(url, withFleetRequestOptions(url, options, authHeader));
}

function wrapAuthedPage(page, authHeader) {
  wrapFleetRequest(page.request, authHeader);
  return page;
}

export async function newAuthedContext(browser, kind = "write") {
  syncHarnessSession();
  if (process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH === "1") {
    throw new Error("fleet bearer auth is disabled for this base URL");
  }
  const origin = pharosOrigin();
  if (!origin) {
    throw new Error("PHAROS_BROWSER_ORIGIN is not set");
  }
  const authHeader = fleetAuthHeaders(kind);
  const context = await browser.newContext();

  await context.route("**/*", async (route) => {
    const requestUrl = route.request().url();
    if (!shouldAttachFleetAuth(requestUrl)) {
      const headers = withoutFleetAuth(route.request().headers());
      await route.continue({ headers });
      return;
    }
    const headers = { ...withoutFleetAuth(route.request().headers()), ...authHeader };
    await route.continue({ headers });
  });

  const originalNewPage = context.newPage.bind(context);
  context.newPage = async (...args) =>
    wrapAuthedPage(await originalNewPage(...args), authHeader);

  return context;
}

export async function expectSettingsSurfaces(
  surface,
  {
    state,
    title,
    noteVisible = false,
    noteCopy = "",
    requestedIconVisible = false,
    readyIconVisible = false,
  },
) {
  const namedSurfaces = surface.locator(
    "a[data-settings-state], [data-settings-note]",
  );
  const namedCount = await namedSurfaces.count();
  expect(namedCount).toBeGreaterThan(0);
  for (let index = 0; index < namedCount; index += 1) {
    const node = namedSurfaces.nth(index);
    await expect(node).toHaveAttribute("data-settings-state", state);
    await expect(node).toHaveAttribute("title", title);
    await expect(node).toHaveAttribute("aria-label", title);
  }

  const stateNodes = surface.locator("[data-settings-state]");
  const count = await stateNodes.count();
  for (let index = 0; index < count; index += 1) {
    const node = stateNodes.nth(index);
    await expect(node).toHaveAttribute("data-settings-state", state);
  }

  const hostActions = surface.locator("[data-host-actions]");
  if ((await hostActions.count()) > 0) {
    await expect(hostActions).toHaveAttribute("data-settings-state", state);
    await expect(hostActions).not.toHaveAttribute("title", title);
    await expect(hostActions).not.toHaveAttribute("aria-label", title);
  }

  const note = surface.locator("[data-settings-note]");
  if (noteVisible) {
    await expect(note).toBeVisible();
    await expect(note).toHaveAttribute("data-settings-state", state);
    await expect(note).toHaveAttribute("title", title);
    await expect(note).toHaveAttribute("aria-label", title);
    await expect(note.locator("[data-settings-note-copy]")).toHaveText(noteCopy);
    const requestedIcon = note.locator(".settings-state-icon.requested");
    if (requestedIconVisible) {
      await expect(requestedIcon).toBeVisible();
    } else {
      await expect(requestedIcon).toBeHidden();
    }
    const readyIcon = note.locator(".settings-state-icon.ready");
    if (readyIconVisible) {
      await expect(readyIcon).toBeVisible();
    } else {
      await expect(readyIcon).toBeHidden();
    }
  } else {
    await expect(note).toBeHidden();
  }
}
