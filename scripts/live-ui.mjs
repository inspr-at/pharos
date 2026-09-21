import fs from "node:fs";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { chromium } from "@playwright/test";
import {
  ENTRY_URL,
  EXIT_CODES,
  INVENTORY_ROUTES,
  PERSONAL_APP_ORIGINS,
  PERSONAL_ISSUER_ORIGIN,
  SESSION_ORDER,
  SERVER_MUTATION_ALLOWLIST,
  assertCommandArgv,
  assertCredentialEntryOrigin,
  assertOutputDir,
  assertRuntimeEnvironment,
  assertSessionPrefix,
  browserContextOptions,
  browserLaunchOptions,
  createTargetGate,
  classifyObservation,
  classifyProbeSurface,
  collectProbeSurface,
  credentialFillPermitted,
  decideIncidental,
  decideRequest,
  disposeFetchGuard,
  enableFetchGuard,
  hostNamesFromPayload,
  isHostPath,
  isUnderBasePath,
  loadDraftFile,
  loadPasswordFile,
  loadUsernameFile,
  planInventory,
  publicLocation,
  publicPath,
  redactEvidence,
  repoRootFromScripts,
  screenshotName,
  screenshotPermitted,
  shutdownLiveSession,
  submitLabelRejected,
  takeAuthenticatedShot,
  LiveUiError,
} from "./live-ui-guard.mjs";

const EMPTY_PROBE = Object.freeze({
  passwordCount: 0,
  mfa: false,
  passkeyAlternative: false,
  noAccess: false,
  accessDenied: false,
  accessRequest: false,
  managerShell: false,
  viewerOnly: false,
  appShell: false,
  authRecovery: false,
  rateLimited: false,
  loginForm: false,
  authUiVisible: false,
});

function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  return pathToFileURL(path.resolve(entry)).href === import.meta.url;
}

function remember(blocked, result, secrets) {
  if (blocked.length >= 80) return;
  const pathName = publicPath(result.path || "/", secrets);
  const method = result.method || "?";
  const reason = result.reason || "denied";
  if (blocked.some((item) => item.method === method && item.path === pathName && item.reason === reason)) {
    return;
  }
  blocked.push({ method, path: pathName, reason });
}

async function installGuard(context, policy, blocked) {
  const secrets = Array.isArray(policy.secrets) ? policy.secrets : [];
  const sessions = [];
  if (typeof context.routeWebSocket !== "function") throw new LiveUiError("browser-context");
  await context.routeWebSocket(
    () => true,
    (socket) => {
      socket.close({ code: 1008, reason: "policy" }).catch(() => {});
    },
  );
  await context.addInitScript(() => {
    window.open = () => null;
  });
  context.on("serviceworker", () => {
    remember(blocked, decideIncidental("serviceworker"), secrets);
  });
  return async function armPage(page) {
    if (!page || typeof page.context !== "function" || typeof page.context().newCDPSession !== "function") {
      throw new LiveUiError("network-guard");
    }
    const session = await page.context().newCDPSession(page);
    sessions.push(session);
    try {
      await enableFetchGuard(session, policy, (verdict) => remember(blocked, verdict, secrets));
    } catch {
      await disposeFetchGuard(session);
      throw new LiveUiError("network-guard");
    }
    return session;
  };
  return { sessions, armPage };
}

async function openDocument(page, href, policy) {
  if (policy?.gate?.compromised?.()) throw new LiveUiError("network-guard");
  const decision = decideRequest({ method: "GET", url: href }, policy);
  if (!decision.allow) throw new LiveUiError("navigation-denied");
  try {
    return await page.goto(href, { waitUntil: "domcontentloaded", timeout: 20_000 });
  } catch {
    throw new LiveUiError("navigation-failed");
  }
}

async function readProbe(page) {
  try {
    const surface = await page.evaluate(collectProbeSurface);
    return classifyProbeSurface(surface);
  } catch {
    return { ...EMPTY_PROBE };
  }
}

function observe(pageUrl, status, probe, managerConfirmed, secrets) {
  let location = { origin: "", pathname: "/" };
  try {
    location = publicLocation(pageUrl, secrets);
  } catch {
    location = { origin: "", pathname: "/" };
  }
  return {
    location,
    classification: classifyObservation({ location, status, probe, managerConfirmed }),
  };
}

async function submitControl(page) {
  const submit = page.locator("button[type='submit'], input[type='submit']");
  const count = await submit.count();
  for (let index = 0; index < count; index += 1) {
    const control = submit.nth(index);
    const label = await control
      .evaluate((element) => {
        const aria = element.getAttribute("aria-label") || "";
        const text = element.innerText || element.value || "";
        return `${aria} ${text}`.slice(0, 180);
      })
      .catch(() => "");
    if (submitLabelRejected(label)) continue;
    await control.click();
    return true;
  }
  return false;
}

async function fillIssuerCredentials(page, username, password) {
  try {
    return await fillIssuerCredentialsOnce(page, username, password);
  } catch (error) {
    if (error instanceof LiveUiError) throw error;
    return "auth-required";
  }
}

async function fillIssuerCredentialsOnce(page, username, password) {
  const origin = await page.evaluate(() => location.origin);
  assertCredentialEntryOrigin(origin);
  const before = await readProbe(page);
  if (before.mfa) return "mfa-required";
  if (!credentialFillPermitted(before)) return "auth-required";
  const passwords = page.locator("input[type='password']");
  const users = page.locator(
    "input[name='loginName'], input[name='username'], input[autocomplete='username'], input[type='email']",
  );
  if ((await passwords.count()) > 1) return "auth-required";
  if ((await passwords.count()) === 0) {
    if ((await users.count()) !== 1) return "auth-required";
    const userOrigin = await users.first().evaluate((element) => element.ownerDocument.location.origin);
    assertCredentialEntryOrigin(userOrigin);
    await users.first().fill(username);
    if (!(await submitControl(page))) return "auth-required";
    try {
      await passwords.first().waitFor({ state: "visible", timeout: 15_000 });
    } catch {
      const stalled = await readProbe(page);
      if (stalled.mfa) return "mfa-required";
      return "auth-required";
    }
  }
  const again = await readProbe(page);
  if (again.mfa) return "mfa-required";
  if (!credentialFillPermitted(again) || (await passwords.count()) !== 1) return "auth-required";
  const fieldOrigin = await passwords.first().evaluate((element) => {
    const autocomplete = (element.getAttribute("autocomplete") || "").toLowerCase();
    const name = (element.getAttribute("name") || "").toLowerCase();
    return {
      origin: element.ownerDocument.location.origin,
      mutation: autocomplete === "new-password" || name.includes("reset") || name.includes("new"),
    };
  });
  assertCredentialEntryOrigin(fieldOrigin.origin);
  if (fieldOrigin.mutation) return "auth-required";
  await passwords.first().fill(password);
  if (!(await submitControl(page))) return "auth-required";
  return "submitted";
}

async function waitForReturnedApp(page) {
  try {
    await page.waitForURL((url) => {
      try {
        const location = publicLocation(url.toString());
        return (
          PERSONAL_APP_ORIGINS.includes(location.origin) &&
          isUnderBasePath(location.pathname) &&
          !location.pathname.includes("/auth/")
        );
      } catch {
        return false;
      }
    }, { timeout: 25_000 });
  } catch {
    return false;
  }
  return true;
}

async function signIn(page, username, password, policy) {
  const response = await openDocument(page, ENTRY_URL, policy);
  let probe = await readProbe(page);
  let viewed = observe(page.url(), response ? response.status() : 0, probe, false, policy.secrets);
  if (viewed.location.origin === PERSONAL_ISSUER_ORIGIN) {
    const filled = await fillIssuerCredentials(page, username, password);
    if (filled !== "submitted") {
      probe = await readProbe(page);
      viewed = observe(page.url(), 0, probe, false, policy.secrets);
      viewed.classification = filled === "mfa-required" || probe.mfa ? "mfa-required" : "auth-required";
      return viewed;
    }
    await waitForReturnedApp(page);
    probe = await readProbe(page);
    viewed = observe(page.url(), 0, probe, false, policy.secrets);
  }
  if (probe.mfa) viewed.classification = "mfa-required";
  return viewed;
}

async function discoverInventory(page, origin, secrets, includeJson) {
  let hrefs = [];
  let hostNames = [];
  let payloads = [];
  try {
    const found = await page.evaluate(async (withJson) => {
      const foundHrefs = [];
      for (const node of document.querySelectorAll("a[href], [data-drawer-workspace-href]")) {
        const href = node.getAttribute("href") || node.getAttribute("data-drawer-workspace-href") || "";
        if (href) foundHrefs.push(href.slice(0, 200));
      }
      const foundNames = [];
      for (const node of document.querySelectorAll("[data-host]")) {
        const name = node.getAttribute("data-host") || "";
        if (name) foundNames.push(name.slice(0, 63));
      }
      const foundPayloads = [];
      if (withJson) {
        for (const path of ["/pharos/hosts.json", "/pharos/declared-hosts.json"]) {
          try {
            const response = await fetch(path, { method: "GET", credentials: "same-origin", cache: "no-store" });
            if (response.ok) foundPayloads.push((await response.text()).slice(0, 250000));
          } catch {
            // A missing inventory source stays empty.
          }
        }
      }
      return { hrefs: foundHrefs.slice(0, 300), hostNames: foundNames, payloads: foundPayloads };
    }, includeJson);
    hrefs = found.hrefs || [];
    hostNames = found.hostNames || [];
    payloads = found.payloads || [];
  } catch {
    hrefs = [];
    hostNames = [];
    payloads = [];
  }
  for (const payload of payloads) hostNames.push(...hostNamesFromPayload(payload));
  return planInventory({ hrefs, hostNames, origin, secrets });
}

async function visitRoute(page, origin, routePath, policy, managerConfirmed) {
  const href = new URL(routePath, origin).href;
  const response = await openDocument(page, href, policy);
  const status = response ? response.status() : 0;
  const probe = await readProbe(page);
  const viewed = observe(page.url(), status, probe, managerConfirmed, policy.secrets);
  return {
    path: routePath,
    status,
    class: viewed.classification,
    location: viewed.location,
    probe,
  };
}

async function waitForAuthUiHidden(page) {
  try {
    await page.waitForFunction(
      () => {
        const nodes = document.querySelectorAll(
          "input[type='password'], input[autocomplete='one-time-code'], input[autocomplete='webauthn'], input[name='otp'], input[name='totp']",
        );
        return [...nodes].every((node) => node.getClientRects().length === 0);
      },
      undefined,
      { timeout: 2000 },
    );
  } catch {
    // The following probe decides whether a shot is allowed.
  }
}

async function shoot(page, outputDir, route, secrets) {
  await waitForAuthUiHidden(page);
  const probe = await readProbe(page);
  const password = Array.isArray(secrets) ? secrets[secrets.length - 1] : "";
  let location = route.location;
  try {
    location = publicLocation(page.url(), Array.isArray(secrets) ? secrets : []);
  } catch {
    return "";
  }
  const fileName = screenshotName(route.path, route.hostIndex);
  if (!fileName) return "";
  const file = path.join(outputDir, fileName);
  let written = false;
  try {
    written = await takeAuthenticatedShot(page, {
      permitted: screenshotPermitted({ classification: route.classification, location, probe }),
      password,
      options: {
        path: file,
        type: "png",
        fullPage: false,
        animations: "disabled",
        caret: "hide",
      },
    });
    if (written) fs.chmodSync(file, 0o600);
  } catch {
    return "";
  }
  return written ? fileName : "";
}

async function applyClientDraft(page, draft) {
  let applied = 0;
  for (const field of draft.fields) {
    const locator = page.locator(field.selector);
    if ((await locator.count()) !== 1) return { applied, result: "not-found" };
    const kind = await locator.evaluate((element) => ({
      tag: element.tagName,
      type: (element.getAttribute("type") || "").toLowerCase(),
      origin: element.ownerDocument.location.origin,
    }));
    if (kind.tag !== "INPUT" && kind.tag !== "TEXTAREA") return { applied, result: "refused" };
    if (["password", "submit", "button", "file", "hidden"].includes(kind.type)) {
      return { applied, result: "refused" };
    }
    if (!PERSONAL_APP_ORIGINS.includes(kind.origin)) return { applied, result: "refused" };
    try {
      await locator.fill(field.value);
    } catch {
      return { applied, result: "refused" };
    }
    applied += 1;
  }
  return { applied, result: "dom-only" };
}

function writeEvidence(dir, body, secrets) {
  const file = path.join(dir, "evidence.json");
  const safe = redactEvidence(
    {
      schema: "inspr.pharos.live-ui-evidence.v1",
      instance: "personal",
      basePath: "/pharos",
      serverRole: "unchanged",
      serverMutationAllowlist: SERVER_MUTATION_ALLOWLIST,
      clientDraft: body.clientDraft,
      class: body.class,
      appOrigin: body.appOrigin,
      routes: body.routes,
      blocked: body.blocked,
    },
    secrets,
  );
  fs.writeFileSync(file, `${JSON.stringify(safe, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function report(overall, routes, blocked, secrets) {
  process.stdout.write(`class=${overall}\n`);
  for (const route of routes) {
    const routePath = publicPath(route.path, secrets);
    process.stdout.write(`route=${routePath} status=${route.status} class=${route.class}\n`);
    if (route.screenshot) process.stdout.write(`screenshot=${route.screenshot}\n`);
  }
  process.stdout.write(`blocked=${blocked.length}\n`);
  process.stdout.write("server-role=unchanged\n");
}

async function run(command) {
  const steps = [];
  const mark = (name) => {
    steps.push(name);
    assertSessionPrefix(steps);
  };
  const repoRoot = repoRootFromScripts();
  assertRuntimeEnvironment(process.env);
  const outputDir = assertOutputDir(process.env.PHAROS_LIVE_UI_OUTPUT_DIR, repoRoot);
  const username = loadUsernameFile(process.env.PHAROS_LIVE_UI_USERNAME_FILE, repoRoot);
  const password = loadPasswordFile(process.env.PHAROS_LIVE_UI_PASSWORD_FILE, repoRoot);
  const draft =
    command === "draft"
      ? loadDraftFile(process.env.PHAROS_LIVE_UI_DRAFT_FILE, repoRoot)
      : null;
  const secrets = [username, password];
  const policy = { secrets, gate: null };
  const blocked = [];
  const routes = [];
  let browser;
  let browserSession;
  let fetchSessions = [];
  let overall = "broken-ui";
  let appOrigin = "";
  let clientDraft = draft ? "dom-only" : "none";
  try {
    const launch = browserLaunchOptions();
    if (launch.headless !== true || Object.keys(launch).length !== 1) {
      throw new LiveUiError("browser-launch");
    }
    browser = await chromium.launch(launch);
    if (browser.browserType().name() !== "chromium") throw new LiveUiError("browser-launch");
    if (typeof browser.newBrowserCDPSession !== "function") throw new LiveUiError("network-guard");
    browserSession = await browser.newBrowserCDPSession();
    const gate = createTargetGate(browserSession, policy, (verdict) => remember(blocked, verdict, secrets));
    policy.gate = gate;
    await gate.enable();
    const options = browserContextOptions();
    if (["storageState", "recordVideo", "recordHar", "userDataDir"].some((key) => key in options)) {
      throw new LiveUiError("browser-context");
    }
    const context = await browser.newContext(options);
    if (browser.contexts().length !== 1) throw new LiveUiError("browser-context");
    mark("install-request-guard");
    const guard = await installGuard(context, policy, blocked);
    fetchSessions = guard.sessions;
    const page = await context.newPage();
    if (gate.compromised()) throw new LiveUiError("network-guard");
    await guard.armPage(page);
    const watchSurface = (target) => {
      target.on("download", (download) => {
        download.cancel().catch(() => {});
        remember(blocked, decideIncidental("download"), secrets);
      });
      target.on("popup", (popup) => {
        remember(blocked, decideIncidental("popup"), secrets);
        popup.close().catch(() => {});
      });
    };
    watchSurface(page);
    context.on("page", (popup) => {
      if (popup === page) return;
      watchSurface(popup);
      remember(blocked, decideIncidental("popup"), secrets);
      popup.close().catch(() => {});
      guard.armPage(popup).catch(() => {});
    });
    mark("open-login");
    const signedIn = await signIn(page, secrets[0], secrets[1], policy);
    mark("classify");
    overall = signedIn.classification;
    if (overall !== "authenticated") {
      writeEvidence(outputDir, {
        class: overall,
        appOrigin: PERSONAL_APP_ORIGINS.includes(signedIn.location.origin)
          ? signedIn.location.origin
          : "",
        clientDraft,
        routes,
        blocked,
      }, secrets);
      report(overall, routes, blocked, secrets);
      return EXIT_CODES[overall] ?? 1;
    }
    appOrigin = signedIn.location.origin;
    mark("read-only-navigation");
    const seen = new Set();
    const pending = await discoverInventory(page, appOrigin, secrets, true);
    if (pending.length === 0) pending.push(...INVENTORY_ROUTES);
    const visited = [];
    let jsonFetched = true;
    while (pending.length > 0 && seen.size < 48) {
      const routePath = pending.shift();
      if (!routePath || seen.has(routePath)) continue;
      seen.add(routePath);
      const viewed = await visitRoute(page, appOrigin, routePath, policy, true);
      visited.push(viewed);
      if (viewed.class === "mfa-required" || viewed.class === "auth-required") {
        overall = viewed.class;
        break;
      }
      if (viewed.class !== "authenticated") {
        overall = viewed.class;
        continue;
      }
      const more = await discoverInventory(page, appOrigin, secrets, !jsonFetched);
      jsonFetched = true;
      for (const extra of more) {
        if (!seen.has(extra)) pending.push(extra);
      }
    }
    mark("screenshot-authenticated-only");
    const hostIndexByName = new Map();
    let nextHostIndex = 1;
    const hostIndexFor = (routePath) => {
      const bare = String(routePath).split("?")[0];
      if (!isHostPath(bare)) return 1;
      const name = bare.slice("/pharos/hosts/".length);
      if (!hostIndexByName.has(name)) {
        hostIndexByName.set(name, nextHostIndex);
        nextHostIndex += 1;
      }
      return hostIndexByName.get(name);
    };
    for (const viewed of visited) {
      let current = viewed;
      let screenshot = "";
      if (viewed.class === "authenticated") {
        current = await visitRoute(page, appOrigin, viewed.path, policy, true);
        if (current.class === "authenticated") {
          screenshot = await shoot(page, outputDir, {
            path: current.path,
            classification: current.class,
            location: current.location,
            probe: current.probe,
            hostIndex: hostIndexFor(current.path),
          }, secrets);
        }
      }
      const record = {
        path: publicPath(viewed.path, secrets),
        status: current.status,
        class: current.class,
      };
      if (screenshot) record.screenshot = screenshot;
      routes.push(record);
    }
    if (draft && routes.length > 0 && routes.every((route) => route.class === "authenticated")) {
      const drafted = await visitRoute(page, appOrigin, draft.path, policy, true);
      const applied = drafted.class === "authenticated" ? await applyClientDraft(page, draft) : { applied: 0, result: "refused" };
      clientDraft = applied.result;
      if (applied.result === "dom-only") {
        const shot = await shoot(page, outputDir, {
          path: draft.path,
          classification: "authenticated",
          location: drafted.location,
          probe: drafted.probe,
          hostIndex: hostIndexFor(draft.path),
        }, secrets);
        const existing = routes.find((route) => route.path === draft.path);
        if (existing && shot) existing.screenshot = shot;
      }
      for (const field of draft.fields) field.value = "";
    }
    if (routes.some((route) => route.class === "mfa-required")) overall = "mfa-required";
    else if (routes.some((route) => route.class === "auth-required")) overall = "auth-required";
    else if (routes.some((route) => route.class === "policy-denied")) overall = "policy-denied";
    else if (routes.length === 0 || routes.some((route) => route.class !== "authenticated")) {
      overall = "broken-ui";
    } else overall = "authenticated";
    writeEvidence(outputDir, { class: overall, appOrigin, clientDraft, routes, blocked }, secrets);
    report(overall, routes, blocked, secrets);
    return EXIT_CODES[overall] ?? 1;
  } finally {
    await shutdownLiveSession({
      close: async () => {
        if (!browser) return;
        for (const context of browser.contexts()) {
          await context.close();
        }
        await browser.close();
      },
      sessions: fetchSessions,
      detach: async () => {
        if (browserSession && typeof browserSession.detach === "function") {
          await browserSession.detach();
        }
      },
      secrets,
      drafts: draft ? draft.fields : [],
    });
  }
}

async function main() {
  let code = 1;
  try {
    const command = assertCommandArgv(process.argv);
    if (SESSION_ORDER[0] !== "install-request-guard") throw new LiveUiError("session-order");
    code = await run(command);
  } catch (error) {
    const reason = error instanceof LiveUiError ? error.code : "broken-ui";
    process.stderr.write(`class=refused reason=${reason}\n`);
    code = 1;
  }
  process.exitCode = code;
}

if (isDirectRun()) {
  main();
}
