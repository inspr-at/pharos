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
  classifyObservation,
  continuationAllowed,
  decideRequest,
  isHostPath,
  isUnderBasePath,
  loadDraftFile,
  loadPasswordFile,
  loadUsernameFile,
  publicLocation,
  repoRootFromScripts,
  screenshotPermitted,
  LiveUiError,
} from "./live-ui-guard.mjs";

const SHOTS = new Map([
  ["/pharos/", "01-home.png"],
  ["/pharos/map", "02-map.png"],
  ["/pharos/alerts", "03-alerts.png"],
  ["/pharos/backups", "04-backups.png"],
  ["/pharos/activity", "05-activity.png"],
  ["/pharos/services", "06-services.png"],
  ["/pharos/settings/providers", "07-providers.png"],
  ["/pharos/agora", "08-agora.png"],
  ["/pharos/version", "09-version.png"],
]);

const EMPTY_PROBE = Object.freeze({
  passwordCount: 0,
  mfa: false,
  noAccess: false,
  accessDenied: false,
  managerShell: false,
  viewerOnly: false,
  appShell: false,
  authRecovery: false,
  rateLimited: false,
  loginForm: false,
});

function isDirectRun() {
  const entry = process.argv[1];
  if (!entry) return false;
  return pathToFileURL(path.resolve(entry)).href === import.meta.url;
}

function remember(blocked, result) {
  if (blocked.length >= 80) return;
  const pathName = result.path || "/";
  const method = result.method || "?";
  const reason = result.reason || "denied";
  if (blocked.some((item) => item.method === method && item.path === pathName && item.reason === reason)) {
    return;
  }
  blocked.push({ method, path: pathName, reason });
}

async function installGuard(context, policy, blocked) {
  await context.route("**/*", async (route) => {
    let result;
    try {
      result = decideRequest(
        { url: route.request().url(), method: route.request().method() },
        policy,
      );
    } catch {
      result = { allow: false, reason: "guard-error", method: "?", path: "/" };
    }
    if (!continuationAllowed(result)) {
      remember(blocked, result.allow ? { ...result, reason: "guard-bypass" } : result);
      await route.abort("blockedbyclient").catch(() => {});
      return;
    }
    await route.continue();
  });
}

async function openDocument(page, href, policy) {
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
    return await page.evaluate(() => {
      const text = (document.body && document.body.innerText ? document.body.innerText : "").slice(0, 4000);
      const passwordCount = Math.min(2, document.querySelectorAll("input[type='password']").length);
      const otp = document.querySelector(
        "input[autocomplete='one-time-code'], input[name='otp' i], input[name='totp' i]",
      );
      const mfaCopy =
        /\b(passkey|security key|webauthn|authenticator|verification code|two-factor|multi-factor|second factor)\b/i.test(
          text,
        );
      const managerShell = Boolean(document.querySelector("[data-can-manage='true']"));
      return {
        passwordCount,
        mfa: Boolean(otp) || mfaCopy,
        noAccess:
          text.includes("No access yet") ||
          text.includes("has not been granted any hosts or settings yet"),
        accessDenied:
          document.title === "Access denied · Pharos" ||
          text.includes("has not granted you operator access"),
        managerShell,
        viewerOnly: Boolean(document.querySelector("[data-can-manage='false']")) && !managerShell,
        appShell: Boolean(document.querySelector("main")),
        authRecovery: Boolean(document.querySelector("[data-auth-recovery]")),
        rateLimited: text.includes("authentication rate limit exceeded"),
        loginForm: Boolean(
          document.querySelector(
            "input[name='loginName'], input[name='username'], input[autocomplete='username'], input[type='email']",
          ),
        ),
      };
    });
  } catch {
    return { ...EMPTY_PROBE };
  }
}

function observe(pageUrl, status, probe, managerConfirmed) {
  let location = { origin: "", pathname: "/" };
  try {
    location = publicLocation(pageUrl);
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
  if ((await submit.count()) < 1) return false;
  await submit.first().click();
  return true;
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
  const passwords = page.locator("input[type='password']");
  const users = page.locator(
    "input[name='loginName'], input[name='username'], input[autocomplete='username'], input[type='email']",
  );
  if ((await passwords.count()) > 1) return "mfa-required";
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
  if (again.mfa || (await passwords.count()) !== 1) {
    return again.mfa ? "mfa-required" : "auth-required";
  }
  const fieldOrigin = await passwords.first().evaluate((element) => element.ownerDocument.location.origin);
  assertCredentialEntryOrigin(fieldOrigin);
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
  let viewed = observe(page.url(), response ? response.status() : 0, probe, false);
  if (viewed.location.origin === PERSONAL_ISSUER_ORIGIN) {
    const filled = await fillIssuerCredentials(page, username, password);
    if (filled !== "submitted") {
      probe = await readProbe(page);
      viewed = observe(page.url(), 0, probe, false);
      viewed.classification = filled === "mfa-required" || probe.mfa ? "mfa-required" : "auth-required";
      return viewed;
    }
    await waitForReturnedApp(page);
    probe = await readProbe(page);
    viewed = observe(page.url(), 0, probe, false);
  }
  if (probe.mfa) viewed.classification = "mfa-required";
  return viewed;
}

async function collectHostPaths(page, origin) {
  let hrefs = [];
  try {
    hrefs = await page.$$eval("a[href]", (nodes) =>
      nodes.map((node) => (node.getAttribute("href") || "").slice(0, 200)),
    );
  } catch {
    return [];
  }
  const found = [];
  for (const href of hrefs) {
    if (found.length >= 8) break;
    let parsed;
    try {
      parsed = new URL(href, origin);
    } catch {
      continue;
    }
    if (!isHostPath(parsed.pathname)) continue;
    const decision = decideRequest({ method: "GET", url: parsed.href }, {});
    if (!decision.allow || decision.path !== parsed.pathname) continue;
    if (!found.includes(parsed.pathname)) found.push(parsed.pathname);
  }
  return found;
}

async function visitRoute(page, origin, routePath, policy, managerConfirmed) {
  const href = new URL(routePath, origin).href;
  const response = await openDocument(page, href, policy);
  const status = response ? response.status() : 0;
  const probe = await readProbe(page);
  const viewed = observe(page.url(), status, probe, managerConfirmed);
  return {
    path: routePath,
    status,
    class: viewed.classification,
    location: viewed.location,
    probe,
  };
}

async function shoot(page, outputDir, route) {
  if (!screenshotPermitted(route)) return "";
  const name = SHOTS.get(route.path) || "";
  if (!name && !isHostPath(route.path)) return "";
  const fileName = name || `host-${String(route.hostIndex).padStart(2, "0")}.png`;
  const file = path.join(outputDir, fileName);
  try {
    await page.screenshot({
      path: file,
      type: "png",
      fullPage: false,
      animations: "disabled",
      caret: "hide",
    });
    fs.chmodSync(file, 0o600);
  } catch {
    return "";
  }
  return fileName;
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

function writeEvidence(dir, body) {
  const file = path.join(dir, "evidence.json");
  const safe = {
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
  };
  fs.writeFileSync(file, `${JSON.stringify(safe, null, 2)}\n`, { mode: 0o600 });
  fs.chmodSync(file, 0o600);
}

function report(overall, routes, blocked) {
  process.stdout.write(`class=${overall}\n`);
  for (const route of routes) {
    process.stdout.write(`route=${route.path} status=${route.status} class=${route.class}\n`);
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
  const policy = { secrets };
  const blocked = [];
  const routes = [];
  let browser;
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
    const options = browserContextOptions();
    if (["storageState", "recordVideo", "recordHar", "userDataDir"].some((key) => key in options)) {
      throw new LiveUiError("browser-context");
    }
    const context = await browser.newContext(options);
    if (browser.contexts().length !== 1) throw new LiveUiError("browser-context");
    mark("install-request-guard");
    await installGuard(context, policy, blocked);
    const page = await context.newPage();
    context.on("page", (popup) => {
      if (popup !== page) popup.close().catch(() => {});
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
      });
      report(overall, routes, blocked);
      return EXIT_CODES[overall] ?? 1;
    }
    appOrigin = signedIn.location.origin;
    const hosts = await collectHostPaths(page, appOrigin);
    mark("read-only-navigation");
    const visited = [];
    for (const routePath of [...new Set([...INVENTORY_ROUTES, ...hosts])]) {
      const viewed = await visitRoute(page, appOrigin, routePath, policy, true);
      visited.push(viewed);
      if (viewed.class === "mfa-required" || viewed.class === "auth-required") {
        overall = viewed.class;
        break;
      }
      if (viewed.class !== "authenticated") overall = viewed.class;
    }
    mark("screenshot-authenticated-only");
    let hostIndex = 1;
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
            hostIndex,
          });
        }
      }
      if (isHostPath(viewed.path)) hostIndex += 1;
      const record = {
        path: viewed.path,
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
          hostIndex,
        });
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
    writeEvidence(outputDir, { class: overall, appOrigin, clientDraft, routes, blocked });
    report(overall, routes, blocked);
    return EXIT_CODES[overall] ?? 1;
  } finally {
    secrets.fill("");
    if (draft) {
      for (const field of draft.fields) field.value = "";
    }
    if (browser) {
      for (const context of browser.contexts()) {
        await context.close().catch(() => {});
      }
      await browser.close().catch(() => {});
    }
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
