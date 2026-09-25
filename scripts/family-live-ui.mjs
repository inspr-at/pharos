import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { pathToFileURL } from "node:url";
import { chromium } from "@playwright/test";
import { FAMILY_ORIGIN, FAMILY_SCHEMA, FAMILY_VIEWPORTS, familyApp, familyRoutes, classifyFamilyObservation } from "./live-ui-apps.mjs";
import { LiveUiError, EXIT_CODES, assertRuntimeEnvironment, assertOutputDir, browserContextOptions, openGuardedBrowser, publicLocation, redactEvidence, repoRootFromScripts, shutdownLiveSession, takeAuthenticatedShot, loadUsernameFile, loadPasswordFile } from "./live-ui-guard.mjs";
import { decodeBase32, loadTotpSecretFile, revokeTotpGrant } from "./live-ui-totp.mjs";
import { installGuard, signIn, visitRoute, readProbe } from "./live-ui.mjs";

const CREDENTIAL_KEYS = Object.freeze(["INSPR_UXQA_USERNAME", "INSPR_UXQA_PASSWORD", "INSPR_UXQA_TOTP_SECRET"]);
const PATH_KEYS = Object.freeze(["INSPR_UXQA_USERNAME_FILE", "INSPR_UXQA_PASSWORD_FILE", "INSPR_UXQA_TOTP_SECRET_FILE"]);

function ownedPrivateFile(file) {
  const stat = fs.lstatSync(file);
  // Owner-only modes: 0600 for a hand-written file, 0400 for one materialized
  // read-only by nixcfg agent-secrets (NIX-579). Any group or other bit refuses.
  const mode = stat.mode & 0o777;
  if (!stat.isFile() || stat.isSymbolicLink() || (mode !== 0o600 && mode !== 0o400) || stat.uid !== process.getuid() || fs.realpathSync(file) !== path.resolve(file)) throw new LiveUiError("family-credential-file");
}

// Capture only this explicit contract, then scrub the inherited environment
// before loading/launching anything that could create a child process.
export function captureFamilyCredentials(env, repoRoot, sourceFile = path.join(os.homedir(), ".inspr/secrets/agents/INSPR-UXQA.env")) {
  const values = CREDENTIAL_KEYS.map((key) => env[key]);
  const files = PATH_KEYS.map((key) => env[key]);
  const unknown = Object.keys(env).filter((key) => key.startsWith("INSPR_UXQA_") &&
    key !== "INSPR_UXQA_PROJECT_REF" && !CREDENTIAL_KEYS.includes(key) && !PATH_KEYS.includes(key));
  for (const key of [...CREDENTIAL_KEYS, ...PATH_KEYS, ...unknown]) delete env[key];
  let totp;
  try {
    if (unknown.length) throw new LiveUiError("family-credential-contract");
    assertRuntimeEnvironment(env);
    if (values.some((value) => value !== undefined)) {
      if (files.some((file) => file !== undefined)) throw new LiveUiError("family-credential-mode");
      ownedPrivateFile(sourceFile);
      if (values.some((value) => typeof value !== "string" || value.length === 0)) throw new LiveUiError("family-credentials");
      const [username, password, seed] = values;
      if (!/^[A-Za-z0-9._%+@=-]{1,128}$/.test(username) || password.length > 4096 || /[\x00-\x1f\x7f]/.test(password)) throw new LiveUiError("family-credentials");
      totp = { bytes: decodeBase32(seed), redaction: seed };
      return { username, password, totp, mode: "protected-env" };
    }
    if (files.some((file) => typeof file !== "string" || !file)) throw new LiveUiError("family-credentials");
    const username = loadUsernameFile(files[0], repoRoot);
    const password = loadPasswordFile(files[1], repoRoot);
    totp = loadTotpSecretFile(files[2], repoRoot);
    return { username, password, totp, mode: "protected-files" };
  } catch (error) {
    if (totp?.bytes) totp.bytes.fill(0);
    if (error instanceof LiveUiError) throw error;
    throw new LiveUiError("family-credentials");
  } finally {
    values.fill("");
    files.fill("");
  }
}

export function createFamilyOutput(appName, repoRoot, home = os.homedir(), now = new Date()) {
  if (!familyApp(appName)) throw new LiveUiError("family-app");
  const base = path.join(home, ".inspr/runtime/inspr-uxqa");
  const stamp = now.toISOString().replaceAll(":", "").replaceAll("-", "").replace(".", "-");
  const output = path.join(base, appName, stamp);
  // Reject symlinked ancestors, including a symlinked home/runtime root.
  let current = path.parse(output).root;
  for (const segment of output.slice(current.length).split(path.sep)) {
    current = path.join(current, segment);
    if (!fs.existsSync(current)) fs.mkdirSync(current, { mode: 0o700 });
    const stat = fs.lstatSync(current);
    if (stat.isSymbolicLink() || !stat.isDirectory()) throw new LiveUiError("output-dir");
    if (current === base || current.startsWith(`${base}${path.sep}`)) {
      if ((stat.mode & 0o777) !== 0o700 || stat.uid !== process.getuid()) throw new LiveUiError("output-dir");
    }
  }
  const checked = assertOutputDir(output, repoRoot);
  if (fs.readdirSync(checked).length) throw new LiveUiError("output-dir-not-empty");
  return checked;
}

export function observeFamilyAuthentication(policy, { origin, pathname, method }) {
  if (origin !== "https://auth.inspr.at" || method !== "POST") return;
  if (pathname === "/ui/login/password") policy.passwordSubmitted = true;
  if (pathname === "/ui/login/mfa/verify" && policy.totpGrant?.uses?.primary === 1 && policy.totpGrant?.uses?.fetch === 1) policy.totpSubmitted = true;
}

export function familyEvidence({ app, started, overall, routes, blocked, callbackConfirmed, credentialMode, passwordSubmitted = false, totpSubmitted = false }) {
  return {
    schema: FAMILY_SCHEMA,
    instance: "inspr-flow",
    basePath: familyApp(app)?.base || "",
    serverRole: app === "pharos" ? "fleet-manager" : app === "janus" ? "flow_viewer" : "scoped-human-reviewer",
    app,
    startedAt: started,
    class: overall,
    appOrigin: FAMILY_ORIGIN,
    oidc: { issuer: "https://auth.inspr.at", callbackConfirmed: !!callbackConfirmed, method: "browser-oidc", passwordSubmitted: !!passwordSubmitted, totpSubmitted: !!totpSubmitted, credentialMode },
    clientDraft: "none",
    serverMutationAllowlist: [],
    browserState: "memory-only",
    routes,
    blocked,
  };
}

export async function runFamily(appName) {
  const repoRoot = repoRootFromScripts();
  const app = familyApp(appName);
  if (!app) throw new LiveUiError("family-app");
  const credentials = captureFamilyCredentials(process.env, repoRoot);
  const secrets = [credentials.username, credentials.password, credentials.totp.redaction];
  const policy = { familyApp: appName, callbackConfirmed: false, issuerObserved: false, secrets, gate: null, totp: credentials.totp, totpGrant: null, totpAttempted: false };
  const routes = [];
  const blocked = [];
  let browser;
  let gate;
  let sessions = [];
  let output;
  let overall = "broken-ui";
  const started = new Date().toISOString();
  try {
    output = createFamilyOutput(appName, repoRoot);
    let planned;
    try { planned = familyRoutes(appName, process.env.INSPR_UXQA_PROJECT_REF || ""); }
    catch { throw new LiveUiError("family-project"); }
    const opened = await openGuardedBrowser((options) => chromium.launch(options));
    browser = opened.browser;
    gate = opened.gate;
    policy.gate = gate;
    const context = await browser.newContext(browserContextOptions());
    const pageRef = { page: null };
    const guard = await installGuard(context, policy, blocked, pageRef);
    sessions = guard.sessions;
    const page = await context.newPage();
    pageRef.page = page;
    if (gate.compromised() || !gate.attachedPrimary()) throw new LiveUiError("network-guard");
    await guard.armPage(page);
    page.on("response", (response) => {
      // Do not retain URLs (OIDC responses carry single-use codes/state).
      const location = publicLocation(response.url(), secrets);
      observeFamilyAuthentication(policy, { ...location, method: response.request().method() });
      if (location.origin === "https://auth.inspr.at") policy.issuerObserved = true;
      if (policy.issuerObserved && location.origin === FAMILY_ORIGIN && location.pathname === app.callback && response.status() >= 200 && response.status() < 400) policy.callbackConfirmed = true;
    });
    page.on("download", (download) => { download.cancel().catch(() => {}); });
    context.on("page", (popup) => { if (popup !== page) popup.close().catch(() => {}); });
    const signedIn = await signIn(page, secrets[0], secrets[1], policy);
    overall = signedIn.classification;
    if (overall === "authenticated") {
      for (const route of planned) {
        for (const [viewport, size] of Object.entries(FAMILY_VIEWPORTS)) {
          if (gate.compromised()) throw new LiveUiError("network-guard");
          await page.setViewportSize(size);
          const visited = await visitRoute(page, FAMILY_ORIGIN, route.path, policy, false);
          // SPA hydration is bounded; permission remains subject to a fresh probe.
          await page.locator(app.shell).first().waitFor({ state: "visible", timeout: 5000 }).catch(() => {});
          await page.waitForLoadState("networkidle", { timeout: 2500 }).catch(() => {});
          const probe = await readProbe(page, policy);
          const location = publicLocation(page.url(), secrets);
          const classification = classifyFamilyObservation({ app: appName, location, status: visited.status, probe, callbackConfirmed: policy.callbackConfirmed });
          const record = { name: route.name, path: route.path, status: visited.status, class: classification, viewport, width: size.width, height: size.height };
          if (classification === "authenticated") {
            const name = `${route.name}-${viewport}.png`;
            const screenshot = path.join(output, name);
            const reasons = [];
            const written = await takeAuthenticatedShot(page, {
              permitted: !gate.compromised() && !probe.accountMutation && !probe.codeField,
              password: secrets[1], material: secrets.slice(2), reasons,
              options: { path: screenshot, type: "png", fullPage: false, animations: "disabled", caret: "hide" },
            });
            if (written) { fs.chmodSync(screenshot, 0o600); record.screenshot = name; }
            else { record.class = "broken-ui"; record.reason = "screenshot-refused"; }
          }
          routes.push(record);
        }
      }
      overall = routes.length > 0 && routes.every((route) => route.class === "authenticated" && route.screenshot) ? "authenticated" : routes.find((route) => route.class !== "authenticated")?.class || "broken-ui";
    }
  } catch (error) {
    overall = "broken-ui";
    // Exception text and browser URLs can contain credentials. Keep only our code.
    blocked.push({ method: "?", path: "/", reason: error instanceof LiveUiError ? error.code : "family-run-failed" });
  } finally {
    const released = await shutdownLiveSession({
      close: async () => {
        gate?.beginShutdown?.();
        if (browser) { for (const context of browser.contexts()) await context.close(); await browser.close(); }
      }, sessions,
      detach: async () => { gate?.close?.(); },
      // Keep redaction material until the final evidence write after browser close.
    });
    if (!released.released) overall = "broken-ui";
    if (output) {
      const evidence = redactEvidence(familyEvidence({ app: appName, started, overall, routes, blocked, callbackConfirmed: policy.callbackConfirmed, credentialMode: credentials.mode, passwordSubmitted: policy.passwordSubmitted, totpSubmitted: policy.totpSubmitted }), secrets);
      fs.writeFileSync(path.join(output, "evidence.json"), `${JSON.stringify(evidence, null, 2)}\n`, { mode: 0o600, flag: "wx" });
    }
    if (released.released) {
      revokeTotpGrant(policy.totpGrant);
      credentials.totp.bytes.fill(0);
      secrets.fill("");
      credentials.username = "";
      credentials.password = "";
      credentials.totp.redaction = "";
    }
  }
  process.stdout.write(`app=${appName} class=${overall} routes=${routes.length}\n`);
  if (output) process.stdout.write(`evidence=${output}\n`);
  return EXIT_CODES[overall] ?? 1;
}

if (process.argv[1] && pathToFileURL(path.resolve(process.argv[1])).href === import.meta.url) {
  try {
    if (process.argv.length !== 3 || !familyApp(process.argv[2])) throw new LiveUiError("family-command");
    process.exitCode = await runFamily(process.argv[2]);
  } catch (error) {
    for (const key of [...CREDENTIAL_KEYS, ...PATH_KEYS]) delete process.env[key];
    process.stderr.write(`class=refused reason=${error instanceof LiveUiError ? error.code : "family-run-failed"}\n`);
    process.exitCode = 1;
  }
}
