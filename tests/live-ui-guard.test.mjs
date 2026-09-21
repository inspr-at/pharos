import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ENTRY_URL,
  PERSONAL_APP_ORIGINS,
  PERSONAL_ISSUER_ORIGIN,
  SERVER_MUTATION_ALLOWLIST,
  SESSION_ORDER,
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
  loadPasswordFile,
  loadUsernameFile,
  parseClientDraft,
  repoRootFromScripts,
  sanitizeNavigationError,
  screenshotPermitted,
  LiveUiError,
} from "../scripts/live-ui-guard.mjs";

const REPO_ROOT = repoRootFromScripts();
const FIXTURE_PASSWORD = "fixture-password-not-used";
const FIXTURE_USER = "person@example.test";

const MUTATIONS = [
  ["POST", "https://pharos.barta.cm/pharos/host-actions/example/remove"],
  ["POST", "https://pharos.barta.cm/pharos/host-actions/jobs/1/apply-declared"],
  ["POST", "https://pharos.barta.cm/pharos/host-actions/jobs/1/confirm"],
  ["POST", "https://pharos.barta.cm/pharos/host-actions/jobs/1/recover"],
  ["POST", "https://pharos.barta.cm/pharos/host-actions/system-update"],
  ["POST", "https://flow.inspr.at/pharos/host-actions/example/remove"],
  ["POST", "https://pharos.barta.cm/pharos/setup/provisioning-jobs"],
  ["POST", "https://pharos.barta.cm/pharos/setup/provisioning-jobs/1/create"],
  ["POST", "https://pharos.barta.cm/pharos/setup/provisioning-jobs/1/confirm"],
  ["POST", "https://pharos.barta.cm/pharos/setup/provisioning-jobs/1/cleanup"],
  ["POST", "https://pharos.barta.cm/pharos/settings/fleet.json"],
  ["POST", "https://pharos.barta.cm/pharos/settings/providers/hetzner-cloud/test"],
  ["POST", "https://pharos.barta.cm/pharos/settings/providers/hetzner-cloud/preferences"],
  ["POST", "https://pharos.barta.cm/pharos/settings/providers/hetzner-cloud/disconnect"],
  ["POST", "https://pharos.barta.cm/pharos/agora/requests/host-preferences.json"],
  ["POST", "https://pharos.barta.cm/pharos/flow/intents"],
  ["POST", "https://pharos.barta.cm/pharos/host-need-intents"],
  ["POST", "https://pharos.barta.cm/pharos/managed-service-setup-intents"],
  ["POST", "https://pharos.barta.cm/pharos/setup/existing-host/preflight"],
  ["POST", "https://pharos.barta.cm/pharos/auth/logout"],
  ["PUT", "https://pharos.barta.cm/pharos/"],
  ["PATCH", "https://flow.inspr.at/pharos/hosts.json"],
  ["DELETE", "https://pharos.barta.cm/pharos/hosts/example"],
  ["POST", "https://pharos.barta.cm/report"],
  ["POST", "https://pharos.barta.cm/register"],
  ["POST", "https://pharos.barta.cm/agent/actions/claim"],
  ["GET", "https://pharos.barta.cm/report"],
  ["GET", "https://pharos.barta.cm/pharos/report"],
  ["GET", "https://pharos.barta.cm/pharos/agent/actions/claim"],
  ["GET", "https://pharos.barta.cm/metrics"],
  ["GET", "https://flow.inspr.at/pharos/metrics"],
];

function request(method, url, secrets = []) {
  return decideRequest({ method, url }, { secrets });
}

test("application mutations and machine routes are denied on every personal origin", () => {
  assert.deepEqual(SERVER_MUTATION_ALLOWLIST, []);
  for (const [method, url] of MUTATIONS) {
    const result = request(method, url);
    assert.equal(result.allow, false, `${method} ${result.path}`);
    assert.equal(continuationAllowed(result), false);
    assert.equal(Object.hasOwn(result, "url"), false);
    assert.equal(result.path.includes("?"), false);
  }
  const draft = request("POST", "https://flow.inspr.at/pharos/agora/requests/host-preferences.json");
  assert.equal(draft.reason, "app-mutation");
});

test("read-only personal app routes and the login entry are allowed", () => {
  for (const origin of PERSONAL_APP_ORIGINS) {
    for (const [method, pathName] of [
      ["GET", "/pharos/"],
      ["HEAD", "/pharos/hosts.json"],
      ["GET", "/pharos/auth/login"],
      ["GET", "/pharos/auth/callback"],
      ["GET", "/pharos/version"],
      ["GET", "/pharos/hosts/example"],
    ]) {
      const result = request(method, `${origin}${pathName}`);
      assert.equal(result.allow, true, `${origin}${pathName}`);
      assert.equal(result.reason, "app-read");
      assert.equal(continuationAllowed(result), true);
    }
  }
  const entry = request("GET", ENTRY_URL);
  assert.equal(entry.allow, true);
  assert.equal(entry.path, "/pharos/auth/login");
});

test("callback query values stay out of the guard decision", () => {
  const result = request(
    "GET",
    "https://pharos.barta.cm/pharos/auth/callback?code=one-time-code&state=opaque-state",
  );
  assert.equal(result.allow, true);
  assert.equal(result.path, "/pharos/auth/callback");
  assert.equal(JSON.stringify(result).includes("one-time-code"), false);
  assert.equal(JSON.stringify(result).includes("opaque-state"), false);
});

test("other origins, prefixes, and schemes are denied", () => {
  const denied = [
    "https://pharos.agm.ng/pharos/",
    "https://pharos.agm.ng/pharos/hosts.json",
    "https://fleet.agm.ng/pharos/",
    "https://flow.inspr.at/paimos/",
    "https://flow.inspr.at/janus/",
    "https://flow.inspr.at/aithema/",
    "https://flow.inspr.at/pharos-extra",
    "https://tiles.openfreemap.org/styles/positron",
    "https://evil.example/pharos/",
    "https://pharos.barta.cm.evil.example/pharos/",
    "https://not-auth.inspr.at/oauth/v2/authorize",
    "http://pharos.barta.cm/pharos/",
    "https://203.0.113.10/pharos/",
    "https://pharos.barta.cm/version",
    "https://pharos.barta.cm/pharos/%2e%2e/paimos",
  ];
  for (const url of denied) {
    const result = request("GET", url);
    assert.equal(result.allow, false, result.path);
    assert.equal(JSON.stringify(result).includes("?"), false);
  }
  assert.equal(PERSONAL_APP_ORIGINS.includes("https://pharos.agm.ng"), false);
});

test("login-provider requests stay on the personal issuer and its login paths", () => {
  const authorize = request("GET", "https://auth.inspr.at/oauth/v2/authorize?client_id=public");
  assert.equal(authorize.allow, true);
  assert.equal(authorize.reason, "issuer-read");
  assert.equal(authorize.path, "/oauth/v2/authorize");
  const loginPost = request("POST", "https://auth.inspr.at/ui/v2/login/password");
  assert.equal(loginPost.allow, true);
  assert.equal(loginPost.reason, "issuer-login");
  assert.equal(continuationAllowed(loginPost), true);
  for (const url of [
    "https://auth.inspr.at/ui/console",
    "https://auth.inspr.at/management/v1/users",
    "https://auth.inspr.at/admin/v1/orgs",
    "https://auth.inspr.at/v2/users",
  ]) {
    assert.equal(request("GET", url).allow, false);
    assert.equal(request("POST", url).allow, false);
  }
  assert.equal(request("POST", "https://auth.inspr.at/ui/v2/assets/app.js").allow, false);
  assert.equal(
    continuationAllowed({ allow: true, reason: "app-mutation", method: "POST", path: "/pharos/" }),
    false,
  );
});

test("credential material in a URL is denied and stripped from navigation errors", () => {
  const leaked = request(
    "GET",
    `https://user:${FIXTURE_PASSWORD}@pharos.barta.cm/pharos/?password=${FIXTURE_PASSWORD}`,
    [FIXTURE_PASSWORD, FIXTURE_USER],
  );
  assert.equal(leaked.allow, false);
  assert.equal(leaked.reason, "secret-in-url");
  assert.equal(JSON.stringify(leaked).includes(FIXTURE_PASSWORD), false);
  const sanitized = sanitizeNavigationError(
    new Error(
      `net::ERR_FAILED at https://auth.inspr.at/oauth/v2/authorize?code=abc&state=xyz ${FIXTURE_USER} ${FIXTURE_PASSWORD}`,
    ),
    [FIXTURE_USER, FIXTURE_PASSWORD],
  );
  assert.equal(sanitized.includes("code="), false);
  assert.equal(sanitized.includes("state="), false);
  assert.equal(sanitized.includes(FIXTURE_PASSWORD), false);
  assert.equal(sanitized.includes(FIXTURE_USER), false);
  assert.equal(sanitized.includes("https://auth.inspr.at/oauth/v2/authorize"), true);
});

test("classification separates auth, MFA, policy denial, and broken UI", () => {
  const app = { origin: "https://pharos.barta.cm", pathname: "/pharos/" };
  const issuer = { origin: PERSONAL_ISSUER_ORIGIN, pathname: "/ui/v2/login/otp" };
  assert.equal(
    classifyObservation({
      location: issuer,
      status: 200,
      probe: { mfa: true, passwordCount: 0, loginForm: false },
    }),
    "mfa-required",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 200,
      probe: { passwordCount: 1, loginForm: true, mfa: false },
    }),
    "auth-required",
  );
  assert.equal(
    classifyObservation({
      location: { origin: "https://flow.inspr.at", pathname: "/pharos/auth/login" },
      status: 200,
      probe: { appShell: true },
    }),
    "auth-required",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 200,
      probe: { noAccess: true, appShell: true },
    }),
    "policy-denied",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 200,
      probe: { viewerOnly: true, managerShell: false, appShell: true },
    }),
    "policy-denied",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 403,
      probe: { appShell: false },
    }),
    "policy-denied",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 200,
      probe: { managerShell: true, appShell: true },
    }),
    "authenticated",
  );
  assert.equal(
    classifyObservation({
      location: { origin: "https://flow.inspr.at", pathname: "/pharos/version" },
      status: 200,
      probe: { appShell: false, managerShell: false },
      managerConfirmed: true,
    }),
    "authenticated",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 500,
      probe: { appShell: false },
      managerConfirmed: true,
    }),
    "broken-ui",
  );
});

test("screenshots require an authenticated application page without a credential form", () => {
  const app = { origin: "https://flow.inspr.at", pathname: "/pharos/map" };
  const ready = { appShell: true, managerShell: true, passwordCount: 0, mfa: false, loginForm: false };
  assert.equal(
    screenshotPermitted({ classification: "authenticated", location: app, probe: ready }),
    true,
  );
  assert.equal(
    screenshotPermitted({
      classification: "authenticated",
      location: { origin: PERSONAL_ISSUER_ORIGIN, pathname: "/ui/v2/login/password" },
      probe: { ...ready, passwordCount: 1, loginForm: true },
    }),
    false,
  );
  assert.equal(
    screenshotPermitted({
      classification: "authenticated",
      location: { origin: "https://pharos.barta.cm", pathname: "/pharos/auth/login" },
      probe: ready,
    }),
    false,
  );
  assert.equal(
    screenshotPermitted({
      classification: "auth-required",
      location: app,
      probe: ready,
    }),
    false,
  );
  assert.equal(
    screenshotPermitted({
      classification: "authenticated",
      location: { origin: "https://pharos.barta.cm", pathname: "/pharos/version" },
      probe: { appShell: false, managerShell: false, passwordCount: 0 },
    }),
    false,
  );
});

test("credentials are typed only at the personal issuer", () => {
  assert.doesNotThrow(() => assertCredentialEntryOrigin(PERSONAL_ISSUER_ORIGIN));
  for (const origin of [
    "https://pharos.barta.cm",
    "https://flow.inspr.at",
    "https://pharos.agm.ng",
    "https://auth.agm.ng",
  ]) {
    assert.throws(() => assertCredentialEntryOrigin(origin), LiveUiError);
  }
});

test("client drafts cannot name a server request", () => {
  const draft = parseClientDraft(
    JSON.stringify({
      path: "/pharos/map",
      fields: [{ selector: "input[name=label]", value: "local-only" }],
    }),
  );
  assert.equal(draft.dispatch, "dom-only");
  assert.deepEqual(draft.serverRequests, []);
  assert.throws(
    () =>
      parseClientDraft(
        JSON.stringify({
          path: "/pharos/",
          method: "POST",
          fields: [{ selector: "input[name=label]", value: "local-only" }],
        }),
      ),
    /draft-server-request/,
  );
  assert.throws(
    () =>
      parseClientDraft(
        JSON.stringify({
          path: "/pharos/host-actions/example/remove",
          fields: [{ selector: "input[name=label]", value: "local-only" }],
        }),
      ),
    /draft-path/,
  );
  assert.throws(
    () =>
      parseClientDraft(
        JSON.stringify({
          path: "/pharos/map",
          fields: [{ selector: "input[type=password]", value: FIXTURE_PASSWORD }],
        }),
      ),
    /draft-selector/,
  );
});

test("runtime input rejects origin overrides, proxies, debug logs, and credential arguments", () => {
  assert.equal(assertCommandArgv(["node", "scripts/live-ui.mjs", "inventory"]), "inventory");
  assert.equal(assertCommandArgv(["node", "scripts/live-ui.mjs", "draft"]), "draft");
  assert.throws(() => assertCommandArgv(["node", "scripts/live-ui.mjs", "https://pharos.agm.ng/pharos/"]), /argv/);
  assert.throws(() => assertCommandArgv(["node", "scripts/live-ui.mjs", "--password=secret"]), /argv/);
  assert.throws(() => assertRuntimeEnvironment({ PHAROS_LIVE_UI_PASSWORD: FIXTURE_PASSWORD }), /runtime-env/);
  assert.throws(() => assertRuntimeEnvironment({ PHAROS_LIVE_UI_APP_ORIGIN: "https://pharos.agm.ng" }), /runtime-env/);
  assert.throws(() => assertRuntimeEnvironment({ DEBUG: "pw:api" }), /runtime-env/);
  assert.throws(() => assertRuntimeEnvironment({ HTTPS_PROXY: "http://127.0.0.1:9" }), /runtime-env/);
  assert.throws(() => assertRuntimeEnvironment({ NODE_TLS_REJECT_UNAUTHORIZED: "0" }), /tls-override/);
  assert.doesNotThrow(() => assertRuntimeEnvironment({ PATH: "/usr/bin" }));
});

test("credential files must be owner-only and errors omit their contents", () => {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-live-ui-"));
  const dir = path.join(root, "private");
  fs.mkdirSync(dir, { mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  const file = path.join(dir, "username");
  try {
    fs.writeFileSync(file, `${FIXTURE_USER}\n`, { mode: 0o644 });
    fs.chmodSync(file, 0o644);
    assert.throws(
      () => loadUsernameFile(file, REPO_ROOT),
      (error) => {
        assert.equal(error.code, "credential-file-mode");
        assert.equal(error.message.includes(FIXTURE_USER), false);
        return true;
      },
    );
    fs.chmodSync(file, 0o600);
    assert.equal(loadUsernameFile(file, REPO_ROOT), FIXTURE_USER);
    fs.chmodSync(dir, 0o755);
    assert.throws(() => loadUsernameFile(file, REPO_ROOT), /credential-file-parent/);
    fs.chmodSync(dir, 0o700);
    const link = path.join(dir, "linked");
    fs.symlinkSync(file, link);
    assert.throws(() => loadUsernameFile(link, REPO_ROOT), /credential-file-symlink/);
    const password = path.join(dir, "password");
    fs.writeFileSync(password, `${FIXTURE_PASSWORD}\nsecond\n`, { mode: 0o600 });
    fs.chmodSync(password, 0o600);
    assert.throws(
      () => loadPasswordFile(password, REPO_ROOT),
      (error) => {
        assert.equal(error.code, "credential-file-multiline");
        assert.equal(error.message.includes(FIXTURE_PASSWORD), false);
        return true;
      },
    );
    fs.writeFileSync(password, `${FIXTURE_PASSWORD}\n`, { mode: 0o600 });
    fs.chmodSync(password, 0o600);
    assert.equal(loadPasswordFile(password, REPO_ROOT), FIXTURE_PASSWORD);
    assert.throws(() => assertOutputDir(REPO_ROOT, REPO_ROOT), /output-dir/);
    const output = path.join(root, "out");
    fs.mkdirSync(output, { mode: 0o700 });
    fs.chmodSync(output, 0o700);
    assert.equal(assertOutputDir(output, REPO_ROOT), fs.realpathSync(output));
  } finally {
    fs.rmSync(root, { recursive: true, force: true });
  }
});

test("the browser session is headless, memory-only, and guarded before login", () => {
  assert.deepEqual(SESSION_ORDER.slice(0, 2), ["install-request-guard", "open-login"]);
  assert.throws(() => assertSessionPrefix(["open-login"]), /session-order/);
  assert.doesNotThrow(() => assertSessionPrefix(["install-request-guard", "open-login"]));
  const launch = browserLaunchOptions();
  assert.equal(launch.headless, true);
  assert.equal(launch.channel, undefined);
  assert.equal(launch.executablePath, undefined);
  const options = browserContextOptions();
  for (const key of ["storageState", "recordVideo", "recordHar", "userDataDir"]) {
    assert.equal(Object.hasOwn(options, key), false);
  }
  assert.equal(options.ignoreHTTPSErrors, false);
  assert.equal(options.acceptDownloads, false);
  const runner = fs.readFileSync(new URL("../scripts/live-ui.mjs", import.meta.url), "utf8");
  const guard = fs.readFileSync(new URL("../scripts/live-ui-guard.mjs", import.meta.url), "utf8");
  for (const source of [runner, guard]) {
    assert.equal(source.includes("launchPersistentContext"), false);
    assert.equal(source.includes(".storageState("), false);
    assert.equal(source.includes("storageState:"), false);
    assert.equal(source.includes("1password"), false);
    assert.equal(source.includes("1Password"), false);
    assert.equal(source.includes("op://"), false);
    assert.equal(source.includes("child_process"), false);
    assert.equal(source.includes("firefox"), false);
    assert.equal(source.includes("webkit"), false);
  }
  const runAt = runner.indexOf("async function run");
  const guardAt = runner.indexOf("await installGuard", runAt);
  const loginAt = runner.indexOf("await signIn", runAt);
  assert.ok(guardAt > runAt);
  assert.ok(loginAt > guardAt);
});
