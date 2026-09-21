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
  createTargetGate,
  classifyProbeSurface,
  collectProbeSurface,
  continuationAllowed,
  credentialFillPermitted,
  decideFetchPause,
  decideIncidental,
  decideRedirect,
  decideRequest,
  disposeFetchGuard,
  enableFetchGuard,
  hostNamesFromPayload,
  ISSUER_LOGIN_POST_PATHS,
  loadPasswordFile,
  loadUsernameFile,
  parseClientDraft,
  planInventory,
  publicPath,
  redactEvidence,
  repoRootFromScripts,
  sanitizeNavigationError,
  screenshotName,
  pausedTargetPlan,
  screenshotPermitted,
  settleFetchAuth,
  shutdownLiveSession,
  settleFetchPause,
  submitLabelRejected,
  takeAuthenticatedShot,
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
  assert.deepEqual(ISSUER_LOGIN_POST_PATHS, ["/ui/login/loginname", "/ui/login/password"]);
  const loginName = request("POST", "https://auth.inspr.at/ui/login/loginname");
  assert.equal(loginName.allow, true);
  assert.equal(loginName.reason, "issuer-login");
  const loginPost = request("POST", "https://auth.inspr.at/ui/login/password", []);
  assert.equal(loginPost.allow, true);
  assert.equal(loginPost.reason, "issuer-login");
  assert.equal(continuationAllowed(loginPost), true);
  const loginBody = decideRequest(
    {
      method: "POST",
      url: "https://auth.inspr.at/ui/login/password",
      postData: "loginName=person%40example.test&password=placeholder",
    },
    {},
  );
  assert.equal(loginBody.allow, true);
  assert.equal(JSON.stringify(loginBody).includes("placeholder"), false);
  for (const url of [
    "https://auth.inspr.at/ui/login/password/reset",
    "https://auth.inspr.at/ui/login/password/init",
    "https://auth.inspr.at/oauth/v2/revoke",
    "https://auth.inspr.at/oauth/v2/token",
    "https://auth.inspr.at/ui/v2/login/password",
    "https://auth.inspr.at/ui/login/password/change",
  ]) {
    const denied = request("POST", url);
    assert.equal(denied.allow, false, url);
    assert.equal(continuationAllowed(denied), false);
  }
  const resetBody = decideRequest(
    {
      method: "POST",
      url: "https://auth.inspr.at/ui/login/password",
      postData: "reset=1",
    },
    {},
  );
  assert.equal(resetBody.allow, false);
  assert.equal(resetBody.reason, "issuer-mutation");
  const resetJson = decideRequest(
    {
      method: "POST",
      url: "https://auth.inspr.at/ui/login/loginname",
      postData: "{\"init\":true}",
    },
    {},
  );
  assert.equal(resetJson.allow, false);
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

function leaks(value, parts) {
  const blob = typeof value === "string" ? value : JSON.stringify(value);
  return parts.some((part) => part && blob.includes(part));
}

function percentOdd(secret) {
  return [...secret]
    .map((char, index) => (index % 2 === 0 ? `%${char.charCodeAt(0).toString(16).padStart(2, "0")}` : char))
    .join("");
}

test("pathname, encoding, fragment, and short secrets stay out of verdicts", () => {
  const secret = FIXTURE_PASSWORD;
  const short = "s3cr";
  const tiny = "ab1";
  const mixed = percentOdd(secret);
  const encodedUser = encodeURIComponent(FIXTURE_USER);
  const cases = [
    `https://pharos.barta.cm/pharos/${secret}`,
    `https://pharos.barta.cm/pharos/${mixed}`,
    `https://pharos.barta.cm/pharos/${encodedUser}`,
    `https://pharos.barta.cm/pharos/map#${secret}`,
    `https://pharos.barta.cm/pharos/map#${short}`,
    `https://pharos.barta.cm/pharos/${short}`,
    `https://pharos.barta.cm/pharos/${tiny}`,
    `https://pharos.barta.cm/pharos/pre-${short}-post`,
    `https://pharos.barta.cm/pharos/hosts/pres3crpost`,
    `https://pharos.barta.cm/pharos/hosts/pre-ab1-post`,
    `https://pharos.barta.cm/pharos/map?x=pre-a%62%31-post`,
    `https://pharos.barta.cm/pharos/hosts/pre-%2561%2562%2531-post`,
    `https://user:${short}@pharos.barta.cm/pharos/map`,
  ];
  const secrets = [secret, FIXTURE_USER, short, tiny];
  for (const url of cases) {
    const result = request("GET", url, secrets);
    assert.equal(result.allow, false);
    assert.equal(result.reason, "secret-in-url");
    assert.equal(leaks(result, [secret, FIXTURE_USER, encodedUser, mixed, short, tiny]), false);
    const sanitized = sanitizeNavigationError(new Error(`navigation failed ${url}`), secrets);
    assert.equal(leaks(sanitized, [secret, FIXTURE_USER, encodedUser, mixed, short, tiny, "a%62%31", "%2561"]), false);
    assert.equal(sanitized.includes("?"), false);
  }
  const embedded = sanitizeNavigationError(new Error("navigation failed pre-a%62%31-post pres3crpost"), ["ab1", "s3cr"]);
  assert.equal(embedded.includes("ab1"), false);
  assert.equal(embedded.includes("s3cr"), false);
  assert.equal(embedded.includes("a%62%31"), false);
  const evidence = redactEvidence(
    { blocked: [{ method: "GET", path: `/pharos/${secret}`, reason: "secret-in-url" }] },
    secrets,
  );
  assert.equal(leaks(evidence, secrets), false);
  assert.equal(publicPath(`/pharos/${short}`, [short]), "path-category");
});

test("issuer reads are allowlisted and incidental channels fail closed", () => {
  assert.equal(request("GET", "https://auth.inspr.at/ui/v2/assets/app.js").allow, true);
  assert.equal(request("GET", "https://auth.inspr.at/.well-known/openid-configuration").allow, true);
  assert.equal(request("GET", "https://auth.inspr.at/v2/sessions").reason, "issuer-read");
  assert.equal(request("GET", "https://auth.inspr.at/robots.txt").allow, false);
  assert.equal(request("POST", "https://auth.inspr.at/v2/sessions").allow, false);
  const socket = decideRequest(
    { method: "GET", url: "https://pharos.barta.cm/pharos/", resourceType: "websocket" },
    {},
  );
  assert.equal(socket.allow, false);
  assert.equal(socket.reason, "websocket");
  assert.equal(continuationAllowed(socket), false);
  const worker = decideRequest(
    { method: "GET", url: "https://pharos.barta.cm/pharos/assets/app.js", resourceType: "serviceworker" },
    {},
  );
  assert.equal(worker.reason, "serviceworker");
  const redirected = decideRedirect({
    method: "POST",
    url: "https://pharos.barta.cm/pharos/agora/requests/host-preferences.json",
  });
  assert.equal(redirected.allow, false);
  assert.equal(redirected.reason, "app-mutation");
  assert.equal(decideRedirect({ method: "GET", url: "https://pharos.agm.ng/pharos/" }).allow, false);
  assert.equal(decideIncidental("download").allow, false);
  assert.equal(decideIncidental("popup").reason, "popup");
  assert.equal(request("GET", "wss://pharos.barta.cm/pharos/socket").allow, false);
});

function matchesSelector(element, selector) {
  return selector.split(",").some((part) => matchesOne(element, part.trim()));
}

function matchesOne(element, selector) {
  const match = selector.match(/^([a-zA-Z]+|\*)?(?:\.([A-Za-z0-9_-]+))?(\[[^\]]+\])?$/);
  if (!match) return false;
  const [, tag, className, attrRaw] = match;
  if (tag && tag !== "*" && element.tagName !== tag.toUpperCase()) return false;
  if (className && !(element.attrs.class || "").split(/\s+/).includes(className)) return false;
  if (!attrRaw) return Boolean(tag || className);
  const attr = attrRaw.match(/^\[([A-Za-z0-9_-]+)(?:='([^']*)')?\]$/);
  if (!attr) return false;
  const [, name, value] = attr;
  if (!Object.prototype.hasOwnProperty.call(element.attrs, name)) return false;
  if (value !== undefined && String(element.attrs[name]) !== value) return false;
  return true;
}

function domNode(tag, attrs = {}, children = [], text = "") {
  const element = {
    tagName: tag.toUpperCase(),
    attrs,
    children,
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(attrs, name) ? String(attrs[name]) : null;
    },
    hasAttribute(name) {
      return Object.prototype.hasOwnProperty.call(attrs, name);
    },
    getClientRects() {
      return Object.prototype.hasOwnProperty.call(attrs, "hidden") ? [] : [1];
    },
    get innerText() {
      return `${text} ${children.map((child) => child.innerText || "").join(" ")}`.trim();
    },
    get textContent() {
      return this.innerText;
    },
    matches(selector) {
      return matchesSelector(this, selector);
    },
    querySelector(selector) {
      return this.querySelectorAll(selector)[0] || null;
    },
    querySelectorAll(selector) {
      const found = [];
      const walk = (items) => {
        for (const child of items) {
          if (child.matches(selector)) found.push(child);
          walk(child.children || []);
        }
      };
      walk(children);
      return found;
    },
  };
  return element;
}

function fakeDocument(children, text = "", title = "") {
  const body = domNode("body", {}, children, text);
  return {
    title,
    body,
    querySelector(selector) {
      return this.querySelectorAll(selector)[0] || null;
    },
    querySelectorAll(selector) {
      return body.querySelectorAll(selector);
    },
  };
}

test("optional passkey login is not MFA and a real challenge is", () => {
  const passwordLogin = fakeDocument([
    domNode("form", {}, [
      domNode("input", { type: "email", name: "loginName" }),
      domNode("input", { type: "password", name: "password" }),
      domNode("a", { href: "/passkey" }, [], "Sign in with a passkey"),
      domNode("button", { type: "submit" }, [], "Next"),
    ]),
  ], "Email Password Sign in with a passkey Next");
  const passwordProbe = classifyProbeSurface(collectProbeSurface(passwordLogin));
  assert.equal(passwordProbe.passkeyAlternative, true);
  assert.equal(passwordProbe.mfa, false);
  assert.equal(passwordProbe.accountMutation, false);
  assert.equal(passwordProbe.loginForm, true);
  assert.equal(passwordProbe.authUiVisible, true);
  assert.equal(credentialFillPermitted(passwordProbe), true);

  const usernameStep = fakeDocument([
    domNode("form", {}, [
      domNode("input", { name: "loginName", autocomplete: "username" }),
      domNode("a", { href: "/passkey" }, [], "Use a security key"),
      domNode("button", { type: "submit" }, [], "Next"),
    ]),
  ]);
  assert.equal(classifyProbeSurface(collectProbeSurface(usernameStep)).mfa, false);

  const otp = fakeDocument([
    domNode("form", {}, [
      domNode("input", { name: "code", autocomplete: "one-time-code" }),
      domNode("button", { type: "submit" }, [], "Verify"),
    ], "Enter the verification code"),
  ]);
  const otpProbe = classifyProbeSurface(collectProbeSurface(otp));
  assert.equal(otpProbe.mfa, true);
  assert.equal(otpProbe.passkeyAlternative, false);

  const webauthn = fakeDocument([
    domNode("form", {}, [
      domNode("button", { type: "submit" }, [], "Continue"),
    ], "Use your security key"),
  ]);
  assert.equal(classifyProbeSurface(collectProbeSurface(webauthn)).mfa, true);

  const reset = fakeDocument([
    domNode("form", {}, [
      domNode("input", { type: "password", name: "password", autocomplete: "new-password" }),
      domNode("button", { type: "submit" }, [], "Reset password"),
    ]),
  ], "Reset password");
  const resetProbe = classifyProbeSurface(collectProbeSurface(reset));
  assert.equal(resetProbe.passwordCount, 1);
  assert.equal(resetProbe.accountMutation, true);
  assert.equal(resetProbe.authRecovery, true);
  assert.equal(resetProbe.mfa, false);
  assert.equal(credentialFillPermitted(resetProbe), false);
  assert.equal(submitLabelRejected("Reset password"), true);
  assert.equal(submitLabelRejected("Next"), false);
  assert.equal(submitLabelRejected("Sign in with a passkey"), true);

  const forgotLink = fakeDocument([
    domNode("form", {}, [
      domNode("input", { type: "password", name: "password", autocomplete: "current-password" }),
      domNode("a", { href: "/ui/login/password/init" }, [], "Forgot password?"),
      domNode("button", { type: "submit" }, [], "Next"),
    ]),
  ]);
  const forgotProbe = classifyProbeSurface(collectProbeSurface(forgotLink));
  assert.equal(forgotProbe.accountMutation, false);
  assert.equal(forgotProbe.mfa, false);
  assert.equal(credentialFillPermitted(forgotProbe), true);
  assert.equal(
    classifyProbeSurface({
      passwordCount: 1,
      passkeyAlternative: true,
      otpField: false,
      webauthnChallenge: false,
      text: "passkey security key webauthn",
    }).mfa,
    false,
  );
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
  assert.equal(
    classifyObservation({
      location: app,
      status: 200,
      probe: { viewerOnly: true, managerShell: false, appShell: true },
      managerConfirmed: true,
    }),
    "policy-denied",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 200,
      probe: { accessRequest: true, appShell: true, managerShell: false },
      managerConfirmed: true,
    }),
    "policy-denied",
  );
  assert.equal(
    classifyObservation({
      location: app,
      status: 200,
      probe: { authUiVisible: true, managerShell: true, appShell: true },
      managerConfirmed: true,
    }),
    "auth-required",
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
  assert.equal(
    screenshotPermitted({
      classification: "authenticated",
      location: app,
      probe: { ...ready, authUiVisible: true },
    }),
    false,
  );
});

test("inventory includes nav, unlinked hosts, and host settings", () => {
  const names = hostNamesFromPayload(
    JSON.stringify({
      hosts: [{ name: "legacy-host" }],
      declared_hosts: [{ name: "declared-only" }],
    }),
  );
  const planned = planInventory({
    hostNames: names,
    hrefs: [
      "https://pharos.agm.ng/pharos/hosts/company",
      "/pharos/settings/providers/hetzner-cloud",
      "https://pharos.barta.cm/pharos/services/legacy-host/backup",
      "https://tiles.openfreemap.org/styles/positron",
    ],
  });
  for (const route of [
    "/pharos/",
    "/pharos/map",
    "/pharos/alerts",
    "/pharos/backups",
    "/pharos/services",
    "/pharos/activity",
    "/pharos/settings/providers",
  ]) {
    assert.equal(planned.includes(route), true);
  }
  assert.equal(planned.includes("/pharos/hosts/legacy-host"), true);
  assert.equal(planned.includes("/pharos/hosts/legacy-host?section=settings"), true);
  assert.equal(planned.includes("/pharos/hosts/declared-only?section=settings"), true);
  assert.equal(planned.includes("/pharos/hosts/company"), false);
  assert.equal(planned.includes("/pharos/settings/providers/hetzner-cloud"), true);
  assert.equal(planned.includes("/pharos/services/legacy-host/backup"), true);
  assert.equal(screenshotName("/pharos/hosts/legacy-host", 3), "host-03.png");
  assert.equal(screenshotName("/pharos/hosts/legacy-host?section=settings", 3), "host-03-settings.png");
  assert.equal(screenshotName("/pharos/hosts/legacy-host", 3).includes("legacy-host"), false);
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
  assert.equal(runner.includes("mfaCopy"), false);
  assert.ok(runner.includes("collectProbeSurface"));
  assert.ok(runner.includes("classifyProbeSurface"));
  assert.ok(runner.includes("routeWebSocket"));
  assert.ok(runner.includes("decideIncidental(\"download\")"));
  assert.equal(runner.includes("context.route("), false);
  assert.equal(runner.includes("context.on(\"response\""), false);
  assert.equal(runner.includes("split(/[^A-Za-z0-9"), false);
  assert.ok(runner.includes("enableFetchGuard"));
  assert.ok(runner.includes("createTargetGate"));
  assert.ok(runner.includes("shutdownLiveSession"));
  assert.ok(runner.includes("newBrowserCDPSession"));
  assert.ok(runner.includes("takeAuthenticatedShot"));
  assert.ok(runner.includes("credentialFillPermitted"));
  assert.ok(guard.includes("Fetch.failRequest"));
  assert.ok(guard.includes('requestStage: "Request"'));
  assert.equal(guard.includes("ProvideCredentials"), false);
  assert.ok(guard.includes("waitForDebuggerOnStart: true"));
  assert.ok(guard.includes("flatten: false"));
  assert.ok(guard.includes("Target.sendMessageToTarget"));
  assert.equal(guard.includes("Target.setDiscoverTargets"), false);
  assert.ok(guard.includes("Target.closeTarget"));
  const discoverAt = runner.indexOf("await gate.enable()", runAt);
  const finallyAt = runner.lastIndexOf("finally");
  assert.ok(runner.indexOf("shutdownLiveSession", finallyAt) > finallyAt);
  assert.equal(runner.indexOf("secrets.fill", finallyAt), -1);
  assert.equal(runner.indexOf("disposeFetchGuard", finallyAt), -1);
  const armAt = runner.indexOf("await guard.armPage", runAt);
  const shotAt = runner.indexOf("takeAuthenticatedShot", runner.indexOf("async function shoot"));
  assert.ok(discoverAt > runAt);
  assert.ok(armAt > discoverAt);
  assert.ok(loginAt > armAt);
  assert.ok(shotAt > runner.indexOf("async function shoot"));
  assert.equal(runner.includes("tracing.start"), false);
  assert.equal(runner.includes("screencast"), false);
  assert.equal(runner.includes(".storageState("), false);
  assert.equal(guard.includes("acceptDownloads: false"), true);
  assert.equal(guard.includes('serviceWorkers: "block"'), true);
});

function fakeFetchSession(options = {}) {
  const calls = [];
  const listeners = {};
  return {
    calls,
    listeners,
    on(event, handler) {
      calls.push({ method: "on", event });
      listeners[event] = handler;
    },
    async send(method, params) {
      calls.push({ method, params });
      if (options.failMethods?.has(method)) throw new Error("send-failed");
    },
    async detach() {
      calls.push({ method: "detach" });
      if (options.failMethods?.has("detach")) throw new Error("detach-failed");
    },
  };
}

test("each redirect hop is failed by Fetch before continue, including preserved POST", async () => {
  const companyHop = {
    requestId: "hop-company",
    redirectedRequestId: "login-post",
    resourceType: "Document",
    request: {
      method: "POST",
      url: "https://pharos.agm.ng/pharos/host-actions/example/remove",
    },
  };
  const company = fakeFetchSession();
  const remembered = [];
  const companyStatus = await settleFetchPause(company, companyHop, { secrets: ["Ab!cdEF12"] }, (verdict) => {
    remembered.push(verdict);
  });
  assert.equal(companyStatus, "failed");
  assert.deepEqual(company.calls.map((call) => call.method), ["Fetch.failRequest"]);
  assert.equal(company.calls[0].params.errorReason, "BlockedByClient");
  assert.equal(company.calls[0].params.requestId, "hop-company");
  assert.equal(JSON.stringify(remembered).includes("pharos.agm.ng"), false);
  assert.equal(JSON.stringify(remembered).includes("Ab!cdEF12"), false);
  assert.equal(decideFetchPause(companyHop).action, "fail");

  const mutationHop = {
    requestId: "hop-mutation",
    redirectedRequestId: "login-post",
    request: {
      method: "POST",
      url: "https://pharos.barta.cm/pharos/agora/requests/host-preferences.json",
    },
  };
  const mutation = fakeFetchSession();
  assert.equal(await settleFetchPause(mutation, mutationHop, {}, () => {}), "failed");
  assert.equal(mutation.calls.some((call) => call.method === "Fetch.continueRequest"), false);
  assert.equal(decideFetchPause(mutationHop).verdict.reason, "app-mutation");

  const allowedHop = {
    requestId: "hop-app",
    redirectedRequestId: "issuer-redirect",
    request: { method: "GET", url: "https://pharos.barta.cm/pharos/auth/callback" },
  };
  const allowed = fakeFetchSession();
  assert.equal(await settleFetchPause(allowed, allowedHop, {}, () => {}), "continued");
  assert.deepEqual(allowed.calls.map((call) => call.method), ["Fetch.continueRequest"]);

  const loginHop = {
    requestId: "hop-login",
    redirectedRequestId: "authorize",
    request: { method: "POST", url: "https://auth.inspr.at/ui/login/password" },
  };
  const login = fakeFetchSession();
  assert.equal(await settleFetchPause(login, loginHop, {}, () => {}), "continued");
  const resetHop = {
    requestId: "hop-reset",
    redirectedRequestId: "authorize",
    request: { method: "POST", url: "https://auth.inspr.at/ui/login/password/reset" },
  };
  const reset = fakeFetchSession();
  assert.equal(await settleFetchPause(reset, resetHop, {}, () => {}), "failed");
  assert.equal(reset.calls.some((call) => call.method === "Fetch.continueRequest"), false);

  const responseStage = {
    requestId: "too-late",
    responseStatusCode: 307,
    request: { method: "POST", url: "https://auth.inspr.at/ui/login/password" },
  };
  const late = fakeFetchSession();
  assert.equal(await settleFetchPause(late, responseStage, {}, () => {}), "failed");
  assert.equal(late.calls.some((call) => call.method === "Fetch.continueRequest"), false);

  const brokenRemember = fakeFetchSession();
  assert.equal(
    await settleFetchPause(brokenRemember, companyHop, {}, () => {
      throw new Error("evidence");
    }),
    "failed",
  );
  assert.equal(brokenRemember.calls[0].method, "Fetch.failRequest");

  const brokenFail = fakeFetchSession({ failMethods: new Set(["Fetch.failRequest"]) });
  assert.equal(await settleFetchPause(brokenFail, companyHop, {}, () => {}), "paused");
  assert.equal(brokenFail.calls.some((call) => call.method === "Fetch.continueRequest"), false);
});

test("fetch guard enables request-stage pauses, cancels auth, and disposes after callback failure", async () => {
  const session = fakeFetchSession();
  await enableFetchGuard(session, { secrets: [] }, () => {});
  assert.deepEqual(
    session.calls.map((call) => call.method === "on" ? `on:${call.event}` : call.method),
    ["on:Fetch.requestPaused", "on:Fetch.authRequired", "Fetch.enable"],
  );
  assert.deepEqual(session.calls[2].params.patterns, [{ urlPattern: "*", requestStage: "Request" }]);
  assert.equal(session.calls[2].params.handleAuthRequests, true);
  await session.listeners["Fetch.requestPaused"]({
    requestId: "direct-post",
    request: { method: "POST", url: "https://pharos.barta.cm/pharos/auth/logout" },
  });
  assert.equal(session.calls.some((call) => call.method === "Fetch.failRequest"), true);
  assert.equal(session.calls.some((call) => call.method === "Fetch.continueRequest"), false);

  const auth = fakeFetchSession();
  assert.equal(await settleFetchAuth(auth, { requestId: "challenge" }), "cancelled");
  assert.equal(auth.calls[0].params.authChallengeResponse.response, "CancelAuth");
  assert.equal(JSON.stringify(auth.calls[0].params).includes("password"), false);
  assert.equal(Object.hasOwn(auth.calls[0].params.authChallengeResponse, "username"), false);

  const enableFailed = fakeFetchSession({ failMethods: new Set(["Fetch.enable"]) });
  await assert.rejects(enableFetchGuard(enableFailed, {}, () => {}), /send-failed/);
  assert.equal(enableFailed.calls.some((call) => call.method === "Fetch.continueRequest"), false);

  const disposeFailed = fakeFetchSession({ failMethods: new Set(["Fetch.disable"]) });
  await disposeFetchGuard(disposeFailed);
  assert.deepEqual(disposeFailed.calls.map((call) => call.method), ["Fetch.disable", "detach"]);
});

function protocolSession(options = {}) {
  const calls = [];
  const listeners = {};
  return {
    calls,
    listeners,
    on(event, handler) {
      calls.push({ method: "on", event });
      listeners[event] = handler;
    },
    async send(method, params) {
      calls.push({ method, params });
      if (method !== "Target.sendMessageToTarget") return;
      const command = JSON.parse(params.message);
      const body = options.failMethod === command.method
        ? { id: command.id, error: { message: "failed" } }
        : { id: command.id, result: {} };
      queueMicrotask(() => {
        listeners["Target.receivedMessageFromTarget"]({
          sessionId: params.sessionId,
          message: JSON.stringify(body),
        });
      });
    },
  };
}

function childMethods(session) {
  return session.calls
    .filter((call) => call.method === "Target.sendMessageToTarget")
    .map((call) => JSON.parse(call.params.message).method);
}

test("paused targets install Fetch before resume and refused targets never resume", async () => {
  assert.equal(pausedTargetPlan({ type: "page", targetId: "primary" }, ""), "guard");
  assert.equal(pausedTargetPlan({ type: "page", targetId: "popup" }, "primary"), "refuse");
  assert.equal(pausedTargetPlan({ type: "iframe", targetId: "frame" }, "primary"), "guard");
  assert.equal(pausedTargetPlan({ type: "service_worker", targetId: "worker" }, "primary"), "refuse");
  const session = protocolSession();
  const notes = [];
  const gate = createTargetGate(session, { secrets: ["synthetic-only-secret"] }, (verdict) => {
    notes.push(verdict);
    if (verdict.reason === "serviceworker") throw new Error("evidence");
  });
  await gate.enable();
  assert.equal(session.calls[0].method, "on");
  assert.equal(session.calls[1].method, "on");
  assert.equal(session.calls[2].method, "Target.setAutoAttach");
  assert.deepEqual(session.calls[2].params, {
    autoAttach: true,
    waitForDebuggerOnStart: true,
    flatten: false,
  });
  await gate.onAttached({
    sessionId: "page-session",
    waitingForDebugger: true,
    targetInfo: { type: "page", targetId: "primary", url: "https://user:secret@pharos.barta.cm/pharos/" },
  });
  assert.deepEqual(childMethods(session), [
    "Fetch.enable",
    "Target.setAutoAttach",
    "Runtime.runIfWaitingForDebugger",
  ]);
  const enable = session.calls.find((call) => call.method === "Target.sendMessageToTarget");
  assert.deepEqual(JSON.parse(enable.params.message).params.patterns, [{ urlPattern: "*", requestStage: "Request" }]);
  assert.equal(JSON.stringify(session.calls).includes("secret"), false);
  assert.equal(gate.compromised(), "");

  await gate.onAttached({
    sessionId: "popup-session",
    waitingForDebugger: true,
    targetInfo: { type: "page", targetId: "popup" },
  });
  await gate.onAttached({
    sessionId: "worker-session",
    waitingForDebugger: true,
    targetInfo: { type: "service_worker", targetId: "worker" },
  });
  const closed = session.calls.filter((call) => call.method === "Target.closeTarget").map((call) => call.params.targetId);
  assert.deepEqual(closed, ["popup", "worker"]);
  assert.equal(notes.some((item) => item.reason === "popup"), true);
  assert.equal(childMethods(session).filter((method) => method === "Runtime.runIfWaitingForDebugger").length, 1);

  const beforeFrame = childMethods(session).length;
  await gate.onMessage({
    sessionId: "page-session",
    message: JSON.stringify({
      method: "Target.attachedToTarget",
      params: {
        sessionId: "frame-session",
        waitingForDebugger: true,
        targetInfo: { type: "iframe", targetId: "frame-1" },
      },
    }),
  });
  assert.deepEqual(childMethods(session).slice(beforeFrame, beforeFrame + 3), [
    "Fetch.enable",
    "Target.setAutoAttach",
    "Runtime.runIfWaitingForDebugger",
  ]);
  const frameCommands = session.calls.filter((call) => {
    if (call.method !== "Target.sendMessageToTarget") return false;
    return call.params.sessionId === "frame-session";
  });
  assert.equal(frameCommands[0].params.sessionId, "frame-session");
  assert.ok(frameCommands.findIndex((call) => JSON.parse(call.params.message).method === "Fetch.enable")
    < frameCommands.findIndex((call) => JSON.parse(call.params.message).method === "Runtime.runIfWaitingForDebugger"));

  await gate.onMessage({
    sessionId: "frame-session",
    message: JSON.stringify({
      method: "Fetch.requestPaused",
      params: {
        requestId: "iframe-post",
        request: { method: "POST", url: "https://pharos.agm.ng/pharos/receive" },
      },
    }),
  });
  const frameTraffic = session.calls.filter((call) => call.method === "Target.sendMessageToTarget" && call.params.sessionId === "frame-session");
  const frameMethods = frameTraffic.map((call) => JSON.parse(call.params.message).method);
  assert.equal(frameMethods.includes("Fetch.failRequest"), true);
  assert.equal(frameMethods.includes("Fetch.continueRequest"), false);
  assert.equal(JSON.stringify(frameTraffic).includes("pharos.agm.ng"), false);

  const unpaused = protocolSession();
  const unpausedGate = createTargetGate(unpaused, {}, () => {});
  await unpausedGate.enable();
  await unpausedGate.onAttached({
    sessionId: "late",
    waitingForDebugger: false,
    targetInfo: { type: "iframe", targetId: "already-running" },
  });
  assert.equal(unpausedGate.compromised(), "iframe");
  assert.equal(childMethods(unpaused).includes("Runtime.runIfWaitingForDebugger"), false);
  assert.equal(unpaused.calls.some((call) => call.method === "Target.closeTarget"), true);

  const broken = protocolSession({ failMethod: "Fetch.enable" });
  const brokenGate = createTargetGate(broken, {}, () => {});
  await brokenGate.enable();
  await brokenGate.onAttached({
    sessionId: "page-session",
    waitingForDebugger: true,
    targetInfo: { type: "page", targetId: "primary" },
  });
  assert.equal(brokenGate.compromised(), "page");
  assert.equal(childMethods(broken).includes("Runtime.runIfWaitingForDebugger"), false);
  assert.equal(broken.calls.some((call) => call.method === "Target.closeTarget" && call.params.targetId === "primary"), true);
});

test("cleanup closes the browser before disabling Fetch or erasing secrets", async () => {
  const secrets = ["person@example.test", "synthetic-only-secret"];
  const drafts = [{ value: "local-draft" }];
  const failed = [];
  const held = await shutdownLiveSession({
    close: async () => {
      failed.push(["close", secrets[1], drafts[0].value]);
      throw new Error("close-failed");
    },
    sessions: [{
      async send(method) {
        failed.push(["disable", method, secrets[1]]);
      },
      async detach() {
        failed.push("detach");
      },
    }],
    detach: async () => {
      failed.push("browser-detach");
    },
    secrets,
    drafts,
  });
  assert.deepEqual(held, { released: false });
  assert.deepEqual(failed, [["close", "synthetic-only-secret", "local-draft"]]);
  assert.equal(secrets[1], "synthetic-only-secret");
  assert.equal(drafts[0].value, "local-draft");

  const order = [];
  const released = await shutdownLiveSession({
    close: async () => {
      order.push(["close", secrets[1]]);
    },
    sessions: [{
      async send(method) {
        order.push(["session", method, secrets[1]]);
      },
      async detach() {
        order.push(["session-detach", secrets[1]]);
      },
    }],
    detach: async () => {
      order.push(["browser-detach", secrets[1]]);
    },
    secrets,
    drafts,
  });
  assert.deepEqual(released, { released: true });
  assert.deepEqual(order, [
    ["close", "synthetic-only-secret"],
    ["session", "Fetch.disable", "synthetic-only-secret"],
    ["session-detach", "synthetic-only-secret"],
    ["browser-detach", "synthetic-only-secret"],
  ]);
  assert.equal(secrets[1], "");
  assert.equal(drafts[0].value, "");
});

test("visible password text blocks the screenshot and username text does not", async () => {
  const password = "Ab!cdEF12";
  const previous = globalThis.document;
  const shots = [];
  const page = {
    async evaluate(fn, arg) {
      return fn(arg);
    },
    async screenshot() {
      shots.push("screenshot");
    },
  };
  const withDocument = async (document, permitted) => {
    shots.length = 0;
    globalThis.document = document;
    return takeAuthenticatedShot(page, {
      permitted,
      password,
      options: { path: "shot.png", type: "png" },
    });
  };
  try {
    const leaked = await withDocument({
      title: "",
      body: { innerText: `Account ${password} shown`, textContent: "hidden label" },
      querySelectorAll() {
        return [];
      },
    }, true);
    assert.equal(leaked, false);
    assert.deepEqual(shots, []);

    for (const [secret, text] of [["s3cr", "pres3crpost"], ["ab1", "pre-ab1-post"]]) {
      shots.length = 0;
      globalThis.document = {
        title: "",
        body: { innerText: text, textContent: text },
        querySelectorAll() {
          return [];
        },
      };
      const blocked = await takeAuthenticatedShot(page, {
        permitted: true,
        password: secret,
        options: { path: "shot.png", type: "png" },
      });
      assert.equal(blocked, false, secret);
      assert.deepEqual(shots, []);
    }

    const hiddenOnly = await withDocument({
      title: "Fleet",
      body: { innerText: "Password", textContent: "Password" },
      querySelectorAll() {
        return [{ value: password, getAttribute() { return "hidden"; } }];
      },
    }, true);
    assert.equal(hiddenOnly, false);
    assert.deepEqual(shots, []);

    const usernameOnly = await withDocument({
      title: "Fleet",
      body: { innerText: FIXTURE_USER, textContent: FIXTURE_USER },
      querySelectorAll() {
        return [];
      },
    }, true);
    assert.equal(usernameOnly, true);
    assert.deepEqual(shots, ["screenshot"]);

    shots.length = 0;
    const refused = await withDocument({
      title: "",
      body: { innerText: "Fleet map", textContent: "Fleet map" },
      querySelectorAll() {
        return [];
      },
    }, false);
    assert.equal(refused, false);
    assert.deepEqual(shots, []);

    const broken = {
      async evaluate() {
        throw new Error("probe");
      },
      async screenshot() {
        shots.push("screenshot");
      },
    };
    shots.length = 0;
    assert.equal(await takeAuthenticatedShot(broken, { permitted: true, password, options: {} }), false);
    assert.deepEqual(shots, []);
  } finally {
    globalThis.document = previous;
  }
});
