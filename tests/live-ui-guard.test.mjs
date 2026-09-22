import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ENTRY_URL,
  EXIT_CODES,
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
  classifyProbeSurface,
  collectProbeSurface,
  connectFlatDebugger,
  continuationAllowed,
  createFlatCdpConnection,
  createFlatTargetGuard,
  credentialFillPermitted,
  debuggerWebSocketUrl,
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
  openGuardedBrowser,
  installPrimaryFrameRoute,
  parseClientDraft,
  planInventory,
  primaryFrameDecision,
  publicPath,
  reserveLoopbackDebuggerPort,
  redactEvidence,
  repoRootFromScripts,
  sanitizeNavigationError,
  screenshotName,
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

test("pathname, encoding, fragment, and short secrets stay out of verdicts", async () => {
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
    `https://pharos.barta.cm/pharos/map?pre-a%62%31-post=1`,
    `https://pharos.barta.cm/pharos/map?${secret}=1`,
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
  const punctuated = "Ab!cdEF12";
  const key = request("GET", `https://pharos.barta.cm/pharos/map?${encodeURIComponent(punctuated)}=1`, [punctuated]);
  assert.equal(key.allow, false);
  assert.equal(key.reason, "secret-in-url");
  assert.equal(leaks(key, [punctuated]), false);
  const keyedFetch = fakeFetchSession();
  assert.equal(
    await settleFetchPause(
      keyedFetch,
      { requestId: "query-key", request: { method: "GET", url: "https://pharos.barta.cm/pharos/map?pre-a%62%31-post=1" } },
      { secrets: ["ab1"] },
    ),
    "failed",
  );
  assert.equal(keyedFetch.calls.some((call) => call.method === "Fetch.continueRequest"), false);
  const main = { id: "main" };
  const routed = primaryFrameDecision(
    {
      url: () => "https://pharos.barta.cm/pharos/map?pre-a%62%31-post=1",
      method: () => "GET",
      resourceType: () => "document",
      frame: () => main,
    },
    { mainFrame: () => main },
    { secrets: ["ab1"] },
  );
  assert.equal(routed.allow, false);
  assert.equal(routed.reason, "secret-in-url");
  assert.equal(leaks(routed, ["ab1"]), false);
});

test("unicode secrets match through percent-decoded paths, keys, and values", async () => {
  const secret = "é!";
  const face = "\u{1F600}";
  const reviewer = "https://pharos.barta.cm/pharos/map?pre-%25C3%25A9!-post=1";
  const hidden = [
    reviewer,
    `https://pharos.barta.cm/pharos/map?${encodeURIComponent(secret)}=1`,
    `https://pharos.barta.cm/pharos/map?note=${encodeURIComponent(secret)}`,
    `https://pharos.barta.cm/pharos/map?note=${encodeURIComponent(encodeURIComponent(secret))}`,
    `https://pharos.barta.cm/pharos/map?pre-${encodeURIComponent(encodeURIComponent(secret))}-post=1`,
    `https://pharos.barta.cm/pharos/${encodeURIComponent(secret)}`,
    `https://pharos.barta.cm/pharos/%25C3%25A9!`,
    `https://pharos.barta.cm/pharos/map#${encodeURIComponent(secret)}`,
    `https://pharos.barta.cm/pharos/map#${encodeURIComponent(encodeURIComponent(secret))}`,
    `https://pharos.barta.cm/pharos/map?${encodeURIComponent(face)}=1`,
    `https://pharos.barta.cm/pharos/map?note=${encodeURIComponent(face)}`,
    `https://pharos.barta.cm/pharos/map?pre-${encodeURIComponent(encodeURIComponent(face))}-post=1`,
    `https://pharos.barta.cm/pharos/${encodeURIComponent(face)}`,
    "https://pharos.barta.cm/pharos/map?x=%ED%A0%BD%ED%B8%80",
    "https://pharos.barta.cm/pharos/map?x=%E0%83%A9!",
  ];
  for (const url of hidden) {
    const result = request("GET", url, [secret, face]);
    assert.equal(result.allow, false, url);
    assert.equal(result.reason, "secret-in-url");
    assert.equal(leaks(result, [secret, face, "%C3%A9", "%25C3%25A9"]), false);
    const sanitized = sanitizeNavigationError(new Error(`navigation failed ${url}`), [secret, face]);
    assert.equal(leaks(sanitized, [secret, face]), false);
  }
  const keyedFetch = fakeFetchSession();
  assert.equal(
    await settleFetchPause(
      keyedFetch,
      { requestId: "unicode-key", request: { method: "GET", url: reviewer } },
      { secrets: [secret] },
    ),
    "failed",
  );
  assert.equal(keyedFetch.calls.some((call) => call.method === "Fetch.continueRequest"), false);
  assert.equal(keyedFetch.calls[0].method, "Fetch.failRequest");
  const main = { id: "main" };
  const routed = primaryFrameDecision(
    {
      url: () => reviewer,
      method: () => "GET",
      resourceType: () => "document",
      frame: () => main,
    },
    { mainFrame: () => main },
    { secrets: [secret] },
  );
  assert.equal(routed.allow, false);
  assert.equal(routed.reason, "secret-in-url");
  assert.equal(leaks(routed, [secret]), false);
  for (const url of [
    "https://pharos.barta.cm/pharos/map?section=settings",
    "https://pharos.barta.cm/pharos/map?q=%",
    "https://pharos.barta.cm/pharos/map?q=%2",
    "https://pharos.barta.cm/pharos/map?q=%ZZ",
    "https://pharos.barta.cm/pharos/map?q=%C3%",
    "https://pharos.barta.cm/pharos/map?q=%ED%A0%80",
    "https://pharos.barta.cm/pharos/map",
  ]) {
    assert.equal(request("GET", url, [secret, face]).allow, true, url);
  }
  assert.equal(
    request("GET", "https://pharos.barta.cm/pharos/map?q=%ZZ&pre-%25C3%25A9!-post=1", [secret]).allow,
    false,
  );
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
  assert.equal(submitLabelRejected("Skip"), true);
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

test("issuer MFA enrollment is account setup and verification stays MFA", () => {
  const provider = (value) => domNode("input", { type: "radio", name: "provider", value, required: "true" });
  const optional = fakeDocument([
    domNode("form", { method: "POST" }, [
      domNode("input", { type: "hidden", name: "authRequestID", value: "synthetic-request" }),
      provider("0"),
      provider("1"),
      domNode("button", { type: "submit", name: "skip", value: "true" }, [], "Skip"),
      domNode("button", { type: "submit" }, [], "Next"),
    ], "Multi-factor authentication Authenticator App Security Key"),
  ]);
  const optionalSurface = collectProbeSurface(optional);
  const optionalProbe = classifyProbeSurface(optionalSurface);
  assert.equal(optionalProbe.accountSetup, true);
  assert.equal(optionalProbe.enrollmentOptional, true);
  assert.equal(optionalProbe.mfa, false);
  assert.equal(optionalSurface.otpField, false);
  assert.equal(optionalSurface.webauthnChallenge, false);
  assert.equal(optionalProbe.passkeyAlternative, false);
  assert.equal(optionalProbe.loginForm, false);
  assert.equal(credentialFillPermitted(optionalProbe), false);
  const issuer = { origin: PERSONAL_ISSUER_ORIGIN, pathname: "/ui/login/mfa/prompt" };
  assert.equal(
    classifyObservation({ location: issuer, status: 200, probe: optionalProbe }),
    "account-setup-required",
  );
  assert.equal(EXIT_CODES["account-setup-required"], 5);
  assert.notEqual(EXIT_CODES["account-setup-required"], 0);
  assert.equal(
    screenshotPermitted({
      classification: "account-setup-required",
      location: issuer,
      probe: optionalProbe,
    }),
    false,
  );

  const required = fakeDocument([
    domNode("form", { method: "POST" }, [
      provider("0"),
      provider("1"),
      domNode("button", { type: "submit" }, [], "Next"),
    ], "Multi-factor authentication Authenticator App Security Key"),
  ]);
  const requiredProbe = classifyProbeSurface(collectProbeSurface(required));
  assert.equal(requiredProbe.accountSetup, true);
  assert.equal(requiredProbe.enrollmentOptional, false);
  assert.equal(requiredProbe.mfa, false);
  assert.equal(
    classifyObservation({ location: issuer, status: 200, probe: requiredProbe }),
    "account-setup-required",
  );

  const otp = fakeDocument([
    domNode("form", {}, [
      provider("0"),
      domNode("input", { name: "code", autocomplete: "one-time-code" }),
      domNode("button", { type: "submit" }, [], "Verify"),
    ]),
  ], "Enter the verification code");
  const otpProbe = classifyProbeSurface(collectProbeSurface(otp));
  assert.equal(otpProbe.accountSetup, false);
  assert.equal(otpProbe.mfa, true);
  assert.equal(
    classifyObservation({ location: issuer, status: 200, probe: otpProbe }),
    "mfa-required",
  );

  const securityKey = fakeDocument([
    domNode("form", {}, [
      domNode("button", { type: "submit" }, [], "Continue"),
    ], "Use your security key"),
  ]);
  const securityProbe = classifyProbeSurface(collectProbeSurface(securityKey));
  assert.equal(securityProbe.accountSetup, false);
  assert.equal(securityProbe.mfa, true);

  const passwordLogin = fakeDocument([
    domNode("form", {}, [
      domNode("input", { type: "password", name: "password", autocomplete: "current-password" }),
      domNode("a", { href: "/passkey" }, [], "Sign in with a passkey"),
      domNode("button", { type: "submit" }, [], "Next"),
    ]),
  ], "Password Sign in with a passkey Next");
  const passwordProbe = classifyProbeSurface(collectProbeSurface(passwordLogin));
  assert.equal(passwordProbe.accountSetup, false);
  assert.equal(passwordProbe.mfa, false);
  assert.equal(passwordProbe.passkeyAlternative, true);
  assert.equal(credentialFillPermitted(passwordProbe), true);

  const copyOnly = fakeDocument([
    domNode("form", {}, [
      domNode("button", { type: "submit" }, [], "Continue"),
    ], "Set up multi-factor authentication"),
  ]);
  const copyProbe = classifyProbeSurface(collectProbeSurface(copyOnly));
  assert.equal(copyProbe.accountSetup, false);
  assert.equal(copyProbe.mfa, true);

  const runner = fs.readFileSync(new URL("../scripts/live-ui.mjs", import.meta.url), "utf8");
  assert.equal(runner.includes("account-setup-required"), true);
  assert.equal(runner.includes("HumanSkip"), false);
  assert.equal(runner.includes("[name='skip']"), false);
  assert.equal(runner.includes("ISSUER_LOGIN_POST_PATHS.push"), false);
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
  assert.equal(
    screenshotPermitted({
      classification: "authenticated",
      location: app,
      probe: { ...ready, codeField: true, mfa: false, authUiVisible: false },
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
  const launch = browserLaunchOptions(47123);
  assert.equal(launch.headless, true);
  assert.deepEqual(launch.args, [
    "--remote-debugging-port=47123",
    "--remote-debugging-address=127.0.0.1",
  ]);
  assert.equal(Object.keys(launch).length, 2);
  assert.equal(launch.channel, undefined);
  assert.equal(launch.executablePath, undefined);
  assert.throws(() => browserLaunchOptions(0), /browser-launch/);
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
  const loginAt = runner.indexOf("await signIn", runAt);
  assert.equal(runner.includes("mfaCopy"), false);
  assert.ok(runner.includes("collectProbeSurface"));
  assert.ok(runner.includes("classifyProbeSurface"));
  assert.ok(runner.includes("routeWebSocket"));
  assert.ok(runner.includes("decideIncidental(\"download\")"));
  assert.equal(runner.includes("context.on(\"response\""), false);
  assert.equal(runner.includes("split(/[^A-Za-z0-9"), false);
  assert.ok(runner.includes("enableFetchGuard"));
  assert.ok(runner.includes("openGuardedBrowser"));
  assert.ok(runner.includes("installPrimaryFrameRoute"));
  assert.equal(runner.includes("createTargetGate"), false);
  assert.equal(runner.includes("newBrowserCDPSession"), false);
  assert.ok(runner.includes("shutdownLiveSession"));
  assert.ok(runner.includes("takeAuthenticatedShot"));
  assert.ok(runner.includes("credentialFillPermitted"));
  assert.ok(guard.includes("context.route("));
  assert.ok(guard.includes("Fetch.failRequest"));
  assert.ok(guard.includes('requestStage: "Request"'));
  assert.equal(guard.includes("ProvideCredentials"), false);
  assert.ok(guard.includes("waitForDebuggerOnStart: true"));
  assert.ok(guard.includes("flatten: true"));
  assert.equal(guard.includes("flatten: false"), false);
  assert.equal(guard.includes("Target.sendMessageToTarget"), false);
  assert.equal(guard.includes("Target.receivedMessageFromTarget"), false);
  assert.equal(guard.includes("sec-fetch-dest"), false);
  assert.equal(guard.includes("allHeaders"), false);
  assert.ok(guard.includes("envelope.sessionId = sessionId"));
  assert.equal(guard.includes("Target.setDiscoverTargets"), false);
  assert.ok(guard.includes("Target.closeTarget"));
  const openedAt = runner.indexOf("openGuardedBrowser", runAt);
  const guardAt = runner.indexOf("await installGuard", runAt);
  const pageAt = runner.indexOf("context.newPage", runAt);
  const bindAt = runner.indexOf("pageRef.page = page", runAt);
  const armAt = runner.indexOf("await guard.armPage", runAt);
  const finallyAt = runner.lastIndexOf("finally");
  assert.ok(openedAt > runAt);
  assert.ok(guardAt > openedAt);
  assert.ok(pageAt > guardAt);
  assert.ok(bindAt > pageAt);
  assert.ok(armAt > bindAt);
  assert.ok(loginAt > armAt);
  assert.ok(runner.indexOf("shutdownLiveSession", finallyAt) > finallyAt);
  assert.ok(runner.indexOf("gate.close()", finallyAt) > runner.indexOf("shutdownLiveSession", finallyAt));
  const shutdownClose = runner.slice(runner.indexOf("close: async () => {"), runner.indexOf("sessions: fetchSessions"));
  assert.ok(shutdownClose.indexOf("beginShutdown") >= 0);
  assert.ok(shutdownClose.indexOf("beginShutdown") < shutdownClose.indexOf("browser.close()"));
  const openedGuard = guard.slice(guard.indexOf("export async function openGuardedBrowser"));
  assert.ok(openedGuard.indexOf("setEmergencyClose") < openedGuard.indexOf("await gate.enable"));
  assert.equal(runner.indexOf("secrets.fill", finallyAt), -1);
  assert.equal(runner.indexOf("disposeFetchGuard", finallyAt), -1);
  const shotAt = runner.indexOf("takeAuthenticatedShot", runner.indexOf("async function shoot"));
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
    ["on:close", "on:Fetch.requestPaused", "on:Fetch.authRequired", "Fetch.enable"],
  );
  const enabled = session.calls.find((call) => call.method === "Fetch.enable");
  assert.deepEqual(enabled.params.patterns, [{ urlPattern: "*", requestStage: "Request" }]);
  assert.equal(enabled.params.handleAuthRequests, true);
  await session.listeners["Fetch.requestPaused"]({
    requestId: "direct-post",
    request: { method: "POST", url: "https://pharos.barta.cm/pharos/auth/logout" },
  });
  assert.equal(session.calls.some((call) => call.method === "Fetch.failRequest"), true);
  assert.equal(session.calls.some((call) => call.method === "Fetch.continueRequest"), false);
  session.listeners.close();
  await session.listeners["Fetch.requestPaused"]({
    requestId: "after-close",
    request: { method: "POST", url: "https://auth.inspr.at/ui/login/password" },
  });
  assert.equal(session.calls.some((call) => call.method === "Fetch.continueRequest"), false);
  assert.equal(session.calls.filter((call) => call.method === "Fetch.failRequest").at(-1).params.requestId, "after-close");

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

function flatTransport(options = {}) {
  const sent = [];
  let receive = () => {};
  const connection = createFlatCdpConnection({
    send(text) {
      const envelope = JSON.parse(text);
      sent.push(envelope);
      queueMicrotask(() => {
        if (options.failMethod === envelope.method) {
          receive(JSON.stringify({
            id: envelope.id,
            sessionId: envelope.sessionId,
            error: { message: "ws://127.0.0.1/devtools/browser/secret-token" },
          }));
          return;
        }
        receive(JSON.stringify({ id: envelope.id, sessionId: envelope.sessionId, result: {} }));
      });
    },
  }, { commandTimeoutMs: 50 });
  receive = (text) => connection.receive(text);
  return { connection, sent };
}

function attachEvent(type, targetId, sessionId, waitingForDebugger = true) {
  return JSON.stringify({
    method: "Target.attachedToTarget",
    sessionId: type === "page" ? undefined : "page-session",
    params: {
      sessionId,
      waitingForDebugger,
      targetInfo: { type, targetId },
    },
  });
}

test("flat attach resumes only the first page and closes every other target", async () => {
  const expectedCloses = [];
  const { connection, sent } = flatTransport();
  const gate = createFlatTargetGuard(connection);
  gate.setEmergencyClose(() => {
    expectedCloses.push("browser");
  });
  await gate.enable();
  assert.equal(sent[0].method, "Target.setAutoAttach");
  assert.equal(Object.hasOwn(sent[0], "sessionId"), false);
  assert.deepEqual(sent[0].params, {
    autoAttach: true,
    waitForDebuggerOnStart: true,
    flatten: true,
  });
  connection.receive(attachEvent("page", "primary", "page-session"));
  await gate.settled();
  assert.deepEqual(sent.slice(1).map((entry) => entry.method), [
    "Target.setAutoAttach",
    "Runtime.runIfWaitingForDebugger",
  ]);
  assert.equal(sent[1].sessionId, "page-session");
  assert.equal(sent[2].sessionId, "page-session");
  assert.equal(Object.hasOwn(sent[1].params, "sessionId"), false);
  assert.equal(sent[1].params.flatten, true);
  assert.equal(gate.attachedPrimary(), "primary");
  assert.equal(gate.compromised(), "");
  assert.equal(sent.some((entry) => entry.method === "Fetch.enable"), false);
  assert.equal(sent.some((entry) => entry.method === "Target.sendMessageToTarget"), false);

  for (const [type, targetId, sessionId] of [
    ["page", "popup", "popup-session"],
    ["iframe", "frame-1", "frame-session"],
    ["worker", "worker-1", "worker-session"],
    ["shared_worker", "shared-1", "shared-session"],
    ["service_worker", "sw-1", "sw-session"],
  ]) {
    connection.receive(attachEvent(type, targetId, sessionId));
  }
  await gate.settled();
  const closed = sent.filter((entry) => entry.method === "Target.closeTarget").map((entry) => entry.params.targetId);
  assert.deepEqual(closed, ["popup", "frame-1", "worker-1", "shared-1", "sw-1"]);
  assert.deepEqual(expectedCloses, []);
  assert.equal(gate.compromised(), "");
  assert.equal(sent.filter((entry) => entry.method === "Runtime.runIfWaitingForDebugger").length, 1);
  assert.equal(sent.filter((entry) => entry.method === "Target.closeTarget").every((entry) => !entry.sessionId), true);
  assert.equal(JSON.stringify(sent).includes("secret"), false);

  const unpausedCloses = [];
  const unpaused = flatTransport();
  const unpausedGate = createFlatTargetGuard(unpaused.connection);
  unpausedGate.setEmergencyClose(() => {
    unpausedCloses.push("browser");
  });
  await unpausedGate.enable();
  unpaused.connection.receive(attachEvent("iframe", "already-running", "late", false));
  await unpausedGate.settled();
  assert.equal(unpausedGate.compromised(), "unpaused");
  assert.equal(unpaused.sent.some((entry) => entry.method === "Runtime.runIfWaitingForDebugger"), false);
  assert.deepEqual(unpausedCloses, ["browser"]);

  const brokenCloses = [];
  const broken = flatTransport({ failMethod: "Runtime.runIfWaitingForDebugger" });
  const brokenGate = createFlatTargetGuard(broken.connection);
  brokenGate.setEmergencyClose(() => {
    brokenCloses.push("browser");
  });
  await brokenGate.enable();
  broken.connection.receive(attachEvent("page", "primary", "page-session"));
  await brokenGate.settled();
  assert.equal(brokenGate.compromised(), "primary");
  assert.deepEqual(brokenCloses, ["browser"]);
  assert.equal(broken.sent.some((entry) => entry.method === "Target.closeTarget"), false);
  assert.equal(JSON.stringify(broken.sent).includes("secret-token"), false);
  assert.equal(JSON.stringify(broken.sent).includes("devtools"), false);
});

test("lost protocol state closes the primary target and stops later continuations", async () => {
  const detachedCloses = [];
  const { connection, sent } = flatTransport();
  const gate = createFlatTargetGuard(connection);
  gate.setEmergencyClose(() => {
    detachedCloses.push("browser");
  });
  await gate.enable();
  connection.receive(attachEvent("page", "primary", "page-session"));
  await gate.settled();
  assert.equal(gate.compromised(), "");
  connection.receive(JSON.stringify({
    method: "Target.detachedFromTarget",
    params: { sessionId: "page-session", targetId: "primary" },
  }));
  await gate.settled();
  assert.equal(gate.compromised(), "detached");
  assert.deepEqual(detachedCloses, ["browser"]);
  assert.equal(sent.some((entry) => entry.method === "Target.closeTarget" && entry.params.targetId === "primary"), false);

  const lostCloses = [];
  const lost = flatTransport();
  const lostGate = createFlatTargetGuard(lost.connection);
  lostGate.setEmergencyClose(() => {
    lostCloses.push("browser");
  });
  await lostGate.enable();
  lost.connection.receive(attachEvent("page", "primary", "page-session"));
  await lostGate.settled();
  lost.connection.failAll();
  lostGate.noteDisconnect();
  lostGate.noteDisconnect();
  await lostGate.settled();
  assert.equal(lostGate.compromised(), "disconnected");
  assert.deepEqual(lostCloses, ["browser"]);
  assert.equal(lost.sent.some((entry) => entry.method === "Target.closeTarget"), false);
  const redirected = fakeFetchSession();
  assert.equal(
    await settleFetchPause(
      redirected,
      {
        requestId: "redirected-login",
        redirectedRequestId: "authorize",
        request: { method: "POST", url: "https://auth.inspr.at/ui/login/password" },
      },
      { secrets: ["synthetic-only-secret"], gate: lostGate },
    ),
    "failed",
  );
  assert.equal(redirected.calls.some((call) => call.method === "Fetch.continueRequest"), false);
  assert.equal(redirected.calls[0].method, "Fetch.failRequest");

  const workerDetach = flatTransport();
  const workerGate = createFlatTargetGuard(workerDetach.connection);
  await workerGate.enable();
  workerDetach.connection.receive(attachEvent("page", "primary", "page-session"));
  await workerGate.settled();
  workerDetach.connection.receive(JSON.stringify({
    method: "Target.detachedFromTarget",
    params: { sessionId: "shared-session", targetId: "shared-1" },
  }));
  await workerGate.settled();
  assert.equal(workerGate.compromised(), "");

  const commandCloses = [];
  const command = flatTransport({ failMethod: "Target.closeTarget" });
  const commandGate = createFlatTargetGuard(command.connection);
  commandGate.setEmergencyClose(() => {
    commandCloses.push("browser");
  });
  await commandGate.enable();
  command.connection.receive(attachEvent("page", "primary", "page-session"));
  await commandGate.settled();
  command.connection.receive(attachEvent("shared_worker", "shared-1", "shared-session"));
  await commandGate.settled();
  assert.equal(commandGate.compromised(), "close");
  assert.deepEqual(commandCloses, ["browser"]);
  assert.equal(JSON.stringify(command.sent).includes("devtools"), false);

  const teardownCloses = [];
  const teardown = flatTransport();
  const teardownGate = createFlatTargetGuard(teardown.connection);
  teardownGate.setEmergencyClose(() => {
    teardownCloses.push("browser");
  });
  await teardownGate.enable();
  teardown.connection.receive(attachEvent("page", "primary", "page-session"));
  await teardownGate.settled();
  teardownGate.beginShutdown();
  teardownGate.noteDisconnect();
  teardown.connection.receive(JSON.stringify({
    method: "Target.detachedFromTarget",
    params: { sessionId: "page-session", targetId: "primary" },
  }));
  await teardownGate.settled();
  teardownGate.close();
  assert.deepEqual(teardownCloses, []);
  assert.equal(teardownGate.compromised(), "");

  const fetchCloses = [];
  const fetchLoss = flatTransport();
  const fetchGate = createFlatTargetGuard(fetchLoss.connection);
  fetchGate.setEmergencyClose(() => {
    fetchCloses.push("browser");
  });
  await fetchGate.enable();
  const session = fakeFetchSession();
  await enableFetchGuard(session, { gate: fetchGate, secrets: ["synthetic-only-secret"] }, () => {});
  session.listeners.close();
  session.listeners.close();
  assert.deepEqual(fetchCloses, ["browser"]);
  assert.equal(fetchGate.compromised(), "disconnected");
  assert.equal(
    await settleFetchPause(
      session,
      {
        requestId: "after-fetch-close",
        redirectedRequestId: "authorize",
        request: { method: "POST", url: "https://auth.inspr.at/ui/login/password" },
      },
      { secrets: ["synthetic-only-secret"], gate: fetchGate },
    ),
    "failed",
  );
});

test("a closed raw debugger socket closes the Playwright browser once", async () => {
  const browser = {
    closes: 0,
    contextsClosed: 0,
    contexts() {
      return [{
        async close() {
          browser.contextsClosed += 1;
        },
      }];
    },
    async close() {
      browser.closes += 1;
    },
  };
  let socket;
  class Socket {
    constructor(url) {
      const parsed = new URL(url);
      assert.equal(parsed.hostname, "127.0.0.1");
      assert.equal(parsed.protocol, "ws:");
      assert.equal(parsed.username, "");
      assert.equal(parsed.search, "");
      socket = this;
      this.listeners = {};
      this.sent = [];
    }

    addEventListener(type, fn) {
      (this.listeners[type] ||= []).push(fn);
      if (type === "open") fn();
    }

    send(text) {
      const envelope = JSON.parse(text);
      this.sent.push(envelope);
      queueMicrotask(() => {
        for (const fn of this.listeners.message || []) {
          fn({ data: JSON.stringify({ id: envelope.id, result: {} }) });
        }
      });
    }

    close() {
      for (const fn of this.listeners.close || []) fn();
    }
  }
  const { gate } = await openGuardedBrowser((options) => {
    assert.equal(options.headless, true);
    assert.equal(options.args.length, 2);
    return browser;
  }, {
    fetch: async (url) => {
      const port = new URL(url).port;
      return {
        ok: true,
        text: async () => JSON.stringify({
          Browser: "Chrome/test",
          webSocketDebuggerUrl: `ws://127.0.0.1:${port}/devtools/browser/local-id`,
        }),
      };
    },
    WebSocket: Socket,
  });
  assert.equal(browser.closes, 0);
  socket.close();
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(gate.compromised(), "disconnected");
  assert.equal(browser.contextsClosed, 1);
  assert.equal(browser.closes, 1);
  assert.equal(socket.sent.some((entry) => entry.method === "Target.closeTarget"), false);
  socket.close();
  for (const fn of socket.listeners.error || []) fn();
  await new Promise((resolve) => setTimeout(resolve, 10));
  assert.equal(browser.closes, 1);

  const errorBrowser = {
    closes: 0,
    contexts() {
      return [];
    },
    async close() {
      errorBrowser.closes += 1;
    },
  };
  let errorSocket;
  class ErrorSocket extends Socket {
    constructor(url) {
      super(url);
      errorSocket = this;
    }
  }
  const opened = await openGuardedBrowser(() => errorBrowser, {
    fetch: async (url) => {
      const port = new URL(url).port;
      return {
        ok: true,
        text: async () => JSON.stringify({
          Browser: "Chrome/test",
          webSocketDebuggerUrl: `ws://127.0.0.1:${port}/devtools/browser/local-id`,
        }),
      };
    },
    WebSocket: ErrorSocket,
  });
  for (const fn of errorSocket.listeners.error || []) fn();
  await new Promise((resolve) => setTimeout(resolve, 30));
  assert.equal(opened.gate.compromised(), "disconnected");
  assert.equal(errorBrowser.closes, 1);
  opened.gate.beginShutdown();
  opened.gate.close();
  assert.equal(errorBrowser.closes, 1);
  gate.beginShutdown();
  gate.close();
});

test("the debugger endpoint stays on the reserved loopback port", async () => {
  const port = await reserveLoopbackDebuggerPort();
  assert.equal(Number.isInteger(port), true);
  assert.ok(port > 0 && port < 65536);
  const endpoint = debuggerWebSocketUrl(port, {
    Browser: "Chrome/test",
    webSocketDebuggerUrl: `ws://127.0.0.1:${port}/devtools/browser/local-id`,
  });
  assert.equal(endpoint, `ws://127.0.0.1:${port}/devtools/browser/local-id`);
  assert.throws(
    () => debuggerWebSocketUrl(port, { Browser: "Chrome/test", webSocketDebuggerUrl: "ws://evil.example/devtools/browser/x" }),
    /network-guard/,
  );
  assert.throws(
    () => debuggerWebSocketUrl(port, {
      Browser: "Chrome/test",
      webSocketDebuggerUrl: `ws://user:secret@127.0.0.1:${port}/devtools/browser/local-id`,
    }),
    (error) => error instanceof LiveUiError && error.code === "network-guard" && !String(error.message).includes("secret"),
  );
  let constructed = false;
  await assert.rejects(
    connectFlatDebugger(port, {
      fetch: async (url) => {
        assert.equal(url, `http://127.0.0.1:${port}/json/version`);
        return {
          ok: true,
          json: async () => ({ Browser: "Chrome/test", webSocketDebuggerUrl: "ws://evil.example/devtools/browser/x" }),
        };
      },
      WebSocket: class {
        constructor() {
          constructed = true;
        }
      },
    }),
    (error) => error instanceof LiveUiError && error.message === "network-guard" && !String(error).includes("evil"),
  );
  assert.equal(constructed, false);
  await assert.rejects(
    connectFlatDebugger(port, {
      fetch: async () => {
        throw new Error("ws://127.0.0.1/devtools/browser/secret-token");
      },
      WebSocket: class {
        constructor() {
          constructed = true;
        }
      },
    }),
    (error) => error instanceof LiveUiError && error.message === "network-guard" && !error.message.includes("secret-token"),
  );
  assert.equal(constructed, false);
});

function frameRequest({ url, method = "GET", resourceType = "document", frame, throwFrame = false }) {
  return {
    url: () => url,
    method: () => method,
    resourceType: () => resourceType,
    frame() {
      if (throwFrame) throw new Error("Frame for this navigation request is not available");
      return frame;
    },
    headers: () => ({ "sec-fetch-dest": "" }),
    async allHeaders() {
      throw new Error("destination metadata is not a control");
    },
  };
}

test("only the primary main frame can pass the route, and worker scripts use ordinary request policy", async () => {
  const main = { id: "main" };
  const page = { mainFrame: () => main };
  const policy = { secrets: ["synthetic-only-secret"] };
  const allowed = "https://pharos.barta.cm/pharos/hosts";
  const primaryGet = primaryFrameDecision(frameRequest({ url: allowed, frame: main }), page, policy);
  assert.equal(primaryGet.allow, true);
  assert.equal(primaryGet.reason, "app-read");
  const workerScript = primaryFrameDecision(
    frameRequest({ url: `${allowed}/worker.js`, resourceType: "script", frame: main }),
    page,
    policy,
  );
  assert.equal(workerScript.allow, true);
  assert.equal(workerScript.reason, "app-read");
  const child = primaryFrameDecision(
    frameRequest({ url: allowed, frame: { id: "child" } }),
    page,
    policy,
  );
  assert.equal(child.allow, false);
  assert.equal(child.reason, "isolated-target");
  const thrown = primaryFrameDecision(frameRequest({ url: allowed, throwFrame: true }), page, policy);
  assert.equal(thrown.allow, false);
  assert.equal(thrown.reason, "isolated-target");
  const unbound = primaryFrameDecision(frameRequest({ url: allowed, frame: main }), null, policy);
  assert.equal(unbound.allow, false);
  const mutation = primaryFrameDecision(
    frameRequest({ url: "https://pharos.barta.cm/pharos/agora/requests/host-preferences.json", method: "POST", frame: main }),
    page,
    policy,
  );
  assert.equal(mutation.allow, false);
  assert.equal(mutation.reason, "app-mutation");
  const leaked = primaryFrameDecision(
    frameRequest({ url: "https://pharos.barta.cm/pharos/pre-synthetic-only-secret-post", frame: main }),
    page,
    policy,
  );
  assert.equal(leaked.allow, false);
  assert.equal(leaked.reason, "secret-in-url");
  assert.equal(leaked.path, "path-category");
  assert.equal(JSON.stringify(leaked).includes("synthetic-only-secret"), false);

  const notes = [];
  const actions = [];
  const pageRef = { page: null };
  const gate = { compromised: () => "" };
  await installPrimaryFrameRoute({
    async route(_pattern, handler) {
      pageRef.handler = handler;
    },
  }, pageRef, policy, (verdict) => notes.push(verdict), gate);
  pageRef.page = page;
  await pageRef.handler({
    request: () => frameRequest({ url: allowed, frame: { id: "popup" }, throwFrame: true }),
    abort: async (reason) => actions.push(["abort", reason]),
    continue: async () => actions.push(["continue"]),
  });
  await pageRef.handler({
    request: () => frameRequest({ url: `${allowed}/worker.js`, resourceType: "script", frame: main }),
    abort: async (reason) => actions.push(["abort", reason]),
    continue: async () => actions.push(["continue"]),
  });
  await pageRef.handler({
    request: () => frameRequest({
      url: "https://pharos.barta.cm/pharos/agora/requests/host-preferences.json",
      method: "POST",
      frame: main,
    }),
    abort: async (reason) => actions.push(["abort", reason]),
    continue: async () => actions.push(["continue"]),
  });
  assert.deepEqual(actions, [
    ["abort", "blockedbyclient"],
    ["continue"],
    ["abort", "blockedbyclient"],
  ]);
  assert.equal(notes.some((item) => item.reason === "isolated-target"), true);
  assert.equal(notes.some((item) => item.reason === "app-mutation"), true);
  assert.equal(JSON.stringify(notes).includes("pharos.agm.ng"), false);
  gate.compromised = () => "disconnected";
  await pageRef.handler({
    request: () => frameRequest({ url: allowed, frame: main }),
    abort: async (reason) => actions.push(["abort", reason]),
    continue: async () => actions.push(["continue"]),
  });
  assert.deepEqual(actions.at(-1), ["abort", "blockedbyclient"]);
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
