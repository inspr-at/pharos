import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import {
  ISSUER_LOGIN_POST_PATHS,
  PERSONAL_ISSUER_ORIGIN,
  assertCommandArgv,
  assertRuntimeEnvironment,
  classifyProbeSurface,
  decideFetchPause,
  decideRedirect,
  decideRequest,
  primaryFrameDecision,
  repoRootFromScripts,
  SCREENSHOT_FIELD_LIMIT,
  SCREENSHOT_TEXT_LIMIT,
  SCREENSHOT_VALUE_LIMIT,
  collectScreenshotSurface,
  screenshotPermitted,
  settleFetchPause,
  takeAuthenticatedShot,
} from "../scripts/live-ui-guard.mjs";
import { submitUnattendedTotp } from "../scripts/live-ui.mjs";
import {
  MFA_TYPE_TOTP,
  TOTP_SECRET_FILE_ENV,
  TOTP_VERIFY_PATH,
  TOTP_VERIFY_URL,
  armTotpGrant,
  clearTotpCodeField,
  decodeBase32,
  decodeTotpPostData,
  freshTotpCode,
  inspectTotpForm,
  isExactTotpPost,
  loadOptionalTotpSecret,
  loadTotpSecretFile,
  publicTotpInspection,
  revokeTotpGrant,
  totpCode,
  totpSecretFileFromEnv,
} from "../scripts/live-ui-totp.mjs";

const REPO_ROOT = repoRootFromScripts();
const RFC_SECRET = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const CSRF = "csrf-synthetic-token";
const AUTH = "auth-synthetic-id";
const OTP_PATH = "https://auth.inspr.at/ui/login/mfa/otp/verify";

function leaks(value, parts) {
  const blob = typeof value === "string" ? value : JSON.stringify(value);
  return parts.some((part) => part && blob.includes(part));
}

function privateDir() {
  const root = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-totp-"));
  const dir = path.join(root, "owned");
  fs.mkdirSync(dir, { mode: 0o700 });
  fs.chmodSync(dir, 0o700);
  return dir;
}

function writeSecret(dir, name, text, mode = 0o600) {
  const file = path.join(dir, name);
  fs.writeFileSync(file, text, { mode });
  fs.chmodSync(file, mode);
  return file;
}

function element(tag, attrs = {}, children = []) {
  const node = {
    tagName: tag.toUpperCase(),
    attrs: { ...attrs },
    children,
    value: Object.prototype.hasOwnProperty.call(attrs, "value") ? String(attrs.value) : "",
    getAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attrs, name) ? String(this.attrs[name]) : null;
    },
    hasAttribute(name) {
      return Object.prototype.hasOwnProperty.call(this.attrs, name);
    },
    setAttribute(name, value) {
      this.attrs[name] = String(value);
      if (name === "value") this.value = String(value);
    },
    getClientRects() {
      return this.attrs.type === "hidden" || Object.prototype.hasOwnProperty.call(this.attrs, "hidden") ? [] : [1];
    },
    querySelectorAll(selector) {
      return queryAll(this, selector);
    },
  };
  return node;
}

function queryAll(node, selector) {
  const found = [];
  const visit = (current) => {
    for (const child of current.children || []) {
      if (child.tagName === selector.toUpperCase()) found.push(child);
      visit(child);
    }
  };
  visit(node);
  return found;
}

function totpDocument(options = {}) {
  const inputs = options.inputs || [
    element("input", { type: "hidden", name: "gorilla.csrf.Token", value: CSRF }),
    element("input", { type: "hidden", name: "authRequestID", value: AUTH }),
    element("input", { type: "hidden", name: "mfaType", value: options.mfaType || "0" }),
    element("input", {
      type: "text",
      id: "code",
      name: "code",
      autocomplete: "off",
      required: "true",
      value: options.codeValue || "",
    }),
  ];
  const buttons = options.buttons || [
    element("button", { id: "submit-button", type: "submit" }),
    element("button", { type: "submit", name: "provider", value: "1" }),
  ];
  const form = element("form", {
    method: options.method || "POST",
    action: options.action || TOTP_VERIFY_PATH,
  }, [...inputs, ...buttons]);
  const view = {};
  view.top = options.frame ? {} : view;
  return {
    location: {
      origin: options.origin || PERSONAL_ISSUER_ORIGIN,
      href: options.href || `${PERSONAL_ISSUER_ORIGIN}/ui/login/password`,
    },
    defaultView: options.defaultView === null ? undefined : view,
    forms: [form],
    querySelectorAll(selector) {
      return queryAll({ children: [form] }, selector);
    },
  };
}

function verifyBody(code, { mfaType = "0", provider = false, csrf = CSRF, auth = AUTH } = {}) {
  const params = new URLSearchParams();
  params.set("gorilla.csrf.Token", csrf);
  params.set("authRequestID", auth);
  params.set("mfaType", mfaType);
  params.set("code", code);
  if (provider) params.set("provider", "1");
  return params.toString();
}

function grantFor(code, secrets = []) {
  return {
    secrets: [...secrets, code],
    totpGrant: armTotpGrant({ code, authRequestId: AUTH, csrf: CSRF, now: () => 1_000_000 }),
  };
}

function mainPage() {
  const frame = { id: "main" };
  return { frame, page: { mainFrame: () => frame } };
}

test("RFC 6238 SHA1 vectors and strict seeds", () => {
  const key = decodeBase32(RFC_SECRET);
  assert.equal(key.toString("utf8"), "12345678901234567890");
  const vectors = [
    [59, "287082"],
    [1111111109, "081804"],
    [1111111111, "050471"],
    [1234567890, "005924"],
    [2000000000, "279037"],
    [20000000000, "353130"],
  ];
  for (const [seconds, code] of vectors) {
    assert.equal(totpCode(key, seconds * 1000), code);
  }
  assert.equal(MFA_TYPE_TOTP, "0");
  assert.throws(() => decodeBase32(RFC_SECRET.toLowerCase()), (error) => error.code === "totp-secret");
  assert.throws(() => decodeBase32(`otpauth://totp/Example?secret=${RFC_SECRET}`), (error) => {
    assert.equal(error.code, "totp-uri");
    assert.equal(error.message.includes(RFC_SECRET), false);
    assert.equal(error.message.includes("otpauth://"), false);
    return true;
  });
  assert.throws(() => decodeBase32("AAAA"), (error) => error.code === "totp-secret");
  assert.throws(() => decodeBase32(`${RFC_SECRET.slice(0, 8)}0${RFC_SECRET.slice(9)}`), (error) => error.code === "totp-secret");
  assert.throws(() => decodeBase32(`${RFC_SECRET}=`), (error) => error.code === "totp-secret");
  assert.throws(() => decodeBase32(`GEZDGN=VGY3TQOJQGEZDGNBVGY3TQOJQ`), (error) => error.code === "totp-secret");
  const padded = "GEZDGNBVGY3TQOJQGEZDGNBVGY======";
  assert.equal(decodeBase32(padded).length > 0, true);
  assert.throws(() => totpCode(Buffer.alloc(0), 0), (error) => error.code === "totp-secret");
});

test("near-expiry waits once into the next step and does not wait early", async () => {
  const key = decodeBase32(RFC_SECRET);
  const waits = [];
  const current = totpCode(key, 10_000);
  const early = await freshTotpCode(key, 10_000, (ms) => {
    waits.push(ms);
  });
  assert.equal(early, current);
  assert.deepEqual(waits, []);

  const boundary = 29_950;
  const before = totpCode(key, boundary);
  const after = totpCode(key, 30_000);
  assert.notEqual(before, after);
  const stepped = await freshTotpCode(key, boundary, (ms) => {
    waits.push(ms);
  });
  assert.equal(stepped, after);
  assert.deepEqual(waits, [50]);

  const started = Date.now();
  const waited = await freshTotpCode(key, 29_950);
  assert.equal(waited, after);
  assert.ok(Date.now() - started >= 40);
  assert.equal(leaks(waited, [RFC_SECRET]), false);
});

test("secret files accept one owned base32 file and reject unsafe input", () => {
  const dir = privateDir();
  const sibling = path.join(dir, "keep.txt");
  fs.writeFileSync(sibling, "keep\n", { mode: 0o600 });
  const file = writeSecret(dir, "seed", `${RFC_SECRET}\n`);
  const before = fs.readFileSync(file);
  const loaded = loadTotpSecretFile(file, REPO_ROOT);
  assert.equal(loaded.bytes.toString("utf8"), "12345678901234567890");
  assert.equal(loaded.redaction, RFC_SECRET);
  assert.equal(fs.readFileSync(file).equals(before), true);
  assert.equal(fs.readFileSync(sibling, "utf8"), "keep\n");
  loaded.bytes.fill(0);
  assert.equal(loaded.bytes.every((byte) => byte === 0), true);
  assert.equal(fs.existsSync(file), true);

  fs.chmodSync(file, 0o644);
  assert.throws(() => loadTotpSecretFile(file, REPO_ROOT), (error) => error.code === "totp-file-mode");
  fs.chmodSync(file, 0o600);
  fs.chmodSync(dir, 0o755);
  assert.throws(() => loadTotpSecretFile(file, REPO_ROOT), (error) => error.code === "totp-file-parent");
  fs.chmodSync(dir, 0o700);
  const link = path.join(dir, "linked");
  fs.symlinkSync(file, link);
  assert.throws(() => loadTotpSecretFile(link, REPO_ROOT), (error) => error.code === "totp-file-symlink");
  assert.equal(fs.readFileSync(file).equals(before), true);

  const uri = writeSecret(dir, "uri", `otpauth://totp/Example?secret=${RFC_SECRET}\n`);
  assert.throws(() => loadTotpSecretFile(uri, REPO_ROOT), (error) => {
    assert.equal(error.code, "totp-uri");
    assert.equal(error.message.includes(RFC_SECRET), false);
    return true;
  });
  const messy = writeSecret(dir, "messy", `${RFC_SECRET}\nsecond\n`);
  assert.throws(() => loadTotpSecretFile(messy, REPO_ROOT), (error) => error.code === "totp-file-multiline");
  assert.equal(loadOptionalTotpSecret({}, REPO_ROOT), null);
  assert.throws(() => totpSecretFileFromEnv({ [TOTP_SECRET_FILE_ENV]: RFC_SECRET }), (error) => error.code === "totp-file-path");
  assert.throws(() => totpSecretFileFromEnv({ [TOTP_SECRET_FILE_ENV]: "135790" }), (error) => error.code === "totp-uri");
  assert.throws(
    () => totpSecretFileFromEnv({ [TOTP_SECRET_FILE_ENV]: `otpauth://totp/Example?secret=${RFC_SECRET}` }),
    (error) => error.code === "totp-uri" && !error.message.includes(RFC_SECRET),
  );
  assert.equal(totpSecretFileFromEnv({ [TOTP_SECRET_FILE_ENV]: file }), file);

  const repoDir = fs.mkdtempSync(path.join(REPO_ROOT, ".totp-file-test-"));
  const inside = path.join(repoDir, "seed");
  try {
    fs.chmodSync(repoDir, 0o700);
    writeSecret(repoDir, "seed", `${RFC_SECRET}\n`);
    assert.throws(() => loadTotpSecretFile(inside, REPO_ROOT), (error) => error.code === "totp-file-repo");
    assert.equal(fs.readFileSync(inside, "utf8").includes(RFC_SECRET), true);
  } finally {
    if (fs.existsSync(inside)) fs.unlinkSync(inside);
    fs.rmdirSync(repoDir);
  }
});

test("runtime input accepts only a secret path and the login commands", () => {
  assert.doesNotThrow(() => assertRuntimeEnvironment({ [TOTP_SECRET_FILE_ENV]: "/tmp/pharos-totp-seed", PATH: "/usr/bin" }));
  assert.throws(() => assertRuntimeEnvironment({ PHAROS_LIVE_UI_TOTP: "135790" }), /runtime-env/);
  assert.throws(() => assertRuntimeEnvironment({ PHAROS_LIVE_UI_TOTP_SECRET: RFC_SECRET }), /runtime-env/);
  assert.throws(() => assertRuntimeEnvironment({ PHAROS_LIVE_UI_TOTP_SEED: RFC_SECRET }), /runtime-env/);
  assert.throws(() => assertRuntimeEnvironment({ TOTP_SECRET: RFC_SECRET }), /runtime-env/);
  assert.equal(assertCommandArgv(["node", "scripts/live-ui.mjs", "inventory"]), "inventory");
  assert.throws(() => assertCommandArgv(["node", "scripts/live-ui.mjs", "135790"]), /argv/);
  assert.throws(() => assertCommandArgv(["node", "scripts/live-ui.mjs", "inventory", RFC_SECRET]), /argv/);
  assert.throws(() => assertCommandArgv(["node", "scripts/live-ui.mjs", "otpauth://totp/example"]), /argv/);
});

test("the TOTP form is structural and generic MFA text is not that form", () => {
  const form = totpDocument();
  const inspected = inspectTotpForm(form);
  const pub = publicTotpInspection(inspected);
  assert.equal(pub.ok, true);
  assert.equal(pub.actionPath, TOTP_VERIFY_PATH);
  assert.equal(pub.mfaType, "0");
  assert.equal(pub.unnamedSubmit, true);
  assert.equal(pub.providerControls, 1);
  assert.equal(leaks(pub, [CSRF, AUTH, RFC_SECRET]), false);
  assert.equal(clearTotpCodeField(form), true);
  form.forms[0].children.find((child) => child.attrs.id === "code").value = "081804";
  assert.equal(clearTotpCodeField(form), true);
  assert.equal(form.forms[0].children.find((child) => child.attrs.id === "code").value, "");

  const cases = [
    totpDocument({ origin: "https://auth.example" }),
    totpDocument({ frame: true }),
    totpDocument({ action: "/ui/login/mfa/otp/verify" }),
    totpDocument({ action: `${TOTP_VERIFY_PATH}?code=081804` }),
    totpDocument({ mfaType: "1" }),
    totpDocument({ mfaType: "4" }),
    totpDocument({ codeValue: "081804" }),
    totpDocument({
      buttons: [element("button", { id: "submit-button", type: "submit", name: "provider", value: "1" })],
    }),
    totpDocument({
      inputs: [
        element("input", { type: "hidden", name: "gorilla.csrf.Token", value: CSRF }),
        element("input", { type: "hidden", name: "authRequestID", value: AUTH }),
        element("input", { type: "hidden", name: "mfaType", value: "0" }),
        element("input", { type: "password", name: "password" }),
        element("input", { type: "text", id: "code", name: "code", autocomplete: "off" }),
      ],
    }),
    {
      location: { origin: PERSONAL_ISSUER_ORIGIN, href: `${PERSONAL_ISSUER_ORIGIN}/ui/login/mfa/prompt` },
      defaultView: { top: null },
      querySelectorAll() {
        return [];
      },
    },
  ];
  cases[cases.length - 1].defaultView.top = cases[cases.length - 1].defaultView;
  for (const doc of cases) {
    const failed = inspectTotpForm(doc);
    assert.equal(failed.ok, false);
    assert.equal(leaks(publicTotpInspection(failed), [CSRF, AUTH, "081804"]), false);
  }
  const copyOnly = classifyProbeSurface({ otpField: false, webauthnChallenge: true, accountSetup: false });
  assert.equal(copyOnly.mfa, true);
  assert.equal(copyOnly.codeField, false);
  const codeProbe = classifyProbeSurface({ otpField: true });
  assert.equal(codeProbe.codeField, true);
  assert.equal(codeProbe.mfa, true);
});

test("both layers allow one exact verify POST and then fail closed", async () => {
  const code = "081804";
  const policy = grantFor(code, [RFC_SECRET, "fixture-password"]);
  const post = verifyBody(code);
  assert.equal(isExactTotpPost("POST", TOTP_VERIFY_URL), true);
  assert.equal(decideRequest({ method: "POST", url: TOTP_VERIFY_URL, postData: post }, policy).allow, false);
  assert.deepEqual(ISSUER_LOGIN_POST_PATHS, ["/ui/login/loginname", "/ui/login/password"]);
  assert.equal(decideRequest({ method: "GET", url: TOTP_VERIFY_URL }, policy).reason, "issuer-read");
  assert.equal(decideRequest({ method: "POST", url: OTP_PATH }, policy).allow, false);
  assert.equal(decideRedirect({ method: "POST", url: TOTP_VERIFY_URL, postData: post }, policy).allow, false);
  const password = decideRequest({ method: "POST", url: "https://auth.inspr.at/ui/login/password" }, policy);
  assert.equal(password.allow, true);
  assert.equal(policy.totpGrant.uses.primary, 0);
  assert.equal(policy.totpGrant.uses.fetch, 0);

  const { frame, page } = mainPage();
  const primary = primaryFrameDecision({
    url: () => TOTP_VERIFY_URL,
    method: () => "POST",
    resourceType: () => "document",
    postData: () => post,
    redirectedFrom: () => null,
    frame: () => frame,
  }, page, policy);
  const fetched = decideFetchPause({
    requestId: "totp-1",
    resourceType: "Document",
    request: { method: "POST", url: TOTP_VERIFY_URL, postData: post },
  }, policy);
  assert.equal(primary.allow, true);
  assert.equal(primary.reason, "issuer-login");
  assert.equal(fetched.action, "continue");
  assert.equal(fetched.verdict.allow, true);
  assert.equal(policy.totpGrant.uses.primary, 1);
  assert.equal(policy.totpGrant.uses.fetch, 1);
  assert.equal(leaks(primary, [code, RFC_SECRET, CSRF, AUTH]), false);
  assert.equal(leaks(fetched.verdict, [code, RFC_SECRET, CSRF, AUTH]), false);

  const session = {
    calls: [],
    async send(method, params) {
      this.calls.push({ method, params });
    },
  };
  assert.equal(await settleFetchPause(session, {
    requestId: "totp-1",
    request: { method: "POST", url: TOTP_VERIFY_URL, postData: post },
  }, policy, () => {}), "failed");
  assert.equal(session.calls[0].method, "Fetch.failRequest");
  assert.equal(leaks(session.calls, [code, RFC_SECRET, CSRF, AUTH]), false);
  assert.equal(policy.totpGrant.revoked, true);

  const encoded = Buffer.from(post).toString("base64");
  const fresh = grantFor(code, [RFC_SECRET]);
  const fromEntries = decideFetchPause({
    requestId: "totp-bytes",
    request: { method: "POST", url: TOTP_VERIFY_URL, postDataEntries: [{ bytes: encoded }] },
  }, fresh);
  assert.equal(fromEntries.action, "continue");
  assert.equal(decodeTotpPostData({ postDataEntries: [{ bytes: encoded }] }), post);
  assert.equal(leaks(fromEntries.verdict, [code, RFC_SECRET]), false);
});

test("retry, redirect, mutation, leakage, expiry, and guard loss deny the verify POST", () => {
  const code = "081804";
  const secrets = [RFC_SECRET, "fixture-password"];
  const { frame, page } = mainPage();
  const requestFor = (url, postData, redirected = false, target = frame) => ({
    url: () => url,
    method: () => "POST",
    resourceType: () => "document",
    postData: () => postData,
    redirectedFrom: () => (redirected ? { url: "https://auth.inspr.at/ui/login/password" } : null),
    frame: () => target,
  });
  const deny = (policy, url, postData, event = {}) => {
    const verdict = decideFetchPause({
      requestId: "totp",
      ...event,
      request: { method: "POST", url, postData },
    }, policy);
    assert.equal(verdict.action, "fail");
    assert.equal(leaks(verdict, [code, RFC_SECRET, CSRF, AUTH, "fixture-password"]), false);
    return verdict;
  };

  const retry = grantFor(code, secrets);
  const post = verifyBody(code);
  assert.equal(primaryFrameDecision(requestFor(TOTP_VERIFY_URL, post), page, retry).allow, true);
  assert.equal(primaryFrameDecision(requestFor(TOTP_VERIFY_URL, post), page, retry).allow, false);
  assert.equal(retry.totpGrant.revoked, true);

  const redirected = grantFor(code, secrets);
  deny(redirected, TOTP_VERIFY_URL, post, { redirectedRequestId: "password-post" });
  assert.equal(redirected.totpGrant.revoked, true);
  deny(redirected, TOTP_VERIFY_URL, post);

  const provider = grantFor(code, secrets);
  deny(provider, TOTP_VERIFY_URL, verifyBody(code, { provider: true }));
  assert.equal(provider.totpGrant.revoked, true);

  const factor = grantFor(code, secrets);
  deny(factor, TOTP_VERIFY_URL, verifyBody(code, { mfaType: "3" }));
  deny(factor, OTP_PATH, post);
  assert.equal(decideRequest({
    method: "POST",
    url: "https://pharos.barta.cm/pharos/agora/requests/host-preferences.json",
  }, factor).allow, false);

  const leakedCode = grantFor(code, secrets);
  const coded = decideRequest({
    method: "POST",
    url: `${TOTP_VERIFY_URL}?code=${code}`,
    postData: post,
  }, leakedCode);
  assert.equal(coded.allow, false);
  assert.equal(coded.reason, "secret-in-url");
  assert.equal(leaks(coded, [code, RFC_SECRET]), false);
  const fetchedLeak = decideFetchPause({
    requestId: "leak",
    request: { method: "POST", url: `${TOTP_VERIFY_URL}?code=${code}`, postData: post },
  }, leakedCode);
  assert.equal(fetchedLeak.action, "fail");
  assert.equal(leakedCode.totpGrant.revoked, true);

  const leakedSeed = grantFor(code, secrets);
  const seeded = decideRequest({
    method: "GET",
    url: `https://pharos.barta.cm/pharos/?q=${RFC_SECRET}`,
  }, leakedSeed);
  assert.equal(seeded.reason, "secret-in-url");
  assert.equal(leaks(seeded, [RFC_SECRET, code]), false);

  const wrong = grantFor(code, secrets);
  deny(wrong, TOTP_VERIFY_URL, verifyBody("000000"));
  assert.equal(wrong.totpGrant.revoked, true);

  const stale = grantFor(code, secrets);
  stale.totpGrant.expiresAt = stale.totpGrant.now() - 1;
  deny(stale, TOTP_VERIFY_URL, post);
  assert.equal(stale.totpGrant.revoked, true);

  const lost = grantFor(code, secrets);
  lost.gate = { compromised: () => "disconnected" };
  const paused = decideFetchPause({
    requestId: "lost",
    request: { method: "POST", url: TOTP_VERIFY_URL, postData: post },
  }, lost);
  assert.equal(paused.action, "fail");
  assert.equal(paused.verdict.reason, "network-guard");
  assert.equal(lost.totpGrant.revoked, true);

  const isolated = grantFor(code, secrets);
  const child = primaryFrameDecision(requestFor(TOTP_VERIFY_URL, post, false, { id: "child" }), page, isolated);
  assert.equal(child.allow, false);
  assert.equal(child.reason, "isolated-target");
  assert.equal(isolated.totpGrant.revoked, true);
  revokeTotpGrant(isolated.totpGrant);
  assert.equal(isolated.totpGrant.code, "");
  assert.equal(isolated.totpGrant.csrf, "");
  assert.equal(isolated.totpGrant.authRequestId, "");
});

test("screenshots reject a code form and the runner does not prompt or send the seed", async () => {
  const app = { origin: "https://flow.inspr.at", pathname: "/pharos/map" };
  const ready = { appShell: true, managerShell: true, passwordCount: 0, mfa: false, loginForm: false };
  assert.equal(screenshotPermitted({
    classification: "authenticated",
    location: app,
    probe: { ...ready, codeField: true },
  }), false);
  assert.equal(screenshotPermitted({
    classification: "mfa-required",
    location: { origin: PERSONAL_ISSUER_ORIGIN, pathname: TOTP_VERIFY_PATH },
    probe: { ...ready, mfa: true, codeField: true },
  }), false);

  const doc = totpDocument();
  const fills = [];
  const clicks = [];
  const key = decodeBase32(RFC_SECRET);
  const policy = {
    secrets: ["person@example.test", "fixture-password", RFC_SECRET],
    totp: { bytes: Buffer.from(key), redaction: RFC_SECRET },
    totpGrant: null,
    totpAttempted: false,
    gate: { compromised: () => "" },
  };
  const page = {
    async evaluate(fn) {
      return fn(doc);
    },
    locator(selector) {
      return {
        async count() {
          return selector.includes("provider") ? 0 : 1;
        },
        async fill(value) {
          fills.push(value);
          const field = doc.forms[0].children.find((child) => child.attrs.id === "code");
          field.value = value;
        },
        async click() {
          clicks.push(selector);
        },
        async evaluate(fn) {
          return fn(element("button", { id: "submit-button", type: "submit" }));
        },
      };
    },
  };
  const result = await submitUnattendedTotp(page, policy, { now: 1111111111 * 1000, sleep: async () => {} });
  assert.equal(result, "submitted");
  assert.deepEqual(fills, ["050471"]);
  assert.deepEqual(clicks, ["button#submit-button"]);
  assert.equal(fills.includes(RFC_SECRET), false);
  assert.equal(policy.totp.bytes.every((byte) => byte === 0), true);
  assert.equal(policy.secrets.includes("050471"), true);
  assert.equal(policy.totpGrant.uses.primary, 0);
  const codeField = doc.forms[0].children.find((child) => child.attrs.id === "code");
  assert.equal(codeField.value, "");
  assert.equal(await submitUnattendedTotp(page, policy, { now: 1111111111 * 1000, sleep: async () => {} }), "mfa-required");
  assert.deepEqual(fills, ["050471"]);

  const other = {
    secrets: ["person@example.test", "fixture-password"],
    totp: { bytes: decodeBase32(RFC_SECRET) },
    totpAttempted: false,
    gate: { compromised: () => "" },
  };
  const skipped = [];
  const plain = {
    async evaluate() {
      return { ok: false, reason: "totp-form" };
    },
    locator() {
      return {
        async fill(value) {
          skipped.push(value);
        },
      };
    },
  };
  assert.equal(await submitUnattendedTotp(plain, other, { now: 10_000 }), "mfa-required");
  assert.deepEqual(skipped, []);
  assert.equal(other.totp.bytes.toString("utf8"), "12345678901234567890");

  const runner = fs.readFileSync(new URL("../scripts/live-ui.mjs", import.meta.url), "utf8");
  const totp = fs.readFileSync(new URL("../scripts/live-ui-totp.mjs", import.meta.url), "utf8");
  const guard = fs.readFileSync(new URL("../scripts/live-ui-guard.mjs", import.meta.url), "utf8");
  for (const source of [runner, totp, guard]) {
    assert.equal(source.includes("1password"), false);
    assert.equal(source.includes("1Password"), false);
    assert.equal(source.includes("setRawMode"), false);
    assert.equal(source.includes("question("), false);
  }
  assert.equal(runner.includes("createServer"), false);
  assert.equal(totp.includes("createServer"), false);
  assert.equal(runner.includes("submitUnattendedTotp"), true);
  assert.equal(runner.includes("loadOptionalTotpSecret"), true);
  assert.equal(runner.includes("otpauth://"), false);
  assert.equal(guard.includes("ISSUER_LOGIN_POST_PATHS.push"), false);
  assert.equal(ISSUER_LOGIN_POST_PATHS.includes(TOTP_VERIFY_PATH), false);
});

test("screenshot secrets are compared in Node and never sent to the page", async () => {
  const password = "Ab!cdEF12";
  const seed = "synthetic-seed-value";
  const code = "135790";
  const username = "person@example.test";
  const secrets = [username, password, seed, code];
  const calls = [];
  const shots = [];
  const previous = globalThis.document;
  const clean = {
    title: "Fleet",
    body: { innerText: "hosts", textContent: "hosts" },
    querySelectorAll() {
      return [{ value: "ok" }];
    },
  };
  const page = {
    async evaluate(fn, ...args) {
      calls.push({ source: String(fn), args });
      return fn(...args);
    },
    async screenshot() {
      shots.push("screenshot");
    },
  };
  const shot = (document) => {
    calls.length = 0;
    shots.length = 0;
    globalThis.document = document;
    return takeAuthenticatedShot(page, {
      permitted: true,
      password,
      material: [seed, code],
      options: { path: "shot.png", type: "png" },
    });
  };
  const argsAreClean = () => {
    assert.ok(calls.length >= 1);
    for (const call of calls) {
      assert.deepEqual(call.args, []);
      for (const secret of secrets) assert.equal(call.source.includes(secret), false);
    }
  };
  try {
    const collector = collectScreenshotSurface.toString();
    assert.equal(collector.includes(String(SCREENSHOT_TEXT_LIMIT)), true);
    assert.equal(collector.includes(String(SCREENSHOT_FIELD_LIMIT)), true);
    assert.equal(collector.includes(String(SCREENSHOT_VALUE_LIMIT)), true);
    assert.equal(/evaluate\([^)]+,/.test(takeAuthenticatedShot.toString()), false);

    assert.equal(await shot(clean), true);
    argsAreClean();
    assert.deepEqual(shots, ["screenshot"]);

    assert.equal(await shot({
      title: "Fleet",
      body: { innerText: `shown ${seed}`, textContent: "hosts" },
      querySelectorAll() {
        return [];
      },
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);

    assert.equal(await shot({
      title: "Fleet",
      body: { innerText: "hosts", textContent: "hosts" },
      querySelectorAll() {
        return [{ value: code }];
      },
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);

    assert.equal(await shot({
      title: "",
      body: { innerText: `Account ${password} shown`, textContent: "hidden label" },
      querySelectorAll() {
        return [];
      },
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);

    const returned = {
      async evaluate(fn, ...args) {
        calls.push({ source: String(fn), args });
        return { values: [], visible: `Fleet ${seed}` };
      },
      async screenshot() {
        shots.push("screenshot");
      },
    };
    calls.length = 0;
    shots.length = 0;
    assert.equal(await takeAuthenticatedShot(returned, {
      permitted: true,
      password,
      material: [seed, code],
      options: {},
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);

    calls.length = 0;
    shots.length = 0;
    globalThis.document = undefined;
    assert.equal(await takeAuthenticatedShot(page, {
      permitted: true,
      password,
      material: [seed, code],
      options: {},
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);

    calls.length = 0;
    shots.length = 0;
    assert.equal(await shot({
      title: "x".repeat(SCREENSHOT_TEXT_LIMIT),
      body: { innerText: "", textContent: "" },
      querySelectorAll() {
        return [];
      },
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);

    calls.length = 0;
    shots.length = 0;
    assert.equal(await shot({
      title: "Fleet",
      body: { innerText: "hosts", textContent: "hosts" },
      querySelectorAll() {
        return [{ value: "v".repeat(SCREENSHOT_VALUE_LIMIT + 1) }];
      },
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);

    const broken = {
      async evaluate(fn, ...args) {
        calls.push({ source: String(fn), args });
        throw new Error("probe");
      },
      async screenshot() {
        shots.push("screenshot");
      },
    };
    calls.length = 0;
    shots.length = 0;
    assert.equal(await takeAuthenticatedShot(broken, {
      permitted: true,
      password,
      material: [seed, code],
      options: {},
    }), false);
    argsAreClean();
    assert.deepEqual(shots, []);
  } finally {
    globalThis.document = previous;
  }
});
