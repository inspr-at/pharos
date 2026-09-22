import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import test from "node:test";
import { FAMILY_ORIGIN, FAMILY_VIEWPORTS, familyApp, familyRoutes, classifyFamilyObservation } from "../scripts/live-ui-apps.mjs";
import { captureFamilyCredentials, createFamilyOutput, familyEvidence } from "../scripts/family-live-ui.mjs";
import { decideRequest, decideRedirect, primaryFrameDecision, decideFetchPause, redactEvidence, assertRuntimeEnvironment, repoRootFromScripts } from "../scripts/live-ui-guard.mjs";

const APP_NAMES = ["aithema", "paimos", "pharos", "janus"];
const SEED = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"; // RFC 6238 test vector, not a credential.
const repo = repoRootFromScripts();
function temp() { return fs.realpathSync(fs.mkdtempSync(path.join(os.tmpdir(), "family-ui-test-"))); }
function credentials() { return { INSPR_UXQA_USERNAME: "synthetic-qa", INSPR_UXQA_PASSWORD: "synthetic-test-password", INSPR_UXQA_TOTP_SECRET: SEED }; }
function credentialFile(dir) { const file = path.join(dir, "synthetic.env"); fs.writeFileSync(file, "# synthetic metadata fixture\n", { mode: 0o600 }); return file; }

test("every family app is restricted to its Flow mount at both network layers and redirects", () => {
  for (const name of APP_NAMES) {
    const app = familyApp(name);
    const policy = { familyApp: name };
    for (const pathname of [app.base + "/", app.login, app.callback]) {
      const url = FAMILY_ORIGIN + pathname;
      assert.equal(decideRequest({ method: "GET", url }, policy).allow, true);
      assert.equal(decideRedirect({ method: "GET", url }, policy).allow, true);
      const frame = {};
      assert.equal(primaryFrameDecision({ method: () => "GET", url: () => url, frame: () => frame }, { mainFrame: () => frame }, policy).allow, true);
    }
    for (const other of APP_NAMES.filter((value) => value !== name)) {
      const url = FAMILY_ORIGIN + familyApp(other).base + "/";
      assert.equal(decideRedirect({ method: "GET", url }, policy).allow, false);
      assert.equal(decideFetchPause({ request: { method: "GET", url } }, policy).verdict.allow, false);
    }
    for (const method of ["POST", "PUT", "PATCH", "DELETE", "OPTIONS"]) {
      assert.equal(decideRequest({ method, url: FAMILY_ORIGIN + app.base + "/flow/intents" }, policy).reason, "app-mutation");
    }
    assert.equal(decideRequest({ method: "GET", url: "https://pharos.barta.cm/pharos/" }, policy).allow, false);
    assert.equal(decideRequest({ method: "GET", url: FAMILY_ORIGIN + app.base + "/logout" }, policy).allow, false);
  }
  assert.equal(decideRequest({ method: "GET", url: FAMILY_ORIGIN + "/pharos/" }, { familyApp: "unknown" }).allow, false);
});

test("Janus secret catalog, values, setup and privileged metadata never enter the read scope", () => {
  for (const route of ["api/warden/descriptors", "api/warden/resolve", "api/posture", "api/audit/recent", "api/evidence", "vault/new", "settings", "managed-service/setup", "internal/credentials", "static/../api/warden/descriptors"]) {
    assert.equal(decideRequest({ method: "GET", url: `${FAMILY_ORIGIN}/janus/${route}` }, { familyApp: "janus" }).allow, false);
  }
});

test("family keeps issuer login restrictions and secret redaction", () => {
  const policy = { familyApp: "paimos", secrets: ["synthetic-test-password"] };
  assert.equal(decideRequest({ method: "POST", url: "https://auth.inspr.at/ui/login/password" }, policy).allow, true);
  for (const target of ["https://auth.inspr.at/ui/login/password/reset", "https://auth.inspr.at/ui/login/mfa/verify", `${FAMILY_ORIGIN}/paimos/api/auth/dev-login`]) {
    assert.equal(decideRequest({ method: "POST", url: target }, policy).allow, false);
  }
  assert.equal(decideRequest({ method: "GET", url: `${FAMILY_ORIGIN}/paimos/?password=synthetic-test-password` }, policy).allow, false);
  assert.equal(JSON.stringify(redactEvidence({ path: "/paimos/api/auth/oidc/callback?code=temporary&state=temporary", note: "synthetic-test-password" }, policy.secrets)).includes("synthetic-test-password"), false);
  assert.equal(decideFetchPause({ request: { method: "GET", url: `${FAMILY_ORIGIN}/paimos/` } }, { ...policy, gate: { compromised: () => true } }).verdict.allow, false);
});

test("HTTP 200, shell-only, callback-only, auth UI and forbidden role are not login proof", () => {
  const observed = { app: "paimos", location: { origin: FAMILY_ORIGIN, pathname: "/paimos/" }, status: 200, probe: { familyShell: true }, callbackConfirmed: true };
  assert.equal(classifyFamilyObservation(observed), "authenticated");
  assert.equal(classifyFamilyObservation({ ...observed, callbackConfirmed: false }), "broken-ui");
  assert.equal(classifyFamilyObservation({ ...observed, probe: {} }), "broken-ui");
  assert.equal(classifyFamilyObservation({ ...observed, probe: { familyShell: true, passwordCount: 1 } }), "auth-required");
  assert.equal(classifyFamilyObservation({ ...observed, status: 403 }), "policy-denied");
  assert.equal(classifyFamilyObservation({ ...observed, location: { origin: FAMILY_ORIGIN, pathname: "/janus/" } }), "broken-ui");
});

test("named routes cannot introduce arbitrary origins or production route suffixes", () => {
  assert.deepEqual(familyRoutes("paimos", "42"), [{ name: "landing", path: "/paimos/" }, { name: "sandbox", path: "/paimos/projects/42" }]);
  for (const bad of ["../1", "1/issues", "https://foreign.example", "x?project=1"]) assert.throws(() => familyRoutes("paimos", bad));
  assert.throws(() => familyRoutes("janus", "42"));
  assert.equal(familyRoutes("aithema", "project:inspr-uxqa")[1].path, "/aithema/projects/project%3Ainspr-uxqa");
  for (const suffix of ["", "/flow-state"]) {
    assert.equal(decideRequest({ method: "GET", url: `${FAMILY_ORIGIN}/aithema/projects/project%3Ainspr-uxqa${suffix}` }, { familyApp: "aithema" }).allow, true);
  }
  for (const encoded of ["project%253Ainspr-uxqa", "project%3Ainspr%2Fuxqa", "project%3Ainspr-uxqa/../secrets%2Fvalue"]) {
    assert.equal(decideRequest({ method: "GET", url: `${FAMILY_ORIGIN}/aithema/projects/${encoded}` }, { familyApp: "aithema" }).allow, false);
  }
});

test("source credentials are removed before child launch, including rejected input", () => {
  const dir = temp();
  const file = credentialFile(dir);
  const input = credentials();
  const material = captureFamilyCredentials(input, repo, file);
  assert.deepEqual(input, {});
  assertRuntimeEnvironment(input);
  assert.equal(material.username, "synthetic-qa");
  material.totp.bytes.fill(0);
  const rejected = { ...credentials(), HTTPS_PROXY: "https://proxy.invalid" };
  assert.throws(() => captureFamilyCredentials(rejected, repo, file), /family-credentials/);
  assert.deepEqual(Object.keys(rejected), ["HTTPS_PROXY"]);
  const extra = { ...credentials(), INSPR_UXQA_CLIENT_SECRET: "synthetic-unused-client-secret" };
  assert.throws(() => captureFamilyCredentials(extra, repo, file), /family-credentials/);
  assert.deepEqual(extra, {});
  fs.chmodSync(file, 0o644);
  const weak = credentials();
  assert.throws(() => captureFamilyCredentials(weak, repo, file), /family-credentials/);
  assert.deepEqual(weak, {});
});

test("runtime evidence is outside the checkout, owned private, new, and never follows a symlink", () => {
  const home = temp();
  const now = new Date("2026-09-22T12:00:00Z");
  const output = createFamilyOutput("paimos", repo, home, now);
  assert.equal(fs.statSync(output).mode & 0o777, 0o700);
  fs.writeFileSync(path.join(output, "evidence.json"), "{}", { mode: 0o600 });
  assert.throws(() => createFamilyOutput("paimos", repo, home, now), /output-dir-not-empty/);
  const symlinked = temp();
  fs.symlinkSync(home, path.join(symlinked, ".inspr"));
  assert.throws(() => createFamilyOutput("paimos", repo, symlinked, now), /output-dir/);
});

test("family evidence records the two real viewport contracts without auth or mutation values", () => {
  assert.deepEqual(FAMILY_VIEWPORTS, { desktop: { width: 1440, height: 1000 }, mobile: { width: 390, height: 844 } });
  const routes = Object.entries(FAMILY_VIEWPORTS).map(([viewport, size]) => ({ name: "landing", path: "/paimos/", viewport, ...size, class: "authenticated", screenshot: `landing-${viewport}.png` }));
  const evidence = familyEvidence({ app: "paimos", started: "2026-09-22T12:00:00Z", overall: "authenticated", routes, blocked: [], callbackConfirmed: true, credentialMode: "protected-env" });
  assert.equal(evidence.schema, "inspr.uxqa.live-ui-evidence.v1");
  assert.equal(evidence.routes.length, 2);
  assert.deepEqual(evidence.serverMutationAllowlist, []);
  assert.equal(evidence.browserState, "memory-only");
});
