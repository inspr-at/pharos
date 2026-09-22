import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { setTimeout as delay } from "node:timers/promises";

// Unattended TOTP for the personal live UI harness.
// Zitadel 98272ab5d1c1074ca81ee31e0895d1e3d73d022a posts the verify form to
// /ui/login/mfa/verify. domain.MFATypeTOTP is iota 0. SMS and email use
// /ui/login/mfa/otp/verify and are not this form. The seed stays in this
// process. Only one derived code may be placed in the verify POST body.

export const TOTP_SECRET_FILE_ENV = "PHAROS_LIVE_UI_TOTP_SECRET_FILE";
export const TOTP_PERIOD_SEC = 30;
export const TOTP_DIGITS = 6;
export const TOTP_NEAR_EXPIRY_MS = 5000;
export const TOTP_GRANT_MS = 8000;
export const TOTP_VERIFY_PATH = "/ui/login/mfa/verify";
export const TOTP_VERIFY_URL = "https://auth.inspr.at/ui/login/mfa/verify";
export const MFA_TYPE_TOTP = "0";

const BASE32 = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
const SECRET_FILE_MAX = 256;

function totpError(code) {
  const error = new Error(code);
  error.name = "LiveUiError";
  error.code = code;
  return error;
}

function outsideRepo(candidate, repoRoot) {
  const root = fs.realpathSync(repoRoot);
  const relative = path.relative(root, candidate);
  return relative.startsWith("..") || path.isAbsolute(relative);
}

export function totpSecretFileFromEnv(env) {
  const value = env?.[TOTP_SECRET_FILE_ENV];
  if (value === undefined || value === "") return "";
  if (typeof value !== "string") throw totpError("totp-file-path");
  if (/otpauth/i.test(value) || value.includes("://") || /^[0-9]{6}$/.test(value)) {
    throw totpError("totp-uri");
  }
  if (!path.isAbsolute(value) || value.length > 1024 || /[\0\r\n]/.test(value)) {
    throw totpError("totp-file-path");
  }
  return value;
}

function assertSecretFile(filePath, repoRoot) {
  const fail = (suffix) => {
    throw totpError(`totp-file-${suffix}`);
  };
  if (!path.isAbsolute(filePath)) fail("path");
  let stat;
  try {
    stat = fs.lstatSync(filePath);
  } catch (error) {
    if (error && error.code === "ENOENT") throw totpError("totp-file-missing");
    fail("path");
  }
  if (stat.isSymbolicLink()) fail("symlink");
  if (!stat.isFile()) fail("type");
  if ((stat.mode & 0o777) !== 0o600) fail("mode");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) fail("owner");
  if (stat.size < 1 || stat.size > SECRET_FILE_MAX) fail("size");
  const parentPath = path.dirname(filePath);
  let parent;
  try {
    parent = fs.lstatSync(parentPath);
  } catch {
    fail("parent");
  }
  if (parent.isSymbolicLink() || !parent.isDirectory()) fail("parent");
  if ((parent.mode & 0o777) !== 0o700) fail("parent");
  if (typeof process.getuid === "function" && parent.uid !== process.getuid()) fail("owner");
  const resolved = fs.realpathSync(filePath);
  const resolvedParent = fs.realpathSync(parentPath);
  if (path.dirname(resolved) !== resolvedParent || path.basename(resolved) !== path.basename(filePath)) {
    fail("symlink");
  }
  if (!outsideRepo(resolved, repoRoot)) fail("repo");
  return stat;
}

export function decodeBase32(text) {
  if (typeof text !== "string") throw totpError("totp-secret");
  if (/otpauth/i.test(text) || text.includes("://")) throw totpError("totp-uri");
  if (text.length < 16 || text.length > 128) throw totpError("totp-secret");
  let body = text;
  const padAt = body.indexOf("=");
  if (padAt !== -1) {
    const padLen = body.length - padAt;
    if (!/^=+$/.test(body.slice(padAt)) || body.length % 8 !== 0) throw totpError("totp-secret");
    const mod = padAt % 8;
    const expectedPad = mod === 2 ? 6 : mod === 4 ? 4 : mod === 5 ? 3 : mod === 7 ? 1 : -1;
    if (padLen !== expectedPad) throw totpError("totp-secret");
    body = body.slice(0, padAt);
  } else if (body.length % 8 === 1 || body.length % 8 === 3 || body.length % 8 === 6) {
    throw totpError("totp-secret");
  }
  if (!/^[A-Z2-7]+$/.test(body)) throw totpError("totp-secret");
  let bits = 0;
  let value = 0;
  const out = [];
  for (const char of body) {
    const index = BASE32.indexOf(char);
    value = (value << 5) | index;
    bits += 5;
    if (bits >= 8) {
      bits -= 8;
      out.push((value >>> bits) & 0xff);
    }
  }
  if (bits >= 5) throw totpError("totp-secret");
  if (bits > 0 && (value & ((1 << bits) - 1)) !== 0) throw totpError("totp-secret");
  if (out.length < 10 || out.length > 64) throw totpError("totp-secret");
  return Buffer.from(out);
}

function readSecretText(filePath) {
  const raw = fs.readFileSync(filePath);
  if (raw.length > SECRET_FILE_MAX) throw totpError("totp-file-size");
  let text = raw.toString("utf8");
  if (text.endsWith("\r\n")) text = text.slice(0, -2);
  else if (text.endsWith("\n") || text.endsWith("\r")) text = text.slice(0, -1);
  if (text.includes("\n") || text.includes("\r") || text.includes("\0")) {
    throw totpError("totp-file-multiline");
  }
  return text;
}

export function loadTotpSecretFile(filePath, repoRoot) {
  try {
    assertSecretFile(filePath, repoRoot);
    const text = readSecretText(filePath);
    const bytes = decodeBase32(text);
    return { bytes, redaction: text };
  } catch (error) {
    if (error && error.name === "LiveUiError") throw error;
    if (error && error.code === "ENOENT") throw totpError("totp-file-missing");
    throw totpError("totp-file-path");
  }
}

export function loadOptionalTotpSecret(env, repoRoot) {
  const filePath = totpSecretFileFromEnv(env);
  if (!filePath) return null;
  return loadTotpSecretFile(filePath, repoRoot);
}

export function totpCode(key, unixMs) {
  if (!Buffer.isBuffer(key) || key.length < 10 || key.length > 64) throw totpError("totp-secret");
  if (!Number.isFinite(unixMs) || unixMs < 0) throw totpError("totp-clock");
  const counter = BigInt(Math.floor(unixMs / 1000 / TOTP_PERIOD_SEC));
  const message = Buffer.alloc(8);
  message.writeBigUInt64BE(counter);
  const hmac = crypto.createHmac("sha1", key).update(message).digest();
  try {
    const offset = hmac[hmac.length - 1] & 0x0f;
    const binary =
      ((hmac[offset] & 0x7f) << 24) |
      ((hmac[offset + 1] & 0xff) << 16) |
      ((hmac[offset + 2] & 0xff) << 8) |
      (hmac[offset + 3] & 0xff);
    return String(binary % 1_000_000).padStart(TOTP_DIGITS, "0");
  } finally {
    hmac.fill(0);
    message.fill(0);
  }
}

export async function freshTotpCode(key, nowMs = Date.now(), sleep = delay) {
  if (typeof sleep !== "function") throw totpError("totp-wait");
  const slot = TOTP_PERIOD_SEC * 1000;
  const remain = slot - (nowMs % slot);
  let at = nowMs;
  if (remain <= TOTP_NEAR_EXPIRY_MS) {
    if (remain < 0 || remain > TOTP_NEAR_EXPIRY_MS) throw totpError("totp-wait");
    await sleep(remain);
    at = nowMs + remain;
  }
  return totpCode(key, at);
}

export function inspectTotpForm(root) {
  const fail = (reason) => ({ ok: false, reason });
  const doc = root && typeof root.querySelectorAll === "function" ? root : globalThis.document;
  if (!doc || typeof doc.querySelectorAll !== "function") return fail("totp-form");
  const view = doc.defaultView;
  if (!view || view.top !== view) return fail("totp-frame");
  const location = doc.location;
  if (!location || location.origin !== "https://auth.inspr.at") return fail("totp-origin");
  const forms = [...doc.querySelectorAll("form")];
  if (forms.length !== 1) return fail("totp-form");
  const form = forms[0];
  const method = String(form.getAttribute("method") || "").toUpperCase();
  if (method !== "POST") return fail("totp-form");
  let action;
  try {
    action = new URL(String(form.getAttribute("action") || ""), location.href);
  } catch {
    return fail("totp-form");
  }
  if (
    action.origin !== "https://auth.inspr.at" ||
    action.pathname !== "/ui/login/mfa/verify" ||
    action.search ||
    action.hash ||
    action.username ||
    action.password
  ) {
    return fail("totp-form");
  }
  const fieldValue = (element) => {
    const live = element && typeof element.value === "string" ? element.value : "";
    if (live) return live;
    const attr = element && typeof element.getAttribute === "function" ? element.getAttribute("value") : null;
    return attr == null ? "" : String(attr);
  };
  const visible = (element) => {
    if (!element || typeof element.getAttribute !== "function") return false;
    const type = String(element.getAttribute("type") || "").toLowerCase();
    if (type === "hidden") return false;
    if (typeof element.hasAttribute === "function" && element.hasAttribute("hidden")) return false;
    if (element.getAttribute("aria-hidden") === "true") return false;
    if (typeof element.getClientRects === "function" && element.getClientRects().length === 0) return false;
    return true;
  };
  const inputs = typeof form.querySelectorAll === "function" ? [...form.querySelectorAll("input")] : [];
  const buttons = typeof form.querySelectorAll === "function" ? [...form.querySelectorAll("button")] : [];
  if (inputs.some((element) => String(element.getAttribute("type") || "").toLowerCase() === "password")) {
    return fail("totp-form");
  }
  const named = (name) => inputs.filter((element) => element.getAttribute("name") === name);
  const csrf = named("gorilla.csrf.Token");
  const auth = named("authRequestID");
  const factor = named("mfaType");
  const code = inputs.filter((element) => element.getAttribute("id") === "code" && element.getAttribute("name") === "code");
  if (csrf.length !== 1 || auth.length !== 1 || factor.length !== 1 || code.length !== 1) return fail("totp-form");
  if (inputs.length !== 4) return fail("totp-form");
  const csrfValue = fieldValue(csrf[0]);
  const authValue = fieldValue(auth[0]);
  if (!csrfValue || !authValue || csrfValue.length > 512 || authValue.length > 200) return fail("totp-form");
  if (/[\0\r\n]/.test(csrfValue) || /[\0\r\n]/.test(authValue)) return fail("totp-form");
  if (String(csrf[0].getAttribute("type") || "").toLowerCase() !== "hidden") return fail("totp-form");
  if (String(auth[0].getAttribute("type") || "").toLowerCase() !== "hidden") return fail("totp-form");
  if (String(factor[0].getAttribute("type") || "").toLowerCase() !== "hidden") return fail("totp-form");
  if (fieldValue(factor[0]) !== "0") return fail("totp-form");
  const codeField = code[0];
  if (String(codeField.getAttribute("type") || "").toLowerCase() !== "text") return fail("totp-form");
  if (String(codeField.getAttribute("autocomplete") || "").toLowerCase() !== "off") return fail("totp-form");
  if (!visible(codeField) || fieldValue(codeField)) return fail("totp-form");
  const submit = buttons.filter((element) => {
    return (
      element.getAttribute("id") === "submit-button" &&
      String(element.getAttribute("type") || "").toLowerCase() === "submit" &&
      !element.hasAttribute("name") &&
      visible(element)
    );
  });
  if (submit.length !== 1) return fail("totp-form");
  const providerControls = buttons.filter((element) => element.getAttribute("name") === "provider").length;
  return {
    ok: true,
    providerControls,
    authRequestId: authValue,
    csrf: csrfValue,
  };
}

export function publicTotpInspection(inspected) {
  if (!inspected || inspected.ok !== true) {
    return { ok: false, reason: inspected?.reason || "totp-form" };
  }
  return {
    ok: true,
    origin: "https://auth.inspr.at",
    method: "POST",
    actionPath: TOTP_VERIFY_PATH,
    mfaType: MFA_TYPE_TOTP,
    codeField: true,
    unnamedSubmit: true,
    providerControls: Number(inspected.providerControls) || 0,
  };
}

export function clearTotpCodeField(root) {
  const doc = root && typeof root.querySelectorAll === "function" ? root : globalThis.document;
  if (!doc || typeof doc.querySelectorAll !== "function") return false;
  const fields = [...doc.querySelectorAll("input")].filter((element) => {
    return element.getAttribute("id") === "code" && element.getAttribute("name") === "code";
  });
  if (fields.length !== 1) return false;
  fields[0].value = "";
  if (typeof fields[0].setAttribute === "function") fields[0].setAttribute("value", "");
  return true;
}

export function armTotpGrant({ code, authRequestId, csrf, now = Date.now, lifetimeMs = TOTP_GRANT_MS }) {
  if (!/^[0-9]{6}$/.test(code)) throw totpError("totp-code");
  if (typeof authRequestId !== "string" || authRequestId.length < 1 || authRequestId.length > 200) {
    throw totpError("totp-form");
  }
  if (typeof csrf !== "string" || csrf.length < 1 || csrf.length > 512) throw totpError("totp-form");
  if (/[\0\r\n]/.test(authRequestId) || /[\0\r\n]/.test(csrf)) throw totpError("totp-form");
  return {
    armed: true,
    revoked: false,
    expiresAt: now() + lifetimeMs,
    now,
    code,
    authRequestId,
    csrf,
    uses: { primary: 0, fetch: 0 },
  };
}

export function revokeTotpGrant(grant) {
  if (!grant) return;
  grant.armed = false;
  grant.revoked = true;
  grant.code = "";
  grant.authRequestId = "";
  grant.csrf = "";
}

export function totpVerifyTarget(method, raw) {
  if (String(method || "").toUpperCase() !== "POST") return false;
  let url;
  try {
    url = new URL(String(raw || ""));
  } catch {
    return false;
  }
  return (
    url.protocol === "https:" &&
    url.origin === "https://auth.inspr.at" &&
    url.pathname === TOTP_VERIFY_PATH &&
    !url.username &&
    !url.password
  );
}

export function isExactTotpPost(method, raw) {
  if (!totpVerifyTarget(method, raw)) return false;
  let url;
  try {
    url = new URL(String(raw || ""));
  } catch {
    return false;
  }
  return url.search === "" && url.hash === "";
}

function bodyCarriesOtherSecret(postData, params, grant, secrets) {
  const list = Array.isArray(secrets) ? secrets : [];
  for (const secret of list) {
    if (typeof secret !== "string" || secret.length === 0 || secret === grant.code) continue;
    if (postData.includes(secret)) return true;
    for (const value of params.values()) {
      if (String(value).includes(secret)) return true;
    }
  }
  return false;
}

function formBodyMatches(postData, grant, secrets) {
  if (typeof postData !== "string" || postData.length < 1 || postData.length > 4096) return false;
  if (postData.includes("\0") || postData.includes("\n") || postData.includes("\r")) return false;
  const params = new URLSearchParams(postData);
  const keys = [...params.keys()];
  const expected = ["gorilla.csrf.Token", "authRequestID", "mfaType", "code"];
  if (keys.length !== expected.length || new Set(keys).size !== expected.length) return false;
  if (expected.some((key) => !keys.includes(key))) return false;
  if (params.get("mfaType") !== MFA_TYPE_TOTP) return false;
  if (params.get("code") !== grant.code) return false;
  if (params.get("authRequestID") !== grant.authRequestId) return false;
  if (params.get("gorilla.csrf.Token") !== grant.csrf) return false;
  if (bodyCarriesOtherSecret(postData, params, grant, secrets)) return false;
  return true;
}

export function decodeTotpPostData(request) {
  if (!request || typeof request !== "object") return "";
  if (typeof request.postData === "string") return request.postData.length > 4096 ? "" : request.postData;
  const entries = request.postDataEntries;
  if (!Array.isArray(entries) || entries.length !== 1) return "";
  const bytes = entries[0] && entries[0].bytes;
  if (typeof bytes !== "string" || bytes.length < 1 || bytes.length > 8192) return "";
  if (!/^[A-Za-z0-9+/=]+$/.test(bytes)) return "";
  const text = Buffer.from(bytes, "base64").toString("utf8");
  return text.length > 4096 ? "" : text;
}

export function consumeTotpGrant(observed, policy = {}) {
  if (!totpVerifyTarget(observed?.method, observed?.url)) return "ignore";
  const grant = policy.totpGrant;
  if (!isExactTotpPost(observed?.method, observed?.url) || observed?.isolated || observed?.redirected) {
    revokeTotpGrant(grant);
    return observed?.isolated ? "keep" : "deny";
  }
  const lost =
    policy.protocolLost === true ||
    (typeof policy.gate?.compromised === "function" && Boolean(policy.gate.compromised()));
  if (lost) {
    revokeTotpGrant(grant);
    return "network-guard";
  }
  if (!grant || grant.revoked || grant.armed !== true) return "deny";
  const now = typeof grant.now === "function" ? grant.now() : Date.now();
  if (!Number.isFinite(grant.expiresAt) || now > grant.expiresAt) {
    revokeTotpGrant(grant);
    return "deny";
  }
  const layer = observed?.layer === "primary" || observed?.layer === "fetch" ? observed.layer : "";
  if (!layer || !formBodyMatches(observed.postData, grant, policy.secrets)) {
    revokeTotpGrant(grant);
    return "deny";
  }
  if (grant.uses[layer] >= 1) {
    revokeTotpGrant(grant);
    return "deny";
  }
  grant.uses[layer] += 1;
  return "allow";
}
