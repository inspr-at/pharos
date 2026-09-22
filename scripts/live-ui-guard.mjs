import fs from "node:fs";
import net from "node:net";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { consumeTotpGrant, decodeTotpPostData, revokeTotpGrant, totpVerifyTarget } from "./live-ui-totp.mjs";

// Browser-side request policy for the personal Pharos live UI harness.
// This does not change the server role of the signed-in Fleet manager account.
// POST /agora/requests/host-preferences.json calls begin_settings_change and
// persists a settings workflow, so it is not a safe server-side draft.
// No application mutation is whitelisted.

export const PERSONAL_APP_ORIGINS = Object.freeze([
  "https://pharos.barta.cm",
  "https://flow.inspr.at",
]);
export const PERSONAL_BASE_PATH = "/pharos";
export const PERSONAL_ISSUER_ORIGIN = "https://auth.inspr.at";
export const ENTRY_URL = "https://pharos.barta.cm/pharos/auth/login";
export const SERVER_MUTATION_ALLOWLIST = Object.freeze([]);
export const SESSION_ORDER = Object.freeze([
  "install-request-guard",
  "open-login",
  "classify",
  "read-only-navigation",
  "screenshot-authenticated-only",
]);
export const EXIT_CODES = Object.freeze({
  authenticated: 0,
  "broken-ui": 1,
  refused: 1,
  "auth-required": 2,
  "mfa-required": 3,
  "policy-denied": 4,
  "account-setup-required": 5,
});
export const INVENTORY_ROUTES = Object.freeze([
  "/pharos/",
  "/pharos/map",
  "/pharos/alerts",
  "/pharos/backups",
  "/pharos/services",
  "/pharos/activity",
  "/pharos/settings/providers",
  "/pharos/agora",
  "/pharos/version",
]);
export const SCREENSHOT_FILES = Object.freeze({
  "/pharos/": "01-home.png",
  "/pharos/map": "02-map.png",
  "/pharos/alerts": "03-alerts.png",
  "/pharos/backups": "04-backups.png",
  "/pharos/activity": "05-activity.png",
  "/pharos/services": "06-services.png",
  "/pharos/settings/providers": "07-providers.png",
  "/pharos/agora": "08-agora.png",
  "/pharos/version": "09-version.png",
});

const APP_ORIGINS = new Set(PERSONAL_APP_ORIGINS);
const SAFE_METHODS = new Set(["GET", "HEAD"]);
const ISSUER_DENY_PREFIXES = Object.freeze([
  "/ui/console",
  "/management",
  "/admin",
  "/system",
  "/debug",
  "/auth/v1",
  "/v2/users",
  "/v2/organizations",
  "/v2/settings",
]);
// Exact Zitadel login v1 credential posts. Reset, init, revoke, and any
// broader auth prefix are not login. Unknown login-v2 session posts stay denied.
// POST /ui/login/mfa/verify is not an allowlist entry. One unattended code is a
// separate grant checked by the primary-frame route and by Fetch.
export const ISSUER_LOGIN_POST_PATHS = Object.freeze([
  "/ui/login/loginname",
  "/ui/login/password",
]);
const ISSUER_GET_PREFIXES = Object.freeze([
  "/.well-known",
  "/oauth",
  "/oidc",
  "/ui/login",
  "/ui/v2",
  "/v2/sessions",
]);
const BLOCKED_RESOURCES = new Set(["websocket", "serviceworker"]);
const PROVIDER_PATH = /^\/pharos\/settings\/providers\/[a-z0-9-]{1,64}$/;
const SERVICE_PATH = /^\/pharos\/services\/[A-Za-z0-9._-]{1,63}\/[A-Za-z0-9._-]{1,63}$/;
const HOST_SETTINGS_PATH = /^\/pharos\/hosts\/[A-Za-z0-9._-]{1,63}\?section=settings$/;
const MAX_HOST_PAGES = 32;
const SECRET_QUERY_KEYS = new Set([
  "password",
  "passwd",
  "client_secret",
  "access_token",
  "refresh_token",
  "code_verifier",
  "id_token",
  "token",
]);
const FORBIDDEN_ENV = Object.freeze([
  "PHAROS_LIVE_UI_USERNAME",
  "PHAROS_LIVE_UI_PASSWORD",
  "PHAROS_LIVE_UI_TOTP",
  "PHAROS_LIVE_UI_TOTP_SECRET",
  "PHAROS_LIVE_UI_TOTP_CODE",
  "PHAROS_LIVE_UI_TOTP_SEED",
  "PHAROS_LIVE_UI_OTP",
  "PHAROS_LIVE_UI_OTP_CODE",
  "PHAROS_LIVE_UI_OTP_SECRET",
  "PHAROS_LIVE_UI_APP_ORIGIN",
  "PHAROS_LIVE_UI_ISSUER",
  "PHAROS_LIVE_UI_ISSUER_ORIGIN",
  "PHAROS_LIVE_UI_BASE_PATH",
  "PHAROS_LIVE_UI_URL",
  "DEBUG",
  "PWDEBUG",
  "HTTP_PROXY",
  "HTTPS_PROXY",
  "ALL_PROXY",
  "http_proxy",
  "https_proxy",
  "all_proxy",
]);

const HOST_ROUTE = /^\/pharos\/hosts\/[A-Za-z0-9._-]{1,63}$/;
const USERNAME_PATTERN = /^[A-Za-z0-9._%+@=-]{1,128}$/;
const SELECTOR_PATTERN = /^[A-Za-z0-9_\[\]="'():*\s.#>,~+-]{1,160}$/;

export class LiveUiError extends Error {
  constructor(code) {
    super(code);
    this.name = "LiveUiError";
    this.code = code;
  }
}

export function assertSessionPrefix(steps) {
  for (let index = 0; index < steps.length; index += 1) {
    if (steps[index] !== SESSION_ORDER[index]) {
      throw new LiveUiError("session-order");
    }
  }
}

export function browserLaunchOptions(port) {
  if (!Number.isInteger(port) || port < 1 || port > 65535) throw new LiveUiError("browser-launch");
  const options = {
    headless: true,
    args: [`--remote-debugging-port=${port}`, "--remote-debugging-address=127.0.0.1"],
  };
  if (Object.keys(options).length !== 2 || options.args.length !== 2) throw new LiveUiError("browser-launch");
  if (options.args[1] !== "--remote-debugging-address=127.0.0.1") throw new LiveUiError("browser-launch");
  return options;
}

export function reserveLoopbackDebuggerPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    const fail = () => {
      server.close(() => {});
      reject(new LiveUiError("network-guard"));
    };
    server.once("error", fail);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      const port = address && typeof address === "object" ? address.port : 0;
      server.close((error) => {
        if (error || !Number.isInteger(port) || port < 1) fail();
        else resolve(port);
      });
    });
  });
}

export function debuggerWebSocketUrl(port, payload) {
  if (!payload || typeof payload.Browser !== "string" || payload.Browser.length < 3) {
    throw new LiveUiError("network-guard");
  }
  let url;
  try {
    url = new URL(String(payload.webSocketDebuggerUrl || ""));
  } catch {
    throw new LiveUiError("network-guard");
  }
  const browserId = url.pathname.startsWith("/devtools/browser/")
    ? url.pathname.slice("/devtools/browser/".length)
    : "";
  if (
    url.protocol !== "ws:" ||
    url.hostname !== "127.0.0.1" ||
    url.port !== String(port) ||
    !browserId ||
    browserId.includes("/") ||
    url.username ||
    url.password ||
    url.search ||
    url.hash
  ) {
    throw new LiveUiError("network-guard");
  }
  return url.href;
}

export function browserContextOptions() {
  return {
    locale: "en-GB",
    timezoneId: "Europe/Vienna",
    viewport: { width: 1440, height: 1000 },
    colorScheme: "light",
    reducedMotion: "reduce",
    serviceWorkers: "block",
    acceptDownloads: false,
    ignoreHTTPSErrors: false,
    javaScriptEnabled: true,
  };
}

export function assertCredentialEntryOrigin(origin) {
  if (origin !== PERSONAL_ISSUER_ORIGIN) {
    throw new LiveUiError("login-origin");
  }
}

export function isUnderBasePath(pathname) {
  return pathname === PERSONAL_BASE_PATH || pathname.startsWith(`${PERSONAL_BASE_PATH}/`);
}

export function isHostPath(pathname) {
  return HOST_ROUTE.test(pathname);
}

export function isInventoryPath(pathname) {
  return INVENTORY_ROUTES.includes(pathname) || isHostPath(pathname);
}

export function continuationAllowed(result) {
  if (!result?.allow) return false;
  if (result.reason === "in-page") return true;
  if (
    (result.reason === "app-read" || result.reason === "issuer-read") &&
    (result.method === "GET" || result.method === "HEAD")
  ) {
    return true;
  }
  return result.reason === "issuer-login" && result.method === "POST";
}

function hasPathPrefix(pathname, prefix) {
  return pathname === prefix || pathname.startsWith(`${prefix}/`);
}

function isMachinePath(pathname) {
  return (
    /(^|\/)(register|report|metrics|internal)(\/|$)/.test(pathname) ||
    /(^|\/)agent(\/|$)/.test(pathname)
  );
}

function isIssuerAdminPath(pathname) {
  return ISSUER_DENY_PREFIXES.some((prefix) => hasPathPrefix(pathname, prefix));
}

function isIssuerLoginPost(pathname) {
  return ISSUER_LOGIN_POST_PATHS.includes(pathname);
}

const ACCOUNT_MUTATION_FIELD = /reset|revoke|enroll|enrol|register|new[-_]?password|recover|change[-_]?password|init/i;

function fieldRequestsAccountMutation(key) {
  return ACCOUNT_MUTATION_FIELD.test(String(key || ""));
}

function jsonRequestsAccountMutation(value) {
  if (!value || typeof value !== "object") return false;
  if (Array.isArray(value)) return value.some((item) => jsonRequestsAccountMutation(item));
  for (const [key, item] of Object.entries(value)) {
    if (fieldRequestsAccountMutation(key) || jsonRequestsAccountMutation(item)) return true;
  }
  return false;
}

function postDataRequestsAccountMutation(postData) {
  if (postData == null || postData === "") return false;
  const raw = String(postData).trim();
  if (raw.startsWith("{") || raw.startsWith("[")) {
    try {
      return jsonRequestsAccountMutation(JSON.parse(raw));
    } catch {
      return true;
    }
  }
  try {
    for (const key of new URLSearchParams(raw).keys()) {
      if (fieldRequestsAccountMutation(key)) return true;
    }
  } catch {
    return true;
  }
  return false;
}

function deniedHost(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return host === "pharos.agm.ng" || host.endsWith(".agm.ng") || host === "agm.ng";
}

function isIpHost(hostname) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
}

function listedSecrets(secrets) {
  return (Array.isArray(secrets) ? secrets : []).filter((secret) => typeof secret === "string" && secret.length > 0);
}

function latin1Bytes(bytes) {
  let out = "";
  for (const byte of bytes) out += String.fromCharCode(byte);
  return out;
}

function structuralUtf8Length(bytes, index) {
  const lead = bytes[index];
  let need = 0;
  if (lead <= 0x7F) need = 1;
  else if ((lead & 0xE0) === 0xC0) need = 2;
  else if ((lead & 0xF0) === 0xE0) need = 3;
  else if ((lead & 0xF8) === 0xF0 && lead <= 0xF7) need = 4;
  if (need === 0 || index + need > bytes.length) return 0;
  for (let cursor = 1; cursor < need; cursor += 1) {
    if ((bytes[index + cursor] & 0xC0) !== 0x80) return 0;
  }
  return need;
}

function codePointFromUtf8(bytes, index, length) {
  if (length === 1) return bytes[index];
  if (length === 2) return ((bytes[index] & 0x1F) << 6) | (bytes[index + 1] & 0x3F);
  if (length === 3) {
    return ((bytes[index] & 0x0F) << 12) | ((bytes[index + 1] & 0x3F) << 6) | (bytes[index + 2] & 0x3F);
  }
  return (
    ((bytes[index] & 0x07) << 18) |
    ((bytes[index + 1] & 0x3F) << 12) |
    ((bytes[index + 2] & 0x3F) << 6) |
    (bytes[index + 3] & 0x3F)
  );
}

function utf8Bytes(bytes) {
  const points = [];
  for (let index = 0; index < bytes.length; ) {
    const length = structuralUtf8Length(bytes, index);
    const point = length === 0 ? null : codePointFromUtf8(bytes, index, length);
    if (point === null || point > 0x10FFFF) {
      points.push(bytes[index]);
      index += 1;
      continue;
    }
    points.push(point);
    index += length;
  }
  let out = "";
  for (let index = 0; index < points.length; index += 1) {
    const point = points[index];
    const next = points[index + 1];
    if (point >= 0xD800 && point <= 0xDBFF && next >= 0xDC00 && next <= 0xDFFF) {
      out += String.fromCodePoint(0x10000 + ((point - 0xD800) << 10) + (next - 0xDC00));
      index += 1;
    } else {
      out += String.fromCodePoint(point);
    }
  }
  return out;
}

function decodeOnceSafe(value, mode) {
  const text = String(value ?? "");
  if (!text.includes("%")) return text;
  let out = "";
  const bytes = [];
  const flush = () => {
    if (bytes.length === 0) return;
    out += mode === "latin1" ? latin1Bytes(bytes) : utf8Bytes(bytes);
    bytes.length = 0;
  };
  for (let index = 0; index < text.length; index += 1) {
    if (text[index] === "%" && /^[0-9A-Fa-f]{2}$/.test(text.slice(index + 1, index + 3))) {
      bytes.push(Number.parseInt(text.slice(index + 1, index + 3), 16));
      index += 2;
    } else {
      flush();
      out += text[index];
    }
  }
  flush();
  return out;
}

function decodeRepeated(value) {
  const forms = new Set([String(value ?? "")]);
  let frontier = [...forms];
  for (let round = 0; round < 8; round += 1) {
    const grown = [];
    for (const current of frontier) {
      if (!current.includes("%")) continue;
      for (const mode of ["utf8", "latin1"]) {
        const next = decodeOnceSafe(current, mode);
        if (!forms.has(next)) {
          forms.add(next);
          grown.push(next);
        }
      }
    }
    if (grown.length === 0) break;
    frontier = grown;
  }
  return [...forms];
}

function percentEncode(secret, alphabet) {
  let out = "";
  for (const byte of new TextEncoder().encode(String(secret))) {
    const hex = byte.toString(16).padStart(2, "0");
    out += `%${alphabet === "upper" ? hex.toUpperCase() : hex}`;
  }
  return out;
}

function secretVariants(secret) {
  const variants = new Set();
  const add = (value) => {
    if (typeof value === "string" && value.includes("%") && value.length >= 6) variants.add(value);
  };
  add(percentEncode(secret, "lower"));
  add(percentEncode(secret, "upper"));
  const chars = [...String(secret)];
  add(chars.map((char, index) => (index % 2 === 0 ? percentEncode(char, "lower") : char)).join(""));
  add(secret.replace(/[@/?#&+=\s]/g, (char) => encodeURIComponent(char)));
  const mid = Math.ceil(chars.length / 2);
  add(`${percentEncode(chars.slice(0, mid).join(""), "lower")}${chars.slice(mid).join("")}`);
  add(`${chars.slice(0, mid).join("")}${percentEncode(chars.slice(mid).join(""), "upper")}`);
  add(percentEncode(percentEncode(secret, "lower"), "lower"));
  return [...variants];
}

function pieceMatchesSecret(piece, secrets) {
  const raw = String(piece ?? "");
  if (!raw) return false;
  const forms = decodeRepeated(raw);
  for (const secret of listedSecrets(secrets)) {
    for (const value of forms) {
      if (value.includes(secret)) return true;
      for (const variant of secretVariants(secret)) {
        if (value.includes(variant)) return true;
      }
    }
  }
  return false;
}

function rawPath(raw, url) {
  const clean = String(raw).split("#")[0].split("?")[0];
  const scheme = clean.indexOf("//");
  const start = scheme >= 0 ? clean.indexOf("/", scheme + 2) : clean.indexOf("/");
  if (start < 0) return url.pathname || "/";
  return clean.slice(start) || "/";
}

function rawQuery(raw) {
  const clean = String(raw).split("#")[0];
  const cut = clean.indexOf("?");
  if (cut < 0) return "";
  return clean.slice(cut + 1);
}

function pathLeaks(url, raw, secrets) {
  return pieceMatchesSecret(url.pathname || "/", secrets) || pieceMatchesSecret(rawPath(raw, url), secrets);
}

function secretInUrl(raw, url, secrets) {
  if (url.username || url.password) return true;
  const pieces = [
    url.username,
    url.password,
    url.hash.startsWith("#") ? url.hash.slice(1) : url.hash,
    url.pathname,
    rawQuery(raw),
    url.search.startsWith("?") ? url.search.slice(1) : url.search,
  ];
  for (const key of url.searchParams.keys()) {
    pieces.push(key);
    if (SECRET_QUERY_KEYS.has(String(key).toLowerCase())) return true;
  }
  for (const value of url.searchParams.values()) pieces.push(value);
  if (pieces.some((piece) => pieceMatchesSecret(piece, secrets))) return true;
  return pathLeaks(url, raw, secrets);
}

function decision(allow, reason, method, pathName, secrets = []) {
  return {
    allow,
    reason,
    method,
    path: publicPath(pathName, secrets),
  };
}

const HIDDEN_PATH = "path-category";

function hiddenPath(secrets = []) {
  if (listedSecrets(secrets).some((secret) => HIDDEN_PATH.includes(secret))) return "/";
  return HIDDEN_PATH;
}

export function publicPath(pathName, secrets = []) {
  if (pathName === HIDDEN_PATH) return hiddenPath(secrets);
  let path = typeof pathName === "string" ? pathName : "/";
  path = path.split("#")[0];
  let query = "";
  const cut = path.indexOf("?");
  if (cut !== -1) {
    query = path.slice(cut);
    path = path.slice(0, cut);
  }
  if (!path.startsWith("/")) path = "/";
  const settings = query === "?section=settings" && isHostPath(path);
  if (
    path.includes("%") ||
    path.includes("\\") ||
    path.includes("\0") ||
    pieceMatchesSecret(path, secrets) ||
    pieceMatchesSecret(query, secrets)
  ) {
    return hiddenPath(secrets);
  }
  return settings ? `${path}${query}` : path;
}

export function decideRequest(request, policy = {}) {
  const method = String(request?.method || "").toUpperCase();
  const secrets = listedSecrets(policy.secrets);
  const raw = String(request?.url || "");
  if (!method || method === "TRACE" || method === "CONNECT" || method === "TRACK") {
    return decision(false, "method", method || "?", "/", secrets);
  }
  let url;
  try {
    url = new URL(raw);
  } catch {
    const leaked = pieceMatchesSecret(raw, secrets);
    return decision(false, leaked ? "secret-in-url" : "url", method, leaked ? hiddenPath(secrets) : "/", secrets);
  }
  const tainted = secretInUrl(raw, url, secrets);
  const leakedPath = pathLeaks(url, raw, secrets);
  const candidate = leakedPath ? hiddenPath(secrets) : safePath(url) || "/";
  if (tainted) {
    return decision(false, "secret-in-url", method, candidate, secrets);
  }
  const resource = String(request?.resourceType || "").toLowerCase();
  const upgrade = String(request?.headers?.upgrade || request?.headers?.Upgrade || "").toLowerCase();
  if (BLOCKED_RESOURCES.has(resource) || upgrade.includes("websocket")) {
    const reason = resource === "serviceworker" ? "serviceworker" : "websocket";
    return decision(false, reason, method, "/", secrets);
  }
  if (url.protocol === "about:" && url.href === "about:blank") {
    return decision(true, "in-page", method, "/", secrets);
  }
  if (url.protocol === "blob:" || url.protocol === "data:") {
    return decision(true, "in-page", method, "/", secrets);
  }
  if (url.protocol !== "https:") {
    return decision(false, "scheme", method, candidate, secrets);
  }
  if (deniedHost(url.hostname) || isIpHost(url.hostname)) {
    return decision(false, "foreign-origin", method, candidate, secrets);
  }
  const pathname = safePath(url);
  if (!pathname) {
    return decision(false, "unsafe-path", method, "/", secrets);
  }
  if (isMachinePath(pathname)) {
    return decision(false, "machine-route", method, pathname, secrets);
  }
  const origin = url.origin.toLowerCase();
  if (APP_ORIGINS.has(origin)) {
    if (!isUnderBasePath(pathname)) {
      return decision(false, "outside-base-path", method, pathname, secrets);
    }
    if (!SAFE_METHODS.has(method)) {
      return decision(false, "app-mutation", method, pathname, secrets);
    }
    return decision(true, "app-read", method, pathname, secrets);
  }
  if (origin === PERSONAL_ISSUER_ORIGIN) {
    if (isIssuerAdminPath(pathname)) {
      return decision(false, "issuer-admin", method, pathname, secrets);
    }
    if (SAFE_METHODS.has(method)) {
      if (isIssuerReadPath(pathname)) return decision(true, "issuer-read", method, pathname, secrets);
      return decision(false, "issuer-path", method, pathname, secrets);
    }
    if (method === "POST" && isIssuerLoginPost(pathname)) {
      if (postDataRequestsAccountMutation(request?.postData)) {
        return decision(false, "issuer-mutation", method, pathname, secrets);
      }
      return decision(true, "issuer-login", method, pathname, secrets);
    }
    return decision(false, "issuer-mutation", method, pathname, secrets);
  }
  return decision(false, "foreign-origin", method, pathname, secrets);
}

function isIssuerReadPath(pathname) {
  return ISSUER_GET_PREFIXES.some((prefix) => hasPathPrefix(pathname, prefix));
}

export function decideRedirect(request, policy = {}) {
  const verdict = decideRequest(request, policy);
  if (verdict.reason === "secret-in-url" || continuationAllowed(verdict)) return verdict;
  return { ...verdict, allow: false, reason: verdict.reason || "redirect" };
}

export function decideIncidental(kind) {
  const reason = kind === "download" || kind === "popup" || kind === "serviceworker" ? kind : "denied";
  return decision(false, reason, "GET", "/");
}

function safePath(url) {
  const pathname = url.pathname || "/";
  if (pathname.includes("%") || pathname.includes("\\") || pathname.includes("\0")) {
    return null;
  }
  return pathname;
}

function scrubText(text, secrets) {
  const secretsList = listedSecrets(secrets).sort((left, right) => right.length - left.length);
  const needles = [];
  for (const secret of secretsList) {
    needles.push(secret);
    for (const variant of secretVariants(secret)) needles.push(variant);
  }
  needles.sort((left, right) => right.length - left.length);
  const apply = (value) => {
    let next = value;
    for (const needle of needles) {
      if (needle && next.includes(needle)) next = next.split(needle).join("[redacted]");
    }
    return next;
  };
  let out = apply(String(text ?? ""));
  if (secretsList.some((secret) => decodeRepeated(out).some((form) => form.includes(secret)))) {
    out = apply(out.replace(/%[0-9A-Fa-f]{2}/g, "[redacted]"));
  }
  if (secretsList.some((secret) => decodeRepeated(out).some((form) => form.includes(secret)) || out.includes(secret))) {
    return "[redacted]";
  }
  return out;
}

function redactUrl(match, secrets) {
  let url;
  try {
    url = new URL(match);
  } catch {
    return "[url]";
  }
  if (pathLeaks(url, match, secrets)) return `${url.origin}/${hiddenPath(secrets)}`;
  const pathname = safePath(url);
  if (!pathname) return `${url.origin}/`;
  return `${url.origin}${pathname}`;
}

export function publicLocation(rawUrl, secrets = []) {
  const raw = String(rawUrl);
  const url = new URL(raw);
  const tainted = secretInUrl(raw, url, secrets) || pathLeaks(url, raw, secrets);
  return {
    origin: url.origin.toLowerCase(),
    pathname: tainted ? hiddenPath(secrets) : safePath(url) || "/",
  };
}

export function sanitizeNavigationError(error, secrets = []) {
  let text = error instanceof Error ? error.message : String(error ?? "");
  text = text.replace(/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s"'<>)]+/g, (match) => redactUrl(match, secrets));
  text = scrubText(text, secrets);
  return text.replace(/[\r\n\u0000-\u001f]+/g, " ").slice(0, 300);
}

export function redactEvidence(value, secrets = []) {
  if (typeof value === "string") {
    if (value.startsWith("/") || value === HIDDEN_PATH) return publicPath(value, secrets);
    return scrubText(value, secrets);
  }
  if (Array.isArray(value)) return value.map((item) => redactEvidence(item, secrets));
  if (value && typeof value === "object") {
    const out = {};
    for (const [key, item] of Object.entries(value)) {
      out[key] = key === "path" && typeof item === "string" ? publicPath(item, secrets) : redactEvidence(item, secrets);
    }
    return out;
  }
  return value;
}

export function classifyObservation({ location, status, probe, managerConfirmed = false }) {
  const onIssuer = location?.origin === PERSONAL_ISSUER_ORIGIN;
  const onApp = APP_ORIGINS.has(location?.origin) && isUnderBasePath(location?.pathname || "");
  const authPath = typeof location?.pathname === "string" && location.pathname.includes("/auth/");
  const permissionDenied = Boolean(
    probe?.noAccess || probe?.accessDenied || probe?.accessRequest || probe?.viewerOnly,
  );
  if (probe?.accountSetup) return "account-setup-required";
  if (probe?.mfa) return "mfa-required";
  if (probe?.rateLimited || probe?.authRecovery) return "auth-required";
  if (probe?.passwordCount > 0 || probe?.loginForm || probe?.authUiVisible || onIssuer || authPath) {
    return "auth-required";
  }
  if (permissionDenied) return "policy-denied";
  if (status === 401) return "auth-required";
  if (status === 403) return "policy-denied";
  if (onApp && probe?.managerShell && (status === 0 || (status >= 200 && status < 400))) {
    return "authenticated";
  }
  if (
    managerConfirmed &&
    onApp &&
    status >= 200 &&
    status < 400 &&
    !probe?.authUiVisible &&
    (probe?.appShell || location?.pathname === "/pharos/version")
  ) {
    return "authenticated";
  }
  if (status >= 500 || status === 0) return "broken-ui";
  return "broken-ui";
}

export function screenshotPermitted({ classification, location, probe }) {
  if (classification !== "authenticated") return false;
  if (!location || !APP_ORIGINS.has(location.origin)) return false;
  if (location.pathname === HIDDEN_PATH || location.pathname.includes("%")) return false;
  if (!isUnderBasePath(location.pathname)) return false;
  if (location.pathname.includes("/auth/")) return false;
  if (location.origin === PERSONAL_ISSUER_ORIGIN) return false;
  if (
    !probe ||
    probe.passwordCount > 0 ||
    probe.mfa ||
    probe.codeField ||
    probe.accountSetup ||
    probe.loginForm ||
    probe.authUiVisible ||
    probe.noAccess ||
    probe.accessDenied ||
    probe.accessRequest ||
    probe.viewerOnly ||
    probe.authRecovery ||
    probe.accountMutation
  ) {
    return false;
  }
  if (!probe.appShell && !probe.managerShell) return false;
  return true;
}

function totpMaterialEnv(name) {
  if (name === "PHAROS_LIVE_UI_TOTP_SECRET_FILE") return false;
  return /(TOTP|OTP_CODE|OTP_SECRET|MFA_CODE|MFA_SEED|MFA_SECRET)/i.test(name);
}

export function assertRuntimeEnvironment(env) {
  for (const name of FORBIDDEN_ENV) {
    if (env[name] !== undefined && env[name] !== "") {
      throw new LiveUiError("runtime-env");
    }
  }
  for (const name of Object.keys(env)) {
    if (totpMaterialEnv(name) && env[name] !== undefined && env[name] !== "") {
      throw new LiveUiError("runtime-env");
    }
  }
  if (env.NODE_TLS_REJECT_UNAUTHORIZED === "0") {
    throw new LiveUiError("tls-override");
  }
}

export function assertCommandArgv(argv) {
  const args = argv.slice(2);
  if (args.length !== 1 || (args[0] !== "inventory" && args[0] !== "draft")) {
    throw new LiveUiError("argv");
  }
  if (args.some((arg) => /:\/\//.test(arg) || /password=/i.test(arg) || arg.includes("@"))) {
    throw new LiveUiError("argv");
  }
  return args[0];
}

function assertOwnedRegularFile(filePath, repoRoot, maxBytes, prefix) {
  const fail = (suffix) => {
    throw new LiveUiError(`${prefix}-${suffix}`);
  };
  if (!path.isAbsolute(filePath)) fail("path");
  const stat = fs.lstatSync(filePath);
  if (stat.isSymbolicLink()) fail("symlink");
  if (!stat.isFile()) fail("type");
  if ((stat.mode & 0o777) !== 0o600) fail("mode");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) fail("owner");
  if (stat.size < 1 || stat.size > maxBytes) fail("size");
  const parentPath = path.dirname(filePath);
  const parent = fs.lstatSync(parentPath);
  if (parent.isSymbolicLink() || !parent.isDirectory()) fail("parent");
  if ((parent.mode & 0o777) !== 0o700) fail("parent");
  if (typeof process.getuid === "function" && parent.uid !== process.getuid()) fail("owner");
  const resolved = fs.realpathSync(filePath);
  const resolvedParent = fs.realpathSync(parentPath);
  if (path.dirname(resolved) !== resolvedParent || path.basename(resolved) !== path.basename(filePath)) {
    fail("symlink");
  }
  assertOutsideRepo(resolved, repoRoot, `${prefix}-repo`);
  return stat;
}

function assertOutsideRepo(candidate, repoRoot, code) {
  const root = fs.realpathSync(repoRoot);
  const relative = path.relative(root, candidate);
  if (relative === "" || (!relative.startsWith("..") && !path.isAbsolute(relative))) {
    throw new LiveUiError(code);
  }
}

function readSingleLine(filePath, maxBytes) {
  const raw = fs.readFileSync(filePath);
  if (raw.length > maxBytes) throw new LiveUiError("credential-file-size");
  let text = raw.toString("utf8");
  if (text.endsWith("\r\n")) text = text.slice(0, -2);
  else if (text.endsWith("\n") || text.endsWith("\r")) text = text.slice(0, -1);
  if (text.includes("\n") || text.includes("\r") || text.includes("\0")) {
    throw new LiveUiError("credential-file-multiline");
  }
  return text;
}

export function loadUsernameFile(filePath, repoRoot) {
  try {
    assertOwnedRegularFile(filePath, repoRoot, 256, "credential-file");
    const username = readSingleLine(filePath, 256);
    if (!USERNAME_PATTERN.test(username)) throw new LiveUiError("credential-username");
    return username;
  } catch (error) {
    if (error instanceof LiveUiError) throw error;
    if (error && error.code === "ENOENT") throw new LiveUiError("credential-file-missing");
    throw new LiveUiError("credential-file");
  }
}

export function loadPasswordFile(filePath, repoRoot) {
  try {
    assertOwnedRegularFile(filePath, repoRoot, 1024, "credential-file");
    const password = readSingleLine(filePath, 1024);
    if (password.length < 1 || password.length > 1024) {
      throw new LiveUiError("credential-file-size");
    }
    for (let index = 0; index < password.length; index += 1) {
      const code = password.charCodeAt(index);
      if (code < 0x20 || code === 0x7f) throw new LiveUiError("credential-password");
    }
    return password;
  } catch (error) {
    if (error instanceof LiveUiError) throw error;
    if (error && error.code === "ENOENT") throw new LiveUiError("credential-file-missing");
    throw new LiveUiError("credential-file");
  }
}

export function assertOutputDir(dirPath, repoRoot) {
  if (!path.isAbsolute(dirPath)) throw new LiveUiError("output-dir");
  let stat;
  try {
    stat = fs.lstatSync(dirPath);
  } catch {
    throw new LiveUiError("output-dir");
  }
  if (stat.isSymbolicLink() || !stat.isDirectory()) throw new LiveUiError("output-dir");
  if ((stat.mode & 0o777) !== 0o700) throw new LiveUiError("output-dir");
  if (typeof process.getuid === "function" && stat.uid !== process.getuid()) {
    throw new LiveUiError("output-dir");
  }
  const resolved = fs.realpathSync(dirPath);
  const resolvedStat = fs.lstatSync(resolved);
  if (resolvedStat.ino !== stat.ino || resolvedStat.dev !== stat.dev) {
    throw new LiveUiError("output-dir");
  }
  assertOutsideRepo(resolved, repoRoot, "output-dir");
  return resolved;
}

export function parseClientDraft(raw) {
  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch {
    throw new LiveUiError("draft-json");
  }
  if (!parsed || Array.isArray(parsed) || typeof parsed !== "object") {
    throw new LiveUiError("draft-json");
  }
  const keys = Object.keys(parsed);
  if (keys.some((key) => key !== "path" && key !== "fields")) {
    throw new LiveUiError("draft-server-request");
  }
  if (typeof parsed.path !== "string" || !isInventoryPath(parsed.path)) {
    throw new LiveUiError("draft-path");
  }
  if (!Array.isArray(parsed.fields) || parsed.fields.length < 1 || parsed.fields.length > 8) {
    throw new LiveUiError("draft-fields");
  }
  const fields = parsed.fields.map((field) => {
    if (!field || Array.isArray(field) || typeof field !== "object") {
      throw new LiveUiError("draft-fields");
    }
    if (Object.keys(field).some((key) => key !== "selector" && key !== "value")) {
      throw new LiveUiError("draft-server-request");
    }
    if (typeof field.selector !== "string" || !SELECTOR_PATTERN.test(field.selector)) {
      throw new LiveUiError("draft-selector");
    }
    if (/password|submit|button|url\s*\(|javascript:/i.test(field.selector)) {
      throw new LiveUiError("draft-selector");
    }
    if (typeof field.value !== "string" || field.value.length < 1 || field.value.length > 200) {
      throw new LiveUiError("draft-value");
    }
    if (/[\r\n\u0000]/.test(field.value) || /:\/\//.test(field.value)) {
      throw new LiveUiError("draft-value");
    }
    return { selector: field.selector, value: field.value };
  });
  return {
    path: parsed.path,
    fields,
    dispatch: "dom-only",
    serverRequests: [],
  };
}

export function loadDraftFile(filePath, repoRoot) {
  try {
    assertOwnedRegularFile(filePath, repoRoot, 16 * 1024, "draft-file");
    const raw = fs.readFileSync(filePath, "utf8");
    return parseClientDraft(raw);
  } catch (error) {
    if (error instanceof LiveUiError) throw error;
    if (error && error.code === "ENOENT") throw new LiveUiError("draft-missing");
    throw new LiveUiError("draft-json");
  }
}

export function collectProbeSurface(root) {
  const probeVisible = (element) => {
    if (!element || typeof element.getAttribute !== "function") return false;
    const type = String(element.getAttribute("type") || "").toLowerCase();
    if (type === "hidden") return false;
    if (typeof element.hasAttribute === "function" && element.hasAttribute("hidden")) return false;
    if (element.getAttribute("aria-hidden") === "true") return false;
    if (typeof element.getClientRects === "function" && element.getClientRects().length === 0) return false;
    return true;
  };
  const emptySurface = () => ({
    passwordCount: 0,
    usernameField: false,
    otpField: false,
    webauthnChallenge: false,
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
    accountMutation: false,
    accountSetup: false,
    enrollmentOptional: false,
  });
  const document = root && typeof root.querySelectorAll === "function" ? root : globalThis.document;
  if (!document || typeof document.querySelectorAll !== "function") return emptySurface();
  const visible = (selector) => [...document.querySelectorAll(selector)].filter(probeVisible);
  const text = String(
    (document.body && (document.body.innerText || document.body.textContent)) || "",
  ).slice(0, 4000);
  const title = String(document.title || "");
  const passwords = visible("input[type='password']");
  const usernames = visible(
    "input[name='loginName'], input[name='username'], input[autocomplete='username'], input[type='email']",
  );
  const otp = visible(
    "input[autocomplete='one-time-code'], input[name='otp'], input[name='totp'], input[name='code']",
  ).filter((element) => {
    const name = String(element.getAttribute("name") || "").toLowerCase();
    const autocomplete = String(element.getAttribute("autocomplete") || "").toLowerCase();
    if (autocomplete === "one-time-code" || name === "otp" || name === "totp") return true;
    return passwords.length === 0 && usernames.length === 0;
  });
  const webauthnInputs = visible("input[autocomplete='webauthn']");
  const providerChoices = visible("input").filter((element) => {
    const type = String(element.getAttribute("type") || "").toLowerCase();
    const name = String(element.getAttribute("name") || "").toLowerCase();
    return type === "radio" && name === "provider";
  });
  const skipEnrollment = visible("button, input[type='submit']").some((element) => {
    const name = String(element.getAttribute("name") || "").toLowerCase();
    const value = String(element.getAttribute("value") || "").toLowerCase();
    const type = String(element.getAttribute("type") || "submit").toLowerCase();
    return name === "skip" && value === "true" && type === "submit";
  });
  const enrollmentPrompt =
    providerChoices.length > 0 &&
    passwords.length === 0 &&
    otp.length === 0 &&
    webauthnInputs.length === 0 &&
    visible("button, input[type='submit']").length > 0;
  const labelOf = (element) =>
    `${element.getAttribute("aria-label") || ""} ${element.getAttribute("value") || ""} ${element.innerText || element.textContent || ""}`.slice(0, 180);
  const passkeyControl = (element) => /\b(passkey|security key|webauthn)\b/i.test(labelOf(element));
  const mutationControl = (element) =>
    /\b(reset password|new password|change password|create account|sign up|sign-up|enroll|enrol|register|recover|recovery)\b/i.test(
      labelOf(element),
    );
  const newPasswordField = passwords.some((element) => {
    const autocomplete = String(element.getAttribute("autocomplete") || "").toLowerCase();
    const name = String(element.getAttribute("name") || "").toLowerCase();
    return (
      autocomplete === "new-password" ||
      name === "newpassword" ||
      name === "new_password" ||
      name === "passwordconfirm" ||
      name === "password_confirm"
    );
  });
  const primaryLogin = passwords.length > 0 || usernames.length > 0;
  const challenge = visible("form, [role='dialog']").some((element) => {
    if (typeof element.querySelector === "function") {
      const loginField = element.querySelector(
        "input[type='password'], input[name='loginName'], input[name='username'], input[type='email']",
      );
      if (loginField && probeVisible(loginField)) return false;
    }
    const sample = String(element.innerText || element.textContent || "").slice(0, 500);
    const challengeCopy =
      /\b(verification code|one-time code|authenticator|security key|webauthn|two-factor|multi-factor|second factor|use your passkey)\b/i.test(
        sample,
      );
    if (!challengeCopy || typeof element.querySelector !== "function") return false;
    return Boolean(
      element.querySelector(
        "button, input[type='submit'], input[autocomplete='webauthn'], input[autocomplete='one-time-code']",
      ),
    );
  });
  const managerShell = Boolean(
    document.querySelector("[data-can-manage='true'], [data-can-manage-fleet='true']"),
  );
  const viewerFlag = Boolean(
    document.querySelector("[data-can-manage='false'], [data-can-manage-fleet='false']"),
  );
  return {
    passwordCount: Math.min(2, passwords.length),
    usernameField: usernames.length > 0,
    otpField: otp.length > 0,
    webauthnChallenge: !enrollmentPrompt && (webauthnInputs.length > 0 || (!primaryLogin && challenge)),
    accountSetup: enrollmentPrompt,
    enrollmentOptional: enrollmentPrompt && skipEnrollment,
    passkeyAlternative: primaryLogin && visible("a, button").some(passkeyControl),
    accountMutation: newPasswordField || visible("button, input[type='submit']").some(mutationControl),
    noAccess:
      text.includes("No access yet") || text.includes("has not been granted any hosts or settings yet"),
    accessDenied: title === "Access denied · Pharos" || text.includes("has not granted you operator access"),
    accessRequest:
      Boolean(document.querySelector("main.access-request-page, [data-access-request-text]")) ||
      text.includes("Send this to your Pharos administrator"),
    managerShell,
    viewerOnly: viewerFlag && !managerShell,
    appShell: Boolean(document.querySelector("main")),
    authRecovery: Boolean(document.querySelector("[data-auth-recovery]")),
    rateLimited: text.includes("authentication rate limit exceeded"),
    loginForm: usernames.length > 0 || passwords.length > 0,
  };
}

export function classifyProbeSurface(surface = {}) {
  const accountSetup = Boolean(surface.accountSetup);
  const codeField = Boolean(surface.codeField || surface.otpField);
  const mfa = !accountSetup && Boolean(codeField || surface.webauthnChallenge);
  return {
    passwordCount: Math.min(2, Number(surface.passwordCount) || 0),
    mfa,
    codeField,
    accountSetup,
    enrollmentOptional: accountSetup && Boolean(surface.enrollmentOptional),
    passkeyAlternative: Boolean(surface.passkeyAlternative) && !mfa && !accountSetup,
    noAccess: Boolean(surface.noAccess),
    accessDenied: Boolean(surface.accessDenied),
    accessRequest: Boolean(surface.accessRequest),
    managerShell: Boolean(surface.managerShell),
    viewerOnly: Boolean(surface.viewerOnly) && !surface.managerShell,
    appShell: Boolean(surface.appShell),
    authRecovery: Boolean(surface.authRecovery || surface.accountMutation),
    accountMutation: Boolean(surface.accountMutation),
    rateLimited: Boolean(surface.rateLimited),
    loginForm: Boolean(surface.loginForm || surface.usernameField || Number(surface.passwordCount) > 0),
    authUiVisible: Boolean(
      Number(surface.passwordCount) > 0 ||
        surface.usernameField ||
        codeField ||
        surface.otpField ||
        surface.webauthnChallenge ||
        surface.accountSetup ||
        surface.loginForm,
    ),
  };
}

export function hostNamesFromPayload(raw) {
  let parsed = raw;
  if (typeof raw === "string") {
    try {
      parsed = JSON.parse(raw);
    } catch {
      return [];
    }
  }
  if (!parsed || typeof parsed !== "object") return [];
  const names = [];
  for (const list of [parsed.hosts, parsed.declared_hosts]) {
    if (!Array.isArray(list)) continue;
    for (const item of list) {
      if (item && typeof item.name === "string" && HOST_ROUTE.test(`/pharos/hosts/${item.name}`)) {
        names.push(item.name);
      }
    }
  }
  return names;
}

export function planInventory({
  hrefs = [],
  hostNames = [],
  origin = PERSONAL_APP_ORIGINS[0],
  secrets = [],
} = {}) {
  const paths = [];
  const add = (candidate) => {
    const path = publicPath(candidate, secrets);
    if (!path.startsWith("/pharos") || path.includes("/auth/") || paths.includes(path)) return;
    paths.push(path);
  };
  for (const route of INVENTORY_ROUTES) add(route);
  const names = new Set();
  const rememberHost = (name) => {
    if (typeof name !== "string" || !HOST_ROUTE.test(`/pharos/hosts/${name}`)) return;
    if (publicPath(`/pharos/hosts/${name}`, secrets) !== `/pharos/hosts/${name}`) return;
    names.add(name);
  };
  for (const name of hostNames) rememberHost(name);
  const base = PERSONAL_APP_ORIGINS.includes(origin) ? origin : PERSONAL_APP_ORIGINS[0];
  for (const href of hrefs) {
    if (typeof href !== "string" || href.length < 1 || href.length > 200) continue;
    let url;
    try {
      url = new URL(href, `${base}/`);
    } catch {
      continue;
    }
    if (!PERSONAL_APP_ORIGINS.includes(url.origin)) continue;
    const verdict = decideRequest({ method: "GET", url: url.href }, { secrets });
    if (!verdict.allow || verdict.reason !== "app-read") continue;
    if (isHostPath(url.pathname)) rememberHost(url.pathname.slice("/pharos/hosts/".length));
    else if (PROVIDER_PATH.test(url.pathname) || SERVICE_PATH.test(url.pathname)) add(url.pathname);
  }
  for (const name of [...names].sort().slice(0, MAX_HOST_PAGES)) {
    add(`/pharos/hosts/${name}`);
    add(`/pharos/hosts/${name}?section=settings`);
  }
  return paths;
}

export function credentialFillPermitted(probe) {
  if (!probe || probe.mfa || probe.accountSetup || probe.authRecovery || probe.accountMutation) return false;
  return true;
}

export function submitLabelRejected(label) {
  return /\b(passkey|security key|webauthn|reset password|new password|change password|sign up|sign-up|create account|enroll|enrol|register|recover|recovery|skip)\b/i.test(
    String(label || ""),
  );
}

export function passwordAppearsInText(text, password) {
  if (typeof password !== "string" || password.length < 1) return false;
  return String(text ?? "").includes(password);
}

export const SCREENSHOT_TEXT_LIMIT = 250000;
export const SCREENSHOT_FIELD_LIMIT = 200;
export const SCREENSHOT_VALUE_LIMIT = 2048;

// Runs in the page. Limits are literals so the serialized function does not
// close over Node state, and it never receives a secret argument.
export function collectScreenshotSurface() {
  const textLimit = 250000;
  const fieldLimit = 200;
  const valueLimit = 2048;
  const document = globalThis.document;
  if (!document || typeof document.querySelectorAll !== "function") return null;
  let nodes;
  try {
    nodes = [...document.querySelectorAll("input, textarea")];
  } catch {
    return null;
  }
  if (nodes.length > fieldLimit) return null;
  const values = [];
  for (const node of nodes) {
    const value = String(node && node.value != null ? node.value : "");
    if (value.length > valueLimit) return null;
    values.push(value);
  }
  const body = document.body;
  const title = String(document.title || "");
  const innerText = String(body ? body.innerText || "" : "");
  const textContent = String(body ? body.textContent || "" : "");
  if (title.length + innerText.length + textContent.length + 2 > textLimit) return null;
  return { values, visible: `${title}\n${innerText}\n${textContent}` };
}

export function screenshotContainsNeedle(surface, needles) {
  if (!surface || typeof surface !== "object") return true;
  if (typeof surface.visible !== "string" || surface.visible.length > SCREENSHOT_TEXT_LIMIT) return true;
  if (!Array.isArray(surface.values) || surface.values.length > SCREENSHOT_FIELD_LIMIT) return true;
  const list = Array.isArray(needles) ? needles : [];
  if (list.length < 1) return true;
  for (const value of surface.values) {
    if (typeof value !== "string" || value.length > SCREENSHOT_VALUE_LIMIT) return true;
  }
  for (const needle of list) {
    if (typeof needle !== "string" || needle.length < 1) return true;
    if (passwordAppearsInText(surface.visible, needle)) return true;
    for (const value of surface.values) {
      if (passwordAppearsInText(value, needle)) return true;
    }
  }
  return false;
}

export async function takeAuthenticatedShot(page, { permitted, password, material, options }) {
  if (!permitted) return false;
  const needles = [];
  if (typeof password === "string" && password.length > 0) needles.push(password);
  if (Array.isArray(material)) {
    for (const item of material) {
      if (typeof item === "string" && item.length > 0 && !needles.includes(item)) needles.push(item);
    }
  }
  if (needles.length === 0) return false;
  let surface;
  try {
    surface = await page.evaluate(collectScreenshotSurface);
  } catch {
    return false;
  }
  if (screenshotContainsNeedle(surface, needles)) return false;
  await page.screenshot(options);
  return true;
}

export function fetchPausePatterns() {
  return [{ urlPattern: "*", requestStage: "Request" }];
}

function headerUpgrade(headers) {
  if (!headers) return "";
  if (Array.isArray(headers)) {
    const entry = headers.find((item) => String(item?.name || "").toLowerCase() === "upgrade");
    return String(entry?.value || "");
  }
  return String(headers.upgrade || headers.Upgrade || "");
}

function protocolLost(policy) {
  if (policy?.protocolLost === true) return true;
  const gate = policy?.gate;
  return typeof gate?.compromised === "function" && Boolean(gate.compromised());
}

export function decideFetchPause(event, policy = {}) {
  if (protocolLost(policy)) {
    revokeTotpGrant(policy?.totpGrant);
    return {
      action: "fail",
      verdict: decision(false, "network-guard", "?", "/", listedSecrets(policy.secrets)),
    };
  }
  if (event?.responseStatusCode || event?.responseErrorReason) {
    return {
      action: "fail",
      verdict: decision(false, "response-stage", "?", "/", listedSecrets(policy.secrets)),
    };
  }
  const request = event?.request || {};
  let verdict;
  try {
    verdict = decideRequest(
      {
        url: request.url,
        method: request.method,
        resourceType: String(event?.resourceType || "").toLowerCase(),
        headers: { upgrade: headerUpgrade(request.headers) },
        postData: request.postData,
      },
      policy,
    );
  } catch {
    verdict = decision(false, "guard-error", "?", "/", listedSecrets(policy.secrets));
  }
  verdict = applyTotpGrant(verdict, {
    method: request.method,
    url: request.url,
    postData: decodeTotpPostData(request),
    redirected: Boolean(event?.redirectedRequestId),
    isolated: false,
    layer: "fetch",
  }, policy);
  return {
    action: continuationAllowed(verdict) ? "continue" : "fail",
    verdict,
  };
}

function applyTotpGrant(verdict, observed, policy) {
  if (!totpVerifyTarget(observed.method, observed.url)) return verdict;
  if (verdict?.reason === "secret-in-url") {
    revokeTotpGrant(policy?.totpGrant);
    return verdict;
  }
  const effect = consumeTotpGrant(observed, policy);
  if (effect === "ignore" || effect === "keep") return verdict;
  const secrets = listedSecrets(policy?.secrets);
  if (effect === "allow") return decision(true, "issuer-login", "POST", "/ui/login/mfa/verify", secrets);
  const reason = effect === "network-guard" ? "network-guard" : "issuer-mutation";
  return decision(false, reason, "POST", "/ui/login/mfa/verify", secrets);
}

export async function settleFetchPause(session, event, policy = {}, rememberFn) {
  const decision = decideFetchPause(event, policy);
  if (decision.action !== "continue") {
    if (typeof rememberFn === "function") {
      try {
        rememberFn(decision.verdict);
      } catch {
        // Evidence failure must not turn a deny into a continue.
      }
    }
    try {
      await session.send("Fetch.failRequest", {
        requestId: event?.requestId,
        errorReason: "BlockedByClient",
      });
      return "failed";
    } catch {
      return "paused";
    }
  }
  try {
    await session.send("Fetch.continueRequest", { requestId: event?.requestId });
    return "continued";
  } catch {
    return "paused";
  }
}

export async function settleFetchAuth(session, event) {
  try {
    await session.send("Fetch.continueWithAuth", {
      requestId: event?.requestId,
      authChallengeResponse: { response: "CancelAuth" },
    });
    return "cancelled";
  } catch {
    return "paused";
  }
}

export async function enableFetchGuard(session, policy, rememberFn) {
  if (!session || typeof session.on !== "function" || typeof session.send !== "function") {
    throw new LiveUiError("network-guard");
  }
  let lost = false;
  const lose = () => {
    lost = true;
    const gate = policy?.gate;
    if (typeof gate?.noteDisconnect === "function") {
      try {
        gate.noteDisconnect();
      } catch {
        // The local flag still stops every later continuation.
      }
    }
  };
  session.on("close", lose);
  session.on("Fetch.requestPaused", (paused) => {
    const active = lost ? { ...policy, protocolLost: true } : policy;
    settleFetchPause(session, paused, active, rememberFn).catch(() => {});
  });
  session.on("Fetch.authRequired", (challenge) => settleFetchAuth(session, challenge).catch(() => {}));
  await session.send("Fetch.enable", {
    patterns: fetchPausePatterns(),
    handleAuthRequests: true,
  });
}

export async function disposeFetchGuard(session) {
  if (!session || typeof session.send !== "function") return;
  try {
    await session.send("Fetch.disable");
  } catch {
    // The session may already be closed. Detach still runs.
  }
  if (typeof session.detach === "function") {
    try {
      await session.detach();
    } catch {
      // Closed sessions have nothing left to release.
    }
  }
}

const FLAT_ATTACH = Object.freeze({
  autoAttach: true,
  waitForDebuggerOnStart: true,
  flatten: true,
});

export function createFlatCdpConnection(transport, options = {}) {
  if (!transport || typeof transport.send !== "function") throw new LiveUiError("network-guard");
  const commandTimeoutMs = Number.isInteger(options.commandTimeoutMs) ? options.commandTimeoutMs : 8000;
  let nextId = 0;
  let closed = false;
  const pending = new Map();
  const listeners = new Set();
  const failAll = () => {
    closed = true;
    for (const waiter of pending.values()) {
      clearTimeout(waiter.timer);
      waiter.reject(new LiveUiError("network-guard"));
    }
    pending.clear();
  };
  return {
    onEvent(listener) {
      listeners.add(listener);
    },
    failAll,
    closed: () => closed,
    receive(text) {
      let message;
      try {
        message = JSON.parse(String(text));
      } catch {
        return false;
      }
      if (!message || typeof message !== "object") return false;
      if (message.id && pending.has(message.id)) {
        const waiter = pending.get(message.id);
        pending.delete(message.id);
        clearTimeout(waiter.timer);
        if (message.error) waiter.reject(new LiveUiError("network-guard"));
        else waiter.resolve(message.result ?? {});
        return true;
      }
      if (typeof message.method === "string") {
        for (const listener of listeners) listener(message.method, message.params || {}, message);
      }
      return true;
    },
    send(method, params, sessionId) {
      if (closed) return Promise.reject(new LiveUiError("network-guard"));
      const id = nextId + 1;
      nextId = id;
      const envelope = { id, method, params: params ?? {} };
      if (sessionId) envelope.sessionId = sessionId;
      return new Promise((resolve, reject) => {
        const timer = setTimeout(() => {
          if (!pending.has(id)) return;
          pending.delete(id);
          reject(new LiveUiError("network-guard"));
        }, commandTimeoutMs);
        pending.set(id, { resolve, reject, timer });
        try {
          transport.send(JSON.stringify(envelope));
        } catch {
          clearTimeout(timer);
          pending.delete(id);
          reject(new LiveUiError("network-guard"));
        }
      });
    },
  };
}

export function createFlatTargetGuard(connection) {
  if (!connection || typeof connection.send !== "function" || typeof connection.onEvent !== "function") {
    throw new LiveUiError("network-guard");
  }
  let primaryId = "";
  let primarySessionId = "";
  let failure = "";
  let intentionalClose = false;
  let emergencyStarted = false;
  let emergencyClose = null;
  let settled = Promise.resolve();
  const fail = (code) => {
    if (!failure) failure = code || "target";
  };
  const terminate = (reason) => {
    if (intentionalClose) return;
    fail(reason);
    if (emergencyStarted || typeof emergencyClose !== "function") return;
    emergencyStarted = true;
    try {
      const pending = emergencyClose();
      if (pending && typeof pending.then === "function") pending.catch(() => {});
    } catch {
      // The compromised flag already denies later Fetch continuations.
    }
  };
  const closeTarget = async (targetId) => {
    if (!targetId) {
      terminate("close");
      return;
    }
    try {
      await connection.send("Target.closeTarget", { targetId });
    } catch {
      terminate("close");
    }
  };
  const onAttached = async (event) => {
    const info = event?.targetInfo || {};
    const type = String(info.type || "");
    if (type === "browser" || type === "tab") return;
    if (!event?.waitingForDebugger) {
      terminate("unpaused");
      return;
    }
    if (type === "page" && !primaryId) {
      const sessionId = String(event.sessionId || "");
      if (!sessionId || !info.targetId) {
        terminate("primary");
        return;
      }
      primaryId = info.targetId;
      primarySessionId = sessionId;
      try {
        await connection.send("Target.setAutoAttach", FLAT_ATTACH, sessionId);
        await connection.send("Runtime.runIfWaitingForDebugger", {}, sessionId);
      } catch {
        terminate("primary");
      }
      return;
    }
    await closeTarget(info.targetId);
  };
  const onDetached = async (event) => {
    const sessionId = String(event?.sessionId || "");
    const targetId = String(event?.targetId || "");
    const primary = (!sessionId && !targetId) || sessionId === primarySessionId || targetId === primaryId;
    if (!primary || !primaryId) return;
    terminate("detached");
  };
  connection.onEvent((method, params) => {
    if (method === "Target.attachedToTarget") {
      settled = settled.then(() => onAttached(params)).catch(() => terminate("attach"));
      return;
    }
    if (method === "Target.detachedFromTarget") {
      settled = settled.then(() => onDetached(params)).catch(() => terminate("detach"));
    }
  });
  return {
    compromised: () => failure,
    attachedPrimary: () => primaryId,
    setEmergencyClose(close) {
      emergencyClose = close;
    },
    beginShutdown() {
      intentionalClose = true;
    },
    noteDisconnect() {
      if (intentionalClose) return;
      terminate("disconnected");
    },
    settled: () => settled,
    async enable() {
      try {
        await connection.send("Target.setAutoAttach", FLAT_ATTACH);
      } catch {
        terminate("protocol");
        throw new LiveUiError("network-guard");
      }
    },
    close() {
      intentionalClose = true;
      if (typeof connection.failAll === "function") connection.failAll();
      if (typeof connection.close === "function") {
        try {
          connection.close();
        } catch {
          // The browser close already owns the process lifetime.
        }
      }
    },
  };
}

async function socketMessageText(data) {
  if (typeof data === "string") return data;
  if (data instanceof ArrayBuffer) return new TextDecoder().decode(data);
  if (ArrayBuffer.isView(data)) return new TextDecoder().decode(data);
  if (data && typeof data.text === "function") return data.text();
  return "";
}

export async function connectFlatDebugger(port, deps = {}) {
  const fetchImpl = deps.fetch || globalThis.fetch;
  const Socket = deps.WebSocket || globalThis.WebSocket;
  if (typeof fetchImpl !== "function" || typeof Socket !== "function") throw new LiveUiError("network-guard");
  let payload;
  try {
    const response = await fetchImpl(`http://127.0.0.1:${port}/json/version`, {
      redirect: "error",
      signal: AbortSignal.timeout(5000),
    });
    if (!response || response.ok !== true) throw new LiveUiError("network-guard");
    if (typeof response.text === "function") {
      const text = await response.text();
      if (typeof text !== "string" || text.length > 8192) throw new LiveUiError("network-guard");
      payload = JSON.parse(text);
    } else if (typeof response.json === "function") {
      payload = await response.json();
    } else {
      throw new LiveUiError("network-guard");
    }
  } catch (error) {
    if (error instanceof LiveUiError) throw error;
    throw new LiveUiError("network-guard");
  }
  const endpoint = debuggerWebSocketUrl(port, payload);
  const socket = new Socket(endpoint);
  let opened = false;
  await new Promise((resolve, reject) => {
    let settled = false;
    const finish = (error) => {
      if (settled) return;
      settled = true;
      clearTimeout(timer);
      if (error) {
        try {
          socket.close();
        } catch {
          // The socket never became usable.
        }
        reject(error);
      } else {
        resolve();
      }
    };
    const timer = setTimeout(() => finish(new LiveUiError("network-guard")), 5000);
    if (typeof socket.addEventListener === "function") {
      socket.addEventListener("open", () => {
        opened = true;
        finish();
      });
      socket.addEventListener("error", () => {
        if (!opened) finish(new LiveUiError("network-guard"));
      });
    } else {
      finish(new LiveUiError("network-guard"));
    }
  });
  if (!opened) throw new LiveUiError("network-guard");
  let transportSend = () => {
    throw new LiveUiError("network-guard");
  };
  const connection = createFlatCdpConnection({
    send(text) {
      transportSend(text);
    },
  });
  transportSend = (text) => {
    socket.send(text);
  };
  const gate = createFlatTargetGuard(connection);
  const onSocketData = (data) => {
    socketMessageText(data).then((text) => {
      if (!connection.receive(text)) gate.noteDisconnect();
    }).catch(() => gate.noteDisconnect());
  };
  socket.addEventListener("message", (event) => onSocketData(event?.data));
  socket.addEventListener("close", () => {
    connection.failAll();
    gate.noteDisconnect();
  });
  socket.addEventListener("error", () => gate.noteDisconnect());
  connection.close = () => {
    try {
      socket.close();
    } catch {
      // Already closed.
    }
  };
  return gate;
}

async function closeLiveBrowser(browser) {
  if (!browser) return;
  try {
    const contexts = typeof browser.contexts === "function" ? browser.contexts() : [];
    for (const context of contexts) {
      if (typeof context?.close === "function") await context.close();
    }
  } catch {
    // The browser close is the termination that does not depend on the raw socket.
  }
  if (typeof browser.close === "function") await browser.close();
}

export async function openGuardedBrowser(launchBrowser, deps) {
  if (typeof launchBrowser !== "function") throw new LiveUiError("browser-launch");
  const port = await reserveLoopbackDebuggerPort();
  const launch = browserLaunchOptions(port);
  let browser;
  let gate;
  try {
    browser = await launchBrowser(launch);
    gate = await connectFlatDebugger(port, deps);
    gate.setEmergencyClose(() => closeLiveBrowser(browser));
    try {
      await gate.enable();
    } catch (error) {
      gate.beginShutdown();
      gate.close();
      throw error;
    }
    return { browser, gate };
  } catch (error) {
    if (browser && typeof browser.close === "function" && !gate?.compromised()) {
      await browser.close().catch(() => {});
    }
    if (error instanceof LiveUiError) throw error;
    throw new LiveUiError("network-guard");
  }
}

export function primaryFrameDecision(request, page, policy = {}) {
  let method = "GET";
  let url = "";
  let resourceType = "";
  let postData = null;
  try {
    method = String(typeof request?.method === "function" ? request.method() : request?.method || "GET");
  } catch {
    method = "GET";
  }
  try {
    url = String(typeof request?.url === "function" ? request.url() : request?.url || "");
  } catch {
    url = "";
  }
  try {
    resourceType = String(typeof request?.resourceType === "function" ? request.resourceType() : "");
  } catch {
    resourceType = "";
  }
  try {
    postData = typeof request?.postData === "function" ? request.postData() : null;
  } catch {
    postData = null;
  }
  const verdict = decideRequest({ method, url, resourceType, postData }, policy);
  let primary = false;
  try {
    const frame = typeof request?.frame === "function" ? request.frame() : null;
    const main = page && typeof page.mainFrame === "function" ? page.mainFrame() : null;
    primary = !!page && !!frame && frame === main;
  } catch {
    primary = false;
  }
  let redirected = false;
  try {
    if (typeof request?.redirectedFrom === "function") redirected = Boolean(request.redirectedFrom());
  } catch {
    redirected = true;
  }
  const observed = {
    method,
    url,
    postData: typeof postData === "string" ? postData : "",
    redirected,
    isolated: !primary,
    layer: "primary",
  };
  if (!primary) {
    consumeTotpGrant(observed, policy);
    if (verdict.reason === "secret-in-url") return { ...verdict, allow: false };
    return { ...verdict, allow: false, reason: "isolated-target" };
  }
  return applyTotpGrant(verdict, observed, policy);
}

export async function installPrimaryFrameRoute(context, pageRef, policy, rememberFn, gate) {
  if (!context || typeof context.route !== "function") throw new LiveUiError("network-guard");
  await context.route("**/*", async (route) => {
    let request;
    try {
      request = route.request();
    } catch {
      await route.abort("blockedbyclient").catch(() => {});
      return;
    }
    let verdict;
    try {
      verdict = primaryFrameDecision(request, pageRef?.page ?? null, policy);
    } catch {
      verdict = decideIncidental("denied");
    }
    const lost = typeof gate?.compromised === "function" && gate.compromised();
    const allow = !lost && verdict.allow === true;
    if (!allow && typeof rememberFn === "function") {
      const recorded = lost && verdict.reason !== "secret-in-url"
        ? { ...verdict, allow: false, reason: "isolated-target" }
        : { ...verdict, allow: false };
      try {
        rememberFn(recorded);
      } catch {
        // The request is still aborted.
      }
    }
    if (!allow) {
      await route.abort("blockedbyclient").catch(() => {});
      return;
    }
    await route.continue().catch(() => {});
  });
}

export async function shutdownLiveSession({ close, sessions = [], detach, secrets, drafts } = {}) {
  try {
    if (typeof close === "function") await close();
  } catch {
    return { released: false };
  }
  for (const session of sessions) {
    await disposeFetchGuard(session);
  }
  if (typeof detach === "function") {
    try {
      await detach();
    } catch {
      // The browser has already closed.
    }
  }
  if (Array.isArray(secrets)) secrets.fill("");
  if (Array.isArray(drafts)) {
    for (const field of drafts) {
      if (field && typeof field === "object") field.value = "";
    }
  }
  return { released: true };
}

export function screenshotName(routePath, hostIndex = 1) {
  const path = publicPath(routePath, []);
  if (!path.startsWith("/pharos") || path.includes("/auth/")) return "";
  if (SCREENSHOT_FILES[path]) return SCREENSHOT_FILES[path];
  const bare = path.split("?")[0];
  if (!isHostPath(bare)) return "";
  const suffix = HOST_SETTINGS_PATH.test(path) ? "-settings" : "";
  const index = Number.isInteger(hostIndex) && hostIndex > 0 && hostIndex < 100 ? hostIndex : 1;
  return `host-${String(index).padStart(2, "0")}${suffix}.png`;
}

export function repoRootFromScripts() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}
