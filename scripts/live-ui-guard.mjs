import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";

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
});
export const INVENTORY_ROUTES = Object.freeze([
  "/pharos/",
  "/pharos/map",
  "/pharos/alerts",
  "/pharos/backups",
  "/pharos/activity",
  "/pharos/services",
  "/pharos/settings/providers",
  "/pharos/agora",
  "/pharos/version",
]);

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
const ISSUER_POST_PREFIXES = Object.freeze([
  "/oauth",
  "/oidc",
  "/ui/login",
  "/ui/v2/login",
]);
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

export function browserLaunchOptions() {
  return { headless: true };
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

function isIssuerPostPath(pathname) {
  return ISSUER_POST_PREFIXES.some((prefix) => hasPathPrefix(pathname, prefix));
}

function deniedHost(hostname) {
  const host = hostname.toLowerCase().replace(/\.$/, "");
  return host === "pharos.agm.ng" || host.endsWith(".agm.ng") || host === "agm.ng";
}

function isIpHost(hostname) {
  return /^\d{1,3}(?:\.\d{1,3}){3}$/.test(hostname) || hostname.includes(":");
}

function decision(allow, reason, method, pathName) {
  return {
    allow,
    reason,
    method,
    path: pathName || "/",
  };
}

function carriesSecret(url, secrets) {
  if (url.username || url.password) return true;
  const values = [];
  if (url.username) values.push(url.username);
  if (url.password) values.push(url.password);
  for (const [key, value] of url.searchParams) {
    if (SECRET_QUERY_KEYS.has(key.toLowerCase())) return true;
    values.push(value);
  }
  for (const secret of secrets) {
    if (!secret) continue;
    if (values.includes(secret)) return true;
    if (secret.length >= 12 && url.href.includes(secret)) return true;
  }
  return false;
}

export function decideRequest(request, policy = {}) {
  const method = String(request?.method || "").toUpperCase();
  const secrets = Array.isArray(policy.secrets) ? policy.secrets : [];
  if (!method || method === "TRACE" || method === "CONNECT" || method === "TRACK") {
    return decision(false, "method", method || "?", "/");
  }
  let url;
  try {
    url = new URL(String(request?.url || ""));
  } catch {
    return decision(false, "url", method, "/");
  }
  if (carriesSecret(url, secrets)) {
    return decision(false, "secret-in-url", method, safePath(url));
  }
  if (url.protocol === "about:" && url.href === "about:blank") {
    return decision(true, "in-page", method, "/");
  }
  if (url.protocol === "blob:" || url.protocol === "data:") {
    return decision(true, "in-page", method, "/");
  }
  if (url.protocol !== "https:") {
    return decision(false, "scheme", method, safePath(url));
  }
  if (deniedHost(url.hostname) || isIpHost(url.hostname)) {
    return decision(false, "foreign-origin", method, safePath(url));
  }
  const pathname = safePath(url);
  if (!pathname) {
    return decision(false, "unsafe-path", method, "/");
  }
  if (isMachinePath(pathname)) {
    return decision(false, "machine-route", method, pathname);
  }
  const origin = url.origin.toLowerCase();
  if (APP_ORIGINS.has(origin)) {
    if (!isUnderBasePath(pathname)) {
      return decision(false, "outside-base-path", method, pathname);
    }
    if (!SAFE_METHODS.has(method)) {
      return decision(false, "app-mutation", method, pathname);
    }
    return decision(true, "app-read", method, pathname);
  }
  if (origin === PERSONAL_ISSUER_ORIGIN) {
    if (isIssuerAdminPath(pathname)) {
      return decision(false, "issuer-admin", method, pathname);
    }
    if (SAFE_METHODS.has(method)) {
      return decision(true, "issuer-read", method, pathname);
    }
    if (method === "POST" && isIssuerPostPath(pathname)) {
      return decision(true, "issuer-login", method, pathname);
    }
    return decision(false, "issuer-mutation", method, pathname);
  }
  return decision(false, "foreign-origin", method, pathname);
}

function safePath(url) {
  const pathname = url.pathname || "/";
  if (pathname.includes("%") || pathname.includes("\\") || pathname.includes("\0")) {
    return null;
  }
  return pathname;
}

export function publicLocation(rawUrl) {
  const url = new URL(rawUrl);
  return {
    origin: url.origin.toLowerCase(),
    pathname: url.pathname,
  };
}

export function sanitizeNavigationError(error, secrets = []) {
  let text = error instanceof Error ? error.message : String(error ?? "");
  text = text.replace(/[A-Za-z][A-Za-z0-9+.-]*:\/\/[^\s"'<>)]+/g, (match) => {
    try {
      const url = new URL(match);
      return `${url.origin}${url.pathname}`;
    } catch {
      return "[url]";
    }
  });
  for (const secret of secrets) {
    if (typeof secret === "string" && secret.length >= 4) {
      text = text.split(secret).join("[redacted]");
    }
  }
  return text.replace(/[\r\n\u0000-\u001f]+/g, " ").slice(0, 300);
}

export function classifyObservation({ location, status, probe, managerConfirmed = false }) {
  const onIssuer = location?.origin === PERSONAL_ISSUER_ORIGIN;
  const onApp = APP_ORIGINS.has(location?.origin) && isUnderBasePath(location?.pathname || "");
  const authPath = typeof location?.pathname === "string" && location.pathname.includes("/auth/");
  if (probe?.mfa) return "mfa-required";
  if (probe?.rateLimited || probe?.authRecovery) return "auth-required";
  if (probe?.passwordCount > 0 || probe?.loginForm || onIssuer || authPath) return "auth-required";
  if (probe?.noAccess || probe?.accessDenied) return "policy-denied";
  if (status === 401) return "auth-required";
  if (status === 403) return "policy-denied";
  if (!managerConfirmed && probe?.viewerOnly) return "policy-denied";
  if (onApp && probe?.managerShell && (status === 0 || (status >= 200 && status < 400))) {
    return "authenticated";
  }
  if (
    managerConfirmed &&
    onApp &&
    status >= 200 &&
    status < 400 &&
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
  if (!isUnderBasePath(location.pathname)) return false;
  if (location.pathname.includes("/auth/")) return false;
  if (location.origin === PERSONAL_ISSUER_ORIGIN) return false;
  if (!probe || probe.passwordCount > 0 || probe.mfa || probe.loginForm || probe.noAccess) {
    return false;
  }
  if (!probe.appShell && !probe.managerShell) return false;
  return true;
}

export function assertRuntimeEnvironment(env) {
  for (const name of FORBIDDEN_ENV) {
    if (env[name] !== undefined && env[name] !== "") {
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

export function repoRootFromScripts() {
  return path.resolve(path.dirname(fileURLToPath(import.meta.url)), "..");
}
