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
const ISSUER_POST_PREFIXES = Object.freeze([
  "/oauth",
  "/oidc",
  "/ui/login",
  "/ui/v2/login",
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

function listedSecrets(secrets) {
  return (Array.isArray(secrets) ? secrets : []).filter((secret) => typeof secret === "string" && secret.length > 0);
}

function decodeRepeated(value) {
  let current = String(value ?? "");
  for (let index = 0; index < 3; index += 1) {
    if (!current.includes("%")) break;
    try {
      const next = decodeURIComponent(current);
      if (next === current) break;
      current = next;
    } catch {
      break;
    }
  }
  return current;
}

function percentEncode(secret, alphabet) {
  return [...secret]
    .map((char) => {
      const hex = char.charCodeAt(0).toString(16).padStart(2, "0");
      return `%${alphabet === "upper" ? hex.toUpperCase() : hex}`;
    })
    .join("");
}

function secretVariants(secret) {
  const variants = new Set();
  const add = (value) => {
    if (typeof value === "string" && value.includes("%") && value.length >= 6) variants.add(value);
  };
  add(percentEncode(secret, "lower"));
  add(percentEncode(secret, "upper"));
  add(
    [...secret]
      .map((char, index) =>
        index % 2 === 0 ? `%${char.charCodeAt(0).toString(16).padStart(2, "0")}` : char,
      )
      .join(""),
  );
  add(secret.replace(/[@/?#&+=\s]/g, (char) => encodeURIComponent(char)));
  const mid = Math.ceil(secret.length / 2);
  add(`${percentEncode(secret.slice(0, mid), "lower")}${secret.slice(mid)}`);
  add(`${secret.slice(0, mid)}${percentEncode(secret.slice(mid), "upper")}`);
  add(percentEncode(percentEncode(secret, "lower"), "lower"));
  return [...variants];
}

function pieceMatchesSecret(piece, secrets) {
  const raw = String(piece ?? "");
  if (!raw) return false;
  const decoded = decodeRepeated(raw);
  const values = decoded === raw ? [raw] : [raw, decoded];
  for (const secret of listedSecrets(secrets)) {
    for (const value of values) {
      if (value === secret) return true;
      const segments = value.split("/").filter(Boolean);
      if (segments.some((segment) => segment === secret || decodeRepeated(segment) === secret)) return true;
      if (secret.length >= 4 && value.split("-").some((part) => part === secret)) return true;
      if (secret.length >= 8 && value.includes(secret)) return true;
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

function pathLeaks(url, raw, secrets) {
  return pieceMatchesSecret(url.pathname || "/", secrets) || pieceMatchesSecret(rawPath(raw, url), secrets);
}

function secretInUrl(raw, url, secrets) {
  if (url.username || url.password) return true;
  for (const key of url.searchParams.keys()) {
    if (SECRET_QUERY_KEYS.has(String(key).toLowerCase())) return true;
  }
  const pieces = [
    url.username,
    url.password,
    url.hash.startsWith("#") ? url.hash.slice(1) : url.hash,
    url.pathname,
    ...url.searchParams.values(),
  ];
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
    if (method === "POST" && isIssuerPostPath(pathname)) {
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
  let out = String(text ?? "");
  const needles = [];
  for (const secret of listedSecrets(secrets)) {
    needles.push(secret);
    for (const variant of secretVariants(secret)) needles.push(variant);
  }
  needles.sort((left, right) => right.length - left.length);
  for (const needle of needles) {
    if (!needle || !out.includes(needle)) continue;
    if (needle.length >= 4) out = out.split(needle).join("[redacted]");
    else {
      const pattern = new RegExp(`(^|[^A-Za-z0-9])${needle.replace(/[\\^$*+?.()|[\]{}]/g, "\\$&")}(?=$|[^A-Za-z0-9])`, "g");
      out = out.replace(pattern, "$1[redacted]");
    }
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
    probe.loginForm ||
    probe.authUiVisible ||
    probe.noAccess ||
    probe.accessDenied ||
    probe.accessRequest ||
    probe.viewerOnly
  ) {
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
  const labelOf = (element) =>
    `${element.getAttribute("aria-label") || ""} ${element.innerText || element.textContent || ""}`.slice(0, 180);
  const passkeyControl = (element) => /\b(passkey|security key|webauthn)\b/i.test(labelOf(element));
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
    webauthnChallenge: webauthnInputs.length > 0 || (!primaryLogin && challenge),
    passkeyAlternative: primaryLogin && visible("a, button").some(passkeyControl),
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
  const mfa = Boolean(surface.otpField || surface.webauthnChallenge);
  return {
    passwordCount: Math.min(2, Number(surface.passwordCount) || 0),
    mfa,
    passkeyAlternative: Boolean(surface.passkeyAlternative) && !mfa,
    noAccess: Boolean(surface.noAccess),
    accessDenied: Boolean(surface.accessDenied),
    accessRequest: Boolean(surface.accessRequest),
    managerShell: Boolean(surface.managerShell),
    viewerOnly: Boolean(surface.viewerOnly) && !surface.managerShell,
    appShell: Boolean(surface.appShell),
    authRecovery: Boolean(surface.authRecovery),
    rateLimited: Boolean(surface.rateLimited),
    loginForm: Boolean(surface.loginForm || surface.usernameField || Number(surface.passwordCount) > 0),
    authUiVisible: Boolean(
      Number(surface.passwordCount) > 0 ||
        surface.usernameField ||
        surface.otpField ||
        surface.webauthnChallenge ||
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
