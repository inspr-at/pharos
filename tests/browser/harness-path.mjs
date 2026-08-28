import crypto from "node:crypto";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";

export const RUN_DIR_PREFIX = "pharos-browser-run-";
export const SESSION_FILE_PREFIX = `${RUN_DIR_PREFIX}session-`;
export const OWNERSHIP_MARKER = ".pharos-browser-harness-owned";

function tmpRoot() {
  return fs.realpathSync(os.tmpdir());
}

export function isUnderTmpRoot(candidate) {
  const resolved = fs.realpathSync(candidate);
  const root = tmpRoot();
  return resolved === root || resolved.startsWith(`${root}${path.sep}`);
}

export function hasExpectedRunDirPrefix(dirPath) {
  const base = path.basename(dirPath);
  return base.startsWith(RUN_DIR_PREFIX) || base.startsWith("pharos-browser-run.");
}

export function hasExpectedSessionFileName(filePath) {
  const base = path.basename(filePath);
  return base.startsWith(SESSION_FILE_PREFIX) && base.endsWith(".json");
}

function assertNotSymlink(filePath) {
  if (fs.lstatSync(filePath).isSymbolicLink()) {
    throw new Error(`Harness path must not be a symlink: ${filePath}`);
  }
}

function assertRegularFileMode(filePath, { requireStrictMode = false } = {}) {
  const stat = fs.lstatSync(filePath);
  if (!stat.isFile()) {
    throw new Error(`Harness session file must be a regular file: ${filePath}`);
  }
  if (requireStrictMode) {
    const mode = stat.mode & 0o777;
    if (mode !== 0o600) {
      throw new Error(`Harness-owned session file must be mode 0600: ${filePath}`);
    }
  }
}

export function ownershipMarkerPath(runDir) {
  return path.join(runDir, OWNERSHIP_MARKER);
}

export function assertHarnessOwnedRunDir(runDir, { createMarker = false } = {}) {
  if (!runDir || typeof runDir !== "string") {
    throw new Error("PHAROS_BROWSER_RUN_DIR is required");
  }
  const resolved = fs.realpathSync(runDir);
  if (!isUnderTmpRoot(resolved)) {
    throw new Error(`PHAROS_BROWSER_RUN_DIR must stay under the system temp directory: ${runDir}`);
  }
  if (!hasExpectedRunDirPrefix(resolved)) {
    throw new Error(
      `PHAROS_BROWSER_RUN_DIR must use the harness prefix (${RUN_DIR_PREFIX}*): ${runDir}`,
    );
  }
  const marker = ownershipMarkerPath(resolved);
  if (createMarker) {
    fs.mkdirSync(resolved, { recursive: true, mode: 0o700 });
    fs.writeFileSync(marker, `${process.pid}\n`, { mode: 0o600 });
    return resolved;
  }
  if (!fs.existsSync(marker)) {
    throw new Error(`PHAROS_BROWSER_RUN_DIR is not harness-owned (missing marker): ${runDir}`);
  }
  return resolved;
}

export function createHarnessRunDirCandidate() {
  const parent = tmpRoot();
  const suffix = crypto.randomBytes(6).toString("hex");
  const runDir = path.join(parent, `${RUN_DIR_PREFIX}${suffix}`);
  fs.mkdirSync(runDir, { recursive: true, mode: 0o700 });
  return runDir;
}

export function allocateHarnessRunDir() {
  return assertHarnessOwnedRunDir(createHarnessRunDirCandidate(), {
    createMarker: true,
  });
}

export function resolveHarnessRunDir(candidate) {
  if (!candidate) {
    return allocateHarnessRunDir();
  }
  return assertHarnessOwnedRunDir(candidate);
}

export function assertHarnessSessionFile(filePath, { requireOwned = false } = {}) {
  if (!filePath || typeof filePath !== "string") {
    throw new Error("PHAROS_BROWSER_HARNESS_ENV_FILE is required");
  }
  const parent = path.dirname(filePath);
  if (fs.existsSync(parent)) {
    assertNotSymlink(parent);
  }
  if (!fs.existsSync(filePath)) {
    throw new Error(`Harness session file does not exist: ${filePath}`);
  }
  assertNotSymlink(filePath);
  const resolved = fs.realpathSync(filePath);
  if (!isUnderTmpRoot(resolved)) {
    throw new Error(
      `PHAROS_BROWSER_HARNESS_ENV_FILE must stay under the system temp directory: ${filePath}`,
    );
  }
  if (!hasExpectedSessionFileName(resolved)) {
    throw new Error(
      `PHAROS_BROWSER_HARNESS_ENV_FILE must use the harness prefix (${SESSION_FILE_PREFIX}*.json): ${filePath}`,
    );
  }
  assertRegularFileMode(resolved, { requireStrictMode: requireOwned });
  return resolved;
}

export function validateExternalHarnessSessionFile(filePath) {
  return assertHarnessSessionFile(filePath, { requireOwned: false });
}

export function allocateHarnessSessionFile() {
  const parent = tmpRoot();
  const suffix = crypto.randomBytes(6).toString("hex");
  const filePath = path.join(parent, `${SESSION_FILE_PREFIX}${suffix}.json`);
  const fd = fs.openSync(
    filePath,
    fs.constants.O_WRONLY | fs.constants.O_CREAT | fs.constants.O_EXCL,
    0o600,
  );
  fs.closeSync(fd);
  return assertHarnessSessionFile(filePath, { requireOwned: true });
}

export function deleteOwnedHarnessSessionFile(filePath) {
  const resolved = assertHarnessSessionFile(filePath, { requireOwned: true });
  fs.unlinkSync(resolved);
}

export function allocateLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const address = server.address();
      if (!address || typeof address === "string") {
        server.close(() => reject(new Error("could not reserve loopback port")));
        return;
      }
      const { port } = address;
      server.close((closeError) => {
        if (closeError) {
          reject(closeError);
          return;
        }
        resolve(port);
      });
    });
  });
}

export function requireSocketAddr(name, value) {
  const socketAddrPattern = /^(?:\[[0-9a-fA-F:.]+\]|[0-9A-Za-z._-]+):\d+$/;
  if (!value || typeof value !== "string") {
    throw new Error(`${name} is required`);
  }
  if (value.includes("//") || value.includes("/")) {
    throw new Error(`${name} must be a numeric socket address, not a URL: ${value}`);
  }
  if (!socketAddrPattern.test(value)) {
    throw new Error(`${name} must be a numeric socket address (host:port): ${value}`);
  }
}

export function pharosAddrForPort(port) {
  return `127.0.0.1:${port}`;
}

export function pharosOriginForPort(port) {
  return `http://127.0.0.1:${port}`;
}

export function isLoopbackHttpOrigin(origin) {
  try {
    const url = new URL(origin);
    if (url.protocol !== "http:") {
      return false;
    }
    if (url.username || url.password) {
      return false;
    }
    if (url.search || url.hash) {
      return false;
    }
    const pathname = url.pathname;
    if (pathname && pathname !== "/") {
      return false;
    }
    return url.hostname === "127.0.0.1" || url.hostname === "localhost";
  } catch {
    return false;
  }
}

export function writeHarnessSessionFile(filePath, session) {
  const resolved = assertHarnessSessionFile(filePath, { requireOwned: true });
  const temporary = `${resolved}.tmp-${crypto.randomBytes(6).toString("hex")}`;
  try {
    fs.writeFileSync(temporary, `${JSON.stringify(session)}\n`, {
      flag: "wx",
      mode: 0o600,
    });
    fs.renameSync(temporary, resolved);
  } finally {
    if (fs.existsSync(temporary)) {
      fs.unlinkSync(temporary);
    }
  }
}

export function readHarnessSessionFile(filePath) {
  if (!filePath || !fs.existsSync(filePath)) {
    return null;
  }
  try {
    const resolved = validateExternalHarnessSessionFile(filePath);
    const body = fs.readFileSync(resolved, "utf8").trim();
    if (!body) {
      return null;
    }
    return JSON.parse(body);
  } catch {
    return null;
  }
}

export function validateHarnessSession(session, expectedOrigin) {
  if (!session || typeof session !== "object" || Array.isArray(session)) {
    throw new Error("Harness session must be an object");
  }
  const keys = Object.keys(session).sort();
  if (keys.join(",") !== "baseURL,origin,runDir") {
    throw new Error("Harness session has an unexpected schema");
  }
  if (
    typeof session.runDir !== "string" ||
    typeof session.origin !== "string" ||
    typeof session.baseURL !== "string"
  ) {
    throw new Error("Harness session fields must be strings");
  }
  if (!expectedOrigin || session.origin !== expectedOrigin) {
    throw new Error("Harness session origin does not match the approved origin");
  }
  let baseOrigin;
  try {
    const parsedBaseURL = new URL(session.baseURL);
    if (
      parsedBaseURL.username ||
      parsedBaseURL.password ||
      parsedBaseURL.search ||
      parsedBaseURL.hash ||
      (parsedBaseURL.pathname && parsedBaseURL.pathname !== "/")
    ) {
      throw new Error("Harness session base URL must be origin-only without credentials");
    }
    baseOrigin = parsedBaseURL.origin;
  } catch {
    throw new Error("Harness session base URL is invalid");
  }
  if (baseOrigin !== expectedOrigin) {
    throw new Error("Harness session base URL does not match the approved origin");
  }
  return {
    runDir: assertHarnessOwnedRunDir(session.runDir),
    origin: expectedOrigin,
    baseURL: session.baseURL,
  };
}

export function readValidatedHarnessSessionFile(filePath, expectedOrigin) {
  const session = readHarnessSessionFile(filePath);
  return session ? validateHarnessSession(session, expectedOrigin) : null;
}
