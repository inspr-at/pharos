import { assertHarnessOwnedRunDir } from "./harness-path.mjs";

const LOOPBACK_DISPATCH_ORIGIN =
  /^http:\/\/(?:127\.0\.0\.1|localhost):\d{1,5}$/;

function requireSocketAddr(name, value) {
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

function requireLoopbackDispatchOrigin(value) {
  if (!LOOPBACK_DISPATCH_ORIGIN.test(value)) {
    throw new Error(
      `PHAROS_NIXCFG_DISPATCH_API_BASE must be an exact loopback http origin: ${value}`,
    );
  }
}

requireSocketAddr("PHAROS_ADDR", process.env.PHAROS_ADDR);
requireSocketAddr("PHAROS_PUBLIC_ADDR", process.env.PHAROS_PUBLIC_ADDR ?? process.env.PHAROS_ADDR);

const dispatchPort = Number(process.env.PHAROS_BROWSER_DISPATCH_PORT);
if (!Number.isInteger(dispatchPort) || dispatchPort <= 0 || dispatchPort > 65535) {
  throw new Error(
    `PHAROS_BROWSER_DISPATCH_PORT must be a valid port number: ${process.env.PHAROS_BROWSER_DISPATCH_PORT}`,
  );
}

const apiBase = process.env.PHAROS_NIXCFG_DISPATCH_API_BASE;
requireLoopbackDispatchOrigin(apiBase);
if (apiBase !== `http://127.0.0.1:${dispatchPort}`) {
  throw new Error(
    `PHAROS_NIXCFG_DISPATCH_API_BASE must match the mock dispatch listener port: ${apiBase}`,
  );
}

assertHarnessOwnedRunDir(process.env.PHAROS_BROWSER_RUN_DIR);

if (process.env.PHAROS_BROWSER_HARNESS_TEST_FAIL_VALIDATION === "1") {
  throw new Error("injected harness validation failure");
}

if (process.env.PHAROS_ALLOW_OPEN !== "true") {
  throw new Error("PHAROS_ALLOW_OPEN=true is required for the browser harness on loopback");
}

if (process.env.PHAROS_HOST_REMOVAL_DISPATCH_ENABLED !== "true") {
  throw new Error(
    "PHAROS_HOST_REMOVAL_DISPATCH_ENABLED=true is required for declared-host cleanup in browser tests",
  );
}
