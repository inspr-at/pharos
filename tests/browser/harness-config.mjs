import {
  isLoopbackHttpOrigin,
  pharosAddrForPort,
  pharosOriginForPort,
  readValidatedHarnessSessionFile,
  requireSocketAddr,
  validateExternalHarnessSessionFile,
} from "./harness-path.mjs";

/**
 * Resolve Playwright harness configuration. Internal mode ignores caller
 * base URL, origin, run dir, and session file paths; external mode validates
 * optional caller paths read-only.
 */
export async function resolvePlaywrightHarnessConfig(env = process.env) {
  const externalServer = env.PHAROS_BROWSER_EXTERNAL_SERVER === "1";
  const port = externalServer
    ? Number(env.PHAROS_BROWSER_PORT ?? 18081)
    : Number(env.PHAROS_BROWSER_INTERNAL_PORT);
  if (!externalServer) {
    if (env.PHAROS_BROWSER_INTERNAL_LAUNCHER !== "1") {
      throw new Error(
        "Internal browser tests must be started through tests/browser/run-playwright.mjs",
      );
    }
    if (!Number.isInteger(port) || port < 1 || port > 65535) {
      throw new Error("PHAROS_BROWSER_INTERNAL_PORT must be a generated TCP port");
    }
  }
  const pharosAddr = pharosAddrForPort(port);
  requireSocketAddr("PHAROS_ADDR", pharosAddr);
  requireSocketAddr("PHAROS_PUBLIC_ADDR", pharosAddr);
  const generatedBaseURL = pharosOriginForPort(port);
  const generatedOrigin = new URL(generatedBaseURL).origin;

  let baseURL;
  let origin;
  let fleetAuthAllowed;
  let harnessEnvFile;
  let ownedSessionFile;
  let runDir;

  if (externalServer) {
    baseURL = env.PHAROS_BROWSER_BASE_URL ?? generatedBaseURL;
    const parsedBaseURL = new URL(baseURL);
    if (
      parsedBaseURL.username ||
      parsedBaseURL.password ||
      parsedBaseURL.search ||
      parsedBaseURL.hash ||
      (parsedBaseURL.pathname && parsedBaseURL.pathname !== "/")
    ) {
      throw new Error("PHAROS_BROWSER_BASE_URL must be an origin-only URL without credentials");
    }
    origin = parsedBaseURL.origin;
    baseURL = origin;
    fleetAuthAllowed =
      origin === generatedOrigin && isLoopbackHttpOrigin(baseURL);
    if (fleetAuthAllowed) {
      if (!env.PHAROS_BROWSER_HARNESS_ENV_FILE) {
        throw new Error(
          "External loopback browser tests with fleet auth require PHAROS_BROWSER_HARNESS_ENV_FILE",
        );
      }
      harnessEnvFile = validateExternalHarnessSessionFile(env.PHAROS_BROWSER_HARNESS_ENV_FILE);
      const session = readValidatedHarnessSessionFile(harnessEnvFile, origin);
      if (!session) {
        throw new Error("External browser harness session is empty");
      }
      runDir = session.runDir;
      ownedSessionFile = false;
    } else {
      harnessEnvFile = undefined;
      ownedSessionFile = false;
      runDir = undefined;
    }
  } else {
    baseURL = generatedBaseURL;
    origin = generatedOrigin;
    fleetAuthAllowed = isLoopbackHttpOrigin(origin);
    harnessEnvFile = validateExternalHarnessSessionFile(
      env.PHAROS_BROWSER_INTERNAL_SESSION_FILE,
    );
    ownedSessionFile = true;
    runDir = undefined;
  }

  const webServerEnv = {
    PHAROS_ADDR: pharosAddr,
    PHAROS_PUBLIC_ADDR: pharosAddr,
    PHAROS_BROWSER_HARNESS_ENV_FILE: harnessEnvFile,
    PHAROS_BROWSER_DISPATCH_PORT: "",
    PHAROS_BROWSER_INTERNAL: externalServer ? "" : "1",
  };
  if (ownedSessionFile) {
    webServerEnv.PHAROS_BROWSER_HARNESS_OWNED_SESSION = "1";
  }

  return {
    externalServer,
    port,
    pharosAddr,
    generatedBaseURL,
    generatedOrigin,
    baseURL,
    origin,
    fleetAuthAllowed,
    harnessEnvFile,
    ownedSessionFile,
    runDir,
    webServerEnv,
  };
}
