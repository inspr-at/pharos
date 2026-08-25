import { spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createDispatchMock } from "./dispatch-fixture.mjs";

const browserDir = path.dirname(fileURLToPath(import.meta.url));
const pharosPort = Number(process.env.PHAROS_BROWSER_PHAROS_PORT ?? 18081);
const mockPort = Number(process.env.PHAROS_BROWSER_DISPATCH_PORT ?? 18981);
const tokenPath = path.join(browserDir, ".dispatch-token");
const acceptFlagPath = path.join(browserDir, ".dispatch-accept");

fs.writeFileSync(tokenPath, "browser-test-dispatch-token\n");
if (!fs.existsSync(acceptFlagPath)) {
  fs.writeFileSync(acceptFlagPath, "false");
}

const mock = createDispatchMock(mockPort, acceptFlagPath);

const pharosd = spawn("target/debug/pharosd", [], {
  env: {
    ...process.env,
    PHAROS_ALLOW_OPEN: "true",
    PHAROS_ADDR: `127.0.0.1:${pharosPort}`,
    PHAROS_PUBLIC_ADDR: `127.0.0.1:${pharosPort}`,
    PHAROS_MANAGED_SERVICE_MANIFEST_PATHS:
      "contracts/managed-service-declarations-v1.json",
    PHAROS_NIXCFG_DISPATCH_ENABLED: "true",
    PHAROS_SYSTEM_UPDATE_DISPATCH_ENABLED: "true",
    PHAROS_NIXCFG_DISPATCH_TOKEN_FILE: tokenPath,
    PHAROS_NIXCFG_DISPATCH_API_BASE: `http://127.0.0.1:${mockPort}`,
    RUST_LOG: "warn",
  },
  stdio: "inherit",
});

function shutdown(code = 0) {
  pharosd.kill("SIGTERM");
  mock.close().finally(() => process.exit(code));
}

pharosd.on("exit", (code, signal) => {
  if (signal) {
    shutdown(1);
    return;
  }
  shutdown(code ?? 0);
});

process.on("SIGINT", () => shutdown(0));
process.on("SIGTERM", () => shutdown(0));
