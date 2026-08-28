import { spawn } from "node:child_process";
import { randomBytes } from "node:crypto";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createDispatchMock } from "./dispatch-fixture.mjs";
import {
  claimFixtureManifest,
  fixtureManifestPathForPort,
  shutdownOwnedChildren,
  writeFixtureManifest,
} from "./harness-runtime.mjs";

const pharosPort = Number(process.env.PHAROS_BROWSER_PHAROS_PORT ?? 18081);
const mockPort = Number(process.env.PHAROS_BROWSER_DISPATCH_PORT ?? 18981);
const fixtureManifestPath = fixtureManifestPathForPort(pharosPort);

function assertPortFree(port) {
  return new Promise((resolve, reject) => {
    const probe = http.createServer();
    probe.once("error", (error) => {
      reject(
        new Error(
          `browser harness port ${port} is already in use: ${error.message}`,
        ),
      );
    });
    probe.listen(port, "127.0.0.1", () => {
      probe.close((error) => (error ? reject(error) : resolve()));
    });
  });
}

let owned = null;

async function main() {
  const fixtureManifestOwner = await claimFixtureManifest(fixtureManifestPath);
  const shuttingDown = { value: false };
  owned = {
    pharosd: null,
    mock: null,
    tempDir: null,
    fixtureManifestPath,
    fixtureManifestOwner,
    shuttingDown,
  };

  let finalizePromise = null;
  const finalize = (exitCode) => {
    if (!finalizePromise) {
      finalizePromise = shutdownOwnedChildren(owned).finally(() => {
        process.exit(exitCode);
      });
    }
    return finalizePromise;
  };

  try {
    await assertPortFree(pharosPort);
    await assertPortFree(mockPort);
    owned.tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-browser-"));
    fs.chmodSync(owned.tempDir, 0o700);

    const tokenPath = path.join(owned.tempDir, "dispatch-token");
    const acceptFlagPath = path.join(owned.tempDir, "dispatch-accept");
    fs.writeFileSync(tokenPath, `${randomBytes(24).toString("hex")}\n`, {
      mode: 0o600,
    });
    fs.writeFileSync(acceptFlagPath, "false", { mode: 0o600 });

    const dispatchMockBase = `http://127.0.0.1:${mockPort}`;
    owned.mock = await createDispatchMock(mockPort, acceptFlagPath);

    writeFixtureManifest(fixtureManifestPath, fixtureManifestOwner, {
      acceptFlagPath,
      dispatchMockBase,
    });

    owned.pharosd = spawn("target/debug/pharosd", [], {
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
        PHAROS_NIXCFG_DISPATCH_API_BASE: dispatchMockBase,
        RUST_LOG: "warn",
      },
      stdio: "inherit",
    });

    owned.pharosd.on("error", (error) => {
      console.error(error.message);
      void finalize(1);
    });

    owned.pharosd.on("exit", (code, signal) => {
      void finalize(signal ? 1 : code ?? 0);
    });

    process.on("SIGINT", () => {
      void finalize(0);
    });

    process.on("SIGTERM", () => {
      void finalize(0);
    });
  } catch (error) {
    await shutdownOwnedChildren(owned);
    throw error;
  }
}

main().catch(async (error) => {
  if (owned) {
    await shutdownOwnedChildren(owned);
  }
  console.error(error.message);
  process.exit(1);
});
