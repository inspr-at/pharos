import fs from "node:fs";
import path from "node:path";
import { createDispatchMock } from "./dispatch-fixture.mjs";
import {
  claimFixtureManifest,
  fixtureManifestPathForPort,
  releaseFixtureManifest,
  writeFixtureManifest,
} from "./harness-runtime.mjs";

const dispatchPort = Number(process.env.PHAROS_BROWSER_DISPATCH_PORT);
if (!Number.isFinite(dispatchPort) || dispatchPort <= 0) {
  throw new Error("PHAROS_BROWSER_DISPATCH_PORT is required");
}

const runDir = process.env.PHAROS_BROWSER_RUN_DIR;
if (!runDir) {
  throw new Error("PHAROS_BROWSER_RUN_DIR is required");
}

const [, pharosPortRaw] = process.env.PHAROS_ADDR?.split(":") ?? [];
const pharosPort = Number(pharosPortRaw);
if (!Number.isInteger(pharosPort) || pharosPort < 1 || pharosPort > 65535) {
  throw new Error("PHAROS_ADDR must include a valid TCP port");
}

const acceptFlagPath = path.join(runDir, "dispatch-accept");
if (!fs.existsSync(acceptFlagPath)) {
  fs.writeFileSync(acceptFlagPath, "false\n", { mode: 0o600 });
}

const dispatchMockBase = `http://127.0.0.1:${dispatchPort}`;
const fixtureManifestPath = fixtureManifestPathForPort(pharosPort);
const fixtureManifestOwner = await claimFixtureManifest(fixtureManifestPath);
writeFixtureManifest(fixtureManifestPath, fixtureManifestOwner, {
  acceptFlagPath,
  dispatchMockBase,
});

const mock = await createDispatchMock(dispatchPort, acceptFlagPath);

function shutdown() {
  mock
    .close()
    .catch(() => {})
    .finally(() => {
      releaseFixtureManifest(fixtureManifestPath, fixtureManifestOwner);
      process.exit(0);
    });
}

process.on("SIGINT", shutdown);
process.on("SIGTERM", shutdown);
