import { spawn } from "node:child_process";
import fs from "node:fs";
import http from "node:http";
import os from "node:os";
import path from "node:path";
import { createDispatchMock } from "./dispatch-fixture.mjs";
import {
  claimFixtureManifest,
  createFixtureManifestOwner,
  fixtureManifestPathForPort,
  isProcessAlive,
  releaseFixtureManifest,
  shutdownOwnedChildren,
  terminateOwnedChild,
  writeFixtureManifest,
} from "./harness-runtime.mjs";

const selftestPort = 19091;
const fixtureManifestPath = fixtureManifestPathForPort(selftestPort);

function assert(condition, message) {
  if (!condition) {
    throw new Error(message);
  }
}

async function testTerminateOwnedChildEscalates() {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"]);
  await terminateOwnedChild(child, { termMs: 100, killMs: 500 });
  assert(child.exitCode !== null || child.signalCode !== null, "child exited");
  assert(!isProcessAlive(child.pid), "child pid reaped");
}

async function testShutdownOwnedChildrenCleansArtifacts() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-browser-selftest-"));
  const tokenPath = path.join(tempDir, "dispatch-token");
  fs.writeFileSync(tokenPath, "token\n", { mode: 0o600 });
  const mock = await createDispatchMock(selftestPort + 1, tokenPath);
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"]);
  const shuttingDown = { value: false };
  const owner = await claimFixtureManifest(fixtureManifestPath);
  writeFixtureManifest(fixtureManifestPath, owner, {
    acceptFlagPath: tokenPath,
    dispatchMockBase: `http://127.0.0.1:${selftestPort + 1}`,
  });
  await shutdownOwnedChildren({
    pharosd: child,
    mock,
    tempDir,
    fixtureManifestPath,
    fixtureManifestOwner: owner,
    shuttingDown,
  });
  assert(shuttingDown.value, "shutdown marked complete");
  assert(!fs.existsSync(tempDir), "temp dir removed");
  assert(!fs.existsSync(fixtureManifestPath), "manifest removed");
  assert(!isProcessAlive(child.pid), "owned child reaped");
}

async function testClaimFixtureManifestRecoversStaleManifest() {
  const dispatchMockBase = `http://127.0.0.1:${selftestPort + 2}`;
  fs.writeFileSync(
    fixtureManifestPath,
    JSON.stringify({
      pid: 999999,
      nonce: "stale-nonce",
      dispatchMockBase,
    }),
    { mode: 0o600 },
  );
  const owner = await claimFixtureManifest(fixtureManifestPath);
  assert(owner.pid === process.pid, "owner pid recorded");
  assert(owner.nonce, "owner nonce recorded");
  releaseFixtureManifest(fixtureManifestPath, owner);
  assert(!fs.existsSync(fixtureManifestPath), "stale manifest removed");
}

async function testClaimFixtureManifestRefusesLiveOwner() {
  const liveOwner = await claimFixtureManifest(fixtureManifestPath);
  writeFixtureManifest(fixtureManifestPath, liveOwner, {
    dispatchMockBase: `http://127.0.0.1:${selftestPort + 3}`,
  });
  let refused = false;
  try {
    await claimFixtureManifest(fixtureManifestPath);
  } catch (error) {
    refused = /live process/.test(error.message);
  }
  releaseFixtureManifest(fixtureManifestPath, liveOwner);
  assert(refused, "live manifest refused");
}

async function testStaleRecoveryNeverDeletesAReplacementWinner() {
  const child = spawn(process.execPath, ["-e", "setInterval(() => {}, 1000)"]);
  let releaseProbe;
  const probeReleased = new Promise((resolve) => {
    releaseProbe = resolve;
  });
  let markProbeSeen;
  const probeSeen = new Promise((resolve) => {
    markProbeSeen = resolve;
  });
  const server = http.createServer((_req, res) => {
    markProbeSeen();
    void probeReleased.then(() => {
      res.writeHead(503);
      res.end();
    });
  });
  await new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(selftestPort + 3, "127.0.0.1", resolve);
  });
  fs.writeFileSync(
    fixtureManifestPath,
    JSON.stringify({
      pid: child.pid,
      nonce: "stale-candidate",
      dispatchMockBase: `http://127.0.0.1:${selftestPort + 3}`,
    }),
    { flag: "wx", mode: 0o600 },
  );

  const staleRecovery = claimFixtureManifest(fixtureManifestPath);
  await probeSeen;
  fs.unlinkSync(fixtureManifestPath);
  const winner = await claimFixtureManifest(fixtureManifestPath);
  releaseProbe();

  let raced = false;
  try {
    await staleRecovery;
  } catch (error) {
    raced = /claim race/.test(error.message);
  }
  const preserved = JSON.parse(fs.readFileSync(fixtureManifestPath, "utf8"));
  assert(raced, "stale recovery detected the replacement race");
  assert(preserved.nonce === winner.nonce, "replacement winner remained owned");

  releaseFixtureManifest(fixtureManifestPath, winner);
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
  await terminateOwnedChild(child, { termMs: 100, killMs: 500 });
}

async function testReleaseFixtureManifestIgnoresForeignOwner() {
  const owner = await claimFixtureManifest(fixtureManifestPath);
  const foreign = createFixtureManifestOwner();
  releaseFixtureManifest(fixtureManifestPath, foreign);
  assert(fs.existsSync(fixtureManifestPath), "foreign release ignored");
  releaseFixtureManifest(fixtureManifestPath, owner);
  assert(!fs.existsSync(fixtureManifestPath), "owner release removed manifest");
}

async function testClaimFixtureManifestExclusiveCreationRace() {
  const owner = await claimFixtureManifest(fixtureManifestPath);
  let raced = false;
  try {
    await claimFixtureManifest(fixtureManifestPath);
  } catch (error) {
    raced = /live process|race/.test(error.message);
  }
  releaseFixtureManifest(fixtureManifestPath, owner);
  assert(raced, "second exclusive claim refused");
}

async function testSpawnErrorFinalizesCleanup() {
  const tempDir = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-browser-selftest-"));
  const shuttingDown = { value: false };
  const owner = await claimFixtureManifest(fixtureManifestPath);
  const owned = {
    pharosd: spawn("target/debug/pharosd-nonexistent-binary", []),
    mock: null,
    tempDir,
    fixtureManifestPath,
    fixtureManifestOwner: owner,
    shuttingDown,
  };
  await new Promise((resolve) => {
    owned.pharosd.once("error", () => resolve());
  });
  await shutdownOwnedChildren(owned);
  assert(!fs.existsSync(tempDir), "temp dir removed after spawn error");
  assert(!fs.existsSync(fixtureManifestPath), "manifest removed after spawn error");
}

async function testOccupiedBootstrapPortReleasesManifest() {
  const occupiedPort = selftestPort + 4;
  const mockPort = selftestPort + 5;
  const occupied = http.createServer();
  await new Promise((resolve, reject) => {
    occupied.once("error", reject);
    occupied.listen(occupiedPort, "127.0.0.1", resolve);
  });
  const manifestPath = fixtureManifestPathForPort(occupiedPort);
  const child = spawn(process.execPath, ["tests/browser/pharosd-browser-server.mjs"], {
    cwd: path.resolve(path.dirname(new URL(import.meta.url).pathname), "../.."),
    env: {
      ...process.env,
      PHAROS_BROWSER_PHAROS_PORT: String(occupiedPort),
      PHAROS_BROWSER_DISPATCH_PORT: String(mockPort),
    },
    stdio: ["ignore", "ignore", "pipe"],
  });
  let stderr = "";
  child.stderr.setEncoding("utf8");
  child.stderr.on("data", (chunk) => {
    stderr += chunk;
  });
  const code = await new Promise((resolve, reject) => {
    child.once("error", reject);
    child.once("exit", resolve);
  });
  await new Promise((resolve, reject) => {
    occupied.close((error) => (error ? reject(error) : resolve()));
  });
  assert(code !== 0, "occupied bootstrap port failed startup");
  assert(/already in use/.test(stderr), "occupied port failure was reported");
  assert(!fs.existsSync(manifestPath), "occupied port failure released manifest");
}

async function main() {
  await testTerminateOwnedChildEscalates();
  await testShutdownOwnedChildrenCleansArtifacts();
  await testClaimFixtureManifestRecoversStaleManifest();
  await testClaimFixtureManifestRefusesLiveOwner();
  await testStaleRecoveryNeverDeletesAReplacementWinner();
  await testReleaseFixtureManifestIgnoresForeignOwner();
  await testClaimFixtureManifestExclusiveCreationRace();
  await testSpawnErrorFinalizesCleanup();
  await testOccupiedBootstrapPortReleasesManifest();
  console.log("pharosd-browser-server-selftest: ok");
}

main().catch((error) => {
  console.error(error.message);
  process.exit(1);
});
