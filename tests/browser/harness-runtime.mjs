import { randomBytes } from "node:crypto";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";

export function fixtureManifestPathForPort(port) {
  return path.join(os.tmpdir(), `pharos-browser-fixture-${port}.json`);
}

export function isProcessAlive(pid) {
  if (!Number.isInteger(pid) || pid <= 0) {
    return false;
  }
  try {
    process.kill(pid, 0);
    return true;
  } catch {
    return false;
  }
}

export async function isHarnessAlive(dispatchMockBase) {
  if (!dispatchMockBase) {
    return false;
  }
  try {
    const response = await fetch(`${dispatchMockBase}/test/harness-alive`);
    return response.ok;
  } catch {
    return false;
  }
}

async function isManifestOwnerAlive(manifest) {
  if (!isProcessAlive(manifest.pid)) {
    return false;
  }
  if (manifest.pid === process.pid) {
    return true;
  }
  if (!manifest.dispatchMockBase) {
    return true;
  }
  return await isHarnessAlive(manifest.dispatchMockBase);
}

function openManifestSnapshot(fixtureManifestPath) {
  const pathStat = fs.lstatSync(fixtureManifestPath);
  if (!pathStat.isFile() || pathStat.isSymbolicLink()) {
    throw new Error(`browser harness fixture manifest must be a regular file: ${fixtureManifestPath}`);
  }
  const fd = fs.openSync(fixtureManifestPath, "r+");
  try {
    const fdStat = fs.fstatSync(fd);
    if (fdStat.dev !== pathStat.dev || fdStat.ino !== pathStat.ino) {
      throw new Error(`browser harness fixture manifest changed while opening: ${fixtureManifestPath}`);
    }
    return {
      fd,
      stat: fdStat,
      manifest: JSON.parse(fs.readFileSync(fd, "utf8")),
    };
  } catch (error) {
    fs.closeSync(fd);
    throw error;
  }
}

function pathStillReferencesSnapshot(fixtureManifestPath, snapshot) {
  try {
    const current = fs.lstatSync(fixtureManifestPath);
    return current.isFile()
      && !current.isSymbolicLink()
      && current.dev === snapshot.stat.dev
      && current.ino === snapshot.stat.ino;
  } catch {
    return false;
  }
}

function readManifest(fixtureManifestPath) {
  const snapshot = openManifestSnapshot(fixtureManifestPath);
  try {
    return snapshot.manifest;
  } finally {
    fs.closeSync(snapshot.fd);
  }
}

function manifestOwnedBy(manifest, owner) {
  return manifest.pid === owner.pid && manifest.nonce === owner.nonce;
}

export function createFixtureManifestOwner() {
  return { pid: process.pid, nonce: randomBytes(16).toString("hex") };
}

export async function claimFixtureManifest(fixtureManifestPath) {
  if (fs.existsSync(fixtureManifestPath)) {
    const staleCandidate = openManifestSnapshot(fixtureManifestPath);
    try {
      const alive = await isManifestOwnerAlive(staleCandidate.manifest);
      if (alive) {
        throw new Error(
          `browser harness fixture manifest is owned by a live process at ${fixtureManifestPath}`,
        );
      }
      if (!pathStillReferencesSnapshot(fixtureManifestPath, staleCandidate)) {
        throw new Error(
          `browser harness fixture manifest claim race at ${fixtureManifestPath}`,
        );
      }
      fs.unlinkSync(fixtureManifestPath);
    } finally {
      fs.closeSync(staleCandidate.fd);
    }
  }

  const owner = createFixtureManifestOwner();
  try {
    fs.writeFileSync(
      fixtureManifestPath,
      JSON.stringify(owner),
      { flag: "wx", mode: 0o600 },
    );
  } catch (error) {
    if (error?.code === "EEXIST") {
      throw new Error(
        `browser harness fixture manifest claim race at ${fixtureManifestPath}`,
      );
    }
    throw error;
  }
  return owner;
}

export function writeFixtureManifest(fixtureManifestPath, owner, data) {
  const snapshot = openManifestSnapshot(fixtureManifestPath);
  try {
    if (!manifestOwnedBy(snapshot.manifest, owner)) {
      throw new Error(`fixture manifest at ${fixtureManifestPath} is owned by another process`);
    }
    const document = Buffer.from(
      JSON.stringify({ ...data, pid: owner.pid, nonce: owner.nonce }),
    );
    fs.ftruncateSync(snapshot.fd, 0);
    fs.writeSync(snapshot.fd, document, 0, document.length, 0);
    fs.fsyncSync(snapshot.fd);
    if (!pathStillReferencesSnapshot(fixtureManifestPath, snapshot)) {
      throw new Error(`fixture manifest ownership changed during write: ${fixtureManifestPath}`);
    }
  } finally {
    fs.closeSync(snapshot.fd);
  }
}

export function releaseFixtureManifest(fixtureManifestPath, owner) {
  if (!owner || !fs.existsSync(fixtureManifestPath)) {
    return;
  }
  let snapshot;
  try {
    snapshot = openManifestSnapshot(fixtureManifestPath);
    if (
      manifestOwnedBy(snapshot.manifest, owner)
      && pathStillReferencesSnapshot(fixtureManifestPath, snapshot)
    ) {
      fs.unlinkSync(fixtureManifestPath);
    }
  } catch {
    // Best-effort release of loopback path reference.
  } finally {
    if (snapshot) {
      fs.closeSync(snapshot.fd);
    }
  }
}

export function waitForChildExit(child, timeoutMs) {
  return new Promise((resolve) => {
    if (!child) {
      resolve(true);
      return;
    }
    if (child.exitCode !== null || child.signalCode !== null) {
      resolve(true);
      return;
    }
    const timer = setTimeout(() => resolve(false), timeoutMs);
    const finish = () => {
      clearTimeout(timer);
      resolve(true);
    };
    child.once("exit", finish);
    child.once("error", finish);
  });
}

export async function terminateOwnedChild(child, options = {}) {
  const termMs = options.termMs ?? 2_000;
  const killMs = options.killMs ?? 1_000;
  if (!child || child.exitCode !== null || child.signalCode !== null) {
    return;
  }
  const pid = child.pid;
  child.kill("SIGTERM");
  const exited = await waitForChildExit(child, termMs);
  if (!exited && pid && isProcessAlive(pid)) {
    child.kill("SIGKILL");
    await waitForChildExit(child, killMs);
  }
}

export async function shutdownOwnedChildren({
  pharosd,
  mock,
  tempDir,
  fixtureManifestPath,
  fixtureManifestOwner,
  shuttingDown,
}) {
  if (shuttingDown?.value) {
    return;
  }
  if (shuttingDown) {
    shuttingDown.value = true;
  }
  await terminateOwnedChild(pharosd);
  if (mock) {
    try {
      await mock.close();
    } catch {
      // Ignore close races during shutdown.
    }
  }
  if (tempDir) {
    try {
      fs.rmSync(tempDir, { recursive: true, force: true });
    } catch {
      // Best-effort cleanup of value-bearing browser fixture files.
    }
  }
  if (fixtureManifestPath) {
    releaseFixtureManifest(fixtureManifestPath, fixtureManifestOwner);
  }
}
