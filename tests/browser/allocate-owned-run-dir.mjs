import fs from "node:fs";
import {
  assertHarnessOwnedRunDir,
  createHarnessRunDirCandidate,
} from "./harness-path.mjs";

let allocatedRunDir;

function cleanupInterruptedAllocation() {
  if (!allocatedRunDir || !fs.existsSync(allocatedRunDir)) return;
  try {
    const owned = assertHarnessOwnedRunDir(allocatedRunDir);
    fs.rmSync(owned, { recursive: true, force: false });
  } catch {
    // Before the ownership marker exists, remove only the exact empty
    // directory this process just created. A non-empty directory fails safe.
    try {
      fs.rmdirSync(allocatedRunDir);
    } catch {}
  }
}

for (const signal of ["SIGINT", "SIGTERM"]) {
  process.once(signal, () => {
    cleanupInterruptedAllocation();
    process.exit(signal === "SIGINT" ? 130 : 143);
  });
}

try {
  allocatedRunDir = createHarnessRunDirCandidate();
  if (process.env.PHAROS_BROWSER_TEST_PAUSE_AFTER_RUN_DIR_CREATE === "1") {
    process.stderr.write(`created:${allocatedRunDir}\n`);
    setInterval(() => {}, 1_000);
    await new Promise(() => {});
  }
  const runDir = assertHarnessOwnedRunDir(allocatedRunDir, {
    createMarker: true,
  });
  process.stdout.write(runDir);
} catch (error) {
  cleanupInterruptedAllocation();
  throw error;
}
