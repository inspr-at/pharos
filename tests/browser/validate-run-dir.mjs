import { assertHarnessOwnedRunDir } from "./harness-path.mjs";

const args = process.argv.slice(2);
let runDir = process.env.PHAROS_BROWSER_RUN_DIR;
let requireOwned = false;

for (let index = 0; index < args.length; index += 1) {
  const arg = args[index];
  if (arg === "--require-owned") {
    requireOwned = true;
  } else if (arg === "--path" && args[index + 1]) {
    runDir = args[index + 1];
    index += 1;
  }
}

if (!runDir) {
  throw new Error("PHAROS_BROWSER_RUN_DIR is required");
}

if (requireOwned) {
  assertHarnessOwnedRunDir(runDir);
}
