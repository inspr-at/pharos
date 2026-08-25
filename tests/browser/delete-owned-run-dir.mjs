import fs from "node:fs";
import { assertHarnessOwnedRunDir } from "./harness-path.mjs";

const runDir = process.argv[2];
const resolved = assertHarnessOwnedRunDir(runDir);
fs.rmSync(resolved, { recursive: true, force: false });
