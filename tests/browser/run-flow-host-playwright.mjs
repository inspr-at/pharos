import { execSync, spawn } from "node:child_process";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { allocateLoopbackPort } from "./harness-path.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const playwrightExecutable = path.join(
  repoRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "playwright.cmd" : "playwright",
);

execSync("cargo build -p pharosd --locked", {
  cwd: repoRoot,
  env: {
    ...process.env,
    CARGO_TARGET_DIR: path.join(repoRoot, "target"),
  },
  stdio: "inherit",
});

const port = await allocateLoopbackPort();
const childEnv = {
  ...process.env,
  PHAROS_BROWSER_INTERNAL_PORT: String(port),
  PHAROS_BROWSER_INTERNAL_LAUNCHER: "1",
};

const playwright = spawn(
  playwrightExecutable,
  ["test", "-c", "playwright.flow-host.config.mjs", ...process.argv.slice(2)],
  { cwd: repoRoot, env: childEnv, stdio: "inherit" },
);

const exitCode = await new Promise((resolve, reject) => {
  playwright.once("error", reject);
  playwright.once("exit", (code, signal) => {
    if (signal) {
      resolve(signal === "SIGINT" ? 130 : 143);
      return;
    }
    resolve(code ?? 1);
  });
});

process.exitCode = exitCode;
