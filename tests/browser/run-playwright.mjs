import { execSync, spawn } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  allocateHarnessSessionFile,
  allocateLoopbackPort,
  deleteOwnedHarnessSessionFile,
} from "./harness-path.mjs";

const externalServer = process.env.PHAROS_BROWSER_EXTERNAL_SERVER === "1";
const childEnv = { ...process.env };
let ownedSessionFile = null;
let playwright = null;
let receivedSignal = null;
const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const playwrightExecutable = path.join(
  repoRoot,
  "node_modules",
  ".bin",
  process.platform === "win32" ? "playwright.cmd" : "playwright",
);

const signalExitCode = (signal) => 128 + (signal === "SIGINT" ? 2 : 15);
const signalHandlers = new Map();
for (const signal of ["SIGINT", "SIGTERM"]) {
  const handler = () => {
    receivedSignal = signal;
    playwright?.kill(signal);
  };
  signalHandlers.set(signal, handler);
  process.once(signal, handler);
}

let exitCode = 1;
try {
  if (!externalServer) {
    // The start script launches target/debug/pharosd as is, and head.html and
    // foot.html are include_str! into that binary. Rebuild first so the suite
    // exercises the working tree, not whatever the last cargo build produced
    // (PHAROS-312). PHAROS_BROWSER_SKIP_BUILD=1 opts out for callers that just
    // built, e.g. a CI job whose earlier step already ran cargo build.
    if (process.env.PHAROS_BROWSER_SKIP_BUILD !== "1") {
      try {
        execSync("cargo build -p pharosd --locked", {
          cwd: repoRoot,
          env: { ...process.env, CARGO_TARGET_DIR: path.join(repoRoot, "target") },
          stdio: "inherit",
        });
      } catch (error) {
        // A shell that cannot find cargo exits 127; a real build failure has
        // already printed the compiler output above.
        const hint = error?.status === 127 || error?.code === "ENOENT"
          ? "cargo is not on PATH; run inside the devenv shell or set PHAROS_BROWSER_SKIP_BUILD=1 after building yourself"
          : "cargo build -p pharosd --locked failed";
        throw new Error(`browser suite refused to start: ${hint}`);
      }
    }
    // The start script prints the same line into the web server log, which
    // Playwright only shows on failure; print it here so every run records
    // which binary was under test.
    const binary = path.join(repoRoot, "target", "debug", "pharosd");
    const mtime = fs.statSync(binary).mtime.toISOString();
    let source = "unknown";
    try {
      source = execSync("git describe --always --dirty", { cwd: repoRoot, encoding: "utf8" }).trim();
    } catch {}
    console.log(`pharosd under test: ${binary} mtime=${mtime} source=${source}`);

    // These values are generated once by this launcher and inherited by every
    // Playwright config/worker process. Never reuse caller-supplied internal
    // harness state.
    delete childEnv.PHAROS_BROWSER_BASE_URL;
    delete childEnv.PHAROS_BROWSER_ORIGIN;
    delete childEnv.PHAROS_BROWSER_RUN_DIR;
    delete childEnv.PHAROS_BROWSER_HARNESS_ENV_FILE;
    delete childEnv.PHAROS_BROWSER_PORT;
    delete childEnv.PHAROS_BROWSER_INTERNAL_PORT;
    delete childEnv.PHAROS_BROWSER_INTERNAL_SESSION_FILE;
    delete childEnv.PHAROS_BROWSER_INTERNAL_LAUNCHER;

    ownedSessionFile = allocateHarnessSessionFile();
    childEnv.PHAROS_BROWSER_INTERNAL_PORT = String(await allocateLoopbackPort());
    childEnv.PHAROS_BROWSER_INTERNAL_SESSION_FILE = ownedSessionFile;
    childEnv.PHAROS_BROWSER_INTERNAL_LAUNCHER = "1";
  }

  if (receivedSignal) {
    exitCode = signalExitCode(receivedSignal);
  } else {
    playwright = spawn(
    playwrightExecutable,
    ["test", ...process.argv.slice(2)],
    { cwd: repoRoot, env: childEnv, stdio: "inherit" },
    );

    exitCode = await new Promise((resolve, reject) => {
      playwright.once("error", reject);
      playwright.once("exit", (code, signal) => {
        if (signal) {
          resolve(signalExitCode(signal));
          return;
        }
        resolve(code ?? 1);
      });
    });
  }
} finally {
  for (const [signal, handler] of signalHandlers) {
    process.removeListener(signal, handler);
  }
  if (ownedSessionFile && fs.existsSync(ownedSessionFile)) {
    deleteOwnedHarnessSessionFile(ownedSessionFile);
  }
}
process.exitCode = exitCode;
