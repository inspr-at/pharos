import { test } from "node:test";
import assert from "node:assert/strict";
import { spawn, spawnSync } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { fileURLToPath } from "node:url";
import {
  allocateHarnessRunDir,
  allocateHarnessSessionFile,
  OWNERSHIP_MARKER,
  RUN_DIR_PREFIX,
} from "./harness-path.mjs";

test("interrupted allocation removes the unmarked run directory", async () => {
  const allocator = spawn(process.execPath, [
    path.join(import.meta.dirname, "allocate-owned-run-dir.mjs"),
  ], {
    env: {
      ...process.env,
      PHAROS_BROWSER_TEST_PAUSE_AFTER_RUN_DIR_CREATE: "1",
    },
    stdio: ["ignore", "pipe", "pipe"],
  });
  const runDir = await new Promise((resolve, reject) => {
    let stderr = "";
    allocator.stderr.setEncoding("utf8");
    allocator.stderr.on("data", (chunk) => {
      stderr += chunk;
      const match = stderr.match(/created:(.+)\n/);
      if (match) resolve(match[1]);
    });
    allocator.once("error", reject);
    allocator.once("exit", (code) => {
      reject(new Error(`allocator exited before pause with ${code}: ${stderr}`));
    });
  });
  assert.equal(fs.existsSync(runDir), true);
  allocator.kill("SIGTERM");
  const exit = await new Promise((resolve) => allocator.once("exit", resolve));
  assert.equal(exit, 143);
  assert.equal(fs.existsSync(runDir), false);
});

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../");

function pharosAddrFromEnv() {
  const addr = process.env.PHAROS_ADDR ?? "127.0.0.1:18081";
  return addr;
}

test("startup validation failure removes tokens, operator generation, run dir, session file, and children", () => {
  const runDir = allocateHarnessRunDir();
  const sessionFile = allocateHarnessSessionFile();

  const result = spawnSync("bash", ["tests/browser/start-pharosd-for-tests.sh"], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PHAROS_ADDR: pharosAddrFromEnv(),
      PHAROS_PUBLIC_ADDR: pharosAddrFromEnv(),
      PHAROS_BROWSER_RUN_DIR: runDir,
      PHAROS_BROWSER_HARNESS_ENV_FILE: sessionFile,
      PHAROS_BROWSER_HARNESS_OWNED_SESSION: "1",
      PHAROS_BROWSER_HARNESS_TEST_FAIL_VALIDATION: "1",
      PHAROS_BROWSER_DISPATCH_PORT: "",
    },
    encoding: "utf8",
  });

  assert.notEqual(result.status, 0);
  assert.equal(fs.existsSync(runDir), false);
  assert.equal(fs.existsSync(sessionFile), false);
  assert.equal(fs.existsSync(path.join(runDir, "read-token")), false);
  assert.equal(fs.existsSync(path.join(runDir, "write-token")), false);
  assert.equal(fs.existsSync(path.join(runDir, "dispatch-token")), false);
  assert.equal(fs.existsSync(path.join(runDir, "machine-operator")), false);
  assert.equal(fs.existsSync(path.join(runDir, OWNERSHIP_MARKER)), false);
});
