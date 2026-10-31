// Runs the browser suite against a freshly built pharosd. Page assets are
// embedded in the binary, so a stale build would test the wrong page
// (PHAROS-312). Each run gets its own loopback port and throwaway store.
import { execFileSync, spawnSync } from "node:child_process";
import fs from "node:fs";
import net from "node:net";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");

function freeLoopbackPort() {
  return new Promise((resolve, reject) => {
    const server = net.createServer();
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const { port } = server.address();
      server.close(() => resolve(port));
    });
  });
}

execFileSync("cargo", ["build", "-p", "pharosd", "--locked"], {
  cwd: repoRoot,
  env: { ...process.env, CARGO_TARGET_DIR: path.join(repoRoot, "target") },
  stdio: "inherit",
});

const runDir = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-browser-"));
let status = 1;
try {
  const result = spawnSync(
    path.join(repoRoot, "node_modules", ".bin", "playwright"),
    ["test", ...process.argv.slice(2)],
    {
      cwd: repoRoot,
      stdio: "inherit",
      env: {
        ...process.env,
        PHAROS_BROWSER_PORT: String(await freeLoopbackPort()),
        PHAROS_BROWSER_RUN_DIR: runDir,
      },
    },
  );
  status = result.status ?? 1;
} finally {
  fs.rmSync(runDir, { recursive: true, force: true });
}
process.exit(status);
