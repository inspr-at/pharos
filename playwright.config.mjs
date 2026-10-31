import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

const port = process.env.PHAROS_BROWSER_PORT;
const barePort = process.env.PHAROS_BROWSER_BARE_PORT;
const flakyPort = process.env.PHAROS_BROWSER_FLAKY_PORT;
const runDir = process.env.PHAROS_BROWSER_RUN_DIR;
if (!port || !barePort || !flakyPort || !runDir) {
  throw new Error("Run the browser suite with `npm run test:browser`.");
}
const baseURL = `http://127.0.0.1:${port}`;

function server(serverPort, env) {
  return {
    command: "target/debug/pharosd",
    env: {
      PHAROS_ADDR: `127.0.0.1:${serverPort}`,
      PHAROS_ALLOW_OPEN: "true",
      RUST_LOG: "warn",
      ...env,
    },
    url: `http://127.0.0.1:${serverPort}/readyz`,
    reuseExistingServer: false,
    timeout: 30_000,
  };
}

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/*.spec.mjs",
  fullyParallel: false,
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["line"], ["html", { open: "never" }]] : "line",
  use: {
    baseURL,
    trace: "off",
    screenshot: "only-on-failure",
    colorScheme: "light",
    reducedMotion: "reduce",
    locale: "en-GB",
    timezoneId: "Europe/Vienna",
  },
  projects: [
    {
      name: "chromium-desktop",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } },
    },
    { name: "chromium-mobile", use: { ...devices["Pixel 7"] } },
  ],
  webServer: [
    // Every state, from fixtures.mjs.
    server(port, {
      PHAROS_DB: path.join(runDir, "hosts.json"),
      PHAROS_FLEET_DATA_FILE: path.join(runDir, "fleet.json"),
      PHAROS_HOST_PROBES_PATH: path.join(runDir, "host-probes.json"),
    }),
    // No data file configured.
    server(barePort, { PHAROS_DB: path.join(runDir, "bare-hosts.json") }),
    // A data file that a test breaks and repairs.
    server(flakyPort, {
      PHAROS_DB: path.join(runDir, "flaky-hosts.json"),
      PHAROS_FLEET_DATA_FILE: path.join(runDir, "flaky-fleet.json"),
    }),
  ],
});
