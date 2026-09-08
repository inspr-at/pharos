import { defineConfig, devices } from "@playwright/test";
import { allocateLoopbackPort } from "./tests/browser/harness-path.mjs";

const port = Number(process.env.PHAROS_BROWSER_INTERNAL_PORT ?? (await allocateLoopbackPort()));
process.env.PHAROS_BROWSER_INTERNAL_PORT = String(port);
process.env.PHAROS_BROWSER_INTERNAL_LAUNCHER = "1";

const baseURL = `http://127.0.0.1:${port}`;

export default defineConfig({
  testDir: "./tests/browser",
  testMatch: "**/flow-host.spec.mjs",
  fullyParallel: false,
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["line"], ["html", { open: "never" }]] : "line",
  use: {
    baseURL,
    trace: "off",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    colorScheme: "light",
    reducedMotion: "reduce",
    locale: "en-GB",
    timezoneId: "Europe/Vienna",
  },
  projects: [
    {
      name: "flow-host-chromium",
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } },
    },
  ],
  webServer: {
    command: "bash tests/browser/start-flow-host-harness.sh",
    env: {
      ...process.env,
      PHAROS_BROWSER_INTERNAL_PORT: String(port),
      PHAROS_BROWSER_INTERNAL_LAUNCHER: "1",
    },
    url: `${baseURL}/healthz`,
    reuseExistingServer: false,
    gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
    timeout: 60_000,
  },
});
