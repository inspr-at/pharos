import { defineConfig, devices } from "@playwright/test";
import { resolvePlaywrightHarnessConfig } from "./tests/browser/harness-config.mjs";

const harness = await resolvePlaywrightHarnessConfig();

process.env.PHAROS_BROWSER_PORT = String(harness.port);
process.env.PHAROS_BROWSER_BASE_URL = harness.baseURL;
process.env.PHAROS_BROWSER_ORIGIN = harness.fleetAuthAllowed ? harness.origin : "";
if (harness.harnessEnvFile) {
  process.env.PHAROS_BROWSER_HARNESS_ENV_FILE = harness.harnessEnvFile;
} else {
  delete process.env.PHAROS_BROWSER_HARNESS_ENV_FILE;
}
if (harness.runDir) {
  process.env.PHAROS_BROWSER_RUN_DIR = harness.runDir;
} else {
  delete process.env.PHAROS_BROWSER_RUN_DIR;
}
if (!harness.fleetAuthAllowed) {
  process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH = "1";
} else {
  delete process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH;
}

export default defineConfig({
  testDir: "./tests/browser",
  testIgnore: [
    "**/harness-path.test.mjs",
    "**/harness-auth.test.mjs",
    "**/harness-config.test.mjs",
    "**/harness-startup.test.mjs",
    "**/harness-redirect.test.mjs",
  ],
  snapshotPathTemplate: "{testDir}/__screenshots__/{arg}-{projectName}{ext}",
  fullyParallel: false,
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["line"], ["html", { open: "never" }]] : "line",
  use: {
    baseURL: harness.baseURL,
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
      name: "chromium-desktop",
      testIgnore: [
        "**/harness-path.test.mjs",
        "**/harness-auth.test.mjs",
        "**/harness-config.test.mjs",
        "**/harness-startup.test.mjs",
        "**/harness-redirect.test.mjs",
        "**/reset-fleet-between-projects.spec.mjs",
      ],
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } },
    },
    {
      name: "fleet-reset-between-projects",
      testMatch: "**/reset-fleet-between-projects.spec.mjs",
      dependencies: ["chromium-desktop"],
    },
    {
      name: "chromium-mobile",
      testIgnore: [
        "**/harness-path.test.mjs",
        "**/harness-auth.test.mjs",
        "**/harness-config.test.mjs",
        "**/harness-startup.test.mjs",
        "**/harness-redirect.test.mjs",
        "**/reset-fleet-between-projects.spec.mjs",
      ],
      dependencies: ["fleet-reset-between-projects"],
      use: { ...devices["Pixel 7"] },
    },
  ],
  webServer: harness.externalServer
    ? undefined
    : {
        command: "bash tests/browser/start-pharosd-for-tests.sh",
        env: harness.webServerEnv,
        url: `${harness.generatedBaseURL}/healthz`,
        reuseExistingServer: false,
        gracefulShutdown: { signal: "SIGTERM", timeout: 5000 },
        timeout: 30_000,
      },
});
