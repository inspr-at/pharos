import { defineConfig, devices } from "@playwright/test";

const port = 18081;
const baseURL = process.env.PHAROS_BROWSER_BASE_URL ?? `http://127.0.0.1:${port}`;
const externalServer = process.env.PHAROS_BROWSER_EXTERNAL_SERVER === "1";

export default defineConfig({
  testDir: "./tests/browser",
  snapshotPathTemplate: "{testDir}/__screenshots__/{arg}-{projectName}{ext}",
  fullyParallel: false,
  forbidOnly: true,
  retries: process.env.CI ? 1 : 0,
  workers: 1,
  reporter: process.env.CI ? [["line"], ["html", { open: "never" }]] : "line",
  use: {
    baseURL,
    trace: "retain-on-failure",
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
      use: { ...devices["Desktop Chrome"], viewport: { width: 1440, height: 1000 } },
    },
    {
      name: "chromium-mobile",
      use: { ...devices["Pixel 7"] },
    },
  ],
  webServer: externalServer
    ? undefined
    : {
        command:
          `env PHAROS_ALLOW_OPEN=true PHAROS_ADDR=127.0.0.1:${port} ` +
          "PHAROS_PUBLIC_ADDR=127.0.0.1:18081 RUST_LOG=warn target/debug/pharosd",
        url: `http://127.0.0.1:${port}/healthz`,
        reuseExistingServer: false,
        timeout: 30_000,
      },
});
