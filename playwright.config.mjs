import path from "node:path";
import { defineConfig, devices } from "@playwright/test";

const port = process.env.PHAROS_BROWSER_PORT;
const runDir = process.env.PHAROS_BROWSER_RUN_DIR;
if (!port || !runDir) {
  throw new Error("Run the browser suite with `npm run test:browser`.");
}
const baseURL = `http://127.0.0.1:${port}`;

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
  webServer: {
    command: "target/debug/pharosd",
    env: {
      PHAROS_ADDR: `127.0.0.1:${port}`,
      PHAROS_ALLOW_OPEN: "true",
      PHAROS_DB: path.join(runDir, "hosts.json"),
      PHAROS_ALLOW_LOCAL_REGISTER: "true",
      PHAROS_REGISTRATION_TOKEN_FILE: path.join(runDir, "registration-token"),
      RUST_LOG: "warn",
    },
    url: `${baseURL}/readyz`,
    reuseExistingServer: false,
    timeout: 30_000,
  },
});
