import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { resolvePlaywrightHarnessConfig } from "./harness-config.mjs";
import {
  allocateHarnessRunDir,
  allocateHarnessSessionFile,
  deleteOwnedHarnessSessionFile,
  RUN_DIR_PREFIX,
  SESSION_FILE_PREFIX,
  writeHarnessSessionFile,
} from "./harness-path.mjs";

test("internal mode ignores hostile caller base URL, origin, run dir, and session path", async () => {
  const hostileSession = path.join(os.tmpdir(), `${SESSION_FILE_PREFIX}evil.json`);
  const generatedSession = allocateHarnessSessionFile();
  try {
    const config = await resolvePlaywrightHarnessConfig({
      PHAROS_BROWSER_BASE_URL: "https://evil.example/pharos",
      PHAROS_BROWSER_ORIGIN: "https://evil.example",
      PHAROS_BROWSER_RUN_DIR: path.join(os.tmpdir(), `${RUN_DIR_PREFIX}evil`),
      PHAROS_BROWSER_HARNESS_ENV_FILE: hostileSession,
      PHAROS_BROWSER_EXTERNAL_SERVER: "",
      PHAROS_BROWSER_INTERNAL_LAUNCHER: "1",
      PHAROS_BROWSER_INTERNAL_PORT: "18142",
      PHAROS_BROWSER_INTERNAL_SESSION_FILE: generatedSession,
    });

    assert.equal(config.baseURL, config.generatedBaseURL);
    assert.equal(config.origin, config.generatedOrigin);
    assert.equal(config.fleetAuthAllowed, true);
    assert.equal(config.runDir, undefined);
    assert.equal(config.harnessEnvFile, generatedSession);
    assert.notEqual(config.harnessEnvFile, hostileSession);
    assert.equal(config.ownedSessionFile, true);
    assert.equal(config.webServerEnv.PHAROS_BROWSER_INTERNAL, "1");
    assert.equal(config.webServerEnv.PHAROS_BROWSER_HARNESS_OWNED_SESSION, "1");
  } finally {
    deleteOwnedHarnessSessionFile(generatedSession);
  }
});

test("internal config refuses direct startup without the secure launcher", async () => {
  await assert.rejects(
    resolvePlaywrightHarnessConfig({ PHAROS_BROWSER_EXTERNAL_SERVER: "" }),
    /run-playwright\.mjs/,
  );
});

test("external mode disables fleet auth when caller base URL is not the generated loopback origin", async () => {
  const sessionFile = allocateHarnessSessionFile();
  try {
    const config = await resolvePlaywrightHarnessConfig({
      PHAROS_BROWSER_EXTERNAL_SERVER: "1",
      PHAROS_BROWSER_PORT: "18141",
      PHAROS_BROWSER_BASE_URL: "http://127.0.0.1:19999",
      PHAROS_BROWSER_HARNESS_ENV_FILE: sessionFile,
    });

    assert.equal(config.fleetAuthAllowed, false);
    assert.equal(config.origin, "http://127.0.0.1:19999");
    assert.notEqual(config.origin, config.generatedOrigin);
  } finally {
    deleteOwnedHarnessSessionFile(sessionFile);
  }
});

test("external mode rejects credential-bearing and non-origin base URLs", async () => {
  for (const baseURL of [
    "http://user:secret@127.0.0.1:18141",
    "http://127.0.0.1:18141/private",
    "http://127.0.0.1:18141/?token=secret",
    "http://127.0.0.1:18141/#secret",
  ]) {
    await assert.rejects(
      resolvePlaywrightHarnessConfig({
        PHAROS_BROWSER_EXTERNAL_SERVER: "1",
        PHAROS_BROWSER_PORT: "18141",
        PHAROS_BROWSER_BASE_URL: baseURL,
      }),
      /origin-only URL without credentials/,
    );
  }
});

test("external mode enables fleet auth only for exact generated loopback origin match", async () => {
  const sessionFile = allocateHarnessSessionFile();
  const runDir = allocateHarnessRunDir();
  try {
    writeHarnessSessionFile(sessionFile, {
      runDir,
      origin: "http://127.0.0.1:18141",
      baseURL: "http://127.0.0.1:18141",
    });
    const config = await resolvePlaywrightHarnessConfig({
      PHAROS_BROWSER_EXTERNAL_SERVER: "1",
      PHAROS_BROWSER_PORT: "18141",
      PHAROS_BROWSER_HARNESS_ENV_FILE: sessionFile,
    });

    assert.equal(config.baseURL, config.generatedBaseURL);
    assert.equal(config.origin, config.generatedOrigin);
    assert.equal(config.fleetAuthAllowed, true);
    assert.equal(config.runDir, runDir);
  } finally {
    deleteOwnedHarnessSessionFile(sessionFile);
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test("external fleet auth rejects session content that changes the approved origin", async () => {
  const sessionFile = allocateHarnessSessionFile();
  const runDir = allocateHarnessRunDir();
  try {
    writeHarnessSessionFile(sessionFile, {
      runDir,
      origin: "https://evil.example",
      baseURL: "https://evil.example",
    });
    await assert.rejects(
      resolvePlaywrightHarnessConfig({
        PHAROS_BROWSER_EXTERNAL_SERVER: "1",
        PHAROS_BROWSER_PORT: "18141",
        PHAROS_BROWSER_HARNESS_ENV_FILE: sessionFile,
      }),
      /approved origin/,
    );
  } finally {
    deleteOwnedHarnessSessionFile(sessionFile);
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test("external fleet auth requires a populated session file", async () => {
  await assert.rejects(
    resolvePlaywrightHarnessConfig({
      PHAROS_BROWSER_EXTERNAL_SERVER: "1",
      PHAROS_BROWSER_PORT: "18141",
    }),
    /require PHAROS_BROWSER_HARNESS_ENV_FILE/,
  );
});
