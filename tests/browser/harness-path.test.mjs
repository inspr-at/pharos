import { test } from "node:test";
import assert from "node:assert/strict";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import {
  allocateHarnessRunDir,
  allocateHarnessSessionFile,
  assertHarnessOwnedRunDir,
  deleteOwnedHarnessSessionFile,
  OWNERSHIP_MARKER,
  RUN_DIR_PREFIX,
  SESSION_FILE_PREFIX,
  validateHarnessSession,
  validateExternalHarnessSessionFile,
} from "./harness-path.mjs";

test("allocateHarnessRunDir creates owned temp directory under tmp", () => {
  const runDir = allocateHarnessRunDir();
  assert.ok(fs.existsSync(path.join(runDir, OWNERSHIP_MARKER)));
  assert.ok(path.basename(runDir).startsWith(RUN_DIR_PREFIX));
  fs.rmSync(runDir, { recursive: true, force: true });
});

test("assertHarnessOwnedRunDir refuses paths outside tmp", () => {
  const outside = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-browser-outside-"));
  const fake = path.join(outside, "nested-run");
  fs.mkdirSync(fake, { recursive: true });
  try {
    assert.throws(
      () => assertHarnessOwnedRunDir(fake, { createMarker: true }),
      /harness prefix/,
    );
  } finally {
    fs.rmSync(outside, { recursive: true, force: true });
  }
});

test("assertHarnessOwnedRunDir refuses caller path without ownership marker", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), `${RUN_DIR_PREFIX}refuse-`));
  try {
    assert.throws(() => assertHarnessOwnedRunDir(parent), /not harness-owned/);
  } finally {
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("assertHarnessOwnedRunDir accepts path with ownership marker", () => {
  const runDir = allocateHarnessRunDir();
  assert.equal(assertHarnessOwnedRunDir(runDir), runDir);
  fs.rmSync(runDir, { recursive: true, force: true });
});

test("allocateHarnessSessionFile creates exclusive owned session file under tmp", () => {
  const sessionFile = allocateHarnessSessionFile();
  assert.ok(path.basename(sessionFile).startsWith(SESSION_FILE_PREFIX));
  assert.ok(sessionFile.endsWith(".json"));
  const stat = fs.statSync(sessionFile);
  assert.equal(stat.mode & 0o777, 0o600);
  deleteOwnedHarnessSessionFile(sessionFile);
  assert.equal(fs.existsSync(sessionFile), false);
});

test("validated harness sessions reject credential-bearing base URLs", () => {
  const runDir = allocateHarnessRunDir();
  try {
    assert.throws(
      () =>
        validateHarnessSession(
          {
            runDir,
            origin: "http://127.0.0.1:18141",
            baseURL: "http://user:secret@127.0.0.1:18141",
          },
          "http://127.0.0.1:18141",
        ),
      /base URL is invalid/,
    );
  } finally {
    fs.rmSync(runDir, { recursive: true, force: true });
  }
});

test("validateExternalHarnessSessionFile rejects symlink session paths", () => {
  const parent = fs.mkdtempSync(path.join(os.tmpdir(), `${RUN_DIR_PREFIX}symlink-parent-`));
  const target = path.join(parent, "session-target.json");
  fs.writeFileSync(target, "{}", { mode: 0o600 });
  const symlink = path.join(os.tmpdir(), `${SESSION_FILE_PREFIX}symlink.json`);
  try {
    if (fs.existsSync(symlink)) {
      fs.unlinkSync(symlink);
    }
    fs.symlinkSync(target, symlink);
    assert.throws(() => validateExternalHarnessSessionFile(symlink), /symlink/);
  } finally {
    if (fs.existsSync(symlink)) {
      fs.unlinkSync(symlink);
    }
    fs.rmSync(parent, { recursive: true, force: true });
  }
});

test("deleteOwnedHarnessSessionFile refuses hostile overwrite targets", () => {
  const hostile = path.join(os.tmpdir(), "important-session.json");
  fs.writeFileSync(hostile, "{}", { mode: 0o600 });
  try {
    assert.throws(() => deleteOwnedHarnessSessionFile(hostile), /harness prefix/);
  } finally {
    fs.unlinkSync(hostile);
  }
});

test("deleteOwnedHarnessSessionFile refuses non-0600 owned targets", () => {
  const sessionFile = allocateHarnessSessionFile();
  fs.chmodSync(sessionFile, 0o644);
  try {
    assert.throws(() => deleteOwnedHarnessSessionFile(sessionFile), /mode 0600/);
  } finally {
    fs.unlinkSync(sessionFile);
  }
});
