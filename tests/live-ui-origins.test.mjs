import assert from "node:assert/strict";
import crypto from "node:crypto";
import test from "node:test";
import {
  LIVE_UI_ORIGINS,
  LIVE_UI_ORIGINS_ENV,
  LiveUiOriginsError,
  loadLiveUiOrigins,
  parseLiveUiOrigins,
  requireLiveUiOrigins,
} from "../scripts/live-ui-origins.mjs";
import { assertRuntimeEnvironment } from "../scripts/live-ui-guard.mjs";

const VALID = {
  schema: "inspr.pharos.live-ui-origins.v1",
  personal_app_origins: ["https://a.example.test"],
  issuer_origin: "https://b.example.test",
  family_origin: "https://c.example.test",
};
const bytes = (value) => Buffer.from(typeof value === "string" ? value : JSON.stringify(value));
const pinOf = (raw) => crypto.createHash("sha256").update(raw).digest("hex");
const refused = (fn) => assert.throws(fn, LiveUiOriginsError);

test("with no file the harness knows only fictional origins", () => {
  const origins = [
    ...LIVE_UI_ORIGINS.personalAppOrigins,
    LIVE_UI_ORIGINS.issuerOrigin,
    LIVE_UI_ORIGINS.familyOrigin,
  ];
  assert.ok(origins.length >= 3);
  for (const origin of origins) assert.ok(new URL(origin).hostname.endsWith(".example.test"), origin);
});

test("a file matching the pin supplies the origins", () => {
  const raw = bytes(VALID);
  const origins = parseLiveUiOrigins(raw, pinOf(raw));
  assert.deepEqual(origins.personalAppOrigins, ["https://a.example.test"]);
  assert.equal(origins.issuerOrigin, "https://b.example.test");
  assert.equal(origins.familyOrigin, "https://c.example.test");
  assert.equal(
    loadLiveUiOrigins({ [LIVE_UI_ORIGINS_ENV]: "/fixture" }, () => raw, pinOf(raw)).familyOrigin,
    "https://c.example.test",
  );
});

test("a file that differs from the pin can add no origin, and its text stays out of the error", () => {
  const raw = bytes({ ...VALID, issuer_origin: "https://attacker.example.test" });
  assert.throws(
    () => parseLiveUiOrigins(raw, pinOf(bytes(VALID))),
    (error) => error instanceof LiveUiOriginsError && !error.message.includes("attacker"),
  );
  assert.throws(() => parseLiveUiOrigins(raw), LiveUiOriginsError);
});

test("a pinned file with the wrong shape is refused", () => {
  for (const value of [
    "not json",
    "null",
    { ...VALID, schema: "other" },
    { ...VALID, extra: true },
    { ...VALID, personal_app_origins: [] },
    { ...VALID, personal_app_origins: "https://a.example.test" },
    { ...VALID, issuer_origin: "http://b.example.test" },
    { ...VALID, family_origin: "https://c.example.test/path" },
  ]) {
    const raw = bytes(value);
    refused(() => parseLiveUiOrigins(raw, pinOf(raw)));
  }
});

test("a named file that cannot be read is refused, and a real run needs one", () => {
  refused(() =>
    loadLiveUiOrigins({ [LIVE_UI_ORIGINS_ENV]: "/missing" }, () => {
      throw new Error("ENOENT");
    }),
  );
  refused(() => requireLiveUiOrigins({}));
  requireLiveUiOrigins({ [LIVE_UI_ORIGINS_ENV]: "/fixture" });
});

test("the guard lets the pinned file through and still refuses a direct origin", () => {
  assertRuntimeEnvironment({ [LIVE_UI_ORIGINS_ENV]: "/fixture" });
  assert.throws(() => assertRuntimeEnvironment({ PHAROS_LIVE_UI_ISSUER: "https://b.example.test" }));
});
