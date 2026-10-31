import crypto from "node:crypto";
import fs from "node:fs";

// The real origins stay out of this public repository. A run against them names
// a private file through PHAROS_LIVE_UI_ORIGINS. Its digest is pinned here, so
// neither the environment nor the file can add an origin where credentials get
// typed without a reviewed change to this line. With no file the harness knows
// only fictional origins and reaches nothing.
export const LIVE_UI_ORIGINS_ENV = "PHAROS_LIVE_UI_ORIGINS";
export const LIVE_UI_ORIGINS_SHA256 = "a78342508e9c1a660933af80096cdf8b49b5c33f81a005cf51805ed69f062ec2";

const SCHEMA = "inspr.pharos.live-ui-origins.v1";
const KEYS = ["family_origin", "issuer_origin", "personal_app_origins", "schema"];
const FICTIONAL = Object.freeze({
  personalAppOrigins: Object.freeze(["https://pharos.example.test", "https://flow.example.test"]),
  issuerOrigin: "https://auth.example.test",
  familyOrigin: "https://flow.example.test",
});

export class LiveUiOriginsError extends Error {
  constructor(reason) {
    super(`live UI origins refused: ${reason}`);
    this.code = "live-ui-origins";
  }
}

function httpsOrigin(value) {
  try {
    const url = new URL(value);
    return url.protocol === "https:" && url.origin === value;
  } catch {
    return false;
  }
}

export function parseLiveUiOrigins(raw, pin = LIVE_UI_ORIGINS_SHA256) {
  if (crypto.createHash("sha256").update(raw).digest("hex") !== pin) {
    throw new LiveUiOriginsError("the file does not match the pinned digest");
  }
  let parsed;
  try {
    parsed = JSON.parse(raw.toString("utf8"));
  } catch {
    throw new LiveUiOriginsError("the file is not JSON");
  }
  const keys = parsed && typeof parsed === "object" ? Object.keys(parsed).sort() : [];
  const origins = [parsed?.issuer_origin, parsed?.family_origin, ...(parsed?.personal_app_origins ?? [])];
  if (
    keys.join() !== KEYS.join() ||
    parsed.schema !== SCHEMA ||
    !Array.isArray(parsed.personal_app_origins) ||
    parsed.personal_app_origins.length === 0 ||
    !origins.every(httpsOrigin)
  ) {
    throw new LiveUiOriginsError("the file has the wrong shape");
  }
  return Object.freeze({
    personalAppOrigins: Object.freeze([...parsed.personal_app_origins]),
    issuerOrigin: parsed.issuer_origin,
    familyOrigin: parsed.family_origin,
  });
}

export function loadLiveUiOrigins(env = process.env, read = fs.readFileSync, pin = LIVE_UI_ORIGINS_SHA256) {
  const file = env[LIVE_UI_ORIGINS_ENV];
  if (!file) return FICTIONAL;
  let raw;
  try {
    raw = read(file);
  } catch {
    throw new LiveUiOriginsError("the file cannot be read");
  }
  return parseLiveUiOrigins(Buffer.from(raw), pin);
}

export const LIVE_UI_ORIGINS = loadLiveUiOrigins();

// A real run says what is missing, not that a fictional origin did not answer.
export function requireLiveUiOrigins(env = process.env) {
  if (!env[LIVE_UI_ORIGINS_ENV]) throw new LiveUiOriginsError(`${LIVE_UI_ORIGINS_ENV} is not set`);
}
