import fs from "node:fs";
import { fixtureManifestPathForPort } from "./harness-runtime.mjs";

const pharosPort = Number(
  process.env.PHAROS_BROWSER_PORT
    ?? process.env.PHAROS_BROWSER_INTERNAL_PORT
    ?? process.env.PHAROS_BROWSER_PHAROS_PORT
    ?? 18081,
);
export const externalServer = process.env.PHAROS_BROWSER_EXTERNAL_SERVER === "1";
export const fixtureManifestPath = fixtureManifestPathForPort(pharosPort);
export const baseURL =
  process.env.PHAROS_BROWSER_BASE_URL ?? `http://127.0.0.1:${pharosPort}`;

export function readFixtureManifestOrNull() {
  if (!fs.existsSync(fixtureManifestPath)) {
    return null;
  }
  return JSON.parse(fs.readFileSync(fixtureManifestPath, "utf8"));
}

export function requireFixtureManifest(test, reason) {
  if (externalServer) {
    test.skip(
      true,
      reason ??
        "requires local browser harness fixture manifest (PHAROS_BROWSER_EXTERNAL_SERVER=1)",
    );
    return null;
  }
  const manifest = readFixtureManifestOrNull();
  if (!manifest?.dispatchMockBase) {
    test.skip(
      true,
      reason ??
        `browser harness fixture manifest not found at ${fixtureManifestPath}`,
    );
    return null;
  }
  return manifest;
}
