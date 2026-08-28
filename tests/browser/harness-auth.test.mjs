import { test } from "node:test";
import assert from "node:assert/strict";
import http from "node:http";
import {
  mergeFleetAuthHeaders,
  withFleetRequestOptions,
  withoutFleetAuth,
} from "./harness.mjs";

const authHeader = { Authorization: "Bearer test-token" };

test("machine routes never receive fleet auth", async () => {
  process.env.PHAROS_BROWSER_ORIGIN = "http://127.0.0.1:18141";
  process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH = "";
  const { isMachineRoute, isPharosOriginUrl, shouldAttachFleetAuth } = await import(
    "./harness.mjs"
  );

  assert.equal(isMachineRoute("/report"), true);
  assert.equal(isMachineRoute("/register"), true);
  assert.equal(shouldAttachFleetAuth("/report"), false);
  const headers = mergeFleetAuthHeaders("/report", {}, authHeader);
  assert.equal(headers.Authorization, undefined);
  assert.equal(isPharosOriginUrl("https://evil.example/pharos"), false);
  assert.equal(shouldAttachFleetAuth("https://evil.example/hosts.json"), false);
  const crossOrigin = mergeFleetAuthHeaders("https://evil.example/hosts.json", {}, authHeader);
  assert.equal(crossOrigin.Authorization, undefined);
  assert.equal(shouldAttachFleetAuth("/hosts.json"), true);
  const human = mergeFleetAuthHeaders("/hosts.json", {}, authHeader);
  assert.equal(human.Authorization, "Bearer test-token");
});

test("request wrapper forces maxRedirects to zero", () => {
  process.env.PHAROS_BROWSER_ORIGIN = "http://127.0.0.1:18141";
  process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH = "";
  const options = withFleetRequestOptions(
    "/hosts.json",
    { maxRedirects: 10 },
    authHeader,
  );
  assert.equal(options.maxRedirects, 0);
  assert.equal(options.headers.Authorization, "Bearer test-token");
});

test("withoutFleetAuth strips inherited authorization headers", () => {
  const stripped = withoutFleetAuth({
    authorization: "Bearer leaked",
    Authorization: "Bearer leaked",
    "content-type": "application/json",
  });
  assert.equal(stripped.authorization, undefined);
  assert.equal(stripped.Authorization, undefined);
  assert.equal(stripped["content-type"], "application/json");
});

async function startRedirectServer(targetPath) {
  return await new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      if (request.url === "/human") {
        response.writeHead(302, { Location: targetPath });
        response.end();
        return;
      }
      if (request.url === targetPath) {
        response.writeHead(200);
        response.end(request.headers.authorization ?? "none");
        return;
      }
      response.writeHead(404);
      response.end();
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => resolve(server));
  });
}

async function closeServer(server) {
  await new Promise((resolve, reject) => {
    server.close((error) => (error ? reject(error) : resolve()));
  });
}

test("same-origin redirect to /report does not forward bearer", async () => {
  const server = await startRedirectServer("/report");
  const { port } = server.address();
  const origin = `http://127.0.0.1:${port}`;
  process.env.PHAROS_BROWSER_ORIGIN = origin;
  process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH = "";

  const humanUrl = `${origin}/human`;
  const firstHeaders = mergeFleetAuthHeaders(`${origin}/hosts.json`, {}, authHeader);
  const first = await fetch(humanUrl, { headers: firstHeaders, redirect: "manual" });
  assert.equal(first.status, 302);
  const location = first.headers.get("location");
  assert.equal(location, "/report");

  const redirectUrl = new URL(location, origin).href;
  const redirectHeaders = mergeFleetAuthHeaders(redirectUrl, firstHeaders, authHeader);
  assert.equal(redirectHeaders.Authorization, undefined);
  const second = await fetch(redirectUrl, { headers: redirectHeaders });
  assert.equal(await second.text(), "none");

  await closeServer(server);
});

test("same-origin redirect to /register does not forward bearer", async () => {
  const server = await startRedirectServer("/register");
  const { port } = server.address();
  const origin = `http://127.0.0.1:${port}`;
  process.env.PHAROS_BROWSER_ORIGIN = origin;
  process.env.PHAROS_BROWSER_DISABLE_FLEET_AUTH = "";

  const humanUrl = `${origin}/human`;
  const firstHeaders = mergeFleetAuthHeaders(`${origin}/hosts.json`, {}, authHeader);
  const first = await fetch(humanUrl, { headers: firstHeaders, redirect: "manual" });
  const location = first.headers.get("location");
  const redirectUrl = new URL(location, origin).href;
  const redirectHeaders = mergeFleetAuthHeaders(redirectUrl, firstHeaders, authHeader);
  const second = await fetch(redirectUrl, { headers: redirectHeaders });
  assert.equal(await second.text(), "none");

  await closeServer(server);
});
