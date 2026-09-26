import { spawn } from "node:child_process";
import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { fileURLToPath } from "node:url";
import { createMockOidcIssuer } from "./mock-oidc-issuer.mjs";
import { AEON_PROJECT_NODE_ID, createMockAeonFixture, createMockPaimosFixture } from "./mock-paimos-fixture.mjs";
import { operatorRef } from "./operator-ref.mjs";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../../..");
const port = Number(process.env.PHAROS_BROWSER_INTERNAL_PORT);
if (!Number.isInteger(port) || port < 1) {
  throw new Error("PHAROS_BROWSER_INTERNAL_PORT must be set to a generated TCP port");
}

const pharosAddr = `127.0.0.1:${port}`;
const runDir = fs.mkdtempSync(path.join(os.tmpdir(), "pharos-flow-harness-"));
fs.chmodSync(runDir, 0o700);

let shuttingDown = false;
let oidc;
let paimos;
let pharosd;

async function shutdown(code = 0) {
  if (shuttingDown) {
    return;
  }
  shuttingDown = true;
  if (pharosd?.pid) {
    pharosd.kill("SIGTERM");
  }
  await Promise.allSettled([oidc?.close(), paimos?.close()]);
  try {
    fs.rmSync(runDir, { recursive: true, force: true });
  } catch {
    // best effort
  }
  process.exit(code);
}

process.on("SIGINT", () => {
  void shutdown(0);
});
process.on("SIGTERM", () => {
  void shutdown(0);
});

try {
  const secretsDir = path.join(runDir, "secrets");
  fs.mkdirSync(secretsDir, { recursive: true, mode: 0o700 });

  const apiKeyPath = path.join(secretsDir, "paimos-api.key");
  fs.writeFileSync(apiKeyPath, "01234567890123456789012345678901", { mode: 0o600 });

  const manifestDir = path.join(runDir, "manifests");
  fs.mkdirSync(manifestDir, { recursive: true, mode: 0o700 });
  const hostName = "browser-retirement-owner";
  const manifestPath = path.join(manifestDir, `${hostName}.json`);
  fs.writeFileSync(
    manifestPath,
    `${JSON.stringify(
      {
        schema: "inspr.hostdash.config.v1",
        version: 1,
        slug: hostName,
        host: { name: hostName },
        wings: [],
        services: [],
        policy: {
          declaredOnly: true,
          runtimeStateOwner: "pharos",
          privilegedActions: { mode: "janus", janusRequired: true },
        },
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );

  oidc = await createMockOidcIssuer(runDir);
  // PHAROS-313: PHAROS_FLOW_HARNESS_UPSTREAM=aeon runs the same suite against a
  // loopback Aeon with the v2 config; the default stays classic.
  const upstream = process.env.PHAROS_FLOW_HARNESS_UPSTREAM === "aeon" ? "aeon" : "classic";
  paimos = upstream === "aeon" ? await createMockAeonFixture() : await createMockPaimosFixture();
  const operator = operatorRef(oidc.issuer, oidc.subject);

  const flowConfigPath = path.join(secretsDir, "flow-host.json");
  const flowConfig =
    upstream === "aeon"
      ? {
          schema: "inspr.pharos.flow-host-config.v2",
          schema_version: 2,
          enabled: true,
          host_id: "pharos-flow-harness",
          upstream: "aeon",
          aeon_origin: paimos.origin,
          api_key_file: apiKeyPath,
          instance_label: "Flow harness",
          tenant_slug: "inspr",
          bindings: [
            {
              project_node_id: AEON_PROJECT_NODE_ID,
              project_key: "PHAROS",
              label: "Harness project",
              hosts: [hostName],
              operator_refs: [operator],
            },
          ],
        }
      : {
          schema: "inspr.pharos.flow-host-config.v1",
          schema_version: 1,
          enabled: true,
          host_id: "pharos-flow-harness",
          paimos_origin: paimos.origin,
          api_key_file: apiKeyPath,
          instance_label: "Flow harness",
          bindings: [
            {
              project_id: 17,
              project_ref: "paimos:proj-9b2899fb59591130607952d66fcb5607",
              label: "Harness project",
              hosts: [hostName],
              operator_refs: [operator],
            },
          ],
        };
  fs.writeFileSync(flowConfigPath, `${JSON.stringify(flowConfig, null, 2)}\n`, { mode: 0o600 });

  fs.writeFileSync(
    path.join(runDir, "flow-harness.json"),
    `${JSON.stringify(
      {
        runDir,
        oidcIssuer: oidc.issuer,
        paimosOrigin: paimos.origin,
        operatorRef: operator,
        upstream,
        reviewPath: upstream === "aeon" ? "/p/PHAROS?view=journey" : "/projects/17?tab=overview#baseline-batch",
        reviewRoute: upstream === "aeon" ? "aeon-project-journey" : "paimos-project-overview-baseline",
        startPath: upstream === "aeon" ? "/p/PHAROS?view=journey&stage=build" : "/projects/17?tab=overview#baseline-batch",
      },
      null,
      2,
    )}\n`,
    { mode: 0o600 },
  );

  process.env.PHAROS_BROWSER_FLOW_HARNESS_RUN_DIR = runDir;

  const redirectUri = `http://${pharosAddr}/auth/callback`;
  const pharosdBinary = path.join(repoRoot, "target/debug/pharosd");

  pharosd = spawn(pharosdBinary, [], {
    cwd: repoRoot,
    env: {
      ...process.env,
      PHAROS_ADDR: pharosAddr,
      PHAROS_PUBLIC_ADDR: pharosAddr,
      PHAROS_OIDC_ISSUER: oidc.issuer,
      PHAROS_OIDC_CLIENT_ID: oidc.clientId,
      PHAROS_OIDC_REDIRECT_URI: redirectUri,
      PHAROS_OIDC_CA_FILE: oidc.caFilePath,
      PHAROS_ALLOWED_OPERATORS: `operator-ref:${operator}`,
      PHAROS_FLOW_CONFIG_FILE: flowConfigPath,
      PHAROS_FLOW_ALLOW_LOOPBACK_ORIGIN: "true",
      PHAROS_MANIFEST_PATHS: manifestPath,
      PHAROS_RETIREMENT_OWNER_HOST: hostName,
      PHAROS_REQUIRE_BEACON_TOKEN: "false",
      PHAROS_BROWSER_FLOW_HARNESS_RUN_DIR: runDir,
      RUST_LOG: process.env.RUST_LOG ?? "warn",
    },
    stdio: "inherit",
  });

  pharosd.on("exit", (code, signal) => {
    void shutdown(signal ? 1 : code ?? 0);
  });
  pharosd.on("error", (error) => {
    console.error(error.message);
    void shutdown(1);
  });
} catch (error) {
  console.error(error instanceof Error ? error.message : String(error));
  await shutdown(1);
}
