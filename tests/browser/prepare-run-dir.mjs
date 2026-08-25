import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";
import { assertHarnessOwnedRunDir } from "./harness-path.mjs";

const MACHINE_OPERATOR_SCHEMA = "inspr.pharos.machine-operator-token-generation.v2";
const runDir = assertHarnessOwnedRunDir(process.env.PHAROS_BROWSER_RUN_DIR);

function writeSecretFile(name, content) {
  const filePath = path.join(runDir, name);
  fs.writeFileSync(filePath, `${content}\n`, { mode: 0o600 });
}

function sha256Hex(value) {
  return crypto.createHash("sha256").update(value).digest("hex");
}

function hashGenerationField(digest, value) {
  const length = Buffer.alloc(8);
  length.writeBigUInt64BE(BigInt(value.length));
  digest.update(length);
  digest.update(value);
}

function machineOperatorGenerationId(operators) {
  const digest = crypto.createHash("sha256");
  digest.update(MACHINE_OPERATOR_SCHEMA);
  digest.update(Buffer.from([0]));
  const sorted = [...operators].sort((left, right) =>
    left.operator_ref.localeCompare(right.operator_ref),
  );
  for (const operator of sorted) {
    hashGenerationField(digest, operator.operator_ref);
    hashGenerationField(digest, operator.label);
    hashGenerationField(digest, operator.token_sha256);
    const scopes = [...operator.scopes].sort();
    const scopeCount = Buffer.alloc(8);
    scopeCount.writeBigUInt64BE(BigInt(scopes.length));
    digest.update(scopeCount);
    for (const scope of scopes) {
      hashGenerationField(digest, scope);
    }
  }
  return digest.digest("hex");
}

const readToken = crypto.randomBytes(32).toString("hex");
const writeToken = crypto.randomBytes(32).toString("hex");
const dispatchToken = crypto.randomBytes(32).toString("hex");

writeSecretFile("read-token", readToken);
writeSecretFile("write-token", writeToken);
writeSecretFile("dispatch-token", dispatchToken);
writeSecretFile("dispatch-accept", "false");
writeSecretFile("dispatch-settings-uncertain", "false");

const operators = [
  {
    operator_ref: "operator:browser-read",
    label: "browser read",
    token_sha256: sha256Hex(readToken),
    scopes: ["fleet:read"],
  },
  {
    operator_ref: "operator:browser-write",
    label: "browser write",
    token_sha256: sha256Hex(writeToken),
    scopes: ["fleet:read", "fleet:write"],
  },
];

const generation = machineOperatorGenerationId(operators);
const operatorRoot = path.join(runDir, "machine-operator");
fs.mkdirSync(operatorRoot, { recursive: true, mode: 0o700 });

const generationPath = path.join(operatorRoot, `generation-${generation}.json`);
const generationBody = JSON.stringify({
  schema: MACHINE_OPERATOR_SCHEMA,
  generation,
  operators,
});
fs.writeFileSync(generationPath, generationBody, { mode: 0o600 });

const currentPath = path.join(operatorRoot, "current");
fs.writeFileSync(currentPath, `${generation}\n`, { mode: 0o600 });

const KERNEL_VS_RESTART_PROJECTS = ["chromium-mobile"];
const SAVED_RESTART_LOADING_PROJECTS = ["chromium-desktop", "chromium-mobile"];
const PREFS_DECLARED_DRIFT_HOST = "bl-prefs-declared-drift";

function janusReadyHostManifest(hostName) {
  return {
    schema: "inspr.hostdash.config.v1",
    version: 1,
    slug: hostName,
    host: { name: hostName },
    wings: [],
    services: [],
    policy: {
      declaredOnly: true,
      runtimeStateOwner: "pharos",
      privilegedActions: {
        mode: "janus",
        janusRequired: true,
      },
    },
  };
}

function declaredDriftHostManifest(hostName) {
  return {
    schema: "inspr.hostdash.config.v1",
    version: 1,
    slug: hostName,
    host: {
      name: hostName,
      preferences: {
        accent: "#48b8a8",
        kind: "server",
        alerts: {
          suppress_down: false,
          suppress_backup: false,
          suppress_nix_freshness: false,
        },
      },
    },
    wings: [],
    services: [],
    policy: {
      declaredOnly: true,
      runtimeStateOwner: "pharos",
      privilegedActions: {
        mode: "janus",
        janusRequired: true,
      },
    },
  };
}

const manifestDir = path.join(runDir, "manifests");
fs.mkdirSync(manifestDir, { recursive: true, mode: 0o700 });
const janusReadyHostNames = [
  ...KERNEL_VS_RESTART_PROJECTS.map((project) => `bl-kernel-vs-restart-${project}`),
  ...SAVED_RESTART_LOADING_PROJECTS.map(
    (project) => `bl-saved-restart-loading-${project}`,
  ),
];
const manifestPaths = janusReadyHostNames.map((hostName) => {
  const manifestPath = path.join(manifestDir, `${hostName}.json`);
  fs.writeFileSync(
    manifestPath,
    `${JSON.stringify(janusReadyHostManifest(hostName), null, 2)}\n`,
    { mode: 0o600 },
  );
  return manifestPath;
});
const prefsDeclaredManifestPath = path.join(manifestDir, `${PREFS_DECLARED_DRIFT_HOST}.json`);
fs.writeFileSync(
  prefsDeclaredManifestPath,
  `${JSON.stringify(declaredDriftHostManifest(PREFS_DECLARED_DRIFT_HOST), null, 2)}\n`,
  { mode: 0o600 },
);
manifestPaths.push(prefsDeclaredManifestPath);
fs.writeFileSync(path.join(runDir, "manifest-paths"), manifestPaths.join(":"), {
  mode: 0o600,
});
