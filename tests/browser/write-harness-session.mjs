import {
  pharosOriginForPort,
  writeHarnessSessionFile,
} from "./harness-path.mjs";

const runDir = process.env.PHAROS_BROWSER_RUN_DIR;
const envFile = process.env.PHAROS_BROWSER_HARNESS_ENV_FILE;
if (!runDir || !envFile) {
  throw new Error("PHAROS_BROWSER_RUN_DIR and PHAROS_BROWSER_HARNESS_ENV_FILE are required");
}

const [, port] = process.env.PHAROS_ADDR?.split(":") ?? [];
if (!port) {
  throw new Error("PHAROS_ADDR must be set for harness session publication");
}

writeHarnessSessionFile(envFile, {
  runDir,
  origin: pharosOriginForPort(Number(port)),
  baseURL: pharosOriginForPort(Number(port)),
});
