import fs from "node:fs";
import http from "node:http";

const SYSTEM_UPDATE_DISPATCH_PATH =
  "/repos/markus-barta/nixcfg/actions/workflows/pharos-system-update.yml/dispatches";
const HOST_SETTINGS_DISPATCH_PATH =
  "/repos/markus-barta/nixcfg/actions/workflows/pharos-host-settings.yml/dispatches";
const HOST_REMOVAL_DISPATCH_PATH =
  "/repos/markus-barta/nixcfg/actions/workflows/pharos-host-removal.yml/dispatches";
const DISPATCH_PATHS = new Set([
  SYSTEM_UPDATE_DISPATCH_PATH,
  HOST_SETTINGS_DISPATCH_PATH,
  HOST_REMOVAL_DISPATCH_PATH,
]);

export function createDispatchMock(port, acceptFlagPath) {
  let attemptCount = 0;
  let acceptedCount = 0;

  const server = http.createServer((req, res) => {
    if (req.url === "/test/dispatch-attempts") {
      res.end(String(attemptCount));
      return;
    }
    if (req.url === "/test/dispatch-accepted") {
      res.end(String(acceptedCount));
      return;
    }
    if (req.url === "/test/harness-alive") {
      res.end("ok");
      return;
    }

    if (req.method === "POST" && DISPATCH_PATHS.has(req.url)) {
      attemptCount += 1;
      req.on("data", () => {});
      req.on("end", () => {
        const accept =
          fs.existsSync(acceptFlagPath) &&
          fs.readFileSync(acceptFlagPath, "utf8").trim() === "true";
        if (accept) {
          acceptedCount += 1;
          res.writeHead(204);
          res.end();
          return;
        }
        req.socket.destroy();
      });
      return;
    }

    res.writeHead(404);
    res.end();
  });

  return new Promise((resolve, reject) => {
    server.once("error", reject);
    server.listen(port, "127.0.0.1", () => {
      server.removeListener("error", reject);
      resolve({
        server,
        port,
        getAttemptCount: () => attemptCount,
        getAcceptedCount: () => acceptedCount,
        close: () =>
          new Promise((closeResolve, closeReject) => {
            server.close((error) => (error ? closeReject(error) : closeResolve()));
          }),
      });
    });
  });
}
