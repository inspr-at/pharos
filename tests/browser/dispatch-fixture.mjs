import fs from "node:fs";
import http from "node:http";

const SYSTEM_UPDATE_DISPATCH_PATH =
  "/repos/markus-barta/nixcfg/actions/workflows/pharos-system-update.yml/dispatches";

export function createDispatchMock(port, acceptFlagPath) {
  let dispatchCount = 0;

  const server = http.createServer((req, res) => {
    if (req.url === "/test/dispatch-count") {
      res.end(String(dispatchCount));
      return;
    }

    if (req.method === "POST" && req.url === SYSTEM_UPDATE_DISPATCH_PATH) {
      req.on("data", () => {});
      req.on("end", () => {
        const accept =
          fs.existsSync(acceptFlagPath) &&
          fs.readFileSync(acceptFlagPath, "utf8").trim() === "true";
        if (accept) {
          dispatchCount += 1;
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

  server.listen(port, "127.0.0.1");
  return {
    server,
    getDispatchCount: () => dispatchCount,
    close: () =>
      new Promise((resolve, reject) => {
        server.close((error) => (error ? reject(error) : resolve()));
      }),
  };
}
