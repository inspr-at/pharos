import http from "node:http";

const port = Number(process.env.PHAROS_BROWSER_DISPATCH_PORT);
if (!Number.isFinite(port) || port <= 0) {
  throw new Error("PHAROS_BROWSER_DISPATCH_PORT is required");
}

http
  .createServer((request, response) => {
    request.on("data", () => {});
    request.on("end", () => {
      const failSettings = request.url?.includes("pharos-host-settings") ?? false;
      response.writeHead(failSettings ? 503 : 204);
      response.end();
    });
  })
  .listen(port, "127.0.0.1");
