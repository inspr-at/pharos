import http from "node:http";
import { URL } from "node:url";

const PROJECT_REF = "paimos:proj-9b2899fb59591130607952d66fcb5607";

function flowState() {
  const now = new Date();
  const evaluatedAt = now.toISOString();
  const freshUntil = new Date(now.getTime() + 10 * 60 * 1000).toISOString();
  return {
    evaluatedAt,
    identityContext: { project_ref: PROJECT_REF },
    header: {
      appName: "Paimos",
      projectName: "Harness project",
      userLabel: "Fixture",
      userInitials: "FX",
    },
    health: { status: "available" },
    delivery: {
      status: "draft",
      batchRef: "batch-harness",
      baselineRef: "baseline-harness",
      baselineDigest:
        "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
    prerequisites: {
      requirementsBaseline: {
        status: "pass",
        gateKind: "requirements_baseline",
        evidenceRef: "paimos:ev-harness",
        observedAt: evaluatedAt,
        freshUntil,
      },
    },
    progress: {},
    executionModes: ["manual"],
    selectedExecutionMode: "manual",
    selectedAction: "build",
  };
}

export function createMockPaimosFixture() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname === "/api/projects/17/baseline-batches/flow-state") {
        const payload = JSON.stringify(flowState());
        response.writeHead(200, {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(payload),
        });
        response.end(payload);
        return;
      }
      response.writeHead(404);
      response.end();
    });
    server.once("error", reject);
    server.listen(0, "127.0.0.1", () => {
      const port = server.address().port;
      resolve({
        server,
        origin: `http://127.0.0.1:${port}`,
        close: () =>
          new Promise((done, fail) => {
            server.close((error) => (error ? fail(error) : done()));
          }),
      });
    });
  });
}
