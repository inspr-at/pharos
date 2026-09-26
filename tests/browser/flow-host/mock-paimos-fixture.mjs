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

export const AEON_PROJECT_NODE_ID = "f9e96f2b-80d9-441f-8369-ba24fcf0acf4";

function journey() {
  return {
    project_node_id: AEON_PROJECT_NODE_ID,
    project_key: "PHAROS",
    node_key: "PRJ-17",
    tenant_slug: "inspr",
    profile: "professional",
    revision: 4,
    stage: "build",
    stage_source: "journey",
    imported: true,
    stages: [
      { key: "inspire", state: "done" },
      { key: "shape", state: "done" },
      { key: "requirements", state: "done" },
      { key: "plan", state: "done" },
      { key: "build", state: "current" },
      { key: "deploy", state: "later" },
      { key: "access", state: "later" },
      { key: "live", state: "later" },
    ],
    next_action: { key: "start_build", label: "Start build", stage: "build", available: true, reason: "" },
    requirements_revision: 2,
    requirements_digest_sha256:
      "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    requirements_approval_scope: "approvals.decide",
    launch_readiness: { can_admit: false, reason: "build not finished" },
    current_release_id: "5e6f7a8b-0000-4000-8000-00000000000a",
  };
}

// PHAROS-313: a loopback Aeon that answers only the bound project's journey.
export function createMockAeonFixture() {
  return new Promise((resolve, reject) => {
    const server = http.createServer((request, response) => {
      const url = new URL(request.url ?? "/", "http://127.0.0.1");
      if (url.pathname === `/api/projects/${AEON_PROJECT_NODE_ID}/journey`) {
        if (request.headers.authorization !== "Bearer 01234567890123456789012345678901") {
          response.writeHead(401, { "Content-Type": "application/json" });
          response.end('{"error":"unauthorized"}');
          return;
        }
        const payload = JSON.stringify(journey());
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
