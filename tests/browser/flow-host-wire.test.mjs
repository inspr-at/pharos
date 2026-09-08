import { test } from "node:test";
import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import path from "node:path";
import { fileURLToPath, pathToFileURL } from "node:url";

const repoRoot = path.resolve(path.dirname(fileURLToPath(import.meta.url)), "../..");
const vendorRoot = path.join(repoRoot, "crates/pharosd/assets/vendor/flow-shell");
const bootstrapPath = path.join(repoRoot, "crates/pharosd/assets/flow-host-bootstrap.mjs");

test("shipped bootstrap reads nested identity and unwraps main on denial", () => {
  const bootstrap = readFileSync(bootstrapPath, "utf8");
  assert.match(bootstrap, /detail\?\.detail\?\.identity/);
  assert.match(bootstrap, /data-flow-host-unavailable/);
  assert.match(bootstrap, /unwrapMainFromShell/);
  assert.match(bootstrap, /shell\.shellState\?\.identity/);
  assert.doesNotMatch(bootstrap, /shell\.hidden\s*=\s*true/);
});

test("review intent omits identity and stays server-resolvable", async () => {
  const { createReviewBatchIntent } = await import(
    pathToFileURL(path.join(vendorRoot, "src/intents.js")).href
  );
  const shellState = {
    delivery: {
      status: "draft",
      batchRef: "batch-test",
      baselineRef: "baseline-test",
      baselineDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
    selectedAction: "build",
  };
  const intent = createReviewBatchIntent(shellState);
  assert.equal(intent.type, "flow:review-batch");
  const wireBody = {
    type: intent.type,
    identity: intent.detail?.identity ?? intent.identity ?? null,
    detail: intent,
  };
  assert.equal(wireBody.identity, null);
  assert.equal(wireBody.detail.detail.batchRef, "batch-test");
});

test("vendored start intent nests identity under detail.detail", async () => {
  const { createStartIntent } = await import(
    pathToFileURL(path.join(vendorRoot, "src/intents.js")).href
  );
  const { confirmationSnapshot } = await import(
    pathToFileURL(path.join(vendorRoot, "src/state.js")).href
  );
  const now = Date.parse("2023-11-14T22:13:20.000Z");
  const shellState = {
    evaluatedAt: "2023-11-14T22:13:20.000Z",
    delivery: {
      status: "draft",
      batchRef: "batch-test",
      baselineRef: "baseline-test",
      baselineDigest: "sha256:0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
    },
    prerequisites: {
      requirementsBaseline: {
        status: "pass",
        gateKind: "requirements_baseline",
        evidenceRef: "paimos:ev-test",
        observedAt: "2023-11-14T22:13:20.000Z",
        freshUntil: "2023-11-14T22:23:20.000Z",
      },
    },
    executionModes: ["manual"],
    selectedExecutionMode: "manual",
    selectedAction: "build",
    identity: {
      status: "present",
      value: {
        hostId: "pharos-test",
        principalKind: "local_host",
        principalRef: "pharos-test:prin-abc",
        bindingRef: "pharos-test:bind-abc",
        projectRef: "paimos:proj-9b2899fb59591130607952d66fcb5607",
        actorKind: "human",
        contextRevision: "pharos-test:ctxrev-abc",
        issuedAt: "2023-11-14T22:13:20.000Z",
        expiresAt: "2023-11-15T06:13:20.000Z",
        freshUntil: "2023-11-14T22:20:00.000Z",
        display: {
          userLabel: "Host-verified human",
          userInitials: "HV",
          projectLabel: "Test project",
        },
      },
    },
  };
  const snapshot = confirmationSnapshot(shellState, {
    now,
    action: "build",
    executionMode: "manual",
  });
  const intent = createStartIntent(shellState, {
    confirmed: true,
    executionMode: "manual",
    action: "build",
    capturedSnapshot: snapshot,
    now,
  });
  assert.equal(intent.error, undefined);
  assert.equal(intent.type, "flow:start-intent");
  assert.equal(intent.detail.identity.status, "present");
  assert.equal(intent.detail.action, "build");
});
