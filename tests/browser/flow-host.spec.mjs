import { test, expect } from "@playwright/test";

async function loginAsVerifiedHuman(page) {
  await page.goto("/auth/login?return_to=/");
  await page.waitForURL(/\/($|\?)/, { timeout: 20_000 });
}

async function waitForFlowProjection(page) {
  await expect
    .poll(
      async () =>
        page.evaluate(async () => {
          const response = await fetch("/flow/shell-state.json", {
            credentials: "same-origin",
            cache: "no-store",
          });
          if (!response.ok) {
            return null;
          }
          const payload = await response.json();
          return payload.shellState?.identityContext?.principal_ref ?? null;
        }),
      { timeout: 20_000 },
    )
    .not.toBeNull();
}

test("OIDC human session projects flow shell with host-verified identity", async ({
  page,
}) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  const payload = await page.evaluate(async () => {
    const response = await fetch("/flow/shell-state.json", {
      credentials: "same-origin",
      cache: "no-store",
    });
    return {
      ok: response.ok,
      body: await response.json(),
    };
  });
  expect(payload.ok).toBe(true);
  expect(payload.body.enabled).toBe(true);
  expect(payload.body.mountShell).toBe(true);
  expect(payload.body.shellState.identityContext.display.user_label).toBe(
    "Host-verified human",
  );

  await expect(page.locator("inspr-flow-shell[data-flow-host]")).toBeVisible();
  const bootstrapLoaded = await page.evaluate(() =>
    Array.from(document.querySelectorAll("script[type='module']")).some((script) =>
      script.src.includes("/assets/flow-host-bootstrap.mjs"),
    ),
  );
  expect(bootstrapLoaded).toBe(true);
});

test("review intent routes through HTTP with bootstrap wire shape", async ({
  page,
}) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  const result = await page.evaluate(async () => {
    const { createReviewBatchIntent } = await import(
      "/assets/vendor/flow-shell/src/intents.js"
    );
    const shellStateResponse = await fetch("/flow/shell-state.json", {
      credentials: "same-origin",
      cache: "no-store",
    });
    const shellPayload = await shellStateResponse.json();
    const intent = createReviewBatchIntent(shellPayload.shellState);
    const response = await fetch("/flow/intents", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: intent.type,
        identity: null,
        detail: intent,
      }),
    });
    return {
      status: response.status,
      body: await response.json(),
    };
  });

  expect(result.status).toBe(200);
  expect(result.body.location).toContain("/projects/17?tab=overview#baseline-batch");
  expect(result.body.executed).toBe(false);
});

test("start intent accepts nested identity from vendored detail shape", async ({
  page,
}) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  const result = await page.evaluate(async () => {
    const shellStateResponse = await fetch("/flow/shell-state.json", {
      credentials: "same-origin",
      cache: "no-store",
    });
    const shellPayload = await shellStateResponse.json();
    const identity = shellPayload.shellState.identityContext;
    const detail = {
      type: "flow:start-intent",
      detail: {
        action: "build",
        identity: {
          status: "present",
          principal_ref: identity.principal_ref,
          project_ref: identity.project_ref,
          binding_ref: identity.binding_ref,
          context_revision: identity.context_revision,
          actor_kind: "human",
          expires_at: identity.expires_at,
          fresh_until: identity.fresh_until,
        },
      },
    };
    const nested = detail?.detail?.identity ?? detail?.identity;
    const response = await fetch("/flow/intents", {
      method: "POST",
      credentials: "same-origin",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        type: detail.type,
        identity: nested,
        detail,
      }),
    });
    return {
      status: response.status,
      body: await response.json(),
    };
  });

  expect(result.status).toBe(200);
  expect(result.body.error).toBeUndefined();
});
