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

async function dispatchFlowIntent(page, intentKind) {
  const paimosOrigin = await page.evaluate(
    () => document.querySelector("inspr-flow-shell")?.dataset.flowPaimosOrigin ?? "",
  );
  let captured = null;
  await page.route("**/flow/intents**", async (route) => {
    const upstream = await route.fetch();
    const body = await upstream.json();
    captured = { status: upstream.status(), body };
    await route.fulfill({
      status: upstream.status(),
      contentType: "application/json",
      body: JSON.stringify(body),
    });
  });
  if (paimosOrigin) {
    await page.route(`${paimosOrigin}/**`, (route) => route.abort());
  }
  await page.evaluate(async (kind) => {
    const { createReviewBatchIntent, createStartIntent } = await import(
      "/assets/vendor/flow-shell/src/intents.js"
    );
    const { confirmationSnapshot } = await import(
      "/assets/vendor/flow-shell/src/state.js"
    );
    const shell = document.querySelector("inspr-flow-shell");
    const shellState = shell.shellState;
    const now = Date.now();

    let intent;
    if (kind === "review") {
      intent = createReviewBatchIntent(shellState);
    } else if (kind === "start") {
      const snapshot = confirmationSnapshot(shellState, {
        now,
        action: shellState.selectedAction ?? "build",
        executionMode: shellState.selectedExecutionMode ?? "manual",
      });
      intent = createStartIntent(shellState, {
        confirmed: true,
        executionMode: shellState.selectedExecutionMode ?? "manual",
        action: shellState.selectedAction ?? "build",
        capturedSnapshot: snapshot,
        now,
      });
      if (intent.error) {
        throw new Error(intent.error);
      }
    } else {
      throw new Error(`unknown intent kind: ${kind}`);
    }

    shell.dispatchEvent(
      new CustomEvent("flow-intent", {
        detail: intent,
        bubbles: true,
        composed: true,
      }),
    );
  }, intentKind);
  await expect.poll(() => captured, { timeout: 10_000 }).not.toBeNull();
  await page.unroute("**/flow/intents**");
  if (paimosOrigin) {
    await page.unroute(`${paimosOrigin}/**`);
  }
  return captured;
}

async function expectFleetMainVisible(page) {
  await expect(page.getByRole("heading", { name: "Fleet" })).toBeVisible();
}

async function expectShellChromeCollapsed(page) {
  await expect(page.locator("inspr-flow-shell[data-flow-host]")).toHaveAttribute(
    "data-flow-host-unavailable",
    "true",
  );
  const state = await page.evaluate(() => {
    const shell = document.querySelector("inspr-flow-shell");
    const main = document.querySelector("main");
    return {
      shellDisplay: shell ? getComputedStyle(shell).display : null,
      mainParent: main?.parentElement?.tagName ?? null,
      mainPrevious: main?.previousElementSibling?.tagName ?? null,
    };
  });
  expect(state.shellDisplay).toBe("none");
  expect(state.mainParent).not.toBe("INSPR-FLOW-SHELL");
  expect(state.mainPrevious).toBe("ASIDE");
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

test("unavailable projection keeps fleet main visible and collapses flow chrome", async ({
  page,
}) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  await page.route("**/flow/shell-state.json**", (route) =>
    route.fulfill({ status: 503, body: "unavailable" }),
  );
  await page.reload();
  await page.waitForTimeout(500);

  await expectFleetMainVisible(page);
  await expectShellChromeCollapsed(page);

  await page.unroute("**/flow/shell-state.json**");
  await page.reload();
  await waitForFlowProjection(page);
  await expect(
    page.locator("inspr-flow-shell[data-flow-host]:not([data-flow-host-unavailable])"),
  ).toBeVisible();
});

test("denied host scope keeps fleet main visible", async ({ page }) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  await page.route("**/flow/shell-state.json**", (route) =>
    route.fulfill({
      status: 200,
      contentType: "application/json",
      body: JSON.stringify({
        enabled: true,
        mountShell: false,
        unavailableReason: "access denied for requested host scope",
      }),
    }),
  );
  await page.reload();
  await page.waitForTimeout(500);

  await expectFleetMainVisible(page);
  await expectShellChromeCollapsed(page);
});

test("review intent routes through bootstrap flow-intent handling", async ({ page }) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  const result = await dispatchFlowIntent(page, "review");

  expect(result.status).toBe(200);
  expect(result.body.location).toContain("/projects/17?tab=overview#baseline-batch");
  expect(result.body.executed).toBe(false);
  expect(result.body.routed).toBe("paimos-project-overview-baseline");
});

test("start intent routes through bootstrap with exact navigation target", async ({
  page,
}) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  const paimosOrigin = await page.evaluate(
    () => document.querySelector("inspr-flow-shell")?.dataset.flowPaimosOrigin ?? "",
  );

  const result = await dispatchFlowIntent(page, "start");

  expect(result.status).toBe(200);
  expect(result.body.error).toBeUndefined();
  expect(result.body.routed).toBe("paimos-project-overview-baseline");
  expect(result.body.location).toBe(
    `${paimosOrigin.replace(/\/$/, "")}/projects/17?tab=overview#baseline-batch`,
  );
});

test("revoked start identity is rejected through bootstrap flow-intent handling", async ({
  page,
}) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/flow/intents") &&
      response.request().method() === "POST",
    { timeout: 10_000 },
  );
  await page.evaluate(async () => {
    const { createStartIntent } = await import(
      "/assets/vendor/flow-shell/src/intents.js"
    );
    const { confirmationSnapshot } = await import(
      "/assets/vendor/flow-shell/src/state.js"
    );
    const shell = document.querySelector("inspr-flow-shell");
    const shellState = shell.shellState;
    const now = Date.now();
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
    intent.detail.identity.principalRef = "pharos-test:revoked-principal";

    shell.dispatchEvent(
      new CustomEvent("flow-intent", {
        detail: intent,
        bubbles: true,
        composed: true,
      }),
    );
  });
  const response = await responsePromise;
  const body = await response.body();
  const result = {
    status: response.status(),
    body: JSON.parse(body.toString()),
  };

  expect(result.status).toBe(409);
  expect(result.body.error).toContain("mismatch");
});

test("stale start identity is rejected through bootstrap flow-intent handling", async ({
  page,
}) => {
  await loginAsVerifiedHuman(page);
  await page.goto("/");
  await waitForFlowProjection(page);

  const responsePromise = page.waitForResponse(
    (response) =>
      response.url().includes("/flow/intents") &&
      response.request().method() === "POST",
    { timeout: 10_000 },
  );
  await page.evaluate(async () => {
    const { createStartIntent } = await import(
      "/assets/vendor/flow-shell/src/intents.js"
    );
    const { confirmationSnapshot } = await import(
      "/assets/vendor/flow-shell/src/state.js"
    );
    const shell = document.querySelector("inspr-flow-shell");
    const shellState = shell.shellState;
    const now = Date.now();
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
    intent.detail.identity.expiresAt = "2000-01-01T00:00:00.000Z";

    shell.dispatchEvent(
      new CustomEvent("flow-intent", {
        detail: intent,
        bubbles: true,
        composed: true,
      }),
    );
  });
  const response = await responsePromise;
  const body = await response.body();
  const result = {
    status: response.status(),
    body: JSON.parse(body.toString()),
  };

  expect(result.status).toBe(409);
  expect(result.body.error).toContain("expired");
});
