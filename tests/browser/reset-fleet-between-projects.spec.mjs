import { test as base, expect } from "@playwright/test";
import { newAuthedContext, waitForHarnessTokens } from "./harness.mjs";

const test = base;

async function listRuntimeHosts(page) {
  const snapshot = await page.request.get("/hosts.json");
  expect(snapshot.ok()).toBe(true);
  const payload = await snapshot.json();
  return payload.hosts ?? [];
}

test("reset runtime fleet before the mobile project", async ({ browser }) => {
  await waitForHarnessTokens();
  const context = await newAuthedContext(browser, "write");
  const page = await context.newPage();

  for (let attempt = 0; attempt < 8; attempt += 1) {
    const hosts = await listRuntimeHosts(page);
    if (hosts.length === 0) {
      break;
    }
    for (const host of hosts) {
      const name = host.name;
      if (!name) {
        continue;
      }
      const removal = await page.request.post(`/host-actions/${name}/remove`, {
        headers: { "x-pharos-action": "1" },
        data: { confirmation: name, disposition: "unmanaged", successor: null },
      });
      if (removal.status() === 202 || removal.status() === 409) {
        await page.request.post(`/host-actions/${name}/allow-reonboarding`, {
          headers: { "x-pharos-action": "1" },
          data: { confirmation: name },
        });
      }
    }
  }

  expect(await listRuntimeHosts(page)).toEqual([]);
  await context.close();
});
