import { expect, test as base } from "@playwright/test";
import {
  newAuthedContext,
  waitForHarnessTokens,
} from "./harness.mjs";

const test = base.extend({
  page: async ({ browser }, use) => {
    await waitForHarnessTokens();
    const context = await newAuthedContext(browser, "write");
    const page = await context.newPage();
    await use(page);
    await context.close();
  },
});

test("history dot hover replaces and restores card metadata", async ({ page }) => {
  await page.goto("/");

  await page.evaluate(() => {
    const fixture = document.createElement("section");
    fixture.className = "grid";
    fixture.dataset.hoverFixture = "true";
    fixture.innerHTML = `
      <article class="card" data-host="demo-host">
        <header class="card-head">
          <div class="host"><div><div class="name">demo-host</div></div></div>
        </header>
        <div class="meta card-meta">
          <span data-seen data-default-text="Seen 2 min ago">Seen 2 min ago</span>
          <span class="meta-separator" aria-hidden="true">·</span>
          <span data-card-asof data-default-text="08:00">08:00</span>
        </div>
        <div class="beat" data-ready="true">
          <div class="beat-stage" aria-label="heartbeat timeline">
            <span class="beat-marks">
              <span
                class="beat-mark"
                role="img"
                tabindex="0"
                data-history-level="down"
                data-history-label="offline gap recovered"
                data-history-detail="9 min after previous · 07:58"
                aria-label="offline gap recovered · 9 min after previous · 07:58"
                style="--mark-x:50%"
              ></span>
            </span>
          </div>
        </div>
      </article>`;
    document.body.append(fixture);
    window.bindHistoryHints(fixture);
  });

  const card = page.locator('.grid [data-host="demo-host"]');
  const seen = card.locator("[data-seen]");
  const asOf = card.locator("[data-card-asof]");
  const mark = card.locator('.beat-mark[data-history-level="down"]').first();
  const beforeSeen = await seen.textContent();
  const beforeAsOf = await asOf.textContent();

  await mark.hover();
  await expect(seen).toHaveText("offline gap recovered");
  await expect(asOf).toContainText("after previous");
  await expect(card.locator(".card-meta")).toHaveScreenshot(
    "history-dot-hover-meta.png",
  );

  await card.locator(".name").hover();
  await expect(seen).toHaveText(beforeSeen ?? "");
  await expect(asOf).toHaveText(beforeAsOf ?? "");

  await mark.focus();
  await expect(seen).toHaveText("offline gap recovered");
  await expect(asOf).toContainText("after previous");
  await mark.blur();
  await expect(seen).toHaveText(beforeSeen ?? "");
  await expect(asOf).toHaveText(beforeAsOf ?? "");
});
