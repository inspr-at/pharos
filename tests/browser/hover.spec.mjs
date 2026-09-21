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

const hintText = "offline gap recovered · 9 min after previous · 07:58";

test("history dot hover keeps geometry and shows a stable hint", async ({ page }) => {
  await page.goto("/");

  const stamp = await page.evaluate(() => {
    const fixture = document.createElement("section");
    fixture.className = "grid";
    fixture.dataset.hoverFixture = "true";
    const stamp = Math.floor(Date.now() / 1000 - 20);
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
        <div class="beat" data-ready="true" data-interval="60" data-grace="15">
          <div class="beat-stage" aria-label="heartbeat timeline">
            <span class="beat-marks">
              <span
                class="beat-mark"
                role="img"
                tabindex="0"
                data-identity-probe="kept"
                data-history-key="sample:${stamp}"
                data-history-level="down"
                data-history-label="offline gap recovered"
                data-history-detail="9 min after previous · 07:58"
                aria-label="offline gap recovered · 9 min after previous · 07:58"
                style="--mark-x:50%"
              ></span>
            </span>
          </div>
        </div>
      </article>
      <table class="list"><tbody>
        <tr data-host="demo-row" data-host-surface="runtime">
          <td class="list-seen">
            <span data-seen>last seen 2m ago</span>
            <span class="list-seen-detail">historic detail must stay collapsed</span>
          </td>
          <td>
            <div class="beat" data-interval="60" data-grace="15" style="width:120px">
              <div class="beat-stage">
                <span class="beat-marks">
                  <span
                    class="beat-mark"
                    role="img"
                    tabindex="0"
                    data-history-level="down"
                    data-history-label="offline gap recovered"
                    data-history-detail="9 min after previous · 07:58 and a longer clause that must not stretch the row"
                    aria-label="offline gap recovered · 9 min after previous · 07:58 and a longer clause that must not stretch the row"
                    style="--mark-x:70%"
                  ></span>
                </span>
              </div>
            </div>
          </td>
        </tr>
      </tbody></table>`;
    document.body.append(fixture);
    window.bindHistoryHints(fixture);
    return stamp;
  });

  const card = page.locator('.grid [data-host="demo-host"]');
  const row = page.locator('.grid [data-host="demo-row"]');
  const seen = card.locator("[data-seen]");
  const asOf = card.locator("[data-card-asof]");
  const mark = card.locator('.beat-mark[data-history-level="down"]').first();
  const hint = page.locator("#history-hint");
  const beforeSeen = await seen.textContent();
  const beforeAsOf = await asOf.textContent();
  const boxes = () => page.evaluate(() => {
    const pack = (box) => ({ width: box.width, height: box.height });
    return {
      card: pack(document.querySelector('[data-host="demo-host"]').getBoundingClientRect()),
      beat: pack(document.querySelector('[data-host="demo-host"] .beat').getBoundingClientRect()),
      row: pack(document.querySelector('[data-host="demo-row"]').getBoundingClientRect()),
    };
  });
  const before = await boxes();

  await mark.hover();
  await expect(seen).toHaveText(beforeSeen ?? "");
  await expect(asOf).toHaveText(beforeAsOf ?? "");
  await expect(card).not.toHaveAttribute("data-history-hint", /.+/);
  await expect(row).not.toHaveAttribute("data-history-hint", /.+/);
  await expect(hint).toBeVisible();
  await expect(hint).toHaveAttribute("data-history-hint-mode", "line");
  await expect(hint).toHaveText(hintText);
  await expect(hint).toHaveAttribute("title", hintText);
  await expect(card.locator("[data-history-readout]")).toHaveCount(0);
  await expect(card.locator("[data-arrival-detail]")).toHaveCount(0);
  await expect(page.locator("#history-hint-chrome")).toHaveCount(0);
  await expect(mark).toHaveAttribute("aria-label", hintText);
  await expect(mark).toHaveAttribute("title", hintText);
  expect(await hint.evaluate((node) => getComputedStyle(node).whiteSpace)).toBe("nowrap");
  expect(await boxes()).toEqual(before);
  expect(await row.locator(".list-seen-detail").evaluate((node) => getComputedStyle(node).display)).toBe("none");

  await card.locator(".name").hover();
  await expect(hint).toBeHidden();
  await expect(card.locator("[data-history-readout]")).toHaveCount(0);
  await expect(seen).toHaveText(beforeSeen ?? "");
  await expect(asOf).toHaveText(beforeAsOf ?? "");
  expect(await boxes()).toEqual(before);

  await mark.focus();
  await expect(seen).toHaveText(beforeSeen ?? "");
  await expect(asOf).toHaveText(beforeAsOf ?? "");
  await expect(hint).toBeVisible();
  await expect(hint).toHaveAttribute("data-history-hint-mode", "full");
  await expect(hint).toHaveText(hintText);
  expect(await hint.evaluate((node) => getComputedStyle(node).whiteSpace)).toBe("normal");
  await expect(mark).toHaveAttribute("aria-describedby", "history-hint");
  expect(await boxes()).toEqual(before);

  await mark.blur();
  await expect(hint).toBeHidden();
  await expect(card.locator("[data-history-readout]")).toHaveCount(0);
  await expect(seen).toHaveText(beforeSeen ?? "");
  await expect(asOf).toHaveText(beforeAsOf ?? "");
  await expect(mark).not.toHaveAttribute("aria-describedby", /.+/);
  expect(await boxes()).toEqual(before);

  await row.locator(".beat-mark").hover();
  await expect(row.locator("[data-seen]")).toHaveText("last seen 2m ago");
  await expect(hint).toHaveAttribute("data-history-hint-mode", "line");
  await expect(hint).toHaveAttribute("title", /must not stretch the row/);
  expect(await row.locator(".list-seen-detail").evaluate((node) => getComputedStyle(node).display)).toBe("none");
  expect(await boxes()).toEqual(before);

  const identity = await page.evaluate((sample) => {
    const beat = document.querySelector('[data-host="demo-host"] .beat');
    const mark = beat.querySelector('[data-identity-probe="kept"]');
    window.setBeatHistory(beat, [sample - 90, sample], 60, Date.now() / 1000, 15);
    const kept = document.querySelector('[data-identity-probe="kept"]');
    return {
      same: kept === mark,
      connected: Boolean(kept?.isConnected),
      key: kept?.dataset.historyKey || "",
      count: document.querySelectorAll('[data-identity-probe="kept"]').length,
    };
  }, stamp);
  expect(identity.same).toBe(true);
  expect(identity.connected).toBe(true);
  expect(identity.count).toBe(1);
  expect(identity.key).toBe(`sample:${stamp}`);
});
