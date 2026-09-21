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

const fixture = `
<section data-timeline-fixture="true">
  <article class="card" data-host="demo-host" data-host-surface="runtime" style="width:280px">
    <div class="meta card-meta">
      <span data-seen>Seen 2 min ago</span>
      <span data-card-asof>08:00</span>
    </div>
    <div class="beat" data-motion-beat="true" data-interval="60" data-grace="15" data-grace-source="fleet" style="width:240px">
      <div class="beat-stage">
        <span class="beat-marks">
          <span class="beat-mark" role="img" tabindex="0" data-history-key="sample:probe" data-identity-probe="kept" data-history-label="on cadence" data-history-detail="30s after previous · 08:00" aria-label="on cadence · 30s after previous · 08:00" style="--mark-x:40%"></span>
        </span>
      </div>
    </div>
  </article>
  <table><tbody>
    <tr data-host="demo-row" data-host-surface="runtime">
      <td><span data-seen>last seen 2m ago</span><span data-card-asof>08:00</span></td>
      <td>
        <div class="beat" data-interval="60" data-grace="15" style="width:80px">
          <div class="beat-stage">
            <span class="beat-marks">
              <span class="beat-mark" role="img" tabindex="0" data-history-label="offline gap recovered" data-history-detail="a very long gap that must stay readable without stretching the row" aria-label="offline gap recovered · a very long gap that must stay readable without stretching the row" style="--mark-x:70%"></span>
            </span>
          </div>
        </div>
      </td>
    </tr>
  </tbody></table>
</section>`;

test("history hover and focus keep card geometry and expose the full hint", async ({ page }) => {
  await page.goto("/");
  await page.evaluate((html) => {
    const holder = document.createElement("div");
    holder.innerHTML = html;
    document.body.append(holder);
    window.bindHistoryHints();
  }, fixture);

  const card = page.locator('[data-timeline-fixture] [data-host="demo-host"]');
  const row = page.locator('[data-timeline-fixture] [data-host="demo-row"]');
  const seen = card.locator("[data-seen]");
  const asOf = card.locator("[data-card-asof]");
  const mark = card.locator(".beat-mark");
  const before = await page.evaluate(() => {
    const cardBox = document.querySelector('[data-host="demo-host"]').getBoundingClientRect();
    const beatBox = document.querySelector('[data-host="demo-host"] .beat').getBoundingClientRect();
    const rowBox = document.querySelector('[data-host="demo-row"]').getBoundingClientRect();
    return {
      seen: document.querySelector('[data-host="demo-host"] [data-seen]').textContent,
      asOf: document.querySelector('[data-host="demo-host"] [data-card-asof]').textContent,
      card: { width: cardBox.width, height: cardBox.height },
      beat: { width: beatBox.width, height: beatBox.height },
      row: { width: rowBox.width, height: rowBox.height },
    };
  });

  await mark.hover();
  await expect(seen).toHaveText(before.seen);
  await expect(asOf).toHaveText(before.asOf);
  const hint = page.locator("#history-hint");
  await expect(hint).toBeVisible();
  await expect(hint).toHaveAttribute("data-history-hint-mode", "line");
  await expect(hint).toHaveAttribute("title", /after previous/);

  await mark.focus();
  await expect(hint).toHaveAttribute("data-history-hint-mode", "full");
  await expect(seen).toHaveText(before.seen);
  await page.keyboard.press("Escape");
  await expect(hint).toBeHidden();

  const narrow = row.locator(".beat-mark");
  await narrow.hover();
  await expect(page.locator("#history-hint")).toHaveAttribute("title", /without stretching the row/);
  await page.evaluate(() => {
    const mark = document.querySelector('[data-host="demo-row"] .beat-mark');
    mark.dispatchEvent(new PointerEvent("pointerup", { bubbles: true, pointerType: "touch" }));
  });
  await expect(page.locator("#history-hint")).toHaveAttribute("data-history-hint-mode", "full");

  const after = await page.evaluate(() => {
    const cardBox = document.querySelector('[data-host="demo-host"]').getBoundingClientRect();
    const beatBox = document.querySelector('[data-host="demo-host"] .beat').getBoundingClientRect();
    const rowBox = document.querySelector('[data-host="demo-row"]').getBoundingClientRect();
    return {
      card: { width: cardBox.width, height: cardBox.height },
      beat: { width: beatBox.width, height: beatBox.height },
      row: { width: rowBox.width, height: rowBox.height },
    };
  });
  expect(after).toEqual({ card: before.card, beat: before.beat, row: before.row });
});

test("history refresh keeps the same mark and arrival uses the grace scale", async ({ page }) => {
  await page.goto("/");
  await page.evaluate((html) => {
    const holder = document.createElement("div");
    holder.innerHTML = html;
    document.body.append(holder);
    window.bindHistoryHints();
    const beat = document.querySelector('[data-host="demo-host"] .beat');
    const now = Date.now() / 1000;
    const stamp = Math.floor(now - 20);
    const mark = beat.querySelector(".beat-mark");
    mark.dataset.historyKey = `sample:${stamp}`;
    window.setBeatHistory(beat, [stamp], 60, now, 15);
    window.__timelineProbe = {
      stamp,
      kept: document.querySelector('[data-identity-probe="kept"]')?.dataset.historyKey || "",
    };
    beat.dataset.last = String(now - 30);
    beat.dataset.interval = "60";
    beat.dataset.grace = "15";
    window.updateBeatClock(beat, now);
    const fill = beat.querySelector("[data-arrival-fill]");
    window.__timelineArrival = {
      state: beat.querySelector("[data-arrival]")?.dataset.arrivalState || "",
      beat: beat.dataset.beat || "",
      x: fill?.style.getPropertyValue("--arrival-x") || "",
      expected: `${window.heartbeatTimelineX(30, 60, 15).toFixed(2)}%`,
    };
  }, fixture);

  const probe = await page.evaluate(() => window.__timelineProbe);
  expect(probe.kept).toBe(`sample:${probe.stamp}`);
  const arrival = await page.evaluate(() => window.__timelineArrival);
  expect(arrival.state).toBe("on-time");
  expect(arrival.beat).toBe("tracking");
  expect(arrival.x).toBe(arrival.expected);

  await page.emulateMedia({ reducedMotion: "reduce" });
  const flashed = await page.evaluate(() => {
    const beat = document.querySelector("[data-motion-beat]");
    window.flashBeat(beat);
    return beat.dataset.flash || "";
  });
  expect(flashed).toBe("");
});
