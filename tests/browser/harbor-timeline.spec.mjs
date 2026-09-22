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
    window.setBeatHistory(beat, [stamp - 90, stamp], 60, now, 15);
    window.__timelineProbe = {
      stamp,
      kept: document.querySelector('[data-identity-probe="kept"]')?.dataset.historyKey || "",
      firstObservationMarks: 0,
    };
    window.setBeatHistory(beat, [stamp], 60, now, 15);
    window.__timelineProbe.firstObservationMarks = beat.querySelectorAll(".beat-mark").length;
    window.__timelineProbe.firstObservationKept = Boolean(document.querySelector('[data-identity-probe="kept"]')?.isConnected);
    window.setBeatHistory(beat, [stamp - 90, stamp], 60, now, 15);
    beat.dataset.last = String(now - 30);
    beat.dataset.interval = "60";
    beat.dataset.grace = "15";
    window.updateBeatClock(beat, now);
    const onTimeX = beat.style.getPropertyValue("--cadence-x") || "";
    beat.dataset.last = String(now - 10);
    window.updateBeatClock(beat, now);
    const earlierX = beat.style.getPropertyValue("--cadence-x") || "";
    beat.dataset.last = String(now - 30);
    window.updateBeatClock(beat, now);
    window.__timelineArrival = {
      state: beat.querySelector("[data-arrival]")?.dataset.arrivalState || "",
      beat: beat.dataset.beat || "",
      live: beat.dataset.beatLive || "",
      caption: beat.querySelector("[data-arrival-label]")?.textContent || "",
      x: beat.style.getPropertyValue("--cadence-x") || "",
      earlierX,
      onTimeX,
      expected: `${window.heartbeatTimelineX(30, 60, 15).toFixed(2)}%`,
      intervalX: beat.style.getPropertyValue("--interval-x") || "",
    };
    beat.dataset.last = String(now - 80);
    window.updateBeatClock(beat, now);
    window.__timelineLate = {
      state: beat.querySelector("[data-arrival]")?.dataset.arrivalState || "",
      beat: beat.dataset.beat || "",
      live: beat.dataset.beatLive || "",
      caption: beat.querySelector("[data-arrival-label]")?.textContent || "",
    };
  }, fixture);

  const probe = await page.evaluate(() => window.__timelineProbe);
  expect(probe.kept).toBe(`sample:${probe.stamp}`);
  expect(probe.firstObservationMarks).toBe(0);
  expect(probe.firstObservationKept).toBe(false);
  const arrival = await page.evaluate(() => window.__timelineArrival);
  expect(arrival.state).toBe("on_time");
  expect(arrival.beat).toBe("tracking");
  expect(arrival.live).toBe("true");
  expect(arrival.x).toBe(arrival.expected);
  expect(arrival.caption).toContain("expected 60s");
  expect(arrival.caption).toContain("late 75s");
  expect(arrival.caption).not.toContain("expected 75s");
  expect(Number.parseFloat(arrival.earlierX)).toBeLessThan(Number.parseFloat(arrival.onTimeX));
  expect(arrival.intervalX).toBe("51.20%");
  const late = await page.evaluate(() => window.__timelineLate);
  expect(late.state).toBe("late");
  expect(late.beat).toBe("late");
  expect(late.live).toBe("false");
  expect(late.caption).toContain("expected 60s");
  expect(late.caption).toContain("late 75s");

  await page.emulateMedia({ reducedMotion: "no-preference" });
  const moved = await page.evaluate(() => {
    const beat = document.querySelector("[data-motion-beat]");
    window.flashBeat(beat);
    return beat.dataset.flash || "";
  });
  expect(moved).toBe("true");
  await page.emulateMedia({ reducedMotion: "reduce" });
  const flashed = await page.evaluate(() => {
    const beat = document.querySelector("[data-motion-beat]");
    delete beat.dataset.flash;
    window.flashBeat(beat);
    return beat.dataset.flash || "";
  });
  expect(flashed).toBe("");
});

test("reduced motion stops heartbeat interpolation and keeps the clock truthful", async ({ page }) => {
  await page.goto("/");
  await page.evaluate(() => {
    document.querySelector("main").dataset.fleetSyncState = "current";
    const unrelated = document.createElement("div");
    unrelated.id = "unrelated-host-fixture";
    unrelated.innerHTML = `
      <article class="card harbor-host" data-host="unrelated-kept">
        <div class="beat" data-interval="60" data-grace="15">
          <div class="beat-readout" data-arrival><span data-arrival-label>Unrelated host stays</span></div>
          <div class="beat-cadence"><span class="beat-now"></span><span class="beat-hit"></span></div>
        </div>
      </article>
      <table class="list"><tbody>
        <tr class="harbor-host" data-host="unrelated-kept">
          <td><details class="revision-evidence"><summary><span data-config-summary>unrelated freshness</span></summary></details></td>
          <td><div class="beat" data-interval="60" data-grace="15">
            <div class="beat-readout" data-arrival><span data-arrival-label>Unrelated host stays</span></div>
            <div class="beat-cadence"><span class="beat-now"></span><span class="beat-hit"></span></div>
          </div></td>
        </tr>
      </tbody></table>`;
    document.body.append(unrelated);
    const holder = document.createElement("div");
    holder.id = "reduced-motion-fixture";
    holder.innerHTML = `
      <article class="card harbor-host" data-host="motion-card">
        <div class="beat" data-interval="60" data-grace="15" data-beat-live="true">
          <div class="beat-readout" data-arrival><span data-arrival-label></span></div>
          <div class="beat-cadence"><span class="beat-now"></span><span class="beat-hit"></span></div>
        </div>
      </article>
      <table class="list"><tbody>
        <tr class="harbor-host" data-host="motion-row">
          <td><details class="revision-evidence"><summary><span data-config-summary>nixpkgs current</span></summary></details></td>
          <td><div class="beat" data-caption-mode="list" data-interval="60" data-grace="15" data-beat-live="true">
            <div class="beat-readout" data-arrival><span data-arrival-label></span></div>
            <div class="beat-cadence"><span class="beat-now"></span><span class="beat-hit"></span></div>
          </div></td>
        </tr>
      </tbody></table>`;
    document.body.append(holder);
  });
  const fixture = page.locator("#reduced-motion-fixture");
  expect(await page.locator("tr.harbor-host .revision-evidence > summary").count()).toBeGreaterThan(1);
  await expect(fixture.locator("tr.harbor-host .revision-evidence > summary")).toHaveCount(1);
  const summaryStyle = await fixture.locator("tr.harbor-host .revision-evidence > summary").evaluate((node) => {
    const style = getComputedStyle(node);
    return { size: style.fontSize, weight: style.fontWeight };
  });
  expect(summaryStyle).toEqual({ size: "12px", weight: "400" });

  await page.emulateMedia({ reducedMotion: "no-preference" });
  const moving = await page.evaluate(() => {
    const holder = document.getElementById("reduced-motion-fixture");
    return {
      card: getComputedStyle(holder.querySelector(".card.harbor-host .beat-cadence .beat-now")).transitionDuration,
      row: getComputedStyle(holder.querySelector("tr.harbor-host .beat-cadence .beat-now")).transitionDuration,
    };
  });
  expect(moving).toEqual({ card: "0.45s", row: "0.45s" });

  await page.emulateMedia({ reducedMotion: "reduce" });
  const reduced = await page.evaluate(() => {
    const holder = document.getElementById("reduced-motion-fixture");
    const card = holder.querySelector(".card.harbor-host .beat");
    const row = holder.querySelector("tr.harbor-host .beat");
    card.dataset.flash = "true";
    row.dataset.flash = "true";
    const duration = (beat) => getComputedStyle(beat.querySelector(".beat-cadence .beat-now")).transitionDuration;
    const animation = (beat) => getComputedStyle(beat.querySelector(".beat-cadence .beat-hit")).animationName;
    const sample = (beat, age) => {
      const now = Date.now() / 1000;
      beat.dataset.last = String(now - age);
      beat.dataset.interval = "60";
      beat.dataset.grace = "15";
      window.updateBeatClock(beat, now);
      const label = beat.querySelector("[data-arrival-label]");
      return {
        caption: label?.textContent || "",
        title: label?.title || "",
        aria: beat.querySelector(".beat-cadence")?.getAttribute("aria-label") || "",
        x: beat.style.getPropertyValue("--cadence-x") || "",
        live: beat.dataset.beatLive || "",
      };
    };
    const cardYoung = sample(card, 12);
    const cardOlder = sample(card, 40);
    const rowYoung = sample(row, 12);
    const unrelatedNode = document.getElementById("unrelated-host-fixture");
    const unrelated = {
      hosts: [...unrelatedNode.querySelectorAll("[data-host]")].map((el) => el.dataset.host),
      captions: [...unrelatedNode.querySelectorAll("[data-arrival-label]")].map((el) => el.textContent),
      summary: unrelatedNode.querySelector("tr.harbor-host .revision-evidence > summary")?.textContent?.trim() || "",
      lasts: [...unrelatedNode.querySelectorAll(".beat")].map((el) => el.dataset.last || ""),
      flashes: [...unrelatedNode.querySelectorAll(".beat")].map((el) => el.dataset.flash || ""),
    };
    return {
      card: duration(card),
      row: duration(row),
      cardFlash: animation(card),
      rowFlash: animation(row),
      cardYoung,
      cardOlder,
      rowYoung,
      unrelated,
    };
  });
  expect(reduced.card).toBe("0s");
  expect(reduced.row).toBe("0s");
  expect(reduced.cardFlash).toBe("none");
  expect(reduced.rowFlash).toBe("none");
  expect(reduced.cardYoung.live).toBe("true");
  expect(reduced.cardYoung.caption).toContain("expected 60s");
  expect(reduced.cardYoung.caption).toContain("late 75s");
  expect(reduced.cardYoung.caption).not.toContain("expected 75s");
  expect(Number.parseFloat(reduced.cardOlder.x)).toBeGreaterThan(Number.parseFloat(reduced.cardYoung.x));
  expect(reduced.rowYoung.caption).toBe("On time · 12s ago");
  expect(reduced.rowYoung.title).toContain("expected 60s");
  expect(reduced.rowYoung.title).toContain("late 75s");
  expect(reduced.rowYoung.aria).toContain("expected 60s");
  expect(reduced.rowYoung.aria).toContain("late 75s");
  expect(reduced.unrelated).toEqual({
    hosts: ["unrelated-kept", "unrelated-kept"],
    captions: ["Unrelated host stays", "Unrelated host stays"],
    summary: "unrelated freshness",
    lasts: ["", ""],
    flashes: ["", ""],
  });

  await page.emulateMedia({ reducedMotion: "no-preference" });
  const restored = await page.evaluate(() => {
    const holder = document.getElementById("reduced-motion-fixture");
    return {
      card: getComputedStyle(holder.querySelector(".card.harbor-host .beat-cadence .beat-now")).transitionDuration,
      row: getComputedStyle(holder.querySelector("tr.harbor-host .beat-cadence .beat-now")).transitionDuration,
    };
  });
  expect(restored).toEqual({ card: "0.45s", row: "0.45s" });
  const unrelated = await page.locator("#unrelated-host-fixture").evaluate((node) => ({
    hosts: [...node.querySelectorAll("[data-host]")].map((el) => el.dataset.host),
    summary: node.querySelector("tr.harbor-host .revision-evidence > summary")?.textContent?.trim() || "",
    lasts: [...node.querySelectorAll(".beat")].map((el) => el.dataset.last || ""),
    flashes: [...node.querySelectorAll(".beat")].map((el) => el.dataset.flash || ""),
  }));
  expect(unrelated).toEqual({
    hosts: ["unrelated-kept", "unrelated-kept"],
    summary: "unrelated freshness",
    lasts: ["", ""],
    flashes: ["", ""],
  });
});
