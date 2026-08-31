import { expect, test } from "@playwright/test";
import fs from "node:fs";

const head = fs.readFileSync(
  new URL("../../crates/pharosd/assets/ui/head.html", import.meta.url),
  "utf8",
);
const stylesheet = head.match(/<style>([\s\S]*?)<\/style>/)?.[1];

if (!stylesheet) {
  throw new Error("Pharos UI stylesheet was not found");
}

const ladder = `
  <ol class="host-workflow-ladder">
    <li data-ladder-state="complete"><span class="host-workflow-ladder-marker"></span><span><strong>Observed</strong><small>No matching host report recorded</small></span></li>
    <li><span class="host-workflow-ladder-marker"></span><span><strong>Declared</strong><small>No declaration merge is observed by this run</small></span></li>
    <li data-ladder-state="current"><span class="host-workflow-ladder-marker"></span><span><strong>Requested</strong><small>Repository handoff accepted</small></span></li>
    <li><span class="host-workflow-ladder-marker"></span><span><strong>Executed</strong><small>No host execution reported</small></span></li>
    <li data-ladder-state="stopped"><span class="host-workflow-ladder-marker"></span><span><strong>Verified</strong><small>No matching host report recorded</small></span></li>
  </ol>
`;

test("lifecycle ladder masks its desktop connector without changing the mobile rail", async ({
  page,
}) => {
  await page.setViewportSize({ width: 760, height: 500 });
  await page.setContent(`<style>${stylesheet}</style><main>${ladder}</main>`);

  const desktop = await page
    .locator(".host-workflow-ladder li")
    .first()
    .evaluate((step) => {
      const marker = step.querySelector(".host-workflow-ladder-marker");
      const copy = step.lastElementChild;
      const connectorStyle = getComputedStyle(step, "::after");
      const markerBox = marker.getBoundingClientRect();
      const stepBox = step.getBoundingClientRect();
      return {
        connectorBackground: connectorStyle.backgroundColor,
        connectorContent: connectorStyle.content,
        connectorHeight: connectorStyle.height,
        connectorStart: stepBox.left + Number.parseFloat(connectorStyle.left),
        copyBackground: getComputedStyle(copy).backgroundColor,
        copyPosition: getComputedStyle(copy).position,
        copyZIndex: getComputedStyle(copy).zIndex,
        markerCentre: markerBox.left + markerBox.width / 2,
      };
    });

  expect(desktop.connectorContent).not.toBe("none");
  expect(desktop.connectorBackground).toBe("rgb(214, 226, 234)");
  expect(desktop.connectorHeight).toBe("1px");
  expect(
    Math.abs(desktop.connectorStart - desktop.markerCentre),
  ).toBeLessThanOrEqual(0.5);
  expect(desktop.copyPosition).toBe("relative");
  expect(desktop.copyZIndex).toBe("1");
  expect(desktop.copyBackground).toBe("rgb(255, 255, 255)");

  await page.setViewportSize({ width: 390, height: 700 });
  const mobile = await page
    .locator(".host-workflow-ladder li")
    .first()
    .evaluate((step) => {
      const marker = step.querySelector(".host-workflow-ladder-marker");
      const copy = step.lastElementChild;
      const connectorStyle = getComputedStyle(step, "::after");
      const markerBox = marker.getBoundingClientRect();
      const stepBox = step.getBoundingClientRect();
      return {
        connectorHeight: connectorStyle.height,
        connectorStart: stepBox.left + Number.parseFloat(connectorStyle.left),
        connectorWidth: connectorStyle.width,
        copyBackground: getComputedStyle(copy).backgroundColor,
        copyPosition: getComputedStyle(copy).position,
        markerCentre: markerBox.left + markerBox.width / 2,
      };
    });

  expect(mobile.connectorWidth).toBe("1px");
  expect(Number.parseFloat(mobile.connectorHeight)).toBeGreaterThan(15);
  expect(
    Math.abs(mobile.connectorStart - mobile.markerCentre),
  ).toBeLessThanOrEqual(0.5);
  expect(mobile.copyPosition).toBe("static");
  expect(mobile.copyBackground).toBe("rgba(0, 0, 0, 0)");
});
