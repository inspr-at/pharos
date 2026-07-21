import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

test("fleet has no serious accessibility violations and serves hardened headers", async ({
  page,
}) => {
  const response = await page.goto("/");
  expect(response).not.toBeNull();
  const headers = response.headers();
  expect(headers["content-security-policy"]).toContain("default-src 'self'");
  expect(headers["content-security-policy"]).toContain("base-uri 'none'");
  expect(headers["content-security-policy"]).toContain("object-src 'none'");
  expect(headers["x-frame-options"]).toBe("DENY");
  expect(headers["x-content-type-options"]).toBe("nosniff");
  expect(headers["referrer-policy"]).toBe("no-referrer");

  const results = await new AxeBuilder({ page }).analyze();
  const serious = results.violations.filter(({ impact }) =>
    ["serious", "critical"].includes(impact),
  );
  expect(serious).toEqual([]);
});

test("setup assistant traps focus, closes with Escape, and restores its trigger", async ({
  page,
}) => {
  await page.goto("/");
  const trigger = page.locator("[data-onboard-open]").first();
  await trigger.focus();
  await trigger.click();

  const dialog = page.getByRole("dialog", { name: "Add a server" });
  await expect(dialog).toBeVisible();
  await expect(page.locator("[data-assistant-path]").first()).toBeFocused();

  for (let index = 0; index < 20; index += 1) {
    await page.keyboard.press("Tab");
    const focusInsideDialog = await page.evaluate(() => {
      const active = document.activeElement;
      return Boolean(active?.closest('[role="dialog"]'));
    });
    expect(focusInsideDialog).toBe(true);
  }

  await page.keyboard.press("Escape");
  await expect(dialog).toBeHidden();
  await expect(trigger).toBeFocused();
});

test("responsive layouts do not overflow and numbered guide circles stay centred", async ({
  page,
}, testInfo) => {
  await page.goto("/settings/providers/hetzner-cloud");
  await expect(page.locator("main")).toBeVisible();

  const horizontalOverflow = await page.evaluate(
    () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
  );
  expect(horizontalOverflow).toBeLessThanOrEqual(1);

  const circles = page.locator(".provider-guide-progress i, .provider-help-number");
  const count = await circles.count();
  expect(count).toBeGreaterThan(0);
  for (let index = 0; index < count; index += 1) {
    const offset = await circles.nth(index).evaluate((element) => {
      const range = document.createRange();
      range.selectNodeContents(element);
      const circle = element.getBoundingClientRect();
      const text = range.getBoundingClientRect();
      return Math.abs(circle.top + circle.height / 2 - (text.top + text.height / 2));
    });
    expect(offset).toBeLessThanOrEqual(1.5);
  }

  if (testInfo.project.name.includes("mobile")) {
    const controls = page.locator("button:visible, a:visible, input:visible, select:visible");
    const controlCount = await controls.count();
    const viewport = page.viewportSize();
    expect(viewport).not.toBeNull();
    for (let index = 0; index < Math.min(controlCount, 40); index += 1) {
      const box = await controls.nth(index).boundingBox();
      if (box) expect(box.x + box.width).toBeLessThanOrEqual(viewport.width + 1);
    }
  }
});

test("provider help visual stays within its reviewed baseline", async ({ page }) => {
  test.skip(process.platform !== "linux", "visual baseline uses the pinned Linux Chromium image");
  await page.goto("/settings/providers/hetzner-cloud");
  const help = page.locator(".provider-help");
  await expect(help).toBeVisible();
  await expect(help).toHaveScreenshot("provider-help.png", {
    animations: "disabled",
    caret: "hide",
    maxDiffPixelRatio: 0.005,
  });
});
