import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";

const PAGES = ["/auth/sign-in", "/auth/sign-in?ended=1", "/auth/logged-out"];

test.describe("signing in", () => {
  for (const route of PAGES) {
    test(`${route} offers one way on and fits the screen`, async ({ page }) => {
      await page.goto(route);
      await expect(page.locator("h1")).toHaveText("Pharos");
      await expect(page.locator(".lead")).toContainText("Every host, its CVEs");
      const action = page.locator(".lcard a");
      await expect(action).toHaveCount(1);
      await expect(action).toHaveAttribute("href", /^\/auth\/login/);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      expect(overflow).toBeLessThanOrEqual(0);
    });

    test(`${route} has no accessibility violations`, async ({ page }) => {
      await page.goto(route);
      const results = await new AxeBuilder({ page }).exclude("[data-calendar-display]").analyze();
      expect(results.violations).toEqual([]);
    });

    test(`${route} is readable in the dark theme`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: "dark" });
      await page.goto(route);
      await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
      const results = await new AxeBuilder({ page })
        .withRules(["color-contrast"])
        .exclude("[data-calendar-display]")
        .analyze();
      expect(results.violations).toEqual([]);
    });
  }

  test("a first visit asks nothing and says nothing about a session", async ({ page }) => {
    await page.goto("/auth/sign-in");
    await expect(page.locator(".expired")).toHaveCount(0);
    await expect(page.locator(".lfor")).toHaveText("For people on the fleet's operator list.");
  });

  test("a session that ended says so and keeps where you were going", async ({ page }) => {
    await page.goto("/auth/sign-in?return_to=%2Fupdates&ended=1");
    await expect(page.getByRole("status")).toContainText("Your session has ended.");
    await expect(page.locator(".lcard a")).toHaveAttribute(
      "href",
      "/auth/login?return_to=%2Fupdates",
    );
  });

  test("signing out says so", async ({ page }) => {
    await page.goto("/auth/logged-out");
    await expect(page.getByRole("status")).toContainText("You have signed out of Pharos.");
  });
});
