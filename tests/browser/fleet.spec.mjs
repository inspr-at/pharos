import fs from "node:fs";
import path from "node:path";
import AxeBuilder from "@axe-core/playwright";
import { expect, test } from "@playwright/test";
import { fleetData } from "./fixtures.mjs";

const RUN_DIR = process.env.PHAROS_BROWSER_RUN_DIR;
const BARE = `http://127.0.0.1:${process.env.PHAROS_BROWSER_BARE_PORT}`;
const FLAKY = `http://127.0.0.1:${process.env.PHAROS_BROWSER_FLAKY_PORT}`;
const PAGES = [
  "/",
  "/updates",
  "/handled",
  "/cves/CVE-2000-1001",
  "/cves/CVE-2000-1002",
  "/hosts/ares",
  "/hosts/artemis",
  "/hosts/selene",
  "/hosts/nyx",
  "/?cve=CVE-2000-1001",
];

/** A host's row at this width: the table on a desktop, the list on a phone. */
function hostRow(page, name) {
  const phone = (page.viewportSize()?.width ?? 1440) <= 700;
  return page.locator(`${phone ? ".hlist li" : ".fleet-table tr"}[data-host^="${name} "]`);
}

/** The first probe round has answered once the silent host says so. */
async function waitForProbes(page) {
  await expect(async () => {
    await page.goto("/");
    await expect(hostRow(page, "hestia")).toContainText("No answer yet");
  }).toPass({ timeout: 20_000 });
}

function watchForViolations(page) {
  const seen = [];
  page.on("console", (message) => {
    if (message.type() === "error") seen.push(message.text());
  });
  page.on("pageerror", (error) => seen.push(error.message));
  page.on("request", (request) => {
    const url = new URL(request.url());
    if (url.protocol !== "data:" && url.hostname !== "127.0.0.1") seen.push(request.url());
  });
  return seen;
}

test.describe("every page", () => {
  for (const route of PAGES) {
    test(`${route} holds the security policy and the layout`, async ({ page }) => {
      const violations = watchForViolations(page);
      const response = await page.goto(route);
      expect(response.status()).toBe(200);
      const policy = response.headers()["content-security-policy"];
      expect(policy).toContain("'nonce-");
      expect(policy).toContain("default-src 'self'");
      await expect(page.locator("h1")).toBeVisible();
      await expect(page.locator("[data-calendar-display]")).toHaveAttribute("data-canonical", /\d/);
      const overflow = await page.evaluate(
        () => document.documentElement.scrollWidth - document.documentElement.clientWidth,
      );
      expect(overflow).toBeLessThanOrEqual(0);
      expect(violations).toEqual([]);
    });

    test(`${route} has no accessibility violations`, async ({ page }) => {
      await page.goto(route);
      // The pinned version renderer dims aria-hidden decorative segments on purpose.
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

  test("an unknown CVE or host is a page, not an error", async ({ page }) => {
    for (const route of ["/cves/CVE-2000-9999", "/hosts/nobody"]) {
      const response = await page.goto(route);
      expect(response.status()).toBe(404);
      await expect(page.getByText("Nothing here by that name.")).toBeVisible();
    }
  });
});

test.describe("fleet page", () => {
  test("shows sections, summary, data age and the coverage note", async ({ page }) => {
    await page.goto("/");
    await expect(page.getByRole("heading", { level: 1, name: "Fleet" })).toBeVisible();
    for (const site of ["Harbor", "Hilltop", "Islands", "Unlisted"]) {
      await expect(page.getByRole("heading", { level: 2, name: site })).toBeVisible();
    }
    await expect(page.locator(".top-meta")).toContainText("Data file updated 2 h ago");
    await expect(page.locator(".top-meta")).toContainText(/last report \d+ min ago/);
    await expect(page.locator(".info")).toContainText(
      "Kernel CVEs are computed from beacon reports. Every other CVE is hand-declared in the data file.",
    );
    await expect(page.locator(".metrics .metric").first()).toContainText("hosts");
    await expect(page.locator(".notice")).toHaveCount(0);
  });

  for (const [host, label] of [
    ["ares", /Online · \d+ min ago/],
    ["hermes", "Late · 3 h ago"],
    ["hades", "Offline 2 d"],
    ["selene", "No contact data"],
    ["atlas", "Never reported"],
    ["nyx", /Online · \d+ min ago/],
  ]) {
    test(`${host} shows contact state ${label}`, async ({ page }) => {
      await page.goto("/");
      await expect(hostRow(page, host)).toContainText(label);
    });
  }

  test("probes show reachability, sleep and silence", async ({ page }) => {
    await waitForProbes(page);
    for (const [host, label] of [
      ["artemis", "Reachable"],
      ["apollo", "Asleep · 2 d"],
      ["hephaestus", "Asleep 41 d · over 30 d"],
      ["poseidon", "Asleep 70 d · over 60 d"],
      ["dionysos", "Offline 50 d · optional"],
      ["hestia", "No answer yet"],
      ["iris", "Can't check · last contact 3 h ago"],
      ["eos", "No result yet"],
      ["charon", "Reachable"],
    ]) {
      await expect(hostRow(page, host)).toContainText(label);
    }
  });

  test("contact colour follows availability", async ({ page }) => {
    await waitForProbes(page);
    const tone = (host) =>
      hostRow(page, host).locator(".contact .line, .hcontact");
    await expect(tone("ares")).toHaveClass(/ok/);
    await expect(tone("hades")).toHaveClass(/danger/);
    await expect(tone("hermes")).toHaveClass(/warn/);
    await expect(tone("hephaestus")).toHaveClass(/warn/);
    await expect(tone("poseidon")).toHaveClass(/danger/);
    await expect(tone("hestia")).toHaveClass(/danger/);
    for (const host of ["apollo", "dionysos", "selene", "eos", "iris"]) {
      await expect(tone(host)).not.toHaveClass(/ok|warn|danger/);
    }
  });

  test("a sleeping host on a vulnerable version still shows as affected", async ({ page }) => {
    await waitForProbes(page);
    await expect(hostRow(page, "artemis")).toContainText("1 critical");
    await expect(hostRow(page, "pan")).toContainText("1 critical");
    await expect(hostRow(page, "hades")).toContainText("1 critical");
    await expect(hostRow(page, "demeter")).toContainText("1 high");
    await expect(hostRow(page, "selene")).not.toContainText("critical");
  });

  test("security cells name what cannot be checked and how current it is", async ({ page }) => {
    await page.goto("/");
    await expect(hostRow(page, "zeus")).toContainText("Can't check");
    await expect(hostRow(page, "atlas")).toContainText("Can't check");
    await expect(hostRow(page, "charon")).toContainText("Can't check: not in the data file");
    await expect(hostRow(page, "hera")).toContainText("Can't check: not declared yet");
    await expect(hostRow(page, "ares")).toContainText("12 commits behind");
    await expect(hostRow(page, "ares")).toContainText("Updated 74 d ago");
    await expect(hostRow(page, "athena")).toContainText("Reboot due");
    await expect(hostRow(page, "athena")).toContainText("next boot 6.18.56");
    await expect(hostRow(page, "hermes")).toContainText("Data from 3 h ago");
    await expect(hostRow(page, "hermes").locator(".stale")).toBeVisible();
    await expect(hostRow(page, "selene")).toContainText("Hand-declared · verified");
    await expect(hostRow(page, "pan")).toContainText("Hand-declared · verified");
    await expect(hostRow(page, "pan").locator(".stale")).toBeVisible();
    await expect(hostRow(page, "nyx")).toContainText(/Beacon/);
  });

  test("the watchlist shows the worst first, and overflows", async ({ page }) => {
    await page.goto("/");
    const cards = page.locator(".wcard");
    await expect(cards.first()).toContainText("Example takeover");
    await expect(cards.first()).toContainText("Critical");
    await expect(cards.first()).toContainText("Open");
    await expect(cards.first()).toContainText("Computed from kernel");
    await expect(cards.nth(1)).toContainText("CVE-2000-1002");
    await expect(cards.nth(1)).toContainText("Hand-declared");
    await expect(page.locator(".wcard").filter({ hasText: "Example leak" })).toContainText(
      "Workaround in place",
    );
    await expect(page.locator(".watch-overflow")).toContainText("+1 more on the watchlist");
    // A fixed CVE leaves the watchlist after three days.
    await expect(page.locator(".watch-grid")).not.toContainText("Example overflow");
  });

  test("a fixed card stays for three days and says so", async ({ page }) => {
    await page.goto(`${FLAKY}/`);
    const fixed = page.locator(".wcard").filter({ hasText: "Example crash" });
    await expect(fixed).toContainText(/Fixed \d+ \w+/);
    await expect(fixed).toContainText("none affected");
    await expect(page.locator(".watch-overflow")).toHaveCount(0);
  });

  test("selecting a card marks its hosts without moving the page", async ({ page }) => {
    await page.goto("/");
    const before = await page.locator(".ptool").boundingBox();
    await page.locator(".wcard").first().click();
    await expect(page).toHaveURL(/cve=CVE-2000-1001/);
    await expect(page.locator(".wcard").first()).toHaveClass(/sel/);
    await expect(page.locator(".wcard").first()).toHaveAttribute("aria-current", "true");
    const after = await page.locator(".ptool").boundingBox();
    expect(after.y).toBe(before.y);
    await expect(hostRow(page, "ares")).toHaveClass(/hl/);
    await expect(hostRow(page, "athena")).toHaveClass(/hl/);
    await expect(hostRow(page, "demeter")).toHaveClass(/dim/);
    await expect(page.locator(".watch-tools")).toContainText("for Example takeover");
    await page.locator(".wcard").first().click();
    await expect(page).not.toHaveURL(/cve=/);
    await expect(hostRow(page, "demeter")).not.toHaveClass(/dim/);
  });

  test("search filters hosts as you type and on the server", async ({ page }) => {
    await page.goto("/");
    await page.getByLabel("Search hosts").fill("ARTEM");
    await expect(hostRow(page, "artemis")).toBeVisible();
    await expect(hostRow(page, "ares")).toBeHidden();
    await expect(page.getByRole("heading", { level: 2, name: "Harbor" })).toBeHidden();
    await expect(page).toHaveURL(/q=ARTEM/);
    await page.getByLabel("Search hosts").fill("no such host");
    await expect(page.locator("[data-host-empty]")).toBeVisible();

    await page.goto("/?q=artem");
    await expect(hostRow(page, "artemis")).toBeVisible();
    await expect(hostRow(page, "ares")).toBeHidden();
    await expect(page.getByLabel("Search hosts")).toHaveValue("artem");
  });

  test("hosts arrange by attention and by name", async ({ page }) => {
    await page.goto("/");
    await page.getByLabel("Arrange by").selectOption("name");
    await expect(page).toHaveURL(/arrange=name/);
    await expect(page.getByRole("heading", { level: 2, name: "All hosts" })).toBeVisible();
    const names = await page
      .locator(".card[data-host-group] tbody tr")
      .evaluateAll((rows) => rows.map((row) => row.dataset.host.split(" ")[0]));
    expect(names).toEqual([...names].sort());
    await page.getByLabel("Arrange by").selectOption("attention");
    await expect(page).toHaveURL(/arrange=attention/);
    const first = await page
      .locator(".card[data-host-group] tbody tr")
      .first()
      .getAttribute("data-host");
    expect(["ares", "artemis", "athena", "hades", "pan"]).toContain(first.split(" ")[0]);
  });

  test("the theme switches and stays", async ({ page }) => {
    await page.goto("/");
    if (await page.getByRole("button", { name: "Menu" }).isVisible()) {
      await page.getByRole("button", { name: "Menu" }).click();
    }
    await page.getByRole("button", { name: "Dark" }).click();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await page.reload();
    await expect(page.locator("html")).toHaveAttribute("data-theme", "dark");
    await expect(page.locator('[data-set-theme="dark"]')).toHaveAttribute("aria-pressed", "true");
  });

  test("handled sits collapsed at the bottom", async ({ page }) => {
    await page.goto("/");
    const handled = page.locator("details.handled");
    await expect(handled).toContainText("Handled");
    await expect(handled).toContainText("CVEs");
    await expect(handled.locator("table")).toBeHidden();
    await handled.locator("summary").click();
    await expect(handled.locator("table")).toBeVisible();
    await handled.getByRole("link", { name: "See the full history" }).click();
    await expect(page).toHaveURL(/\/handled$/);
  });
});

test.describe("updates page", () => {
  test("every updates state has its group", async ({ page }) => {
    await page.goto("/updates");
    const group = (title) =>
      page.locator("section.card").filter({ has: page.getByRole("heading", { level: 2, name: title, exact: true }) });
    await expect(group("Reboot due")).toContainText("athena");
    await expect(group("Reboot due")).toContainText("6.18.56");
    await expect(group("Reboot due")).toContainText("Reboot pending");
    await expect(group("Behind the declared config")).toContainText("ares");
    await expect(group("Behind the declared config")).toContainText("12 commits behind");
    await expect(group("Old nixpkgs")).toContainText("Lock 74 d old");
    await expect(group("Old nixpkgs")).toContainText("Older than 30 d");
    await expect(group("Hand-declared")).toContainText("selene");
    await expect(group("Hand-declared")).toContainText("Raspberry Pi OS 13");
    await expect(group("Hand-declared")).toContainText("pan");
    await expect(group("Hand-declared").locator(".stale").first()).toBeVisible();
    await expect(group("Can't tell yet")).toContainText("hermes");
    await expect(group("Can't tell yet")).toContainText("Last known: up to date");
    await expect(group("Can't tell yet")).toContainText("atlas");
    await expect(group("Can't tell yet")).toContainText("Never reported");
    await expect(group("Can't tell yet")).toContainText("Unknown, never shown as up to date");
    await expect(group("Up to date")).toContainText("demeter");
    await expect(group("Up to date")).toContainText("Matches the declared config");
    await expect(group("Up to date")).toContainText("Confirmed by the report");
    await expect(page.locator(".top-meta")).toContainText(
      "Pharos shows what is due. It confirms done only when a later report shows it.",
    );
    // Stale reports never read as current.
    await expect(group("Up to date")).not.toContainText("hermes");
  });
});

test.describe("handled page", () => {
  test("lists the file's entries and fixed CVEs past three days, newest first", async ({ page }) => {
    await page.goto("/handled");
    const rows = page.locator("table tbody tr");
    await expect(rows).toHaveCount(3);
    await expect(rows.first()).toContainText("CVE-2000-1005");
    await expect(rows.first()).toContainText("Example overflow");
    await expect(rows.first()).toContainText("Marked fixed in the data file.");
    await expect(rows.nth(1)).toContainText("Example old flaw");
    await expect(rows.nth(1)).toContainText("EXAMPLE-1");
    await expect(rows.nth(2)).toContainText("CVE-1999-0002");
    await expect(rows.nth(2)).toContainText("Two flaws in one package.");
    // Several ids stay apart, and an empty cell says so instead of looking broken.
    await expect(rows.nth(2).locator(".cve-id")).toHaveCount(2);
    await expect(rows.first().locator('[data-label="Ticket"]')).toContainText("none");
  });
});

test.describe("CVE page", () => {
  test("a kernel CVE groups hosts by computed status", async ({ page }) => {
    await page.goto("/cves/CVE-2000-1001");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Example takeover");
    await expect(page.locator(".top-sub")).toContainText("CVE-2000-1001");
    await expect(page.locator(".top-sub")).toContainText("Linux kernel");
    await expect(page.locator(".eli")).toContainText("lets a local program take over");
    await expect(page.locator(".tip")).toContainText("Update, then reboot.");
    await expect(page.locator(".fixline")).toContainText("6.18.56");
    await expect(page.locator(".kv")).toContainText("Computed from kernel reports");
    const group = (title) =>
      page.locator(".groups .card").filter({ has: page.getByRole("heading", { name: title, exact: true }) });
    await expect(group("Affected")).toContainText("ares");
    await expect(group("Affected")).toContainText("waiting for the next deploy");
    await expect(group("Affected")).toContainText("Runs a held-back kernel · hand-declared, verified");
    await expect(group("Affected").locator("li").filter({ hasText: "pan" }).locator(".stale")).toBeVisible();
    await expect(group("Reboot due")).toContainText("athena");
    await expect(group("Reboot due")).toContainText("Running 6.18.52 · next boot 6.18.56");
    await expect(group("Can't check")).toContainText("No fix line for 5.4");
    await expect(group("Can't check")).toContainText("Never reported");
    await expect(group("Can't check")).toContainText("Not in the data file");
    await expect(group("Fixed")).toContainText("demeter");
    await expect(group("Fixed").locator("li").filter({ hasText: "hermes" })).toContainText("data 3 h old");
    await expect(group("Fixed").locator("li").filter({ hasText: "hermes" }).locator(".stale")).toBeVisible();
    await expect(group("Fixed").locator("li").filter({ hasText: "selene" })).toContainText("hand-declared");
    await expect(page.locator(".note")).toContainText("Not applicable: hera");
  });

  test("a CVE without a name reads by its id, hand-declared", async ({ page }) => {
    await page.goto("/cves/CVE-2000-1002");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("CVE-2000-1002");
    await expect(page.locator(".kv")).toContainText("Hand-declared per host in the data file");
    await expect(page.locator(".groups")).toContainText("Waiting on a vendor update");
    await expect(page.locator(".groups")).toContainText("Vendor has not said");
  });

  test("a CVE that left the watchlist still has its page", async ({ page }) => {
    await page.goto("/cves/CVE-2000-1005");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("Example overflow");
    await expect(page.locator(".eyebrow")).toContainText("Fixed");
  });
});

test.describe("host page", () => {
  test("a reporting host shows its checks one by one", async ({ page }) => {
    await page.goto("/hosts/ares");
    await expect(page.getByRole("heading", { level: 1 })).toHaveText("ares");
    await expect(page.locator(".top-sub")).toContainText("Server · Harbor");
    await expect(page.locator(".pills")).toContainText("Beacon");
    await expect(page.locator(".pills")).toContainText("Always on");
    const tiles = page.locator(".tiles .tile");
    await expect(tiles.nth(0)).toContainText("No reboot due");
    await expect(page.locator(".two")).toContainText("From the running kernel.");
    await expect(tiles.nth(1)).toContainText("12 commits behind");
    await expect(tiles.nth(2)).toContainText("Lock 74 d old");
    await expect(page.locator("table")).toContainText("Example takeover");
    await expect(page.locator("table")).toContainText("Affected");
  });

  test("a reboot says what the next boot runs", async ({ page }) => {
    await page.goto("/hosts/athena");
    // A later fix line also applies here, so the reboot does not fix everything.
    await expect(page.locator(".two")).toContainText("The next boot fixes part of this. Reboot due.");
    await expect(page.locator(".tiles .tile").first()).toContainText("Reboot due");
    await expect(page.locator(".tiles .tile").first()).toContainText("next boot 6.18.56");
  });

  test("patch status and availability stay separate on a sleeping client", async ({ page }) => {
    await waitForProbes(page);
    await page.goto("/hosts/hephaestus");
    await expect(page.locator(".two")).toContainText("Asleep 41 d · over 30 d");
    await expect(page.locator(".two")).toContainText(
      "Client: asleep is normal. Yellow after 30 d and red after 60 d without contact.",
    );
    await expect(page.locator(".two")).toContainText(", by probe.");
    await page.goto("/hosts/artemis");
    await expect(page.locator(".two")).toContainText("1 critical");
    await expect(page.locator(".two")).toContainText("It stays affected while the host is away.");
    await expect(page.locator(".note").first()).toContainText("Patch status and availability are separate.");
  });

  test("a hand-declared host says so, with no offline colour", async ({ page }) => {
    await page.goto("/hosts/selene");
    await expect(page.locator(".two")).toContainText("No contact data");
    await expect(page.locator(".two")).toContainText("there is no offline colour");
    await expect(page.locator(".tiles")).toContainText("Declared OS");
    await expect(page.locator(".tiles")).toContainText("Raspberry Pi OS 13");
    await expect(page.locator(".pills")).toContainText("Hand-declared · verified");
  });

  test("a hand-declared host past its check is marked stale", async ({ page }) => {
    await page.goto("/hosts/pan");
    await expect(page.locator(".pills .warn")).toContainText("Stale");
  });

  test("an unlisted host says what is missing", async ({ page }) => {
    await page.goto("/hosts/nyx");
    await expect(page.locator(".hkind")).toHaveText("Unlisted");
    await expect(page.locator(".two")).toContainText("isn't in the data file");
  });
});

test.describe("the data file", () => {
  test("without one the page still works and says so", async ({ page }) => {
    await page.goto(`${BARE}/`);
    await expect(page.locator(".notice")).toContainText("No data file is configured.");
    await expect(page.locator(".top-meta")).toContainText("No data file");
    await expect(hostRow(page, "ares")).toBeVisible();
    await expect(page.getByRole("heading", { level: 2, name: "Unlisted" })).toBeVisible();
    await page.goto(`${BARE}/updates`);
    await expect(page.locator(".notice")).toContainText("No data file is configured.");
    await page.goto(`${BARE}/handled`);
    await expect(page.getByText("Nothing handled yet.")).toBeVisible();
  });

  test("an invalid file keeps the last good data and says so", async ({ page }) => {
    test.setTimeout(90_000);
    const file = path.join(RUN_DIR, "flaky-fleet.json");
    const good = fs.readFileSync(file);
    await page.goto(`${FLAKY}/`);
    await expect(page.locator(".notice")).toHaveCount(0);
    await expect(hostRow(page, "demeter")).toBeVisible();
    try {
      const broken = fleetData(Math.floor(Date.now() / 1000));
      broken.cves[0].severity = "catastrophic";
      fs.writeFileSync(file, JSON.stringify(broken));
      await expect(async () => {
        await page.goto(`${FLAKY}/`);
        await expect(page.locator(".notice")).toContainText("The data file is invalid");
      }).toPass({ timeout: 30_000 });
      await expect(page.locator(".notice")).toContainText("this page shows the last good data");
      await expect(page.locator(".notice")).toContainText("Beacon reports stay live");
      await expect(page.locator(".top-meta")).toContainText("Data file invalid");
      await expect(hostRow(page, "demeter")).toBeVisible();
      await expect(page.locator(".wcard").first()).toContainText("Example takeover");
    } finally {
      fs.writeFileSync(file, good);
    }
    await expect(async () => {
      await page.goto(`${FLAKY}/`);
      await expect(page.locator(".notice")).toHaveCount(0);
    }).toPass({ timeout: 30_000 });
  });
});
