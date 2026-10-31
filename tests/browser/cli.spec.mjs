import { execFile } from "node:child_process";
import fs from "node:fs";
import path from "node:path";
import { expect, test } from "@playwright/test";
import { fleetData } from "./fixtures.mjs";

const RUN_DIR = process.env.PHAROS_BROWSER_RUN_DIR;
const MAIN = `http://127.0.0.1:${process.env.PHAROS_BROWSER_PORT}`;
const BARE = `http://127.0.0.1:${process.env.PHAROS_BROWSER_BARE_PORT}`;
const FLAKY = `http://127.0.0.1:${process.env.PHAROS_BROWSER_FLAKY_PORT}`;
const TOKEN_FILE = path.join(RUN_DIR, "operator-token");

function pharos(args, env = {}) {
  return new Promise((resolve) => {
    execFile(
      path.resolve("target/debug/pharos"),
      args,
      { env: { PHAROS_URL: MAIN, PHAROS_OPERATOR_TOKEN_FILE: TOKEN_FILE, ...env } },
      (error, stdout, stderr) => resolve({ code: error ? (error.code ?? 1) : 0, stdout, stderr }),
    );
  });
}

/** A table's rows, its cells split on the padding between columns. */
function rows(stdout) {
  return stdout
    .trimEnd()
    .split("\n")
    .slice(1)
    .map((line) => line.split(/ {2,}/));
}

/** The hosts listed under one heading on the Updates page. */
async function updatesGroup(page, title) {
  const section = page.locator("section.card").filter({
    has: page.getByRole("heading", { name: title, exact: true }),
  });
  if ((await section.count()) === 0) return [];
  const names = await section.locator("tbody th.host a").allTextContents();
  return names.map((name) => name.trim()).sort();
}

const metric = (page, label) =>
  page.locator(".metrics > *").filter({ hasText: label }).first().innerText();

// The CLI runs once per suite; the phone project draws the same data.
test.describe("the pharos CLI", () => {
  test.skip(({ isMobile }) => isMobile, "runs once, on the desktop project");

  test("cves says what the watchlist cards say", async ({ page }) => {
    await page.goto(`${MAIN}/`);
    const { code, stdout } = await pharos(["cves"]);
    expect(code).toBe(0);
    expect(stdout.split("\n")[0]).toMatch(/^ID +SEV +STATE +SOURCE +HOSTS$/);
    const table = new Map(rows(stdout).map((row) => [row[0], row]));
    const cards = page.locator(".wcard:not(.watch-overflow)");
    expect(await cards.count()).toBeGreaterThan(0);
    for (const card of await cards.all()) {
      const id = (await card.locator(".cve-id").innerText()).trim();
      const row = table.get(id);
      expect(row, id).toBeTruthy();
      expect(row[4], id).toBe((await card.locator(".wcard-counts").innerText()).trim());
      expect(row[1], id).toBe((await card.locator(".wcard-top > span").first().innerText()).trim().toLowerCase());
      expect(row[3], id).toBe((await card.locator(".wnote").last().innerText()).includes("kernel") ? "kernel" : "declared");
    }
  });

  test("updates says what the Updates page says", async ({ page }) => {
    await page.goto(`${MAIN}/updates`);
    const { code, stdout } = await pharos(["updates"]);
    expect(code).toBe(0);
    expect(stdout.split("\n")[0]).toMatch(/^HOST +DUE +SOURCE$/);
    const lines = stdout.trimEnd().split("\n");
    const summary = lines.pop();
    const table = rows(lines.join("\n"));
    const hostsWith = (pattern) =>
      table
        .filter((row) => pattern.test(row[1]))
        .map((row) => row[0])
        .sort();
    expect(hostsWith(/reboot due/)).toEqual(await updatesGroup(page, "Reboot due"));
    expect(hostsWith(/commits? behind/)).toEqual(
      await updatesGroup(page, "Behind the declared config"),
    );
    expect(hostsWith(/lock \d+ d old/)).toEqual(await updatesGroup(page, "Old nixpkgs"));
    const count = async (title) => (await updatesGroup(page, title)).length;
    expect(summary).toBe(
      `${await count("Hand-declared")} hand-declared · ${await count("Up to date")} up to date · ${await count("Can't tell yet")} can't tell`,
    );
    // The page's own words for a host that is behind.
    const behind = page
      .locator("section.card")
      .filter({ has: page.getByRole("heading", { name: "Behind the declared config" }) });
    for (const row of await behind.locator("tbody tr").all()) {
      const host = (await row.locator("th.host a").innerText()).trim();
      const words = (await row.locator("td").first().innerText()).trim();
      expect(table.find((cells) => cells[0] === host)[1]).toContain(words);
    }
  });

  test("hosts lists every row on Fleet, with its counts", async ({ page }) => {
    await page.goto(`${MAIN}/`);
    const { code, stdout } = await pharos(["hosts"]);
    expect(code).toBe(0);
    const lines = stdout.trimEnd().split("\n");
    const summary = lines.pop();
    const table = rows(lines.join("\n"));
    const onPage = await page
      .locator(".fleet-table tr[data-host]")
      .evaluateAll((items) => items.map((item) => item.dataset.host.split(" ")[0]));
    expect(table.map((row) => row[0]).sort()).toEqual([...onPage].sort());
    const number = async (label) => /\d+/.exec(await metric(page, label))[0];
    expect(summary).toBe(
      `${await number("hosts")} hosts · ${await number("affected")} affected · ${await number("can't check")} can't check`,
    );
  });

  test("beacon shows last seen and kernels, and finds one host", async () => {
    const all = await pharos(["beacon"]);
    expect(all.code).toBe(0);
    expect(all.stdout.split("\n")[0]).toMatch(/^HOST +LAST SEEN +RUNNING +NEXT BOOT$/);
    const one = await pharos(["beacon", "ares"]);
    expect(one.code).toBe(0);
    expect(rows(one.stdout).map((row) => row[0])).toEqual(["ares"]);
    const lastSeen = await pharos(["beacon", "last-seen", "ares"]);
    expect(lastSeen.stdout.split("\n")[0]).toMatch(/^HOST +LAST SEEN$/);
    const missing = await pharos(["beacon", "nobody"]);
    expect(missing.code).toBe(1);
    expect(missing.stderr).toContain("host was not found");
  });

  test("health and version work without a token, and say more with one", async () => {
    const bare = await pharos(["health"], { PHAROS_OPERATOR_TOKEN_FILE: "" });
    // An empty path is not a token file; a missing variable is the no-token case.
    expect(bare.code).toBe(1);
    const noToken = await new Promise((resolve) => {
      execFile(
        path.resolve("target/debug/pharos"),
        ["health"],
        { env: { PHAROS_URL: MAIN } },
        (error, stdout) => resolve({ code: error ? 1 : 0, stdout }),
      );
    });
    expect(noToken).toEqual({ code: 0, stdout: "ok\n" });
    const health = await pharos(["health"]);
    expect(health.code).toBe(0);
    expect(health.stdout).toMatch(/^ok · server up .+ · data file valid, updated .+ ago\n/);
    expect(health.stdout).toMatch(/\nbeacons: 7 reporting · 1 offline · 1 never reported\n$/);
    const version = await pharos(["version"]);
    expect(version.code).toBe(0);
    expect(version.stdout).toMatch(/^pharos \S+\ndata file schema 3 · \d+ hosts · \d+ watched CVEs\n$/);
  });

  test("a command fails without a token, and with a wrong one says nothing", async () => {
    const without = await new Promise((resolve) => {
      execFile(
        path.resolve("target/debug/pharos"),
        ["hosts"],
        { env: { PHAROS_URL: MAIN } },
        (error, stdout, stderr) => resolve({ code: error ? 1 : 0, stdout, stderr }),
      );
    });
    expect(without.code).toBe(1);
    expect(without.stderr).toContain("PHAROS_OPERATOR_TOKEN_FILE is required");

    const wrongFile = path.join(RUN_DIR, "wrong-token");
    fs.writeFileSync(wrongFile, "not-the-token", { mode: 0o600 });
    for (const command of ["hosts", "cves", "updates", "beacon", "health", "version"]) {
      const wrong = await pharos([command], { PHAROS_OPERATOR_TOKEN_FILE: wrongFile });
      expect(wrong.code, command).toBe(1);
      expect(wrong.stderr, command).toContain("rejected");
      expect(wrong.stdout, command).toBe("");
    }

    // The server without a hash file takes no token at all.
    const unset = await pharos(["hosts"], { PHAROS_URL: BARE });
    expect(unset.code).toBe(1);
    expect(unset.stderr).toContain("rejected");
  });

  test("the server refuses to start with a bad token hash file", async () => {
    const run = (hashFile) =>
      new Promise((resolve) => {
        execFile(
          path.resolve("target/debug/pharosd"),
          [],
          {
            timeout: 5_000,
            env: {
              PHAROS_ADDR: "127.0.0.1:0",
              PHAROS_ALLOW_OPEN: "true",
              PHAROS_OPERATOR_TOKEN_HASH_FILE: hashFile,
              RUST_LOG: "error",
            },
          },
          (error, stdout, stderr) => resolve({ error, output: stdout + stderr }),
        );
      });
    const missing = await run(path.join(RUN_DIR, "no-such-file"));
    expect(missing.error?.killed).toBeFalsy();
    expect(missing.error?.code).toBeTruthy();
    expect(missing.output).toContain("PHAROS_OPERATOR_TOKEN_HASH_FILE");

    const badFile = path.join(RUN_DIR, "bad-hash");
    fs.writeFileSync(badFile, "not-a-digest", { mode: 0o600 });
    const bad = await run(badFile);
    expect(bad.error?.killed).toBeFalsy();
    expect(bad.error?.code).toBeTruthy();
    expect(bad.output).toContain("64 lowercase hex");
  });

  test("health fails while the data file is invalid", async () => {
    test.setTimeout(90_000);
    const file = path.join(RUN_DIR, "flaky-fleet.json");
    const good = fs.readFileSync(file);
    const env = { PHAROS_URL: FLAKY };
    try {
      const broken = fleetData(Math.floor(Date.now() / 1000));
      broken.cves[0].severity = "catastrophic";
      fs.writeFileSync(file, JSON.stringify(broken));
      await expect(async () => {
        const health = await pharos(["health"], env);
        expect(health.code).toBe(1);
        expect(health.stdout).toContain("data file invalid");
        expect(health.stdout).toContain("showing the last good file");
      }).toPass({ timeout: 30_000 });
    } finally {
      fs.writeFileSync(file, good);
    }
    await expect(async () => {
      const health = await pharos(["health"], env);
      expect(health.code).toBe(0);
      expect(health.stdout).toContain("data file valid");
    }).toPass({ timeout: 30_000 });
  });
});
