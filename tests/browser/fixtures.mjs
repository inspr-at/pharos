// A fictional fleet with one host in every state the pages can show. Times are
// relative to now, so a state never ages out from under a test. Only example
// names and documentation addresses belong here: this repository is public.
import crypto from "node:crypto";
import fs from "node:fs";
import path from "node:path";

const MINUTE = 60;
const HOUR = 60 * MINUTE;
const DAY = 24 * HOUR;
const FIXED = "6.18.56";
const VULNERABLE = "6.18.52";
const CHANNEL = "nixos-26.05";

const hex = (length) => "a1".repeat(length / 2);

function report(now, { name, role, seen, interval = HOUR, kernel, nextBoot, behind = 0, age = 2 }) {
  const nixpkgsCurrent = age <= 30;
  return {
    name,
    role,
    is_nix: true,
    last_seen: now - seen,
    heartbeat_interval_secs: interval,
    freshness: {
      applicable: true,
      flake_lock_age_days: age,
      commits_behind: behind,
      nixpkgs_age_days: age,
      nixpkgs_channel: CHANNEL,
      deployment_evidence: {
        schema: "inspr.pharos.nix-deployment-evidence.v1",
        version: 1,
        source_revision: hex(40),
        flake_lock_sha256: hex(64),
        nixpkgs_revision: hex(40),
        nixpkgs_last_modified: now - age * DAY,
        nixpkgs_channel: CHANNEL,
      },
      nixcfg_comparison: {
        upstream_revision: hex(40),
        relation: behind > 0 ? "behind" : "current",
        ...(behind > 0 ? { commits_behind: behind } : {}),
      },
      nixpkgs_comparison: {
        upstream_revision: hex(40),
        relation: nixpkgsCurrent ? "current" : "different",
      },
    },
    kernel: {
      schema: "inspr.pharos.kernel-posture.v1",
      version: 1,
      state: nextBoot ? "reboot_required" : "current",
      running_version: kernel,
      expected_version: nextBoot ?? kernel,
      observed_at: now - seen,
    },
  };
}

function reports(now) {
  return [
    report(now, { name: "ares", role: "Server", seen: 2 * MINUTE, kernel: VULNERABLE, behind: 12, age: 74 }),
    report(now, { name: "athena", role: "Server", seen: 5 * MINUTE, kernel: VULNERABLE, nextBoot: FIXED }),
    report(now, { name: "demeter", role: "Server", seen: MINUTE, kernel: FIXED }),
    report(now, { name: "hermes", role: "Server", seen: 3 * HOUR, kernel: FIXED }),
    report(now, { name: "hades", role: "Server", seen: 2 * DAY, kernel: VULNERABLE, age: 74 }),
    report(now, { name: "zeus", role: "Server", seen: 9 * MINUTE, kernel: "5.4.1" }),
    {
      name: "hera",
      role: "Workstation",
      is_nix: false,
      last_seen: now - 4 * MINUTE,
      heartbeat_interval_secs: HOUR,
      freshness: { applicable: false, flake_lock_age_days: null, commits_behind: null },
      kernel: {
        schema: "inspr.pharos.kernel-posture.v1",
        version: 1,
        state: "not_applicable",
        observed_at: now - 4 * MINUTE,
      },
    },
    report(now, { name: "nyx", role: "Scratch", seen: 7 * MINUTE, kernel: FIXED }),
  ];
}

function day(now, secondsAgo) {
  return new Date((now - secondsAgo) * 1000).toISOString().slice(0, 10);
}

function moment(now, secondsAgo) {
  return new Date((now - secondsAgo) * 1000).toISOString().replace(/\.\d+Z$/, "Z");
}

export function fleetData(now) {
  const checked = moment(now, 7 * DAY);
  const staleCheck = moment(now, 120 * DAY);
  const host = (name, kind, availability, extra = {}) => ({
    name,
    kind,
    role: "Server",
    tailnet: { state: "online", ip: "192.0.2.10" },
    lan: "192.0.2.11",
    availability,
    cve: {},
    ...extra,
  });
  const client = (name, extra = {}) =>
    host(name, "mac", "client", {
      role: "Laptop",
      os: "macOS",
      version: "26.1",
      tailnet: { state: "offline", ip: "192.0.2.20" },
      last_verified: checked,
      ...extra,
    });
  return closed({
    schema_version: 3,
    title: "Example fleet",
    updated_at: moment(now, 2 * HOUR),
    updated_by: "example-operator",
    defaults: { client: { offline_warn_days: 30, offline_red_days: 60 } },
    cves: [
      {
        id: "CVE-2000-1001",
        name: "Example takeover",
        severity: "critical",
        state: "open",
        component: "kernel",
        eli10: "A flaw in the kernel lets a local program take over the machine.",
        tip: "Update, then reboot.",
        fixed_in: [FIXED, "7.2.10", "7.3"],
      },
      {
        id: "CVE-2000-1002",
        severity: "high",
        state: "open",
        component: "example-library",
        eli10: "A library lets a crafted file run code.",
        tip: "Update the library.",
        fixed_in: ["2.4.1"],
      },
      {
        id: "CVE-2000-1003",
        name: "Example leak",
        severity: "medium",
        state: "mitigated",
        component: "kernel",
        eli10: "A driver can leak memory.",
        tip: "The driver stays unloaded until the fix ships.",
        fixed_in: ["6.18.60"],
      },
      {
        id: "CVE-2000-1004",
        name: "Example crash",
        severity: "low",
        state: "fixed",
        component: "example-tool",
        eli10: "A tool can crash on bad input.",
        tip: "Nothing left to do.",
        fixed_in: ["1.2.0"],
        fixed_on: day(now, DAY),
      },
      {
        id: "CVE-2000-1005",
        name: "Example overflow",
        severity: "high",
        state: "fixed",
        component: "example-tool",
        eli10: "A tool could overflow a buffer.",
        tip: "Nothing left to do.",
        fixed_in: ["1.1.9"],
        fixed_on: day(now, 10 * DAY),
      },
      {
        id: "CVE-2000-1006",
        name: "Example bypass",
        severity: "medium",
        state: "open",
        component: "example-proxy",
        eli10: "A proxy can skip a check.",
        tip: "Update the proxy.",
        fixed_in: ["3.0.2"],
      },
    ],
    handled: [
      {
        ids: ["CVE-1999-0001"],
        name: "Example old flaw",
        eli10: "An older flaw, patched everywhere.",
        hosts: ["demeter", "hermes"],
        action: "Updated and rebooted.",
        done: day(now, 21 * DAY),
        ticket: "EXAMPLE-1",
      },
      {
        ids: ["CVE-1999-0002", "CVE-1999-0003"],
        eli10: "Two flaws in one package.",
        hosts: ["ares"],
        action: "Removed the package.",
        done: day(now, 40 * DAY),
      },
    ],
    sections: [
      {
        id: "harbor",
        name: "Harbor",
        place: "Example City",
        hosts: [
          host("ares", "nixos", "always_on", {
            os: "NixOS",
            cve: {
              "CVE-2000-1002": { state: "fixed", since: day(now, 9 * DAY), last_verified: checked },
              "CVE-2000-1006": { state: "na" },
            },
          }),
          host("athena", "nixos", "always_on", { os: "NixOS", public: "athena.example.test" }),
          host("demeter", "nixos", "always_on", {
            os: "NixOS",
            cve: {
              "CVE-2000-1002": { state: "affected", note: "Waiting on a vendor update", last_verified: checked },
            },
          }),
          host("hermes", "vm", "always_on", { os: "NixOS" }),
          host("hades", "nixos", "always_on", { os: "NixOS" }),
          host("zeus", "appliance", "always_on", { os: "ExampleOS", version: "5", last_verified: checked }),
          host("hera", "mac", "optional", {
            role: "Workstation",
            os: "macOS",
            cve: { "CVE-2000-1001": { state: "na" } },
          }),
          host("hestia", "nixos", "always_on", { os: "NixOS", version: "26.05", kernel: FIXED, last_verified: checked }),
        ],
      },
      {
        id: "hilltop",
        name: "Hilltop",
        place: "Example Hill",
        hosts: [
          client("artemis", {
            kernel: VULNERABLE,
            cve: {
              "CVE-2000-1001": { state: "affected", note: "Runs a held-back kernel", last_verified: checked },
              "CVE-2000-1002": { state: "unknown", note: "vendor has not said", last_verified: checked },
            },
          }),
          client("apollo"),
          client("hephaestus"),
          client("poseidon"),
          client("dionysos", { availability: "optional" }),
          client("iris", { availability: "always_on" }),
          client("eos", { availability: "always_on" }),
        ],
      },
      {
        id: "islands",
        name: "Islands",
        hosts: [
          host("selene", "pi", "always_on", {
            os: "Raspberry Pi OS",
            version: "13",
            kernel: FIXED,
            tailnet: { state: "none" },
            last_verified: checked,
            cve: {
              "CVE-2000-1001": { state: "fixed", since: day(now, 9 * DAY), last_verified: checked },
            },
          }),
          host("pan", "pi", "always_on", {
            os: "Raspberry Pi OS",
            version: "12",
            kernel: VULNERABLE,
            last_verified: staleCheck,
            cve: {
              "CVE-2000-1001": { state: "affected", last_verified: staleCheck },
            },
          }),
          host("atlas", "nixos", "always_on"),
        ],
      },
    ],
  }, "CVE-2000-1005");
}

// Every listed host answers for the old fixed CVE, so it can leave the watchlist.
function closed(data, id) {
  for (const section of data.sections) {
    for (const host of section.hosts) host.cve[id] ??= { state: "na" };
  }
  return data;
}

function probeRegistry(port) {
  const answers = (host) => ({ host, target: "127.0.0.1", tcp_port: Number(port) });
  const silent = (host) => ({ host, target: "192.0.2.1", tcp_port: 22 });
  const unresolvable = (host) => ({ host, target: "nothing-here.invalid" });
  return {
    schema: "inspr.pharos.host-probes.v1",
    version: 1,
    probe_interval_secs: 30,
    hosts: [
      answers("artemis"),
      silent("apollo"),
      silent("hephaestus"),
      silent("poseidon"),
      silent("dionysos"),
      silent("hestia"),
      unresolvable("iris"),
      unresolvable("eos"),
      answers("charon"),
    ],
  };
}

function probeState(now) {
  return {
    schema: "inspr.pharos.host-probe-state.v1",
    version: 1,
    last_reachable_at: {
      apollo: now - 2 * DAY,
      hephaestus: now - 41 * DAY,
      poseidon: now - 70 * DAY,
      dionysos: now - 50 * DAY,
      iris: now - 3 * HOUR,
    },
  };
}

function writeJson(file, value, mode = 0o644) {
  fs.writeFileSync(file, JSON.stringify(value, null, 2), { mode });
}

/** Everything the servers read from the run directory. */
export function writeFixtures(runDir, port) {
  const now = Math.floor(Date.now() / 1000);
  // A token for this run only. The server gets its hash, the CLI the token.
  const token = crypto.randomBytes(32).toString("hex");
  fs.writeFileSync(path.join(runDir, "operator-token"), token, { mode: 0o600 });
  fs.writeFileSync(
    path.join(runDir, "operator-token.sha256"),
    crypto.createHash("sha256").update(token).digest("hex"),
    { mode: 0o600 },
  );
  writeJson(path.join(runDir, "fleet.json"), fleetData(now));
  // One CVE fewer, so the fixed card is on the watchlist instead of past its end.
  const flaky = fleetData(now);
  flaky.cves = flaky.cves.filter((cve) => cve.id !== "CVE-2000-1006");
  flaky.sections[0].hosts[0].cve = { "CVE-2000-1005": { state: "na" } };
  writeJson(path.join(runDir, "flaky-fleet.json"), flaky);
  writeJson(path.join(runDir, "hosts.json"), reports(now), 0o600);
  writeJson(path.join(runDir, "hosts.json.host-probes.json"), probeState(now), 0o600);
  writeJson(path.join(runDir, "host-probes.json"), probeRegistry(port));
  writeJson(path.join(runDir, "bare-hosts.json"), reports(now).slice(0, 1), 0o600);
  writeJson(path.join(runDir, "flaky-hosts.json"), reports(now).slice(0, 1), 0o600);
}
