{
  pkgs,
  pharosd,
  pharosBeacon,
  pharosModule,
}:

let
  preferencesRegistry = pkgs.writeText "pharos-test-host-preferences.json" (
    builtins.toJSON {
      schema = "inspr.pharos.host-preferences.v1";
      version = 1;
      hosts.vm-beacon = {
        accent = "#48b8a8";
        kind = "workstation";
        alerts = {
          suppress_down = true;
          suppress_backup = false;
          suppress_nix_freshness = true;
        };
      };
    }
  );

  deploymentEvidence = pkgs.writeText "pharos-test-deployment-evidence.json" (
    builtins.toJSON {
      schema = "inspr.pharos.nix-deployment-evidence.v1";
      version = 1;
      source_revision = builtins.concatStringsSep "" (builtins.genList (_: "1") 40);
      flake_lock_sha256 = builtins.concatStringsSep "" (builtins.genList (_: "2") 64);
      nixpkgs_revision = builtins.concatStringsSep "" (builtins.genList (_: "3") 40);
      nixpkgs_last_modified = 1700000000;
      nixpkgs_channel = "nixos-unstable";
    }
  );

  pharosdTestRunner = pkgs.writeShellScript "pharosd-test-runner" ''
    set -euo pipefail
    export PHAROS_REGISTRATION_TOKEN_FILE="$CREDENTIALS_DIRECTORY/registration-token"
    exec ${pharosd}/bin/pharosd
  '';

  registerTestBeacon = pkgs.writeShellScript "register-pharos-test-beacon" ''
    set -euo pipefail

    work=/run/pharos-test
    {
      printf 'Authorization: Bearer '
      cat "$work/registration-token"
      printf '\nContent-Type: application/json\n'
    } >"$work/register.headers"
    chmod 0600 "$work/register.headers"

    printf '%s' '{"schema":"inspr.pharos.host-registration.v1","version":1,"name":"vm-beacon","role":"NixOS integration test","is_nix":true,"heartbeat_interval_secs":10}' \
      >"$work/register.json"
    ${pkgs.curl}/bin/curl \
      --fail \
      --silent \
      --show-error \
      --header @"$work/register.headers" \
      --data @"$work/register.json" \
      http://127.0.0.1:18080/register \
      >"$work/register.response"

    ${pkgs.jq}/bin/jq -er '.token | strings | select(length > 0)' \
      "$work/register.response" >"$work/beacon-token.tmp"
    install -m 0600 "$work/beacon-token.tmp" "$work/beacon-token"
    truncate -s 0 "$work/beacon-token.tmp" "$work/register.response" "$work/register.headers"
  '';

  verifyFirstHeartbeat = pkgs.writeShellScript "verify-pharos-test-heartbeat" ''
    set -euo pipefail
    ${pkgs.curl}/bin/curl --fail --silent http://127.0.0.1:18080/hosts.json \
      | ${pkgs.jq}/bin/jq -e 'any(.hosts[]?;
          .name == "vm-beacon"
          and (.last_seen | type == "number")
          and .kernel.schema == "inspr.pharos.kernel-posture.v1"
          and .kernel.version == 1
          and .kernel.state == "current"
          and (.kernel.running_version | type == "string" and length > 0)
          and (.kernel.expected_version | type == "string" and length > 0)
          and (.kernel.observed_at | type == "number")
          and .preferences.accent == "#48b8a8"
          and .preferences.kind == "workstation"
          and .preferences.alerts.suppress_down == true
          and .preferences.alerts.suppress_nix_freshness == true
          and .freshness.deployment_evidence.schema == "inspr.pharos.nix-deployment-evidence.v1"
          and .freshness.deployment_evidence.version == 1
          and .freshness.deployment_evidence.source_revision == ("1" * 40)
          and .freshness.deployment_evidence.flake_lock_sha256 == ("2" * 64)
          and .freshness.deployment_evidence.nixpkgs_revision == ("3" * 40)
          and .freshness.nixcfg_comparison == null
          and .freshness.nixpkgs_comparison == null
        )' \
      >/dev/null
  '';
in
pkgs.testers.nixosTest {
  name = "pharos-beacon-runtime-token";

  nodes.machine =
    { lib, ... }:
    {
      imports = [ pharosModule ];

      networking.hostName = "pharos-test";

      virtualisation = {
        cores = 2;
        memorySize = 1536;
      };

      environment.systemPackages = [
        pkgs.curl
        pkgs.jq
      ];

      services.pharos-beacon = {
        enable = true;
        package = pharosBeacon;
        url = "http://127.0.0.1:18080";
        interval = 10;
        hostName = "vm-beacon";
        role = "NixOS integration test";
        tokenFile = "/run/pharos-test/beacon-token";
        preferencesFile = toString preferencesRegistry;
        deploymentEvidenceFile = toString deploymentEvidence;
        extraEnvironment = {
          PHAROS_BACKUP_MODE = "off";
          PHAROS_LOCATION_MODE = "off";
        };
      };

      systemd.services.pharosd-test = {
        description = "Pharos integration-test controller";
        environment = {
          PHAROS_ADDR = "127.0.0.1:18080";
          PHAROS_ALLOW_LOCAL_REGISTER = "1";
          PHAROS_DB = "/run/pharos-test/hosts.json";
          PHAROS_REQUIRE_BEACON_TOKEN = "1";
          RUST_LOG = "warn";
        };
        serviceConfig = {
          ExecStart = pharosdTestRunner;
          LoadCredential = "registration-token:/run/pharos-test/registration-token";
          Restart = "on-failure";
        };
      };

      systemd.services.pharos-beacon.wantedBy = lib.mkForce [ ];
    };

  testScript = ''
    with subtest("boot without an enrollment token"):
      machine.start()
      machine.wait_for_unit("multi-user.target", timeout=90)

    with subtest("register a host with runtime-only credentials"):
      machine.succeed("install -d -m 0700 /run/pharos-test")
      machine.succeed("head -c 48 /dev/urandom | base64 | tr -d '\\n' > /run/pharos-test/registration-token")
      machine.succeed("chmod 0600 /run/pharos-test/registration-token")
      machine.succeed("systemctl start pharosd-test.service")
      machine.wait_for_open_port(18080, timeout=90)
      machine.succeed("curl --fail --silent http://127.0.0.1:18080/healthz >/dev/null")
      machine.succeed("${registerTestBeacon}")

    with subtest("deliver the root-only token and observe first heartbeat"):
      machine.succeed("test \"$(stat -c %a /run/pharos-test/beacon-token)\" = 600")
      machine.fail("runuser -u pharos-beacon -- test -r /run/pharos-test/beacon-token")
      machine.succeed("systemctl restart pharos-beacon.service")
      machine.wait_for_unit("pharos-beacon.service", timeout=90)
      machine.wait_until_succeeds("${verifyFirstHeartbeat}", timeout=90)
  '';
}
