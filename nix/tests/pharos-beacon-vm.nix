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

  pharosdTestRunner = pkgs.writeShellScript "pharosd-test-runner" ''
    set -euo pipefail
    export PHAROS_REGISTRATION_TOKEN="$(<"$CREDENTIALS_DIRECTORY/registration-token")"
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

    printf '%s' '{"name":"vm-beacon","role":"NixOS integration test","is_nix":true,"heartbeat_interval_secs":1}' \
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
          and .preferences.accent == "#48b8a8"
          and .preferences.kind == "workstation"
          and .preferences.alerts.suppress_down == true
          and .preferences.alerts.suppress_nix_freshness == true
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
        interval = 1;
        hostName = "vm-beacon";
        role = "NixOS integration test";
        tokenFile = "/run/pharos-test/beacon-token";
        preferencesFile = toString preferencesRegistry;
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
