{
  config,
  lib,
  pkgs,
  ...
}:

let
  cfg = config.services.pharos-beacon;

  defaultPackage = pkgs.callPackage ../packages/pharos.nix {
    binaryName = "pharos-beacon";
    src = lib.cleanSource ../..;
  };

  baseEnvironment = {
    PHAROS_URL = cfg.url;
    PHAROS_INTERVAL = toString cfg.interval;
    PHAROS_HOSTNAME = cfg.hostName;
    PHAROS_ROLE = cfg.role;
  }
  // lib.optionalAttrs (cfg.nixcfgDir != null) {
    NIXCFG_DIR = cfg.nixcfgDir;
  }
  // lib.optionalAttrs (cfg.tokenFile != null) {
    PHAROS_TOKEN_FILE = cfg.tokenFile;
  }
  // cfg.extraEnvironment;
in
{
  options.services.pharos-beacon = {
    enable = lib.mkEnableOption "Pharos host status beacon";

    package = lib.mkOption {
      type = lib.types.package;
      default = defaultPackage;
      defaultText = lib.literalExpression "inputs.pharos.packages.${pkgs.system}.pharos-beacon";
      description = "Package that provides the pharos-beacon binary.";
    };

    url = lib.mkOption {
      type = lib.types.str;
      default = "http://100.64.0.4:8088";
      description = "Base URL of pharosd. The beacon posts reports to /report.";
    };

    interval = lib.mkOption {
      type = lib.types.ints.positive;
      default = 60;
      description = "Heartbeat interval in seconds.";
    };

    hostName = lib.mkOption {
      type = lib.types.str;
      default = config.networking.hostName;
      defaultText = lib.literalExpression "config.networking.hostName";
      description = "Host name reported to Pharos.";
    };

    role = lib.mkOption {
      type = lib.types.str;
      default = "server";
      description = "Human-readable host role reported to Pharos.";
    };

    nixcfgDir = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/home/mba/Code/nixcfg";
      description = "Optional nixcfg checkout path used for flake.lock age and commits-behind freshness.";
    };

    tokenEnvironmentFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/agenix/pharos-beacon-env";
      description = ''
        Runtime environment file containing PHAROS_TOKEN. Use an agenix-managed
        file; do not place raw token values in Nix.
      '';
    };

    tokenFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/run/agenix/pharos-beacon-token";
      description = ''
        Runtime file containing only the raw beacon token. Prefer this for
        agenix-backed deployments when possible. Do not place raw token values
        in Nix.
      '';
    };

    allowLegacyReports = lib.mkOption {
      type = lib.types.bool;
      default = false;
      description = ''
        Allow running without tokenEnvironmentFile during the temporary
        PHAROS-37 rollout window. Leave false for token-enforced deployments.
      '';
    };

    user = lib.mkOption {
      type = lib.types.str;
      default = "pharos-beacon";
      description = "User that runs the beacon service.";
    };

    group = lib.mkOption {
      type = lib.types.str;
      default = "pharos-beacon";
      description = "Group that runs the beacon service.";
    };

    extraEnvironment = lib.mkOption {
      type = lib.types.attrsOf lib.types.str;
      default = { };
      description = "Additional non-secret environment variables for pharos-beacon.";
    };
  };

  config = lib.mkIf cfg.enable {
    assertions = [
      {
        assertion = cfg.tokenEnvironmentFile != null || cfg.tokenFile != null || cfg.allowLegacyReports;
        message = ''
          services.pharos-beacon requires tokenFile or tokenEnvironmentFile
          unless allowLegacyReports = true is set explicitly for the PHAROS-37
          rollout.
        '';
      }
    ];

    users.groups = lib.mkIf (cfg.group == "pharos-beacon") {
      pharos-beacon = { };
    };

    users.users = lib.mkIf (cfg.user == "pharos-beacon") {
      pharos-beacon = {
        isSystemUser = true;
        group = cfg.group;
        description = "Pharos beacon service user";
      };
    };

    systemd.services.pharos-beacon = {
      description = "Pharos host status beacon";
      wantedBy = [ "multi-user.target" ];
      wants = [ "network-online.target" ];
      after = [ "network-online.target" ];

      path = [
        pkgs.gitMinimal
        pkgs.restic
      ];
      environment = baseEnvironment;

      serviceConfig = {
        ExecStart = lib.getExe cfg.package;
        Restart = "always";
        RestartSec = "10s";
        User = cfg.user;
        Group = cfg.group;
        NoNewPrivileges = true;
        PrivateDevices = true;
        PrivateTmp = true;
        ProtectClock = true;
        ProtectControlGroups = true;
        ProtectHome = "read-only";
        ProtectKernelLogs = true;
        ProtectKernelModules = true;
        ProtectKernelTunables = true;
        ProtectSystem = "strict";
        RestrictAddressFamilies = [
          "AF_INET"
          "AF_INET6"
          "AF_UNIX"
        ];
        RestrictNamespaces = true;
        RestrictRealtime = true;
        RestrictSUIDSGID = true;
        SystemCallArchitectures = "native";
      }
      // lib.optionalAttrs (cfg.tokenEnvironmentFile != null) {
        EnvironmentFile = cfg.tokenEnvironmentFile;
      };
    };
  };
}
