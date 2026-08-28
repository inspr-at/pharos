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
  // lib.optionalAttrs (cfg.deploymentEvidenceFile != null) {
    PHAROS_NIX_DEPLOYMENT_EVIDENCE_FILE = cfg.deploymentEvidenceFile;
  }
  // lib.optionalAttrs (cfg.nixcfgRemoteUrl != null) {
    PHAROS_NIXCFG_REMOTE_URL = cfg.nixcfgRemoteUrl;
  }
  // lib.optionalAttrs (cfg.nixcfgRemoteRef != null) {
    PHAROS_NIXCFG_REMOTE_REF = cfg.nixcfgRemoteRef;
  }
  // lib.optionalAttrs (cfg.nixpkgsRemoteUrl != null) {
    PHAROS_NIXPKGS_REMOTE_URL = cfg.nixpkgsRemoteUrl;
  }
  // lib.optionalAttrs (cfg.nixpkgsChannelBaseUrl != null) {
    PHAROS_NIXPKGS_CHANNEL_BASE_URL = cfg.nixpkgsChannelBaseUrl;
  }
  // lib.optionalAttrs (cfg.preferencesFile != null) {
    PHAROS_PREFERENCES_FILE = cfg.preferencesFile;
  }
  // cfg.extraEnvironment
  // lib.optionalAttrs (cfg.tokenFile != null) {
    PHAROS_TOKEN_FILE = "%d/pharos-token";
  };
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
      example = "https://pharos.example";
      description = "Base URL of pharosd. The beacon posts reports to /report.";
    };

    interval = lib.mkOption {
      type = lib.types.ints.between 10 3600;
      default = 60;
      description = "Heartbeat interval in seconds (10–3600).";
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
      example = "/srv/nixcfg";
      description = ''
        Optional read-only nixcfg checkout. Report v5 uses it only as a Git
        object source and accepts lock context only when its SHA-256 matches
        the active-generation evidence.
      '';
    };

    deploymentEvidenceFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/etc/pharos-deployment/evidence.json";
      description = ''
        Generation-owned inspr.pharos.nix-deployment-evidence.v1 document.
        Without valid evidence, Nix freshness is explicitly unverified.
      '';
    };

    nixcfgRemoteUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://github.com/example/nixcfg.git";
      description = "Credential-free HTTPS Git repository used for the authoritative nixcfg comparison.";
    };

    nixcfgRemoteRef = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "refs/heads/main";
      description = "Exact refs/heads/* branch used as authoritative nixcfg state.";
    };

    nixpkgsRemoteUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://github.com/NixOS/nixpkgs.git";
      description = ''
        Credential-free HTTPS Git repository used for custom nixpkgs sources.
        The official NixOS/nixpkgs repository is resolved through the bounded
        official channel publication instead of downloading GitHub's complete
        ref advertisement.
      '';
    };

    nixpkgsChannelBaseUrl = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "https://channels.nixos.org/";
      description = ''
        Optional credential-free HTTPS base URL for exact channel
        git-revision documents. When unset, the official NixOS/nixpkgs Git
        remote uses https://channels.nixos.org/ automatically.
      '';
    };

    preferencesFile = lib.mkOption {
      type = lib.types.nullOr lib.types.str;
      default = null;
      example = "/etc/pharos/host-preferences.json";
      description = ''
        Optional declared inspr.pharos.host-preferences.v1 registry. The beacon
        selects its own host and reports that validated preference set as
        applied runtime fact.
      '';
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
        pkgs.docker-client
        pkgs.gitMinimal
        pkgs.restic
      ];
      environment = baseEnvironment;

      serviceConfig = {
        Type = "notify";
        NotifyAccess = "main";
        WatchdogSec = "${toString (cfg.interval * 3)}s";
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
        ReadOnlyPaths =
          lib.optional (cfg.preferencesFile != null) cfg.preferencesFile
          ++ lib.optional (cfg.deploymentEvidenceFile != null) cfg.deploymentEvidenceFile;
      }
      // lib.optionalAttrs (cfg.tokenFile != null) {
        LoadCredential = "pharos-token:${cfg.tokenFile}";
      }
      // lib.optionalAttrs (cfg.tokenEnvironmentFile != null) {
        EnvironmentFile = cfg.tokenEnvironmentFile;
      };
    };
  };
}
