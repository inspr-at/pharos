{
  description = "Pharos fleet management and host beacon";

  inputs = {
    nixpkgs.url = "github:NixOS/nixpkgs/nixos-unstable";
  };

  outputs =
    {
      self,
      nixpkgs,
    }:
    let
      systems = [
        "x86_64-linux"
        "aarch64-linux"
        "x86_64-darwin"
        "aarch64-darwin"
      ];
      forAllSystems = nixpkgs.lib.genAttrs systems;
      pkgsFor = system: import nixpkgs { inherit system; };
      pharosSource = nixpkgs.lib.cleanSourceWith {
        src = ./.;
        filter =
          path: type:
          let
            relative = nixpkgs.lib.removePrefix "${toString ./.}/" (toString path);
          in
          nixpkgs.lib.cleanSourceFilter path type
          && relative != "nix/tests"
          && !nixpkgs.lib.hasPrefix "nix/tests/" relative;
      };
      mkPharosPackage =
        pkgs: binaryName:
        pkgs.callPackage ./nix/packages/pharos.nix {
          inherit binaryName;
          src = pharosSource;
        };
    in
    {
      packages = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        rec {
          pharosd = mkPharosPackage pkgs "pharosd";
          pharos-beacon = mkPharosPackage pkgs "pharos-beacon";
          default = pharosd;
        }
      );

      checks = forAllSystems (
        system:
        let
          pkgs = pkgsFor system;
        in
        {
          pharos-beacon = self.packages.${system}.pharos-beacon;
          pharosd = self.packages.${system}.pharosd;
        }
        // nixpkgs.lib.optionalAttrs (system == "x86_64-linux") {
          pharos-beacon-vm = import ./nix/tests/pharos-beacon-vm.nix {
            inherit pkgs;
            pharosd = self.packages.${system}.pharosd;
            pharosBeacon = self.packages.${system}.pharos-beacon;
            pharosModule = ./nix/modules/pharos-beacon.nix;
          };
        }
      );

      nixosModules = {
        pharos-beacon = ./nix/modules/pharos-beacon.nix;
        default = self.nixosModules.pharos-beacon;
      };
    };
}
