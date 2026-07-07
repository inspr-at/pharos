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
      mkPharosPackage =
        pkgs: binaryName:
        pkgs.callPackage ./nix/packages/pharos.nix {
          inherit binaryName;
          src = nixpkgs.lib.cleanSource ./.;
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
        {
          pharos-beacon = self.packages.${system}.pharos-beacon;
          pharosd = self.packages.${system}.pharosd;
        }
      );

      nixosModules = {
        pharos-beacon = ./nix/modules/pharos-beacon.nix;
        default = self.nixosModules.pharos-beacon;
      };
    };
}
