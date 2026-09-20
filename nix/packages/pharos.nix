{
  lib,
  rustPlatform,
  gitMinimal,
  openssl,
  src ? lib.cleanSource ../..,
  binaryName,
  cargoPackage ? binaryName,
}:
let
  # cleanSource and cleanSourceWith retain the original tree. Plain src
  # overrides remain authoritative for both metadata and build contents.
  metadataSource = src.origSrc or src;
in
rustPlatform.buildRustPackage {
  pname = binaryName;
  # Evaluation must read the original tree, not a filtered store path that
  # `nix flake check --no-build` may only compute without materialising.
  version = (builtins.fromJSON (builtins.readFile (metadataSource + "/RELEASE.json"))).version;

  inherit src;

  cargoLock.lockFile = metadataSource + "/Cargo.lock";
  cargoBuildFlags = [
    "-p"
    cargoPackage
  ];
  cargoTestFlags = [
    "-p"
    cargoPackage
  ];
  nativeCheckInputs =
    lib.optionals (cargoPackage == "pharos-beacon") [ gitMinimal ]
    ++ lib.optionals (cargoPackage == "pharosd") [ openssl ];

  meta = {
    description = "Pharos fleet management binary: ${binaryName}";
    homepage = "https://github.com/inspr-at/pharos";
    license = lib.licenses.agpl3Only;
    mainProgram = binaryName;
    maintainers = [ ];
  };
}
