{
  lib,
  rustPlatform,
  gitMinimal,
  src ? lib.cleanSource ../..,
  binaryName,
  cargoPackage ? binaryName,
}:

rustPlatform.buildRustPackage {
  pname = binaryName;
  version = lib.removeSuffix "\n" (builtins.readFile (src + "/VERSION"));

  inherit src;

  cargoLock.lockFile = src + "/Cargo.lock";
  cargoBuildFlags = [
    "-p"
    cargoPackage
  ];
  cargoTestFlags = [
    "-p"
    cargoPackage
  ];
  nativeCheckInputs = lib.optionals (cargoPackage == "pharos-beacon") [ gitMinimal ];

  meta = {
    description = "Pharos fleet management binary: ${binaryName}";
    homepage = "https://github.com/inspr-at/pharos";
    license = lib.licenses.agpl3Only;
    mainProgram = binaryName;
    maintainers = [ ];
  };
}
