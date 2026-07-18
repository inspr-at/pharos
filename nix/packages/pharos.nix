{
  lib,
  rustPlatform,
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

  meta = {
    description = "Pharos fleet management binary: ${binaryName}";
    homepage = "https://github.com/markus-barta/pharos";
    license = lib.licenses.agpl3Only;
    mainProgram = binaryName;
    maintainers = [ ];
  };
}
