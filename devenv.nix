{ pkgs, ... }:
{
  # Rust toolchain from nixpkgs (no global rustup install). cargo-leptos +
  # wasm target get added when the Leptos UI lands (PHAROS-10).
  packages = with pkgs; [
    cargo
    cargo-deny
    rustc
    clippy
    rustfmt
    just
  ];

  enterShell = ''
    echo "🔦 pharos devenv — $(cargo --version 2>/dev/null || echo cargo)"
  '';
}
