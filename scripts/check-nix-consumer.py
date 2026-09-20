#!/usr/bin/env python3
"""Evaluate external beacon consumers with empty Nix stores and fetcher caches."""

import argparse
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import tempfile


CONSUMER = """{
  inputs.pharos.url = @SOURCE@;
  inputs.nixpkgs.follows = "pharos/nixpkgs";
  outputs = { nixpkgs, pharos, ... }: {
    nixosConfigurations = nixpkgs.lib.genAttrs
      [ "x86_64-linux" "aarch64-linux" ]
      (system: nixpkgs.lib.nixosSystem {
        inherit system;
        modules = [ pharos.nixosModules.pharos-beacon {
          networking.hostName = "pharos-consumer";
          system.stateVersion = "26.05";
          fileSystems."/" = { device = "/dev/disk/by-label/probe"; fsType = "ext4"; };
          boot.loader.grub.enable = false;
          services.pharos-beacon = {
            enable = true;
            url = "https://pharos.example.invalid";
            # Runtime-only: evaluation must not need a real credential file.
            tokenFile = "/run/pharos-consumer/nonexistent-token";
            @PACKAGE@
          };
        } ];
      });
  };
}
"""


def filtered_sources(repo: Path, archive: Path) -> dict[str, str]:
    lock = json.loads((repo / "flake.lock").read_text())
    nixpkgs = lock["nodes"]["nixpkgs"]["locked"]
    nixpkgs_ref = f"github:{nixpkgs['owner']}/{nixpkgs['repo']}/{nixpkgs['rev']}"
    expression = f"""
      let
        lib = (builtins.getFlake {json.dumps(nixpkgs_ref)}).lib;
        original = builtins.fetchTarball {json.dumps(archive.as_uri())};
        exported = lib.cleanSourceWith {{
          src = original;
          filter = path: type:
            let relative = lib.removePrefix "${{toString original}}/" (toString path); in
            lib.cleanSourceFilter path type
            && relative != "nix/tests"
            && !(lib.hasPrefix "nix/tests/" relative);
        }};
      in {{
        default = toString (lib.cleanSource original);
        exported = toString exported;
      }}
    """
    result = subprocess.run(
        [
            "nix", "--extra-experimental-features", "nix-command flakes",
            "eval", "--impure", "--json", "--expr", expression,
        ],
        cwd=repo,
        check=True,
        capture_output=True,
        text=True,
    )
    return json.loads(result.stdout)


def assert_absent(store: Path, logical: str, mode: str, phase: str) -> None:
    path = Path(logical)
    if path.parent != Path("/nix/store"):
        raise RuntimeError(f"{mode} filtered source is not a Nix store path: {logical}")
    physical = store / "nix/store" / path.name
    if physical.exists():
        raise RuntimeError(f"{mode} filtered source was materialised {phase}: {physical}")


def check(repo: Path, work: Path) -> None:
    # Copy the working contents of tracked files, including intent-to-add
    # entries. Never include local build caches or untracked credentials.
    tracked = subprocess.check_output(
        ["git", "ls-files", "-z"], cwd=repo
    ).decode().split("\0")
    archive = work / "pharos.tar.gz"
    with tarfile.open(archive, "w:gz") as output:
        for relative in sorted(filter(None, tracked)):
            source = repo / relative
            if source.is_file() or source.is_symlink():
                output.add(source, arcname=f"source/{relative}", recursive=False)
        # Force cleanSource to differ from its input, also for the module's
        # default package. A warm or unchanged source otherwise hides the bug.
        marker = tarfile.TarInfo("source/consumer-filter-probe.o")
        payload = b"PHAROS-276: deliberately removed by cleanSourceFilter\n"
        marker.size = len(payload)
        output.addfile(marker, io.BytesIO(payload))

    sources = filtered_sources(repo, archive)
    failures = []
    for mode in ("default", "exported"):
        case = work / mode
        consumer = case / "consumer"
        consumer.mkdir(parents=True)
        package = (
            "package = pharos.packages.${system}.pharos-beacon;"
            if mode == "exported"
            else ""
        )
        (consumer / "flake.nix").write_text(
            CONSUMER.replace("@SOURCE@", json.dumps(archive.as_uri())).replace(
                "@PACKAGE@", package
            )
        )
        store, cache = case / "store", case / "cache"
        if store.exists() or cache.exists():
            raise RuntimeError("consumer must start with an empty store and cache")
        context = os.environ.copy()
        context["XDG_CACHE_HOME"] = str(cache)
        context["NIX_CACHE_HOME"] = str(cache / "nix")
        nix = [
            "nix", "--extra-experimental-features", "nix-command flakes",
            "--store", str(store),
            "--option", "substituters", "",
            "--option", "eval-cache", "false",
            "--option", "allow-import-from-derivation", "false",
        ]
        assert_absent(store, sources[mode], mode, "before flake check")
        command = [
            *nix,
            "flake", "check", "--no-build", "--all-systems", "--show-trace",
            f"path:{consumer}",
        ]
        print(f"Checking {mode} package with an empty store and cache", flush=True)
        result = subprocess.run(command, cwd=repo, env=context, check=False)
        print(f"{mode} consumer exit: {result.returncode}", flush=True)
        if result.returncode:
            failures.append(mode)
        else:
            assert_absent(store, sources[mode], mode, "after flake check")
    if failures:
        raise SystemExit(f"Cold consumer checks failed: {', '.join(failures)}")


def main() -> None:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--source", type=Path, default=Path(__file__).resolve().parent.parent)
    parser.add_argument("--work-dir", type=Path, help="keep evidence in a new directory")
    args = parser.parse_args()
    repo = args.source.resolve()
    if args.work_dir:
        work = args.work_dir.resolve()
        work.mkdir(parents=True, exist_ok=False)
        check(repo, work)
    else:
        with tempfile.TemporaryDirectory(prefix="pharos-consumer-") as directory:
            check(repo, Path(directory).resolve())


if __name__ == "__main__":
    main()
