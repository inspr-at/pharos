#!/usr/bin/env python3
"""Fail closed when the pinned INSPR Calendar display bundle drifts."""
import hashlib
import json
import stat
import sys
from pathlib import Path

SOURCE = "83d26aa605b21493d22805ba477e6ac279b6409d"
CONFIG_SHA256 = "7843f3515ce329277d2d576000bd60ac410d725b241d502a9a3fecb2533d956d"
MANIFEST_SHA256 = "e7052c82af0d0cdfe4a466bf3129c1de56014253247106f2670788419f118812"
FILES = {
    "display.json": (1656, CONFIG_SHA256),
    "version.js": (4871, "9a09693e0cef3af586f617ba24cdae96165d95d12f5c447b1d2e67d35a70c9b8"),
    "presentation.js": (2769, "fd0354837edd05179aeeaa86c271bced25031a3f29e148c448b684116b7dd3ca"),
    "version-interaction.js": (7671, "cfe539ad84651666d18b192f37659dab7c36aa8e68c43c9bdd42b42e85de2ba1"),
    "auto-animate.js": (28022, "2fae336f3ed3e814356df4721cfa747a393ff037fee2644d95bbbe1236551753"),
    "auto-animate-license.js": (1100, "57677685789ebe6233671cef7f78b37f74942936b0d42ef2168d6a2195acf606"),
    "package.json": (18, "1239d4d885dcad42201a27ed9324f8f0f760b78700d8db9ced39a511cffe7eae"),
}


def fail(message):
    raise SystemExit(f"calendar-version-display: {message}")


def sha256(raw):
    return hashlib.sha256(raw).hexdigest()


def check(root):
    bundle = root / "crates/pharosd/assets/vendor/calendar-version-display"
    if not bundle.is_dir() or bundle.is_symlink():
        fail("bundle directory is missing or unsafe")
    observed = {path.name for path in bundle.iterdir()}
    if observed != set(FILES) | {"manifest.json"}:
        fail("bundle file set drifted")
    manifest_path = bundle / "manifest.json"
    manifest_raw = manifest_path.read_bytes()
    if sha256(manifest_raw) != MANIFEST_SHA256:
        fail("manifest digest drifted")
    try:
        manifest = json.loads(manifest_raw)
    except (UnicodeDecodeError, ValueError):
        fail("manifest is invalid")
    if (manifest.get("repository") != "inspr-at/inspr" or manifest.get("revision") != SOURCE
            or manifest.get("expectedConfigSha256") != CONFIG_SHA256
            or manifest.get("schema") != "inspr.calendar-version-display.v2"
            or manifest.get("mode") != "build-time-only"
            or manifest.get("consumers") != [] or manifest.get("runtimeConsumers") is not False):
        fail("manifest provenance drifted")
    entries = manifest.get("files")
    if not isinstance(entries, list) or len(entries) != len(FILES):
        fail("manifest entries drifted")
    by_name = {entry.get("outputPath"): entry for entry in entries if isinstance(entry, dict)}
    if set(by_name) != set(FILES):
        fail("manifest output paths drifted")
    for name, (expected_size, expected_digest) in FILES.items():
        path = bundle / name
        info = path.lstat()
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            fail(f"{name} is not a single-link regular file")
        raw = path.read_bytes()
        entry = by_name[name]
        if len(raw) != expected_size or sha256(raw) != expected_digest:
            fail(f"{name} bytes drifted")
        if entry.get("size") != expected_size or entry.get("sha256") != expected_digest:
            fail(f"{name} manifest entry drifted")
    display = json.loads((bundle / "display.json").read_text())
    if display.get("schema") != "inspr.calendar-version-display.v2" or display.get("scheme") != "inspr-calendar-v2":
        fail("display contract drifted")
    if display.get("design_revision") != 3 or set(display.get("weights", {})) != {"v","yy","mm","dd","hh","mi","ss","tail"}:
        fail("display design drifted")
    if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1 for value in display["weights"].values()):
        fail("display weights are outside 0-100 percent")
    print(f"calendar-version-display: ok source={SOURCE} manifest=sha256:{MANIFEST_SHA256}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        fail("usage: check-calendar-version-display.py REPOSITORY_ROOT")
    check(Path(sys.argv[1]).resolve())
