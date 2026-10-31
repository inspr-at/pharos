#!/usr/bin/env python3
"""Fail closed when the pinned INSPR Calendar display bundle drifts."""
import hashlib
import json
import stat
import sys
from pathlib import Path

SOURCE = "bd0a13816f728ad91c36d849f88168bcac4fdc6e"
CONFIG_SHA256 = "bf6aa144cd73dc97dc941f0f0914138b04ae0a28fbead5123465b15b1f2a2fd9"
MANIFEST_SHA256 = "a3d2d8d45f4f9c2c1f978225f4737d2248f654595237cb12231e78cff0e2ed6e"
FILES = {
    "display.json": (1423, CONFIG_SHA256),
    "version.js": (6334, "5711296a2f551745073dc416c1cf676c0fa584976ea7680dedff923cf7ac5faf"),
    "presentation.js": (5275, "37ae4b7757c76bb46960219724f448e4027396a017748d96edb89d25a7c54fe2"),
    "version-interaction.js": (8317, "37d420e346defff5c01fe849c39c1f7ed93017e62f7e2a8d0b6299e00ede99ff"),
    "schemes.json": (284, "d88195791de1fe2c8a1fcaa1098c85f1af9c58fc049ef4186c28d6962da0474d"),
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
            or manifest.get("schema") != "inspr.calver-display.v3"
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
    if display.get("schema") != "inspr.calver-display.v3" or display.get("scheme") != "inspr-calver-3":
        fail("display contract drifted")
    if display.get("design_revision") != 4 or display.get("segments") != ["yy", "mm", "dd", "hh", "mi", "ss"]:
        fail("display design drifted")
    weights = display.get("weights", {})
    if set(weights) != set(display["segments"]):
        fail("display weights drifted")
    if any(not isinstance(value, (int, float)) or isinstance(value, bool) or not 0 <= value <= 1 for value in weights.values()):
        fail("display weights are outside 0-100 percent")
    print(f"calendar-version-display: ok source={SOURCE} manifest=sha256:{MANIFEST_SHA256}")


if __name__ == "__main__":
    if len(sys.argv) != 2:
        fail("usage: check-calendar-version-display.py REPOSITORY_ROOT")
    check(Path(sys.argv[1]).resolve())
