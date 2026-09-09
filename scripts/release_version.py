#!/usr/bin/env python3
"""Strict INSPR Calendar Version v1/v2 validation and Cargo mapping.

v2 (PHAROS-259 / INSPR-395) is the UTC reservation second as ``YYMMDDhhmmss.0.0``:
SemVer-syntactic, fixed width, string-sortable. v1 records stay valid history.
"""

from __future__ import annotations

import argparse
import datetime as dt
import hashlib
import json
import re
import subprocess
from dataclasses import dataclass
from pathlib import Path

CALENDAR_SCHEME = "inspr-calendar-v1"
CALENDAR_V2_SCHEME = "inspr-calendar-v2"
CALENDAR_SCHEMES = (CALENDAR_SCHEME, CALENDAR_V2_SCHEME)
LEGACY_SCHEME = "legacy"
RELEASE_SCHEMA_V1 = "inspr.release-coordinate.v1"
RELEASE_SCHEMA_V2 = "inspr.release-coordinate.v2"
# Immutable v1 → v2 anchor: the last v1 coordinate and its stable sequence.
LAST_CALENDAR_V1_VERSION = "26.09.08.23.58.28"
LAST_CALENDAR_V1_SEQUENCE = 5
FIRST_CALENDAR_V2_SEQUENCE = 6
CALENDAR_LONG = re.compile(
    r"^([0-9]{2})\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])\."
    r"([01][0-9]|2[0-3])\.([0-5][0-9])\.([0-5][0-9])$"
)
CALENDAR_SHORT = re.compile(r"^([0-9]{2})\.(0[1-9]|1[0-2])\.(0[1-9]|[12][0-9]|3[01])$")
CALENDAR_V2 = re.compile(
    r"^([1-9][0-9])(0[1-9]|1[0-2])(0[1-9]|[12][0-9]|3[01])"
    r"([01][0-9]|2[0-3])([0-5][0-9])([0-5][0-9])\.0\.0$"
)
LEGACY_SEMVER = re.compile(r"^(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
CARGO_SEMVER = re.compile(r"^(200[0-9]|20[1-9][0-9])\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)$")
SHA256 = re.compile(r"^sha256:[0-9a-f]{64}$")
SOURCE_COMMIT = re.compile(r"^[0-9a-f]{40}$")
IMAGE = "ghcr.io/inspr-at/pharos/pharosd"
LEGACY_ROLLBACK = {
    "version_scheme": "legacy",
    "version": "0.2.0",
    "release_channel": "stable",
    "release_sequence": 0,
    "source_commit": "5c8bd1fbd2271a5c157ca239ec2d98b66b201e19",
    "tag": "v0.2.0",
    "image": IMAGE,
    "digest": "sha256:a00b9dc078ce4930e50f47da684409468c6996dba64338926ad790c1e1d1b74b",
    "reference": "ghcr.io/inspr-at/pharos/pharosd:0.2.0@sha256:a00b9dc078ce4930e50f47da684409468c6996dba64338926ad790c1e1d1b74b",
}
SOURCE_LOCK_DOMAIN = b"inspr.pharos.source-lock-set.v1\0"
SOURCE_LOCK_PATHS = ("Cargo.lock", "devenv.lock", "flake.lock", "package-lock.json")


class ReleaseVersionError(ValueError):
    pass


def parse_calendar(value: str) -> tuple[int, int, int, int, int, int]:
    match = CALENDAR_LONG.fullmatch(value)
    if match:
        raw_fields = match.groups()
    else:
        short = CALENDAR_SHORT.fullmatch(value)
        raw_fields = (*short.groups(), "00", "00", "00") if short else None
    if raw_fields is None:
        raise ReleaseVersionError("calendar version must use YY.MM.DD[.hh.mm.ss]")
    fields = tuple(int(part) for part in raw_fields)
    year, month, day, hour, minute, second = fields
    try:
        dt.datetime(2000 + year, month, day, hour, minute, second, tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise ReleaseVersionError("calendar version is not a real UTC date") from error
    return fields


def parse_calendar_v2(value: str) -> tuple[int, int, int, int, int, int]:
    """Exact YYMMDDhhmmss.0.0 with a real UTC date; never a short form."""

    match = CALENDAR_V2.fullmatch(value)
    if match is None:
        raise ReleaseVersionError("calendar v2 version must use YYMMDDhhmmss.0.0")
    fields = tuple(int(part) for part in match.groups())
    year, month, day, hour, minute, second = fields
    try:
        dt.datetime(2000 + year, month, day, hour, minute, second, tzinfo=dt.timezone.utc)
    except ValueError as error:
        raise ReleaseVersionError("calendar v2 version is not a real UTC date") from error
    return fields


def parse_scheme_version(scheme: str, value: str) -> tuple[int, int, int, int, int, int]:
    if scheme == CALENDAR_SCHEME:
        return parse_calendar(value)
    if scheme == CALENDAR_V2_SCHEME:
        return parse_calendar_v2(value)
    raise ReleaseVersionError("absent, unknown, ambiguous, or invalid version scheme")


def calendar_to_cargo(value: str) -> str:
    if CALENDAR_V2.fullmatch(value):
        # A v2 coordinate is itself valid SemVer; the ecosystem mapping is the identity.
        parse_calendar_v2(value)
        return value
    if not CALENDAR_LONG.fullmatch(value):
        raise ReleaseVersionError("Pharos Cargo mapping requires a long calendar coordinate")
    year, month, day, hour, minute, second = parse_calendar(value)
    return f"{2000 + year}.{month * 100 + day}.{hour * 10000 + minute * 100 + second}"


def cargo_to_calendar(value: str) -> str:
    if CALENDAR_V2.fullmatch(value):
        parse_calendar_v2(value)
        return value
    match = CARGO_SEMVER.fullmatch(value)
    if not match:
        raise ReleaseVersionError("Cargo compatibility version is not canonical")
    full_year, month_day, clock = (int(part) for part in match.groups())
    month, day = divmod(month_day, 100)
    hour, remainder = divmod(clock, 10000)
    minute, second = divmod(remainder, 100)
    canonical = f"{full_year - 2000:02d}.{month:02d}.{day:02d}.{hour:02d}.{minute:02d}.{second:02d}"
    parse_calendar(canonical)
    return canonical


def source_lock_digest(repo: Path) -> str:
    """Hash the exact ordered dependency-lock set with an unambiguous framing."""

    digest = hashlib.sha256()
    digest.update(SOURCE_LOCK_DOMAIN)
    for relative in SOURCE_LOCK_PATHS:
        path_bytes = relative.encode("ascii")
        try:
            contents = (repo / relative).read_bytes()
        except OSError as error:
            raise ReleaseVersionError(f"dependency lock is unreadable: {relative}") from error
        digest.update(path_bytes)
        digest.update(b"\0")
        digest.update(len(contents).to_bytes(8, "big"))
        digest.update(contents)
    return f"sha256:{digest.hexdigest()}"


@dataclass(frozen=True)
class ReleaseIdentity:
    scheme: str
    version: str
    sequence: int

    def validated_key(self) -> tuple[int, ...]:
        if self.sequence < 0:
            raise ReleaseVersionError("release sequence must be non-negative")
        if self.scheme == CALENDAR_SCHEME:
            return parse_calendar(self.version)
        if self.scheme == CALENDAR_V2_SCHEME:
            return parse_calendar_v2(self.version)
        if self.scheme == LEGACY_SCHEME and LEGACY_SEMVER.fullmatch(self.version):
            return tuple(int(part) for part in self.version.split("."))
        raise ReleaseVersionError("absent, unknown, ambiguous, or invalid version scheme")


def compare_releases(left: ReleaseIdentity, right: ReleaseIdentity) -> int:
    left_key = left.validated_key()
    right_key = right.validated_key()
    if left.scheme == right.scheme:
        result = (left_key > right_key) - (left_key < right_key)
        sequence_result = (left.sequence > right.sequence) - (left.sequence < right.sequence)
        if result != sequence_result:
            raise ReleaseVersionError("version order disagrees with release sequence")
        return result
    sequence_result = (left.sequence > right.sequence) - (left.sequence < right.sequence)
    if sequence_result == 0:
        raise ReleaseVersionError("cross-era releases must not share a release sequence")
    return sequence_result


def validate_reservation_history(
    current: dict[str, object],
    recorded: tuple[dict[str, object], ...],
    tagged: tuple[dict[str, object], ...],
) -> None:
    """Validate the union of first-parent records and every repository Calendar tag."""

    validate_release(current)
    by_sequence: dict[int, dict[str, object]] = {}
    by_version: dict[str, dict[str, object]] = {}
    current_anchor = current["migration_anchor"]
    assert isinstance(current_anchor, dict)
    for candidate in (*recorded, *tagged, current):
        validate_release(candidate)
        anchor = candidate["migration_anchor"]
        assert isinstance(anchor, dict)
        # Every era agrees on the legacy → v1 anchor; v2 records also agree on
        # the v1 → v2 anchor. A v1 record cannot carry v2 keys it predates.
        for key in V1_ANCHOR_KEYS:
            if anchor.get(key) != current_anchor.get(key):
                raise ReleaseVersionError("repository Calendar reservations disagree on migration anchor")
        if candidate["version_scheme"] == CALENDAR_V2_SCHEME:
            for key in V2_ANCHOR_EXTRA_KEYS:
                if anchor.get(key) != current_anchor.get(key):
                    raise ReleaseVersionError("repository Calendar reservations disagree on the v2 migration anchor")
        sequence = int(candidate["release_sequence"])
        version = str(candidate["version"])
        existing_sequence = by_sequence.get(sequence)
        if existing_sequence is not None and existing_sequence != candidate:
            raise ReleaseVersionError("repository Calendar reservations reuse a release sequence")
        existing_version = by_version.get(version)
        if existing_version is not None and existing_version != candidate:
            raise ReleaseVersionError("repository Calendar reservations reuse a coordinate")
        by_sequence[sequence] = candidate
        by_version[version] = candidate

    ordered = [by_sequence[sequence] for sequence in sorted(by_sequence)]
    first_sequence = int(current["migration_anchor"]["first_calendar_release_sequence"])  # type: ignore[index]
    expected_sequences = list(range(first_sequence, first_sequence + len(ordered)))
    if [int(candidate["release_sequence"]) for candidate in ordered] != expected_sequences:
        raise ReleaseVersionError("repository Calendar reservation sequence has a gap or regression")
    for previous, following in zip(ordered, ordered[1:]):
        left = ReleaseIdentity(str(previous["version_scheme"]), str(previous["version"]), int(previous["release_sequence"]))
        right = ReleaseIdentity(str(following["version_scheme"]), str(following["version"]), int(following["release_sequence"]))
        if compare_releases(left, right) >= 0:
            raise ReleaseVersionError("repository Calendar coordinates are not strictly monotonic")
        if previous["version_scheme"] == CALENDAR_V2_SCHEME and following["version_scheme"] == CALENDAR_SCHEME:
            raise ReleaseVersionError("calendar v1 reservations are closed after the first v2 coordinate")
    if ordered[-1] != current:
        raise ReleaseVersionError("current reservation does not follow the full stable-channel history")


def load_release(path: Path) -> dict[str, object]:
    try:
        release = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise ReleaseVersionError("RELEASE.json is not readable canonical JSON") from error
    if not isinstance(release, dict):
        raise ReleaseVersionError("RELEASE.json must contain an object")
    return release


def _workspace_cargo_version(cargo_toml: str) -> str:
    match = re.search(
        r"(?ms)^\[workspace\.package\]\s*$.*?^version\s*=\s*\"([^\"]+)\"\s*$",
        cargo_toml,
    )
    if not match:
        raise ReleaseVersionError("Cargo workspace version is absent")
    return match.group(1)


V1_ANCHOR_KEYS = (
    "last_legacy_version",
    "last_legacy_release_sequence",
    "first_calendar_version",
    "first_calendar_release_sequence",
)
V2_ANCHOR_EXTRA_KEYS = (
    "last_calendar_v1_version",
    "last_calendar_v1_release_sequence",
    "first_calendar_v2_version",
    "first_calendar_v2_release_sequence",
)


def validate_release(release: dict[str, object]) -> None:
    """Validate a v1 (history) or v2 (current default) release coordinate record."""

    schema = release.get("schema")
    if schema == RELEASE_SCHEMA_V2:
        _validate_release_v2(release)
        return
    _validate_release_v1(release)


def _validate_release_v1(release: dict[str, object]) -> None:
    required = {
        "schema",
        "schema_version",
        "version_scheme",
        "version",
        "release_channel",
        "release_sequence",
        "ecosystem_versions",
        "migration_anchor",
        "legacy_rollback",
        "compatibility_window",
    }
    if set(release) != required:
        raise ReleaseVersionError("RELEASE.json fields do not match the v1 contract")
    if release["schema"] != "inspr.release-coordinate.v1" or release["schema_version"] != 1:
        raise ReleaseVersionError("release coordinate schema is unsupported")
    if release["version_scheme"] != CALENDAR_SCHEME:
        raise ReleaseVersionError("version_scheme must be inspr-calendar-v1")
    if release["release_channel"] != "stable":
        raise ReleaseVersionError("release_channel must be stable")
    version = release["version"]
    sequence = release["release_sequence"]
    if not isinstance(version, str) or not isinstance(sequence, int) or isinstance(sequence, bool):
        raise ReleaseVersionError("version and release_sequence have invalid types")
    parse_calendar(version)
    if not CALENDAR_LONG.fullmatch(version):
        raise ReleaseVersionError("the stable Pharos channel requires long calendar coordinates")
    ecosystem = release["ecosystem_versions"]
    if not isinstance(ecosystem, dict) or set(ecosystem) != {"cargo_semver"}:
        raise ReleaseVersionError("Cargo ecosystem mapping is absent or ambiguous")
    cargo_version = ecosystem["cargo_semver"]
    if not isinstance(cargo_version, str) or calendar_to_cargo(version) != cargo_version:
        raise ReleaseVersionError("Cargo ecosystem mapping is not injective")
    if cargo_to_calendar(cargo_version) != version:
        raise ReleaseVersionError("Cargo ecosystem mapping does not round trip")
    anchor = release["migration_anchor"]
    if not isinstance(anchor, dict) or set(anchor) != {
        "last_legacy_version",
        "last_legacy_release_sequence",
        "first_calendar_version",
        "first_calendar_release_sequence",
    }:
        raise ReleaseVersionError("migration anchor fields do not match the v1 contract")
    first_version = anchor["first_calendar_version"]
    first_sequence = anchor["first_calendar_release_sequence"]
    if (
        anchor["last_legacy_version"] != "0.2.0"
        or anchor["last_legacy_release_sequence"] != 0
        or not isinstance(first_version, str)
        or not CALENDAR_LONG.fullmatch(first_version)
        or not isinstance(first_sequence, int)
        or isinstance(first_sequence, bool)
        or first_sequence != 1
    ):
        raise ReleaseVersionError("migration anchor does not bind v0.2.0 to the first calendar release")
    parse_calendar(first_version)
    first_calendar = ReleaseIdentity(CALENDAR_SCHEME, first_version, first_sequence)
    calendar = ReleaseIdentity(CALENDAR_SCHEME, version, sequence)
    if compare_releases(first_calendar, calendar) > 0:
        raise ReleaseVersionError("release predates the immutable first-calendar anchor")
    if release["compatibility_window"] != "legacy-rollback-until-owner-approved-removal":
        raise ReleaseVersionError("legacy compatibility window is absent")
    expected_rollback = {
        "version_scheme": LEGACY_SCHEME,
        "version": "0.2.0",
        "release_channel": "stable",
        "release_sequence": 0,
        "source_commit": "5c8bd1fbd2271a5c157ca239ec2d98b66b201e19",
        "tag": "v0.2.0",
        "image": "ghcr.io/inspr-at/pharos/pharosd",
        "digest": "sha256:a00b9dc078ce4930e50f47da684409468c6996dba64338926ad790c1e1d1b74b",
        "reference": "ghcr.io/inspr-at/pharos/pharosd:0.2.0@sha256:a00b9dc078ce4930e50f47da684409468c6996dba64338926ad790c1e1d1b74b",
    }
    if release["legacy_rollback"] != expected_rollback:
        raise ReleaseVersionError("legacy rollback authority changed or is incomplete")
    legacy = ReleaseIdentity(LEGACY_SCHEME, "0.2.0", 0)
    if compare_releases(legacy, first_calendar) >= 0:
        raise ReleaseVersionError("migration anchor does not order calendar after legacy")


def _validate_release_v2(release: dict[str, object]) -> None:
    required = {
        "schema",
        "schema_version",
        "version_scheme",
        "version",
        "release_channel",
        "release_sequence",
        "ecosystem_versions",
        "migration_anchor",
        "legacy_rollback",
        "compatibility_window",
    }
    if set(release) != required:
        raise ReleaseVersionError("RELEASE.json fields do not match the v2 contract")
    if release["schema"] != RELEASE_SCHEMA_V2 or release["schema_version"] != 2:
        raise ReleaseVersionError("release coordinate schema is unsupported")
    if release["version_scheme"] != CALENDAR_V2_SCHEME:
        raise ReleaseVersionError("version_scheme must be inspr-calendar-v2 in a v2 record")
    if release["release_channel"] != "stable":
        raise ReleaseVersionError("release_channel must be stable")
    version = release["version"]
    sequence = release["release_sequence"]
    if not isinstance(version, str) or not isinstance(sequence, int) or isinstance(sequence, bool):
        raise ReleaseVersionError("version and release_sequence have invalid types")
    parse_calendar_v2(version)
    ecosystem = release["ecosystem_versions"]
    if not isinstance(ecosystem, dict) or set(ecosystem) != {"cargo_semver"}:
        raise ReleaseVersionError("Cargo ecosystem mapping is absent or ambiguous")
    if ecosystem["cargo_semver"] != version:
        raise ReleaseVersionError("Cargo mapping of a v2 coordinate is the identity")
    anchor = release["migration_anchor"]
    if not isinstance(anchor, dict) or set(anchor) != set(V1_ANCHOR_KEYS) | set(V2_ANCHOR_EXTRA_KEYS):
        raise ReleaseVersionError("migration anchor fields do not match the v2 contract")
    first_version = anchor["first_calendar_version"]
    if (
        anchor["last_legacy_version"] != "0.2.0"
        or anchor["last_legacy_release_sequence"] != 0
        or not isinstance(first_version, str)
        or not CALENDAR_LONG.fullmatch(first_version)
        or anchor["first_calendar_release_sequence"] != 1
    ):
        raise ReleaseVersionError("migration anchor does not bind v0.2.0 to the first calendar release")
    parse_calendar(first_version)
    first_v2 = anchor["first_calendar_v2_version"]
    if (
        anchor["last_calendar_v1_version"] != LAST_CALENDAR_V1_VERSION
        or anchor["last_calendar_v1_release_sequence"] != LAST_CALENDAR_V1_SEQUENCE
        or anchor["first_calendar_v2_release_sequence"] != FIRST_CALENDAR_V2_SEQUENCE
        or not isinstance(first_v2, str)
    ):
        raise ReleaseVersionError("migration anchor does not bind the last calendar v1 release to the first v2 coordinate")
    parse_calendar_v2(first_v2)
    first_identity = ReleaseIdentity(CALENDAR_V2_SCHEME, first_v2, FIRST_CALENDAR_V2_SEQUENCE)
    current = ReleaseIdentity(CALENDAR_V2_SCHEME, version, sequence)
    if sequence < FIRST_CALENDAR_V2_SEQUENCE or compare_releases(first_identity, current) > 0:
        raise ReleaseVersionError("release predates the immutable first-calendar-v2 anchor")
    if (sequence == FIRST_CALENDAR_V2_SEQUENCE) != (version == first_v2):
        raise ReleaseVersionError("first calendar v2 coordinate and sequence disagree")
    last_v1 = ReleaseIdentity(CALENDAR_SCHEME, LAST_CALENDAR_V1_VERSION, LAST_CALENDAR_V1_SEQUENCE)
    if compare_releases(last_v1, first_identity) >= 0:
        raise ReleaseVersionError("migration anchor does not order calendar v2 after calendar v1")
    if release["compatibility_window"] != "legacy-rollback-until-owner-approved-removal":
        raise ReleaseVersionError("legacy compatibility window is absent")
    if release["legacy_rollback"] != LEGACY_ROLLBACK:
        raise ReleaseVersionError("legacy rollback authority changed or is incomplete")


def validate_release_set(document: dict[str, object], release: dict[str, object]) -> None:
    validate_release(release)
    required = {
        "schema",
        "schema_version",
        "version_scheme",
        "version",
        "release_channel",
        "release_sequence",
        "migration_anchor",
        "cargo_version",
        "source_commit",
        "source_lock_digest",
        "tag",
        "image",
        "digest",
        "reference",
        "sha_reference",
        "legacy_rollback",
        "artifacts",
        "attestations",
    }
    if set(document) != required:
        raise ReleaseVersionError("release-set fields do not match the v1 contract")
    if document["schema"] != "inspr.pharos.release-set.v1" or document["schema_version"] != 1:
        raise ReleaseVersionError("release-set schema is unsupported")
    for field in ("version_scheme", "version", "release_channel", "release_sequence"):
        if document[field] != release[field]:
            raise ReleaseVersionError(f"release-set {field} does not match RELEASE.json")
    if document["migration_anchor"] != release["migration_anchor"]:
        raise ReleaseVersionError("release-set migration anchor changed")
    if document["legacy_rollback"] != release["legacy_rollback"]:
        raise ReleaseVersionError("release-set legacy rollback authority changed")
    cargo = release["ecosystem_versions"]
    assert isinstance(cargo, dict)
    if document["cargo_version"] != cargo["cargo_semver"]:
        raise ReleaseVersionError("release-set Cargo mapping changed")
    source = document["source_commit"]
    digest = document["digest"]
    lock_digest = document["source_lock_digest"]
    if not isinstance(source, str) or not SOURCE_COMMIT.fullmatch(source):
        raise ReleaseVersionError("release-set source commit is invalid")
    if not isinstance(digest, str) or not SHA256.fullmatch(digest):
        raise ReleaseVersionError("release-set OCI digest is invalid")
    if not isinstance(lock_digest, str) or not SHA256.fullmatch(lock_digest):
        raise ReleaseVersionError("release-set source-lock digest is invalid")
    version = str(release["version"])
    if document["tag"] != f"v{version}" or document["image"] != IMAGE:
        raise ReleaseVersionError("release-set tag or image coordinate is invalid")
    if document["reference"] != f"{IMAGE}:{version}@{digest}":
        raise ReleaseVersionError("release-set version reference is not exact")
    if document["sha_reference"] != f"{IMAGE}:sha-{source}@{digest}":
        raise ReleaseVersionError("release-set source reference is not exact")

    artifacts = document["artifacts"]
    if not isinstance(artifacts, list) or len(artifacts) != 3:
        raise ReleaseVersionError("release-set artifact inventory is incomplete")
    expected_index_coordinate = {
        "class": "oci-index",
        "version_reference": document["reference"],
        "source_reference": document["sha_reference"],
    }
    if artifacts[0] != {"coordinate": expected_index_coordinate, "digest": digest}:
        raise ReleaseVersionError("release-set OCI index coordinate is invalid")
    if (
        not isinstance(artifacts[1], dict)
        or artifacts[1].get("coordinate") != {"class": "oci-image", "platform": "linux/amd64"}
        or not isinstance(artifacts[1].get("digest"), str)
        or not SHA256.fullmatch(str(artifacts[1]["digest"]))
    ):
        raise ReleaseVersionError("release-set linux/amd64 artifact is invalid")
    if (
        not isinstance(artifacts[2], dict)
        or artifacts[2].get("coordinate")
        != {"class": "spdx-sbom", "filename": "pharos.spdx.json"}
        or not isinstance(artifacts[2].get("digest"), str)
        or not SHA256.fullmatch(str(artifacts[2]["digest"]))
    ):
        raise ReleaseVersionError("release-set standalone SPDX artifact is invalid")

    attestations = document["attestations"]
    if not isinstance(attestations, dict) or set(attestations) != {
        "signature",
        "provenance",
        "sbom",
    }:
        raise ReleaseVersionError("release-set attestation inventory is incomplete")
    signature = attestations["signature"]
    expected_signature_tag = f"{IMAGE}:{digest.replace(':', '-')}.sig"
    if (
        not isinstance(signature, dict)
        or set(signature) != {"coordinate", "digest"}
        or not isinstance(signature.get("digest"), str)
        or not SHA256.fullmatch(str(signature["digest"]))
        or signature.get("coordinate") != f"{expected_signature_tag}@{signature['digest']}"
    ):
        raise ReleaseVersionError("release-set signature reference is not verifiable")
    for name, predicate in (
        ("provenance", "https://slsa.dev/provenance/v1"),
        ("sbom", "https://spdx.dev/Document"),
    ):
        evidence = attestations[name]
        if (
            not isinstance(evidence, dict)
            or set(evidence) != {
                "coordinate",
                "manifest_digest",
                "layer_digest",
                "predicate_type",
            }
            or not isinstance(evidence.get("manifest_digest"), str)
            or not SHA256.fullmatch(str(evidence["manifest_digest"]))
            or not isinstance(evidence.get("layer_digest"), str)
            or not SHA256.fullmatch(str(evidence["layer_digest"]))
            or evidence.get("coordinate") != f"{IMAGE}@{evidence['manifest_digest']}"
            or evidence.get("predicate_type") != predicate
        ):
            raise ReleaseVersionError(f"release-set {name} reference is not verifiable")
    if attestations["provenance"]["manifest_digest"] != attestations["sbom"][
        "manifest_digest"
    ]:
        raise ReleaseVersionError("embedded attestations do not share the signed OCI manifest")


def validate_release_workflow(workflow: str) -> None:
    forbidden = ("branches: [main]", "type=semver", "sort -V")
    if any(fragment in workflow for fragment in forbidden):
        raise ReleaseVersionError("release workflow still contains a legacy publication path")
    ordered_steps = (
        "outputs: type=image,name=${{ steps.version.outputs.image }},push-by-digest=true,name-canonical=true,push=true",
        "verify candidate runtime identity",
        "scan candidate image",
        "verify embedded OCI provenance and SBOM",
        "verify frozen legacy rollback authority",
        "sign image digest with GitHub OIDC",
        "verify image signature",
        "capture verifiable OCI signature and attestation references",
        "generate immutable release set",
        "sign and verify release set",
        "verify release-set contract, assets, and OCI evidence",
        "stage exact immutable forge assets",
        "admit immutable version and source coordinates",
        "publish immutable forge release",
        "move mutable latest alias after admission",
    )
    positions = [workflow.find(fragment) for fragment in ordered_steps]
    if any(position < 0 for position in positions) or positions != sorted(positions):
        raise ReleaseVersionError("release admission gates are absent or out of order")
    if workflow.count("steps.build.outputs.digest") != 1:
        raise ReleaseVersionError("only candidate selection may read the staging build digest")
    recovery_fragments = (
        "group: pharos-release-stable",
        "push-by-digest=true,name-canonical=true,push=true",
        "state=$(jq -r 'if .isDraft then \"draft\" else \"published\" end'",
        'cmp recovered-release-assets/pharos.spdx.json pharos.spdx.generated.json',
        'cmp recovered-release-assets/release-set.json release-set.generated.json',
        '[[ "${HAS_RELEASE_SET}" == true ]] || gh release upload',
        'gh release edit "${GITHUB_REF_NAME}" --draft=false',
        'signature_tag=$(cosign triangulate "${IMAGE}@${DIGEST}")',
        'if output=$(docker buildx imagetools inspect "${signature_tag}" 2>&1); then',
        'and .annotations["vnd.docker.reference.digest"] == $platform_digest',
        "PLATFORM_DIGEST: ${{ steps.oci_evidence.outputs.platform_digest }}",
        "python3 scripts/release_version.py lock-digest",
        "git cat-file -t refs/tags/v0.2.0",
        "git rev-parse 'refs/tags/v0.2.0^{}'",
        "{{json .Image.Config.Labels}}",
        "@refs/tags/v0.2.0",
    )
    if any(fragment not in workflow for fragment in recovery_fragments) or "--clobber" in workflow:
        raise ReleaseVersionError("release workflow does not recover partial publication safely")
    if ":candidate-${{" in workflow:
        raise ReleaseVersionError("release workflow leaves a tagged staging coordinate")
    if "schema: \"inspr.pharos.release-set.v1\"" not in workflow:
        raise ReleaseVersionError("release-set producer schema is absent")
    if "legacy_rollback: $release.legacy_rollback" not in workflow:
        raise ReleaseVersionError("release-set omits the immutable legacy rollback authority")


def _first_parent_calendar_releases(repo: Path) -> tuple[dict[str, object], ...]:
    history = subprocess.run(
        ["git", "rev-list", "--first-parent", "HEAD"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if history.returncode != 0:
        return ()
    current = load_release(repo / "RELEASE.json")
    releases: list[dict[str, object]] = []
    for commit in history.stdout.splitlines():
        result = subprocess.run(
            ["git", "show", f"{commit}:RELEASE.json"],
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            continue
        try:
            candidate = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ReleaseVersionError(
                f"first-parent RELEASE.json is malformed at {commit}"
            ) from error
        if not isinstance(candidate, dict):
            raise ReleaseVersionError(f"first-parent RELEASE.json is not an object at {commit}")
        scheme = candidate.get("version_scheme")
        if scheme in CALENDAR_SCHEMES:
            validate_release(candidate)
            if candidate != current and candidate not in releases:
                releases.append(candidate)
        elif scheme != LEGACY_SCHEME:
            raise ReleaseVersionError(
                f"first-parent RELEASE.json has an absent or unknown scheme at {commit}"
            )
    return tuple(releases)


def _tagged_calendar_releases(repo: Path) -> tuple[dict[str, object], ...]:
    result = subprocess.run(
        ["git", "tag", "--list", "v*"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=True,
    )
    releases = []
    for tag in result.stdout.splitlines():
        value = tag.removeprefix("v")
        try:
            parse_calendar(value)
            tag_scheme = CALENDAR_SCHEME
        except ReleaseVersionError:
            try:
                parse_calendar_v2(value)
                tag_scheme = CALENDAR_V2_SCHEME
            except ReleaseVersionError:
                if re.fullmatch(r"v[0-9]{2}\..*", tag) or re.fullmatch(r"v[0-9]{10,}\..*", tag):
                    raise ReleaseVersionError(f"Calendar-looking tag is invalid: {tag}")
                continue
        tag_ref = f"refs/tags/{tag}"
        kind = subprocess.run(
            ["git", "cat-file", "-t", tag_ref],
            cwd=repo,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        if kind != "tag":
            raise ReleaseVersionError(f"Calendar tag is not annotated: {tag}")
        result = subprocess.run(
            ["git", "show", f"{tag_ref}^{{}}:RELEASE.json"],
            cwd=repo,
            text=True,
            capture_output=True,
            check=False,
        )
        if result.returncode != 0:
            raise ReleaseVersionError(f"Calendar tag has no RELEASE.json: {tag}")
        try:
            release = json.loads(result.stdout)
        except json.JSONDecodeError as error:
            raise ReleaseVersionError(f"Calendar tag has invalid RELEASE.json: {tag}") from error
        if not isinstance(release, dict):
            raise ReleaseVersionError(f"Calendar tag release coordinate is not an object: {tag}")
        validate_release(release)
        if release["version_scheme"] != tag_scheme or release["version"] != value:
            raise ReleaseVersionError(f"Calendar tag does not match its explicit release identity: {tag}")
        releases.append(release)
    return tuple(releases)


def check_repository(repo: Path) -> None:
    release = load_release(repo / "RELEASE.json")
    validate_release(release)
    version = str(release["version"])
    validate_reservation_history(
        release,
        _first_parent_calendar_releases(repo),
        _tagged_calendar_releases(repo),
    )
    cargo_version = str(release["ecosystem_versions"]["cargo_semver"])  # type: ignore[index]
    if _workspace_cargo_version((repo / "Cargo.toml").read_text(encoding="utf-8")) != cargo_version:
        raise ReleaseVersionError("Cargo.toml does not match the mapped Cargo version")
    lock = (repo / "Cargo.lock").read_text(encoding="utf-8")
    for package in ("pharos-core", "pharosd", "pharos-beacon", "pharos-cli"):
        pattern = rf'(?ms)^name = "{re.escape(package)}"\nversion = "{re.escape(cargo_version)}"$'
        if not re.search(pattern, lock):
            raise ReleaseVersionError(f"Cargo.lock does not map {package} to the release")
    changelog = (repo / "docs/CHANGELOG.md").read_text(encoding="utf-8")
    if f"## {version} - " not in changelog:
        raise ReleaseVersionError("changelog has no dated calendar release heading")
    readme = (repo / "README.md").read_text(encoding="utf-8")
    if f"version-{version}-" not in readme:
        raise ReleaseVersionError("README badge does not match the calendar version")
    workflow = (repo / ".github/workflows/release.yml").read_text(encoding="utf-8")
    validate_release_workflow(workflow)
    compose = (repo / "docker-compose.selfhost.yml").read_text(encoding="utf-8")
    if "PHAROS_IMAGE_REFERENCE:?" not in compose:
        raise ReleaseVersionError("self-host Compose does not require an immutable image reference")
    tag = f"v{version}"
    ref_type = subprocess.run(
        ["git", "cat-file", "-t", f"refs/tags/{tag}"],
        cwd=repo,
        text=True,
        capture_output=True,
        check=False,
    )
    if ref_type.returncode == 0:
        if ref_type.stdout.strip() != "tag":
            raise ReleaseVersionError("calendar releases require an annotated Git tag")
        tag_target = subprocess.run(
            ["git", "rev-parse", f"refs/tags/{tag}^{{}}"],
            cwd=repo,
            text=True,
            capture_output=True,
            check=True,
        ).stdout.strip()
        head = subprocess.run(
            ["git", "rev-parse", "HEAD"], cwd=repo, text=True, capture_output=True, check=True
        ).stdout.strip()
        if tag_target != head:
            raise ReleaseVersionError("calendar release tag does not target HEAD")


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "command", choices=("check", "check-set", "lock-digest", "to-cargo", "from-cargo")
    )
    parser.add_argument("value", nargs="?")
    parser.add_argument("--repo", type=Path, default=Path(__file__).resolve().parent.parent)
    args = parser.parse_args()
    try:
        if args.command == "check":
            check_repository(args.repo.resolve())
            release = load_release(args.repo.resolve() / "RELEASE.json")
            print(
                "release_consistency=ok"
                f" scheme={release['version_scheme']} version={release['version']}"
                f" sequence={release['release_sequence']}"
            )
        elif args.command == "check-set" and args.value is not None:
            release_set = load_release(Path(args.value))
            release = load_release(args.repo.resolve() / "RELEASE.json")
            validate_release_set(release_set, release)
            print(f"release_set=ok version={release['version']}")
        elif args.command == "lock-digest" and args.value is None:
            print(source_lock_digest(args.repo.resolve()))
        elif args.command == "to-cargo" and args.value is not None:
            print(calendar_to_cargo(args.value))
        elif args.command == "from-cargo" and args.value is not None:
            print(cargo_to_calendar(args.value))
        else:
            parser.error("a version value is required")
    except (ReleaseVersionError, OSError, subprocess.CalledProcessError) as error:
        print(f"error: {error}", file=__import__("sys").stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
