import importlib.util
import copy
import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "release_version.py"
SPEC = importlib.util.spec_from_file_location("release_version", MODULE_PATH)
assert SPEC and SPEC.loader
release_version = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = release_version
SPEC.loader.exec_module(release_version)

# Immutable first-calendar history. These stay fixed when the live document
# advances; live RELEASE.json is only the current successor under test.
FIRST_CALENDAR_VERSION = "26.09.01.13.29.31"
FIRST_CALENDAR_SEQUENCE = 1
NEXT_CALENDAR_VERSION = "26.09.01.13.29.32"
NEXT_CALENDAR_SEQUENCE = 2
LATER_CALENDAR_VERSION = "26.09.01.13.29.33"
# Real v1 stable-channel history (sequences 1–5) that precedes the v2 era.
V1_HISTORY = (
    ("26.09.01.13.29.31", 1),
    ("26.09.07.20.52.53", 2),
    ("26.09.07.22.08.13", 3),
    ("26.09.08.11.36.59", 4),
    ("26.09.08.23.58.28", 5),
)
FIRST_V2_SEQUENCE = 6


class CalendarVersionTests(unittest.TestCase):
    @staticmethod
    def release_document():
        return json.loads(
            (Path(__file__).resolve().parents[1] / "RELEASE.json").read_text(encoding="utf-8")
        )

    @classmethod
    def calendar_release(cls, version, sequence, *, first=None):
        """A v1 release-coordinate record (schema v1) as it exists in history."""

        live = cls.release_document()
        anchor = live["migration_anchor"]
        document = {
            "schema": release_version.RELEASE_SCHEMA_V1,
            "schema_version": 1,
            "version_scheme": release_version.CALENDAR_SCHEME,
            "version": version,
            "release_channel": "stable",
            "release_sequence": sequence,
            "ecosystem_versions": {"cargo_semver": release_version.calendar_to_cargo(version)},
            "migration_anchor": {
                "last_legacy_version": anchor["last_legacy_version"],
                "last_legacy_release_sequence": anchor["last_legacy_release_sequence"],
                "first_calendar_version": anchor["first_calendar_version"],
                "first_calendar_release_sequence": anchor["first_calendar_release_sequence"],
            },
            "legacy_rollback": copy.deepcopy(live["legacy_rollback"]),
            "compatibility_window": live["compatibility_window"],
        }
        if first is not None:
            document["migration_anchor"]["first_calendar_version"] = first
        return document

    @classmethod
    def calendar_v2_release(cls, version, sequence):
        """A v2 release-coordinate record derived from the live document."""

        document = copy.deepcopy(cls.release_document())
        document["version"] = version
        document["release_sequence"] = sequence
        document["ecosystem_versions"]["cargo_semver"] = version
        return document

    @classmethod
    def v1_history(cls):
        return tuple(cls.calendar_release(version, sequence) for version, sequence in V1_HISTORY)

    @classmethod
    def first_calendar_release(cls):
        return cls.calendar_release(FIRST_CALENDAR_VERSION, FIRST_CALENDAR_SEQUENCE)

    @classmethod
    def release_set_document(cls):
        release = cls.release_document()
        digest = f"sha256:{'1' * 64}"
        platform_digest = f"sha256:{'2' * 64}"
        sbom_digest = f"sha256:{'3' * 64}"
        signature_digest = f"sha256:{'4' * 64}"
        attestation_digest = f"sha256:{'5' * 64}"
        provenance_layer = f"sha256:{'6' * 64}"
        sbom_layer = f"sha256:{'7' * 64}"
        source = "8" * 40
        image = release_version.IMAGE
        reference = f"{image}:{release['version']}@{digest}"
        sha_reference = f"{image}:sha-{source}@{digest}"
        return {
            "schema": "inspr.pharos.release-set.v1",
            "schema_version": 1,
            "version_scheme": release["version_scheme"],
            "version": release["version"],
            "release_channel": release["release_channel"],
            "release_sequence": release["release_sequence"],
            "migration_anchor": release["migration_anchor"],
            "cargo_version": release["ecosystem_versions"]["cargo_semver"],
            "source_commit": source,
            "source_lock_digest": f"sha256:{'9' * 64}",
            "tag": f"v{release['version']}",
            "image": image,
            "digest": digest,
            "reference": reference,
            "sha_reference": sha_reference,
            "legacy_rollback": release["legacy_rollback"],
            "artifacts": [
                {
                    "coordinate": {
                        "class": "oci-index",
                        "version_reference": reference,
                        "source_reference": sha_reference,
                    },
                    "digest": digest,
                },
                {
                    "coordinate": {"class": "oci-image", "platform": "linux/amd64"},
                    "digest": platform_digest,
                },
                {
                    "coordinate": {"class": "spdx-sbom", "filename": "pharos.spdx.json"},
                    "digest": sbom_digest,
                },
            ],
            "attestations": {
                "signature": {
                    "coordinate": f"{image}:{digest.replace(':', '-')}.sig@{signature_digest}",
                    "digest": signature_digest,
                },
                "provenance": {
                    "coordinate": f"{image}@{attestation_digest}",
                    "manifest_digest": attestation_digest,
                    "layer_digest": provenance_layer,
                    "predicate_type": "https://slsa.dev/provenance/v1",
                },
                "sbom": {
                    "coordinate": f"{image}@{attestation_digest}",
                    "manifest_digest": attestation_digest,
                    "layer_digest": sbom_layer,
                    "predicate_type": "https://spdx.dev/Document",
                },
            },
        }

    def test_valid_long_forms_and_round_trip(self):
        for value in (
            "00.01.01.00.00.00",
            "24.02.29.23.59.59",
            "26.09.01.13.29.31",
            "99.12.31.23.59.59",
        ):
            cargo = release_version.calendar_to_cargo(value)
            self.assertEqual(release_version.cargo_to_calendar(cargo), value)

    def test_valid_short_forms_normalize_to_midnight(self):
        self.assertEqual(
            release_version.parse_calendar("26.09.01"),
            (26, 9, 1, 0, 0, 0),
        )
        self.assertEqual(
            release_version.parse_calendar("24.02.29"),
            (24, 2, 29, 0, 0, 0),
        )

    def test_invalid_dates_widths_and_short_form_fail_closed(self):
        invalid = (
            "2026.09.01.13.29.31",
            "26.9.01.13.29.31",
            "26.02.29.13.29.31",
            "26.04.31.13.29.31",
            "26.09.01.24.00.00",
            "26.09.01.12.60.00",
            "26.09.01.12.00",
            "26.09.01.13.29.31Z",
            "٢٦.09.01.13.29.31",
            "26.０９.01.13.29.31",
        )
        for value in invalid:
            with self.subTest(value=value), self.assertRaises(release_version.ReleaseVersionError):
                release_version.parse_calendar(value)

    def test_same_day_order_and_collision(self):
        earlier = release_version.ReleaseIdentity(
            release_version.CALENDAR_SCHEME, "26.09.01.13.29.31", 1
        )
        later = release_version.ReleaseIdentity(
            release_version.CALENDAR_SCHEME, "26.09.01.13.29.32", 2
        )
        self.assertLess(release_version.compare_releases(earlier, later), 0)
        collision = release_version.ReleaseIdentity(
            release_version.CALENDAR_SCHEME, "26.09.01.13.29.31", 2
        )
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.compare_releases(earlier, collision)

    def test_mixed_era_uses_sequence(self):
        legacy = release_version.ReleaseIdentity(release_version.LEGACY_SCHEME, "0.2.0", 0)
        calendar = release_version.ReleaseIdentity(
            release_version.CALENDAR_SCHEME, "26.09.01.13.29.31", 1
        )
        self.assertLess(release_version.compare_releases(legacy, calendar), 0)
        duplicate = release_version.ReleaseIdentity(
            release_version.CALENDAR_SCHEME, "26.09.01.13.29.31", 0
        )
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.compare_releases(legacy, duplicate)

    def test_subsequent_release_preserves_first_calendar_anchor(self):
        first = self.first_calendar_release()
        subsequent = self.calendar_release(NEXT_CALENDAR_VERSION, NEXT_CALENDAR_SEQUENCE)
        release_version.validate_release(subsequent)
        release_version.validate_reservation_history(subsequent, (first,), ())
        self.assertEqual(subsequent["migration_anchor"], first["migration_anchor"])
        self.assertEqual(
            subsequent["migration_anchor"]["first_calendar_version"], FIRST_CALENDAR_VERSION
        )
        self.assertEqual(
            subsequent["migration_anchor"]["first_calendar_release_sequence"],
            FIRST_CALENDAR_SEQUENCE,
        )

    def test_current_release_is_valid_calendar_v2_successor(self):
        current = self.release_document()
        self.assertEqual(current["schema"], release_version.RELEASE_SCHEMA_V2)
        self.assertEqual(current["version_scheme"], release_version.CALENDAR_V2_SCHEME)
        self.assertGreaterEqual(current["release_sequence"], FIRST_V2_SEQUENCE)
        anchor = current["migration_anchor"]
        self.assertEqual(anchor["first_calendar_version"], FIRST_CALENDAR_VERSION)
        self.assertEqual(anchor["last_calendar_v1_version"], V1_HISTORY[-1][0])
        self.assertEqual(anchor["last_calendar_v1_release_sequence"], V1_HISTORY[-1][1])
        self.assertEqual(anchor["first_calendar_v2_release_sequence"], FIRST_V2_SEQUENCE)
        # The Cargo mapping of a v2 coordinate is the identity.
        self.assertEqual(current["ecosystem_versions"]["cargo_semver"], current["version"])
        release_version.validate_release(current)
        last_v1 = release_version.ReleaseIdentity(
            release_version.CALENDAR_SCHEME, *V1_HISTORY[-1]
        )
        current_identity = release_version.ReleaseIdentity(
            release_version.CALENDAR_V2_SCHEME, current["version"], current["release_sequence"]
        )
        self.assertLess(release_version.compare_releases(last_v1, current_identity), 0)
        recorded = list(self.v1_history())
        if current["release_sequence"] > FIRST_V2_SEQUENCE:
            recorded.append(
                self.calendar_v2_release(anchor["first_calendar_v2_version"], FIRST_V2_SEQUENCE)
            )
        release_version.validate_reservation_history(current, tuple(recorded), ())

    def test_calendar_v2_grammar_is_exact_and_gregorian(self):
        for value in ("260909194540.0.0", "261231235959.0.0", "280229120000.0.0", "100101000000.0.0"):
            with self.subTest(value=value):
                release_version.parse_calendar_v2(value)
                self.assertEqual(release_version.calendar_to_cargo(value), value)
                self.assertEqual(release_version.cargo_to_calendar(value), value)
        for value in (
            "26.09.09", "26.09.09.19.45.40", "2609091945.0.0", "20260909194540.0.0",
            "260909194540", "260909194540.0", "260909194540.0.1", "260909194540.1.0",
            "260909194540.0.0-rc1", "260909194540.0.0+g1", "090909194540.0.0",
            "260230194540.0.0", "260431194540.0.0", "260909240000.0.0", "260909196000.0.0",
            "260909194560.0.0", "260909194540.00.0", " 260909194540.0.0", "v260909194540.0.0",
        ):
            with self.subTest(value=value), self.assertRaises(release_version.ReleaseVersionError):
                release_version.parse_calendar_v2(value)
        # Mixed-era readers discriminate on the scheme, never on shape.
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.ReleaseIdentity(
                release_version.CALENDAR_SCHEME, "260909194540.0.0", 6
            ).validated_key()
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.ReleaseIdentity(
                release_version.CALENDAR_V2_SCHEME, "26.09.09.19.45.40", 6
            ).validated_key()

    def test_v2_history_closes_v1_and_orders_across_eras_by_sequence(self):
        current = self.release_document()
        first_v2 = current["migration_anchor"]["first_calendar_v2_version"]
        history = self.v1_history()
        # A v1 reservation after the first v2 coordinate is closed.
        stray_v1 = self.calendar_release("26.09.09.23.00.00", FIRST_V2_SEQUENCE + 1)
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.validate_reservation_history(
                stray_v1, (*history, self.calendar_v2_release(first_v2, FIRST_V2_SEQUENCE)), ()
            )
        # A v2 record that disagrees on the v1 → v2 anchor is refused.
        drifted = self.calendar_v2_release(first_v2, FIRST_V2_SEQUENCE)
        drifted["migration_anchor"]["last_calendar_v1_version"] = "26.09.08.11.36.59"
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.validate_release(drifted)
        # Cross-era ordering is by sequence, never by string or SemVer shape.
        last_v1 = release_version.ReleaseIdentity(release_version.CALENDAR_SCHEME, *V1_HISTORY[-1])
        v2 = release_version.ReleaseIdentity(release_version.CALENDAR_V2_SCHEME, first_v2, FIRST_V2_SEQUENCE)
        self.assertLess(release_version.compare_releases(last_v1, v2), 0)
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.compare_releases(
                last_v1,
                release_version.ReleaseIdentity(release_version.CALENDAR_V2_SCHEME, first_v2, V1_HISTORY[-1][1]),
            )

    def test_repository_reservation_must_advance_coordinate_and_sequence(self):
        first = self.first_calendar_release()
        for version, sequence, tags in (
            (FIRST_CALENDAR_VERSION, 2, ()),
            (NEXT_CALENDAR_VERSION, 3, ()),
            (NEXT_CALENDAR_VERSION, 2, (FIRST_CALENDAR_VERSION,)),
            (NEXT_CALENDAR_VERSION, 2, (LATER_CALENDAR_VERSION,)),
        ):
            candidate = self.calendar_release(version, sequence)
            with self.subTest(version=version, sequence=sequence, tags=tags), self.assertRaises(
                release_version.ReleaseVersionError
            ):
                tagged = tuple(self.calendar_release(tag, 2) for tag in tags)
                release_version.validate_reservation_history(candidate, (first,), tagged)

    def test_reservation_history_rejects_gap_regression_and_collision(self):
        first = self.first_calendar_release()
        next_release = self.calendar_release(NEXT_CALENDAR_VERSION, NEXT_CALENDAR_SEQUENCE)
        later = self.calendar_release(LATER_CALENDAR_VERSION, 3)
        collision = self.calendar_release(LATER_CALENDAR_VERSION, NEXT_CALENDAR_SEQUENCE)
        regressed_anchor = self.calendar_release(
            NEXT_CALENDAR_VERSION, NEXT_CALENDAR_SEQUENCE, first="26.09.01.13.29.30"
        )

        with self.subTest("sequence gap"), self.assertRaises(release_version.ReleaseVersionError):
            release_version.validate_reservation_history(later, (first,), ())
        with self.subTest("history regression"), self.assertRaises(
            release_version.ReleaseVersionError
        ):
            release_version.validate_reservation_history(first, (next_release,), ())
        with self.subTest("sequence collision"), self.assertRaises(
            release_version.ReleaseVersionError
        ):
            release_version.validate_reservation_history(collision, (first, next_release), ())
        with self.subTest("coordinate reuse"), self.assertRaises(
            release_version.ReleaseVersionError
        ):
            release_version.validate_reservation_history(
                self.calendar_release(FIRST_CALENDAR_VERSION, NEXT_CALENDAR_SEQUENCE),
                (first,),
                (),
            )
        with self.subTest("regressed migration anchor"), self.assertRaises(
            release_version.ReleaseVersionError
        ):
            release_version.validate_reservation_history(regressed_anchor, (first,), ())

    def test_repository_history_includes_annotated_off_branch_calendar_tags(self):
        def coordinate(version, sequence, *, first=None):
            return self.calendar_release(version, sequence, first=first)

        with tempfile.TemporaryDirectory() as raw_directory:
            repo = Path(raw_directory)

            def git(*args):
                return subprocess.run(
                    ["git", *args], cwd=repo, text=True, capture_output=True, check=True
                ).stdout.strip()

            def commit_release(document, message):
                (repo / "RELEASE.json").write_text(
                    json.dumps(document, indent=2) + "\n", encoding="utf-8"
                )
                git("add", "RELEASE.json")
                git("commit", "-m", message)

            git("init", "-b", "main")
            git("config", "user.name", "Calendar Test")
            git("config", "user.email", "calendar@example.invalid")
            (repo / "README").write_text("fixture\n", encoding="utf-8")
            git("add", "README")
            git("commit", "-m", "base")
            first = coordinate(FIRST_CALENDAR_VERSION, FIRST_CALENDAR_SEQUENCE)
            commit_release(first, "first")
            git("tag", "-a", f"v{FIRST_CALENDAR_VERSION}", "-m", "first")
            git("checkout", "-b", "off-branch")
            second = coordinate(NEXT_CALENDAR_VERSION, NEXT_CALENDAR_SEQUENCE)
            commit_release(second, "second off branch")
            git("tag", "-a", f"v{NEXT_CALENDAR_VERSION}", "-m", "second")
            git("checkout", "main")
            current = coordinate(LATER_CALENDAR_VERSION, 3)
            commit_release(current, "third on main")

            release_version.validate_reservation_history(
                current,
                release_version._first_parent_calendar_releases(repo),
                release_version._tagged_calendar_releases(repo),
            )

            git("checkout", "-b", "collision", f"v{FIRST_CALENDAR_VERSION}^{{}}")
            collision = coordinate("26.09.01.13.29.34", 2)
            commit_release(collision, "colliding off branch")
            git("tag", "-a", "v26.09.01.13.29.34", "-m", "collision")
            git("checkout", "main")
            with self.assertRaises(release_version.ReleaseVersionError):
                release_version.validate_reservation_history(
                    current,
                    release_version._first_parent_calendar_releases(repo),
                    release_version._tagged_calendar_releases(repo),
                )

            git("tag", "-d", "v26.09.01.13.29.34")
            git("checkout", "collision")
            regressed_anchor = coordinate(
                "26.09.01.13.29.35", 4, first="26.09.01.13.29.30"
            )
            commit_release(regressed_anchor, "regressed anchor")
            git("tag", "-a", "v26.09.01.13.29.35", "-m", "regressed anchor")
            git("checkout", "main")
            with self.assertRaises(release_version.ReleaseVersionError):
                release_version.validate_reservation_history(
                    current,
                    release_version._first_parent_calendar_releases(repo),
                    release_version._tagged_calendar_releases(repo),
                )

    def test_unknown_absent_and_ambiguous_schemes_fail_closed(self):
        for scheme in ("", "semver", "inspr-calendar-v3"):
            with self.subTest(scheme=scheme), self.assertRaises(
                release_version.ReleaseVersionError
            ):
                release_version.ReleaseIdentity(scheme, "26.09.01", 1).validated_key()

    def test_cargo_mapping_is_order_preserving(self):
        values = ("26.09.01.13.29.31", "26.09.01.13.29.32", "26.09.02.00.00.00")
        mapped = [tuple(int(part) for part in release_version.calendar_to_cargo(v).split(".")) for v in values]
        self.assertEqual(mapped, sorted(mapped))

    def test_source_lock_digest_frames_every_exact_lock_path_and_bytes(self):
        repo = Path(__file__).resolve().parents[1]
        expected = hashlib.sha256()
        expected.update(b"inspr.pharos.source-lock-set.v1\0")
        for relative in ("Cargo.lock", "devenv.lock", "flake.lock", "package-lock.json"):
            contents = (repo / relative).read_bytes()
            expected.update(relative.encode("ascii"))
            expected.update(b"\0")
            expected.update(len(contents).to_bytes(8, "big"))
            expected.update(contents)
        baseline = release_version.source_lock_digest(repo)
        self.assertEqual(baseline, f"sha256:{expected.hexdigest()}")

        with tempfile.TemporaryDirectory() as raw_directory:
            directory = Path(raw_directory)
            for relative in release_version.SOURCE_LOCK_PATHS:
                (directory / relative).write_bytes((repo / relative).read_bytes())
            for relative in release_version.SOURCE_LOCK_PATHS:
                path = directory / relative
                original = path.read_bytes()
                path.write_bytes(original + b"\nmutation")
                with self.subTest(relative=relative):
                    self.assertNotEqual(release_version.source_lock_digest(directory), baseline)
                path.write_bytes(original)

    def test_release_contract_mutations_fail_closed(self):
        release = self.release_document()
        mutations = []
        missing_scheme = copy.deepcopy(release)
        del missing_scheme["version_scheme"]
        mutations.append(missing_scheme)
        unknown_scheme = copy.deepcopy(release)
        unknown_scheme["version_scheme"] = "inspr-calendar-v3"
        mutations.append(unknown_scheme)
        short_version = copy.deepcopy(release)
        short_version["version"] = "2609091945.0.0"
        mutations.append(short_version)
        wrong_mapping = copy.deepcopy(release)
        wrong_mapping["ecosystem_versions"]["cargo_semver"] = "2026.901.132932"
        mutations.append(wrong_mapping)
        duplicate_sequence = copy.deepcopy(release)
        duplicate_sequence["release_sequence"] = 0
        mutations.append(duplicate_sequence)
        changed_anchor = copy.deepcopy(release)
        changed_anchor["migration_anchor"]["last_legacy_version"] = "0.1.98"
        mutations.append(changed_anchor)
        changed_rollback = copy.deepcopy(release)
        changed_rollback["legacy_rollback"]["digest"] = f"sha256:{'f' * 64}"
        mutations.append(changed_rollback)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                release_version.ReleaseVersionError
            ):
                release_version.validate_release(mutation)

    def test_release_set_requires_exact_coordinates_and_verifiable_evidence(self):
        release = self.release_document()
        release_set = self.release_set_document()
        release_version.validate_release_set(release_set, release)
        mutations = []
        for path, value in (
            (("schema",), "inspr.release-set.v1"),
            (("sha_reference",), release_set["reference"]),
            (("legacy_rollback", "release_sequence"), 1),
            (("attestations", "signature", "coordinate"), "synthetic#signature"),
            (("attestations", "provenance", "coordinate"), "synthetic#slsa"),
            (("attestations", "sbom", "layer_digest"), "sha256:missing"),
        ):
            mutation = copy.deepcopy(release_set)
            target = mutation
            for key in path[:-1]:
                target = target[key]
            target[path[-1]] = value
            mutations.append(mutation)
        for mutation in mutations:
            with self.subTest(mutation=mutation), self.assertRaises(
                release_version.ReleaseVersionError
            ):
                release_version.validate_release_set(mutation, release)

    def test_release_workflow_admits_final_coordinates_only_after_all_gates(self):
        workflow = (
            Path(__file__).resolve().parents[1] / ".github" / "workflows" / "release.yml"
        ).read_text(encoding="utf-8")
        release_version.validate_release_workflow(workflow)
        mutation = workflow.replace(
            "      - name: admit immutable version and source coordinates",
            "      - name: admit immutable version and source coordinates-copy",
            1,
        ).replace(
            "      - name: sign and verify release set",
            "      - name: admit immutable version and source coordinates\n"
            "        run: true\n"
            "      - name: sign and verify release set",
            1,
        )
        with self.assertRaises(release_version.ReleaseVersionError):
            release_version.validate_release_workflow(mutation)
        for fragment in (
            "verify frozen legacy rollback authority",
            "git cat-file -t refs/tags/v0.2.0",
            "{{json .Image.Config.Labels}}",
            "@refs/tags/v0.2.0",
        ):
            with self.subTest(fragment=fragment), self.assertRaises(
                release_version.ReleaseVersionError
            ):
                release_version.validate_release_workflow(
                    workflow.replace(fragment, "legacy-proof-removed", 1)
                )


if __name__ == "__main__":
    unittest.main()
