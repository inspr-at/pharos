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


class CalendarVersionTests(unittest.TestCase):
    @staticmethod
    def release_document():
        return json.loads(
            (Path(__file__).resolve().parents[1] / "RELEASE.json").read_text(encoding="utf-8")
        )

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
        release = self.release_document()
        subsequent = copy.deepcopy(release)
        subsequent["version"] = "26.09.01.13.29.32"
        subsequent["release_sequence"] = 2
        subsequent["ecosystem_versions"]["cargo_semver"] = "2026.901.132932"
        release_version.validate_release(subsequent)
        release_version.validate_reservation_history(subsequent, (release,), ())
        self.assertEqual(subsequent["migration_anchor"], release["migration_anchor"])

    def test_repository_reservation_must_advance_coordinate_and_sequence(self):
        release = self.release_document()
        for version, sequence, tags in (
            ("26.09.01.13.29.31", 2, ()),
            ("26.09.01.13.29.32", 3, ()),
            ("26.09.01.13.29.32", 2, ("26.09.01.13.29.31",)),
            ("26.09.01.13.29.32", 2, ("26.09.01.13.29.33",)),
        ):
            candidate = copy.deepcopy(release)
            candidate["version"] = version
            candidate["release_sequence"] = sequence
            candidate["ecosystem_versions"]["cargo_semver"] = release_version.calendar_to_cargo(
                version
            )
            with self.subTest(version=version, sequence=sequence, tags=tags), self.assertRaises(
                release_version.ReleaseVersionError
            ):
                tagged = tuple(
                    {
                        **release,
                        "version": tag,
                        "release_sequence": 2,
                        "ecosystem_versions": {
                            "cargo_semver": release_version.calendar_to_cargo(tag)
                        },
                    }
                    for tag in tags
                )
                release_version.validate_reservation_history(candidate, (release,), tagged)

    def test_repository_history_includes_annotated_off_branch_calendar_tags(self):
        template = self.release_document()

        def coordinate(version, sequence, *, first=None):
            document = copy.deepcopy(template)
            document["version"] = version
            document["release_sequence"] = sequence
            document["ecosystem_versions"]["cargo_semver"] = release_version.calendar_to_cargo(
                version
            )
            if first is not None:
                document["migration_anchor"]["first_calendar_version"] = first
            return document

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
            first = coordinate("26.09.01.13.29.31", 1)
            commit_release(first, "first")
            git("tag", "-a", "v26.09.01.13.29.31", "-m", "first")
            git("checkout", "-b", "off-branch")
            second = coordinate("26.09.01.13.29.32", 2)
            commit_release(second, "second off branch")
            git("tag", "-a", "v26.09.01.13.29.32", "-m", "second")
            git("checkout", "main")
            current = coordinate("26.09.01.13.29.33", 3)
            commit_release(current, "third on main")

            release_version.validate_reservation_history(
                current,
                release_version._first_parent_calendar_releases(repo),
                release_version._tagged_calendar_releases(repo),
            )

            git("checkout", "-b", "collision", "v26.09.01.13.29.31^{}")
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
        for scheme in ("", "semver", "inspr-calendar-v2"):
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
        unknown_scheme["version_scheme"] = "inspr-calendar-v2"
        mutations.append(unknown_scheme)
        short_version = copy.deepcopy(release)
        short_version["version"] = "26.09.01"
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
