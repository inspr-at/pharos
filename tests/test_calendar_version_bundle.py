import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CHECK = ROOT / "scripts/check-calendar-version-display.py"


class CalendarVersionBundleTest(unittest.TestCase):
    def run_check(self, root):
        return subprocess.run(["python3", str(CHECK), str(root)], text=True, capture_output=True)

    def fixture(self, directory):
        target = Path(directory) / "crates/pharosd/assets/vendor/calendar-version-display"
        target.parent.mkdir(parents=True)
        shutil.copytree(ROOT / "crates/pharosd/assets/vendor/calendar-version-display", target)
        return target

    def test_exact_bundle_passes(self):
        result = self.run_check(ROOT)
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("source=317f872bc061576fc0b45d274d3a22f69bcd4c8a", result.stdout)

    def test_scheme_label_drift_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.fixture(directory)
            labels = json.loads(bundle.joinpath("schemes.json").read_text())
            labels["labels"]["inspr-calendar-v2"] = "Invented label"
            bundle.joinpath("schemes.json").write_text(json.dumps(labels))
            result = self.run_check(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("schemes.json bytes drifted", result.stderr)

    def test_renderer_or_manifest_drift_fails(self):
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.fixture(directory)
            bundle.joinpath("version.js").write_text("export const drift = true;\n")
            result = self.run_check(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("version.js bytes drifted", result.stderr)
        with tempfile.TemporaryDirectory() as directory:
            bundle = self.fixture(directory)
            manifest = json.loads(bundle.joinpath("manifest.json").read_text())
            manifest["revision"] = "0" * 40
            bundle.joinpath("manifest.json").write_text(json.dumps(manifest))
            result = self.run_check(directory)
            self.assertNotEqual(result.returncode, 0)
            self.assertIn("manifest digest drifted", result.stderr)


if __name__ == "__main__":
    unittest.main()
