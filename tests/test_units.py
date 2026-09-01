"""Reader-unit eligibility, including extensionless executable scripts."""

from __future__ import annotations

from pathlib import Path
import tempfile
import unittest

from lucy.runtime.trial import _validate_canary_coverage
from lucy.runtime.units import compute_units


class UnitEligibilityTests(unittest.TestCase):
    def test_extensionless_shebang_script_is_scanned_and_can_host_canary(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            repo = root / "service"
            repo.mkdir()
            (repo / "main.py").write_text("one\ntwo\n", encoding="utf-8")
            (repo / "runner").write_text("#!/bin/sh\nexec true\n", encoding="utf-8")
            (repo / "notes").write_text("not source\n", encoding="utf-8")

            plan = compute_units(root)
            files = {
                path
                for unit in plan["units"]
                for path in unit["files"]
            }
            self.assertIn("service/main.py", files)
            self.assertIn("service/runner", files)
            self.assertNotIn("service/notes", files)
            self.assertEqual(plan["scannable_loc"], 4)

            _validate_canary_coverage(
                {"canaries": [{"path": "service/runner"}]},
                root,
                baseline_paths=files,
            )
            with self.assertRaisesRegex(ValueError, "impossible recall trial"):
                _validate_canary_coverage(
                    {"canaries": [{"path": "service/notes"}]},
                    root,
                    baseline_paths=files,
                )
            with self.assertRaisesRegex(ValueError, "impossible recall trial"):
                _validate_canary_coverage(
                    {"canaries": [{"path": "service/runner"}]},
                    root,
                    baseline_paths={"service/main.py"},
                )


if __name__ == "__main__":
    unittest.main()
