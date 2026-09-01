"""Undefined-name gate for refactors that remove an import while a
rarely-exercised success path still uses the name. Python compilation does
not resolve global names, so static analysis must catch this class."""

from __future__ import annotations

from pathlib import Path
import shutil
import subprocess
import unittest


ROOT = Path(__file__).parents[1]


class UndefinedNameTests(unittest.TestCase):
    def test_no_undefined_names_in_runtime_or_tools(self) -> None:
        ruff = shutil.which("ruff")
        if ruff is None:
            self.fail(
                "ruff is required by the release gate (pip install ruff): "
                "undefined-name checking is what catches removed-import "
                "regressions that unit tests miss"
            )
        result = subprocess.run(
            [ruff, "check", "--select", "F821", str(ROOT / "lucy"), str(ROOT / "tools")],
            capture_output=True,
            text=True,
            check=False,
        )
        self.assertEqual(0, result.returncode, result.stdout + result.stderr)


if __name__ == "__main__":
    unittest.main()
