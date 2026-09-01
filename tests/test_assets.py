import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

from lucy.runtime.assets import verify


TOOLBOX = Path(__file__).parents[1] / "lucy" / "toolbox"


class AssetTests(unittest.TestCase):
    def test_committed_toolbox_hashes_verify(self) -> None:
        self.assertEqual([], verify(TOOLBOX))

    def test_tamper_is_detected(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            destination = Path(directory) / "toolbox"
            __import__("shutil").copytree(TOOLBOX, destination)
            (destination / "census.py").write_text("tampered\n")
            self.assertTrue(any("hash mismatch" in error for error in verify(destination)))

    def test_packaged_executable_assets_start(self) -> None:
        manifest = json.loads((TOOLBOX / "assets.json").read_text(encoding="utf-8"))
        executable_assets = {
            asset["path"] for asset in manifest["assets"]
            if asset["path"].endswith(".py")
        }
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            dispositions = root / "dispositions.jsonl"
            dispositions.write_text('{"disposition":"folded"}\n', encoding="utf-8")
            required = root / "required.txt"
            required.write_text("RESULT-TOKEN:\n", encoding="utf-8")
            completion = root / "completion.md"
            completion.write_text("RESULT-TOKEN: complete\n", encoding="utf-8")
            mutations = root / "mutations.txt"
            mutations.write_text("[demo]\nunsafe-call\n", encoding="utf-8")
            patterns = root / "patterns.txt"
            patterns.write_text("demo: unsafe-call\n", encoding="utf-8")
            instrument = root / "coverage_instrument.py"
            instrument.write_text(
                "class Verdict:\n"
                "    coverage_lb = 0.5\n"
                "    decision = 'STOP-INFEASIBLE'\n"
                "def assess(scans, history_lb=None, diversified=False):\n"
                "    return Verdict()\n",
                encoding="utf-8",
            )

            invocations = {
                "HERMETIC_RUNNER.py": ["--", sys.executable, "-c", "pass"],
                "census.py": ["--selftest"],
                "certification_gate.py": ["--selftest"],
                "conservation_gate.py": [str(dispositions)],
                "detector_battery_v3_3_1.py": ["--selftest"],
                "gates_selftest.py": [],
                "mint_canaries.py": ["--selftest"],
                "mutation_battery.py": [str(mutations), str(patterns)],
                "scam_battery_v1_1.py": ["--instrument", str(instrument)],
                "scan_report_gate.py": ["--selftest"],
                "seal_card_gate.py": ["--selftest"],
                "token_gate.py": [str(required), str(completion)],
                "visitation_check.py": ["--selftest"],
            }
            self.assertEqual(executable_assets, set(invocations))
            for script, arguments in invocations.items():
                with self.subTest(script=script):
                    result = subprocess.run(
                        [sys.executable, str(TOOLBOX / script), *arguments],
                        capture_output=True,
                        text=True,
                        check=False,
                        timeout=60,
                    )
                    self.assertEqual(
                        0, result.returncode, result.stdout + result.stderr
                    )
                    if script == "gates_selftest.py":
                        self.assertIn("GATES SELFTEST: 10/10 PASS", result.stdout)


if __name__ == "__main__":
    unittest.main()
