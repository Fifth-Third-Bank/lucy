from pathlib import Path
import tempfile
import unittest

from lucy.runtime.trial import prepare_fixture_trial


SUPER_REPO = Path(__file__).parents[2] / "lucy-super-repo"


@unittest.skipUnless(SUPER_REPO.is_dir(), "lucy-super-repo fixture is not available")
class TrialPreparationTests(unittest.TestCase):
    def test_prepare_hides_answer_key_and_leaves_target_unchanged(self) -> None:
        before = (SUPER_REPO / "shared" / "webhook.py").read_bytes()
        with tempfile.TemporaryDirectory() as directory:
            trial = prepare_fixture_trial(
                SUPER_REPO,
                Path(directory) / "results",
                custody_root=Path(directory) / "custody",
            )
            workspace = Path(trial["workspace"])
            custody = Path(trial["_custody"])
            custody_document = __import__("json").loads(custody.read_text())
            answer_key = Path(custody_document["answer_key"])
            self.assertTrue(answer_key.is_file())
            self.assertFalse((workspace / "ANSWER_KEY.json").exists())
            public_trial = __import__("json").loads(
                (Path(trial["run_directory"]) / "trial.json").read_text()
            )
            self.assertNotIn("answer_key", public_trial)
            self.assertNotIn("_custody", public_trial)
            self.assertFalse((workspace / "tools").exists())
            self.assertFalse((workspace / "tests").exists())
            self.assertFalse((workspace / "docs").exists())
            self.assertFalse((workspace / "README.md").exists())
            # The git oracle must be destroyed: after prepare, the planted
            # state is the only commit, so status/diff reveal nothing about
            # canary loci (adversarially confirmed regression).
            status = subprocess_output(["git", "status", "--short"], workspace)
            self.assertEqual(0, len(status.splitlines()))
            log = subprocess_output(["git", "log", "--oneline"], workspace)
            self.assertEqual(1, len(log.splitlines()))
            self.assertNotIn("Trial baseline", log)
            # L2-KEY moved to shared/signing.py when the placement law
            # (same-family plants in different files) landed.
            planted_source = (workspace / "shared" / "signing.py").read_text()
            self.assertIn("local-development-signing-key", planted_source)
            self.assertNotIn("LUCY_CANARY:", planted_source)
            self.assertNotIn(
                "LUCY_CANARY:", (workspace / "shared" / "webhook.py").read_text()
            )
        self.assertEqual(before, (SUPER_REPO / "shared" / "webhook.py").read_bytes())


def subprocess_output(command: list[str], cwd: Path) -> str:
    import subprocess

    return subprocess.run(command, cwd=cwd, check=True, capture_output=True, text=True).stdout


if __name__ == "__main__":
    unittest.main()
