import json
from pathlib import Path
import tempfile
import unittest

from lucy.runtime.trial import prepare_fixture_trial, score_recall, write_trial_verdict


SUPER_REPO = Path(__file__).parents[2] / "lucy-super-repo"


@unittest.skipUnless(SUPER_REPO.is_dir(), "lucy-super-repo fixture is not available")
class RecallScoringTests(unittest.TestCase):
    def test_score_runs_outside_orchestrator_and_removes_custody(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            trial = prepare_fixture_trial(
                SUPER_REPO, results, custody_root=Path(directory) / "custody"
            )
            run_directory = Path(trial["run_directory"])
            custody_path = Path(trial["_custody"])
            answer = json.loads(Path(json.loads(custody_path.read_text())["answer_key"]).read_text())
            rows = [
                {
                    "path": canary["path"],
                    "line": canary["line"],
                    "severity": "HIGH",
                    "title": canary["title"],
                }
                for canary in answer["canaries"]
            ]
            (run_directory / "candidates.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
            )
            # Interrupted run (no findings.jsonl): scoring is provisional and
            # custody survives so --resume can re-score after remaining lanes.
            receipt = score_recall(
                run_directory, custody_path, Path(trial["workspace"]), results
            )
            self.assertEqual("PASS", receipt["status"])
            self.assertEqual("reader-candidates", receipt["source"])
            self.assertEqual(8, receipt["found"])
            self.assertTrue(receipt.get("provisional"))
            self.assertTrue(custody_path.parent.exists())
            # Finalized run: custody is destroyed on scoring.
            (run_directory / "findings.jsonl").write_text("", encoding="utf-8")
            receipt = score_recall(
                run_directory, custody_path, Path(trial["workspace"]), results
            )
            self.assertNotIn("provisional", receipt)
            self.assertFalse(custody_path.parent.exists())

    def test_trial_verdict_requires_process_completion_and_recall(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            trial = prepare_fixture_trial(
                SUPER_REPO, results, custody_root=Path(directory) / "custody"
            )
            run_directory = Path(trial["run_directory"])
            workspace = Path(trial["workspace"])
            for name in ("FINDINGS.md", "findings.jsonl", "candidates.jsonl"):
                (run_directory / name).write_text("\n", encoding="utf-8")
            (run_directory / "COMPLETION.md").write_text(
                "RECALL: EXTERNAL-PENDING\npassword=do-not-ship\n", encoding="utf-8"
            )
            __import__("shutil").rmtree(run_directory / "staging", ignore_errors=True)
            recall = {
                "status": "PASS",
                "found": 8,
                "total": 8,
                "source": "reader-candidates",
                "answer_key_sha256": "a" * 64,
            }
            verdict = write_trial_verdict(
                run_directory, workspace, SUPER_REPO, results, recall
            )
            self.assertEqual("PASS", verdict["status"])
            self.assertNotIn("do-not-ship", (run_directory / "COMPLETION.md").read_text())


if __name__ == "__main__":
    unittest.main()


@unittest.skipUnless(SUPER_REPO.is_dir(), "lucy-super-repo fixture is not available")
class RecallSaturationTests(unittest.TestCase):
    def test_shotgun_candidate_set_scores_saturated_not_pass(self) -> None:
        """8/8 is only meaningful when the candidate set could not have
        blanketed unknown loci: exceeding the density law (max(64, LOC/100))
        marks the receipt SATURATED, which can never certify."""
        with tempfile.TemporaryDirectory() as directory:
            results = Path(directory) / "results"
            trial = prepare_fixture_trial(
                SUPER_REPO, results, custody_root=Path(directory) / "custody"
            )
            run_directory = Path(trial["run_directory"])
            custody_path = Path(trial["_custody"])
            answer = json.loads(Path(json.loads(custody_path.read_text())["answer_key"]).read_text())
            rows = [
                {
                    "path": canary["path"],
                    "line": canary["line"],
                    "severity": "HIGH",
                    "title": canary["title"],
                }
                for canary in answer["canaries"]
            ]
            filler = [
                {"path": "apps/filler.py", "line": index + 1, "severity": "LOW",
                 "title": "auth secrets injection infra blanket row"}
                for index in range(200)
            ]
            (run_directory / "candidates.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in rows + filler),
                encoding="utf-8",
            )
            receipt = score_recall(
                run_directory, custody_path, Path(trial["workspace"]), results
            )
            self.assertEqual("SATURATED", receipt["status"])
            self.assertEqual(8, receipt["found"])
            self.assertGreater(receipt["candidate_count"], receipt["saturation_limit"])


class RecallLineWindowTests(unittest.TestCase):
    def test_far_same_file_keyword_finding_does_not_score(self) -> None:
        """CWE-1390 regression: a same-file finding with a generic
        lens keyword in its title used to credit the plant regardless of
        location. The 40-line window is a hard gate now."""
        import json
        import os
        import tempfile
        from pathlib import Path as _Path
        from unittest.mock import patch

        from lucy.runtime.trial import score_recall

        with tempfile.TemporaryDirectory() as tmp:
            root = _Path(tmp)
            run = root / "runs" / "r-x"
            (run / "receipts").mkdir(parents=True)
            workspace = root / "ws"
            workspace.mkdir()
            canaries = [
                {"slot": index, "family": "L2-secrets", "path": "a/app.py", "line": 500}
                for index in range(1, 9)
            ]
            custody_dir = root / "custody"
            custody_dir.mkdir()
            import hashlib

            key = custody_dir / "ANSWER_KEY.json"
            key.write_text(json.dumps({"canaries": canaries}))
            key_sha = hashlib.sha256(key.read_bytes()).hexdigest()
            custody = custody_dir / "custody.json"
            custody.write_text(json.dumps({"answer_key": str(key), "answer_key_sha256": key_sha, "run_id": "r-x"}))
            rows = [
                {"id": f"LUCY-{index}", "path": "a/app.py", "line": 3,
                 "severity": "HIGH", "title": "hardcoded key in config"}
                for index in range(1, 9)
            ]
            (run / "candidates.jsonl").write_text(
                "\n".join(json.dumps(row) for row in rows)
            )
            with patch.dict(
                os.environ, {"LUCY_CUSTODY_HOME": str(root / "custody-home")}
            ):
                receipt = score_recall(run, custody, workspace, root)
            self.assertEqual(0, receipt["found"])
