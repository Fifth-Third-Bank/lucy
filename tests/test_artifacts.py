import json
from pathlib import Path
import tempfile
import unittest

from lucy.runtime.artifacts import finalize, merge_candidates


class ArtifactPipelineTests(unittest.TestCase):
    def test_fingerprint_is_stable_across_reader_wording(self) -> None:
        from lucy.runtime.artifacts import normalize_candidate

        base = {
            "path": "apps/api.py",
            "line": 10,
            "lens": "L1",
            "category": "authorization",
            "severity": "HIGH",
            "title": "Missing owner check",
            "evidence": "No binding found.",
            "reach_basis": "apps/api.py:2 route",
        }
        alternate = dict(base, title="Account route lacks ownership binding")
        self.assertEqual(normalize_candidate(base)["id"], normalize_candidate(alternate)["id"])

    def test_merge_court_finalize_and_redact(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            workspace = base / "workspace"
            workspace.mkdir()
            results = base / "results"
            run_directory = results / "runs" / "r-test"
            staging = run_directory / "staging"
            staging.mkdir(parents=True)
            candidate = {
                "path": "apps/api.py",
                "line": 10,
                "lens": "L1",
                "category": "authorization",
                "severity": "HIGH",
                "title": "Missing owner check",
                "evidence": "password=do-not-ship",
                "reach_basis": "apps/api.py:2 route",
            }
            (staging / "lane-pass1-l1.jsonl").write_text(json.dumps(candidate) + "\n")
            rows = merge_candidates(run_directory, workspace, results)
            self.assertEqual(1, len(rows))
            court = {
                "candidate_id": rows[0]["id"],
                "verdict": "VERIFIED",
                "severity": "HIGH",
                "cwe": "CWE-862",
                "disproof_attempt": "No owner binding found.",
                "basis": "static-reasoned",
                "fix": "Bind the account id to the authenticated owner.",
            }
            (staging / "courts.jsonl").write_text(json.dumps(court) + "\n")
            findings = finalize(run_directory, workspace, results)
            self.assertEqual(1, len(findings))
            delivered = (run_directory / "findings.jsonl").read_text()
            self.assertNotIn("do-not-ship", delivered)
            self.assertIn("[REDACTED]", delivered)
            self.assertFalse(staging.exists())


if __name__ == "__main__":
    unittest.main()


class ConvergenceReducerTests(unittest.TestCase):
    def _estate(self, root: Path) -> tuple[Path, Path, Path]:
        workspace = root / "workspace"
        results = root / "results"
        run = results / "runs" / "r-test"
        staging = run / "staging"
        workspace.mkdir()
        staging.mkdir(parents=True)
        (workspace / "a.py").write_text("print('a')\n", encoding="utf-8")
        (staging / "UNIT-001.txt").write_text("a.py\n", encoding="utf-8")
        (staging / "UNITS.json").write_text(
            json.dumps({"units": [{"id": "UNIT-001", "loc": 1}]}),
            encoding="utf-8",
        )
        return workspace, results, run

    @staticmethod
    def _row(severity: str) -> str:
        return json.dumps(
            {
                "path": "a.py",
                "line": 1,
                "lens": "L1-auth",
                "category": "missing-authorization",
                "severity": severity,
                "title": "authorization is not enforced",
                "evidence": "kind-only",
                "reach_basis": "a.py:1",
            }
        ) + "\n"

    def test_severity_upgrade_is_new_serious_on_upgrade_pass(self) -> None:
        from lucy.runtime.artifacts import merge_candidates

        with tempfile.TemporaryDirectory() as directory:
            workspace, results, run = self._estate(Path(directory))
            staging = run / "staging"
            (staging / "lane-pass1-L1-auth-UNIT-001.jsonl").write_text(
                self._row("MEDIUM"), encoding="utf-8"
            )
            (staging / "lane-pass2-L1-auth-UNIT-001.jsonl").write_text(
                self._row("HIGH"), encoding="utf-8"
            )
            candidates = merge_candidates(run, workspace, results)
            history = json.loads(
                (run / "receipts" / "PASS_HISTORY.json").read_text(encoding="utf-8")
            )["passes"]
            self.assertEqual([], history[0]["new_serious"])
            self.assertEqual([candidates[0]["id"]], history[1]["new_serious"])

    def test_full_then_zero_light_confirmation_closes_unit(self) -> None:
        from lucy.runtime.artifacts import merge_candidates, unit_convergence_map

        with tempfile.TemporaryDirectory() as directory:
            workspace, results, run = self._estate(Path(directory))
            staging = run / "staging"
            for lens in ("L1-auth", "L2-secrets", "L3-injection", "L4-infra"):
                (staging / f"lane-pass1-{lens}-UNIT-001.jsonl").write_text("", encoding="utf-8")
            (staging / "lane-pass2-L2-secrets-UNIT-001.jsonl").write_text("", encoding="utf-8")
            merge_candidates(run, workspace, results)
            self.assertEqual("quiet", unit_convergence_map(run)["UNIT-001"])

    def test_confirmation_finding_reopens_and_sweep_never_confirms(self) -> None:
        from lucy.runtime.artifacts import merge_candidates, unit_convergence_map

        with tempfile.TemporaryDirectory() as directory:
            workspace, results, run = self._estate(Path(directory))
            staging = run / "staging"
            for lens in ("L1-auth", "L2-secrets", "L3-injection", "L4-infra"):
                (staging / f"lane-pass1-{lens}-UNIT-001.jsonl").write_text("", encoding="utf-8")
            (staging / "lane-sweep-L1-auth.jsonl").write_text("", encoding="utf-8")
            merge_candidates(run, workspace, results)
            self.assertEqual("confirm", unit_convergence_map(run)["UNIT-001"])
            (staging / "lane-pass2-L3-injection-UNIT-001.jsonl").write_text(
                self._row("HIGH"), encoding="utf-8"
            )
            merge_candidates(run, workspace, results)
            self.assertEqual("loud", unit_convergence_map(run)["UNIT-001"])

class SweepQuietAccountingTests(unittest.TestCase):
    def test_sweep_serious_rows_enter_pass_history_after_pass_one(self) -> None:
        """A serious sweep finding must be visible to the quiet law (C2):
        sweeps form their own history slot ordered right after pass 1."""

        def row(path: str, severity: str) -> dict:
            return {
                "path": path,
                "line": 3,
                "lens": "L2-secrets",
                "category": "shared-credential",
                "severity": severity,
                "title": f"Claim at {path}.",
                "evidence": "kind-only",
                "reach_basis": f"{path}:3",
            }

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            workspace = base / "ws"
            workspace.mkdir()
            results = base / "results"
            run_dir = results / "runs" / "r-test"
            staging = run_dir / "staging"
            staging.mkdir(parents=True)
            (staging / "lane-pass1-L2-secrets.jsonl").write_text(
                json.dumps(row("repo-a/config.py", "MEDIUM")) + "\n", encoding="utf-8"
            )
            (staging / "lane-sweep-L2-secrets.jsonl").write_text(
                json.dumps(row("repo-b/config.py", "HIGH")) + "\n", encoding="utf-8"
            )
            (staging / "lane-pass2-L2-secrets.jsonl").write_text(
                json.dumps(row("repo-a/config.py", "MEDIUM")) + "\n", encoding="utf-8"
            )
            merge_candidates(run_dir, workspace, results)
            history = json.loads(
                (run_dir / "receipts" / "PASS_HISTORY.json").read_text(encoding="utf-8")
            )["passes"]
            phases = [(entry["pass"], entry.get("phase")) for entry in history]
            self.assertEqual(phases, [(1, None), (1, "sweep"), (2, None)])
            sweep_entry = history[1]
            self.assertEqual(len(sweep_entry["new_serious"]), 1)
