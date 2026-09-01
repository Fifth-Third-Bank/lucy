"""OpenAI-host path: workspace tools, budget, and orchestrator e2e via a fake host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lucy.runtime.localtools import WorkspaceTools  # noqa: E402
from lucy.runtime.orchestrator import run_review  # noqa: E402
from lucy.runtime.trial import (  # noqa: E402
    prepare_fixture_trial,
    score_recall,
    write_trial_verdict,
)
from lucy.runtime.seal import generate_certification  # noqa: E402

POLYGLOT = ROOT / "tests" / "fixtures" / "polyglot"


class WorkspaceToolsTests(unittest.TestCase):
    def test_tools_are_workspace_bound(self) -> None:
        tools = WorkspaceTools(POLYGLOT)
        self.assertIn("ERROR", tools.dispatch("read_file", {"path": "../../etc/hosts"}))
        self.assertIn("apps/", tools.dispatch("list_files", {"glob": "apps/**/*.ts"}))
        self.assertIn("middleware.ts", tools.dispatch("grep", {"pattern": "jwtVerify"}))
        self.assertIn(
            "ERROR: editing is not permitted",
            tools.dispatch("edit_file", {"path": "README.md", "old": "x", "new": "y"}),
        )


class FakeHost:
    """Scripted host: readers report the planted canaries; courts verify."""

    def __init__(self, answer_key: dict) -> None:
        self.answer_key = answer_key
        self.calls: list[str] = []

    def run_agent(self, *, system, task, workspace, allow_edit=False, max_turns=60):
        self.calls.append(task.splitlines()[0])
        if task.startswith("LUCY READER"):
            lens = task.split("LENS=")[1].split()[0]
            unit_files = set()
            in_files = False
            for line in task.splitlines():
                if line.startswith("UNIT_FILE contents"):
                    in_files = True
                    continue
                if line.startswith("BATTERY"):
                    break
                if in_files and line.strip():
                    unit_files.add(line.strip())
            rows = [
                json.dumps(
                    {
                        "path": canary["path"],
                        "line": canary["line"],
                        "lens": lens,
                        "category": {
                            "L1-auth": "missing-authorization",
                            "L2-secrets": "weakened-signature-validation",
                            "L3-injection": "sql-injection",
                            "L4-infra": "public-exposure",
                        }[lens],
                        "severity": "HIGH",
                        "title": f"Observed: {canary['title']}",
                        "evidence": "kind-only evidence",
                        "reach_basis": f"{canary['path']}:{canary['line']}",
                    }
                )
                for canary in self.answer_key["canaries"]
                if canary["family"] == lens and canary["path"] in unit_files
            ]
            return "\n".join(rows)
        if task.startswith("LUCY SWEEP"):
            return ""
        if task.startswith("LUCY COURT"):
            candidate_id = task.split("CANDIDATE_ID=")[1].splitlines()[0]
            locus = task.split("LOCUS=")[1].splitlines()[0]
            return json.dumps(
                {
                    "candidate_id": candidate_id,
                    "verdict": "VERIFIED",
                    "severity": "HIGH",
                    "cwe": "CWE-862",
                    "disproof_attempt": "Disproof failed on bytes.",
                    "basis": "static-reasoned",
                    "reach_basis": locus,
                    "fix": "Restore the weakened control at the cited locus and add a regression test.",
                }
            )
        raise AssertionError(f"unexpected task: {task[:60]}")


class OrchestratorEndToEndTests(unittest.TestCase):
    def test_fake_host_pipeline_reaches_certified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ,
            {"LUCY_CUSTODY_HOME": str(Path(tmp) / "custody-home")},
        ):
            results = Path(tmp) / "results"
            trial = prepare_fixture_trial(
                POLYGLOT, results, custody_root=Path(tmp) / "custody"
            )
            workspace = Path(trial["workspace"])
            run_dir = Path(trial["run_directory"])
            custody = Path(trial["_custody"])
            answer = json.loads(
                (custody.parent / "ANSWER_KEY.json").read_text(encoding="utf-8")
            )
            host = FakeHost(answer)
            summary = run_review(host, workspace, run_dir, results)
            self.assertGreaterEqual(summary["passes"], 2)
            self.assertEqual(summary["quiet_units"], summary["units"])
            recall = score_recall(run_dir, custody, workspace, results)
            self.assertEqual(recall["found"], 8, recall)
            verdict = write_trial_verdict(run_dir, workspace, POLYGLOT, results, recall)
            self.assertEqual(verdict["status"], "PASS", verdict)
            valid_dispositions = {
                "schema": "lucy-dispositions/v1",
                "planted_file_candidates": 8,
                "dispositioned": 8,
                "unresolved": 0,
                "rows": [],
            }
            outcome = generate_certification(
                run_dir, workspace, results, trial["run_id"], trial["started_at"],
                recall_receipt=recall,
                dispositions=valid_dispositions,
            )
            self.assertTrue(outcome["certified"], outcome)


class OpenAIHostConfigTests(unittest.TestCase):
    def test_requires_model_and_key(self) -> None:
        import os

        from lucy.runtime.host import OpenAIHost

        saved = {k: os.environ.pop(k, None) for k in ("OPENAI_MODEL", "OPENAI_API_KEY")}
        try:
            with self.assertRaisesRegex(ValueError, "OPENAI_MODEL"):
                OpenAIHost()
            os.environ["OPENAI_MODEL"] = "test-model"
            with self.assertRaisesRegex(ValueError, "OPENAI_API_KEY"):
                OpenAIHost()
        finally:
            for key, value in saved.items():
                if value is not None:
                    os.environ[key] = value

    def test_budget_enforcement(self) -> None:
        import os

        from lucy.runtime.host import BudgetExceeded, OpenAIHost

        os.environ.setdefault("OPENAI_MODEL", "test-model")
        os.environ.setdefault("OPENAI_API_KEY", "test-key")
        host = OpenAIHost(max_budget_usd=0.001)
        host.usd_per_mtoken = 10.0
        with self.assertRaises(BudgetExceeded):
            host._charge({"total_tokens": 1_000_000})


if __name__ == "__main__":
    unittest.main()


class ProgressAndTeeTests(unittest.TestCase):
    def test_progress_reporter_derives_phases_from_receipts(self) -> None:
        import io

        from lucy.runtime.progress import ProgressReporter

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp) / "runs" / "r-x"
            staging = run_dir / "staging"
            staging.mkdir(parents=True)
            out = io.StringIO()
            reporter = ProgressReporter(run_dir, out=out)
            reporter._tick()
            (staging / "UNIT-001.txt").write_text("a\n", encoding="utf-8")
            (staging / "lane-pass1-L1-auth.jsonl").write_text("", encoding="utf-8")
            reporter._tick()
            (staging / "courts").mkdir()
            (staging / "courts" / "LUCY-1.json").write_text("{}", encoding="utf-8")
            reporter._tick()
            import shutil as _shutil

            (run_dir / "findings.jsonl").write_text("", encoding="utf-8")
            _shutil.rmtree(staging)
            reporter._tick()
            text = out.getvalue()
            self.assertIn("preflight", text)
            self.assertIn("reading    units 1 · lanes 1/4 (pass 1)", text)
            self.assertIn("courts", text)
            self.assertIn("finalize", text)

    def test_tee_duplicates_to_log(self) -> None:
        import io

        from lucy.runtime.progress import Tee

        console, log = io.StringIO(), io.StringIO()
        tee = Tee(console, log)
        tee.write("hello\n")
        tee.flush()
        self.assertEqual(console.getvalue(), "hello\n")
        self.assertEqual(log.getvalue(), "hello\n")
