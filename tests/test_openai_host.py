"""OpenAI-host path: workspace tools, budget, and orchestrator e2e via a fake host."""

from __future__ import annotations

import json
import os
from pathlib import Path
import sys
import tempfile
import threading
import time
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

    def test_courts_share_the_cap_and_start_before_confirmation_reader(self) -> None:
        class TrackingHost(FakeHost):
            def __init__(self, answer_key):
                super().__init__(answer_key)
                self.active = 0
                self.maximum = 0
                self.sequence = []
                self.lock = threading.Lock()

            def run_agent(self, **kwargs):
                first = kwargs["task"].splitlines()[0]
                with self.lock:
                    self.active += 1
                    self.maximum = max(self.maximum, self.active)
                    self.sequence.append(first)
                try:
                    time.sleep(0.005)
                    return super().run_agent(**kwargs)
                finally:
                    with self.lock:
                        self.active -= 1

        with tempfile.TemporaryDirectory() as tmp:
            results = Path(tmp) / "results"
            trial = prepare_fixture_trial(
                POLYGLOT, results, custody_root=Path(tmp) / "custody"
            )
            answer = json.loads(
                (Path(trial["_custody"]).parent / "ANSWER_KEY.json").read_text(
                    encoding="utf-8"
                )
            )
            host = TrackingHost(answer)
            with patch.dict("os.environ", {"LUCY_MAX_LANES": "2"}):
                summary = run_review(
                    host,
                    Path(trial["workspace"]),
                    Path(trial["run_directory"]),
                    results,
                )
            self.assertEqual(summary["quiet_units"], summary["units"])
            self.assertLessEqual(host.maximum, 2)
            first_court = next(i for i, value in enumerate(host.sequence) if value == "LUCY COURT")
            pass_two = next(
                i for i, value in enumerate(host.sequence) if value.startswith("LUCY READER PASS=2")
            )
            self.assertLess(first_court, pass_two)
            final_pass = f"LUCY READER PASS={summary['passes']}"
            self.assertEqual(
                summary["units"],
                sum(value.startswith(final_pass) for value in host.sequence),
            )

    def test_interrupted_wave_resumes_without_redoing_completed_lanes(self) -> None:
        class EmptyHost:
            def __init__(self, fail_lens=None):
                self.fail_lens = fail_lens
                self.calls = []

            def run_agent(self, *, system, task, workspace, allow_edit=False, max_turns=60):
                self.calls.append(task.splitlines()[0])
                if self.fail_lens and self.fail_lens in task:
                    raise RuntimeError("simulated lane crash")
                return ""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            workspace.mkdir()
            (workspace / "app.py").write_text("print('ok')\n", encoding="utf-8")
            results = root / "results"
            run_dir = results / "runs" / "r-resume"
            broken = EmptyHost("LENS=L4-infra")
            with self.assertRaisesRegex(RuntimeError, "simulated lane crash"):
                run_review(broken, workspace, run_dir, results, width=1)
            self.assertTrue((run_dir / "staging" / "CURRENT_WAVE.json").is_file())
            healthy = EmptyHost()
            summary = run_review(healthy, workspace, run_dir, results, width=1)
            self.assertEqual(summary["quiet_units"], summary["units"])
            # Three pass-one lanes finished atomically before the crash; only
            # the missing L4 lane plus one light confirmation are dispatched.
            self.assertEqual(2, len(healthy.calls), healthy.calls)

    def test_resumed_pass_one_backfills_multi_repo_sweeps(self) -> None:
        class EmptyHost:
            def __init__(self, fail_lens=None):
                self.fail_lens = fail_lens
                self.calls = []

            def run_agent(self, *, system, task, workspace, allow_edit=False, max_turns=60):
                self.calls.append(task.splitlines()[0])
                if self.fail_lens and self.fail_lens in task:
                    raise RuntimeError("simulated lane crash")
                return ""

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            workspace = root / "workspace"
            (workspace / "repo-a").mkdir(parents=True)
            (workspace / "repo-b").mkdir(parents=True)
            (workspace / "repo-a" / "a.py").write_text("print('a')\n", encoding="utf-8")
            (workspace / "repo-b" / "b.py").write_text("print('b')\n", encoding="utf-8")
            results = root / "results"
            run_dir = results / "runs" / "r-sweep-resume"
            with self.assertRaisesRegex(RuntimeError, "simulated lane crash"):
                run_review(
                    EmptyHost("LENS=L4-infra"), workspace, run_dir, results, width=1
                )
            healthy = EmptyHost()
            summary = run_review(healthy, workspace, run_dir, results, width=1)
            self.assertEqual(summary["quiet_units"], summary["units"])
            self.assertEqual(
                4,
                sum(call.startswith("LUCY SWEEP") for call in healthy.calls),
                healthy.calls,
            )
            self.assertFalse(
                any(call.startswith("LUCY READER PASS=1 LENS=L1") for call in healthy.calls),
                healthy.calls,
            )


class OrchestratorMechanicsTests(unittest.TestCase):
    def test_severity_upgrade_invalidates_only_a_stale_court(self) -> None:
        from lucy.runtime.orchestrator import court_needs_dispatch

        candidate = {"id": "LUCY-1", "severity": "CRITICAL"}
        with tempfile.TemporaryDirectory() as tmp:
            verdict = Path(tmp) / "LUCY-1.json"
            verdict.write_text(
                json.dumps(
                    {
                        "candidate_id": "LUCY-1",
                        "verdict": "VERIFIED",
                        "severity": "MEDIUM",
                        "proposed_severity": "HIGH",
                    }
                ),
                encoding="utf-8",
            )
            self.assertTrue(court_needs_dispatch(candidate, verdict))
            candidate["severity"] = "HIGH"
            self.assertFalse(court_needs_dispatch(candidate, verdict))

    def test_invalid_court_contract_falls_back_once_without_refuting(self) -> None:
        from lucy.runtime.orchestrator import normalized_court_verdict

        candidate = {
            "id": "LUCY-1",
            "severity": "HIGH",
            "reach_basis": "app.py:1",
        }
        verdict = normalized_court_verdict(
            [
                {
                    "candidate_id": "LUCY-WRONG",
                    "verdict": "REFUTED",
                    "severity": "HIGH",
                }
            ],
            candidate,
        )
        self.assertEqual("LUCY-1", verdict["candidate_id"])
        self.assertEqual("CONDITIONAL", verdict["verdict"])
        self.assertEqual("HIGH", verdict["severity"])

    def test_resume_success_closes_an_orphaned_lane_death(self) -> None:
        from lucy.runtime.orchestrator import _lane_guarded

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            receipts = run_dir / "receipts"
            receipts.mkdir()
            (receipts / "LIVENESS.jsonl").write_text(
                json.dumps({"event": "lane-dead", "lane": "pass1-L1-auth-UNIT-001"}) + "\n",
                encoding="utf-8",
            )
            _lane_guarded(run_dir, "pass1-L1-auth-UNIT-001", lambda: None)
            rows = [
                json.loads(line)
                for line in (receipts / "LIVENESS.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertEqual("lane-relaunched", rows[-1]["event"])


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
