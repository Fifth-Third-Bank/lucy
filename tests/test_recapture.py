"""Recapture laps: below-bar run is refused, recapture lifts it to CERTIFIED."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import os
import tempfile
import unittest
from unittest.mock import patch

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lucy.runtime.artifacts import finalize, merge_candidates  # noqa: E402
from lucy.runtime.recapture import restore_courts, run_recapture, unit_bounds  # noqa: E402
from lucy.runtime.seal import generate_certification  # noqa: E402
from lucy.runtime.trial import (  # noqa: E402
    prepare_fixture_trial,
    resume_trial,
    score_recall,
    write_trial_verdict,
)
from lucy.runtime.units import write_units  # noqa: E402

POLYGLOT = ROOT / "tests" / "fixtures" / "polyglot"

SERIOUS_PATHS = [
    "apps/notify-svc/main.go",
    "apps/notify-svc/auth.go",
    "apps/portal-bff/Program.cs",
    "apps/ledger-api/src/main/java/com/example/ledger/web/LedgerController.java",
    "infra/iam.tf",
]


def serious_row(path: str) -> dict:
    return {
        "path": path,
        "line": 5,
        "lens": "L1-auth",
        "category": "missing-authorization",
        "severity": "HIGH",
        "title": f"An access-control weakness claim at {path}.",
        "evidence": "kind-only evidence",
        "reach_basis": f"{path}:5",
    }


class RecaptureTests(unittest.TestCase):
    def test_restored_court_preserves_original_proposed_severity(self) -> None:
        from lucy.runtime.orchestrator import court_needs_dispatch

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            candidate = {
                "id": "LUCY-1",
                "severity": "HIGH",
            }
            finding = {
                "id": "LUCY-1",
                "status": "verified",
                # The first court lowered the proposal from HIGH to MEDIUM.
                "severity": "MEDIUM",
            }
            (run_dir / "candidates.jsonl").write_text(
                json.dumps(candidate) + "\n", encoding="utf-8"
            )
            (run_dir / "findings.jsonl").write_text(
                json.dumps(finding) + "\n", encoding="utf-8"
            )

            restore_courts(run_dir)

            verdict_file = run_dir / "staging" / "courts" / "LUCY-1.json"
            verdict = json.loads(verdict_file.read_text(encoding="utf-8"))
            self.assertEqual("HIGH", verdict["proposed_severity"])
            self.assertFalse(
                court_needs_dispatch(
                    {"id": "LUCY-1", "severity": "HIGH"}, verdict_file
                )
            )
            self.assertTrue(
                court_needs_dispatch(
                    {"id": "LUCY-1", "severity": "CRITICAL"}, verdict_file
                )
            )

    def test_below_bar_run_recaptures_to_certified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            original_custody = os.environ.get("LUCY_CUSTODY_HOME")

            def restore_custody_home() -> None:
                if original_custody is None:
                    os.environ.pop("LUCY_CUSTODY_HOME", None)
                else:
                    os.environ["LUCY_CUSTODY_HOME"] = original_custody

            self.addCleanup(restore_custody_home)
            os.environ["LUCY_CUSTODY_HOME"] = str(Path(tmp) / "custody-home")
            results = Path(tmp) / "results"
            trial = prepare_fixture_trial(
                POLYGLOT, results, custody_root=Path(tmp) / "custody"
            )
            workspace = Path(trial["workspace"])
            run_dir = Path(trial["run_directory"])
            custody = Path(trial["_custody"])
            staging = run_dir / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            write_units(workspace, run_dir)
            answer = json.loads(
                (custody.parent / "ANSWER_KEY.json").read_text(encoding="utf-8")
            )

            # Pass 1: canaries (MEDIUM, recall fodder) + serious rows A,B,C.
            canary_rows = [
                json.dumps(
                    {
                        "path": canary["path"],
                        "line": canary["line"],
                        "lens": canary["family"],
                        "category": "recall-fodder " + canary["family"],
                        "severity": "MEDIUM",
                        "title": f"Observed: {canary['title']}",
                        "evidence": "kind-only",
                        "reach_basis": f"{canary['path']}:{canary['line']}",
                    }
                )
                for canary in answer["canaries"]
            ]
            pass1 = canary_rows + [json.dumps(serious_row(p)) for p in SERIOUS_PATHS[:3]]
            # Pass 2: serious rows C,D,E — low overlap => Chapman bound < 0.95.
            pass2 = [json.dumps(serious_row(p)) for p in SERIOUS_PATHS[2:]]
            (staging / "lane-pass1-L1-auth.jsonl").write_text(
                "\n".join(pass1) + "\n", encoding="utf-8"
            )
            (staging / "lane-pass2-L1-auth.jsonl").write_text(
                "\n".join(pass2) + "\n", encoding="utf-8"
            )
            candidates = merge_candidates(run_dir, workspace, results)
            court_dir = staging / "courts"
            court_dir.mkdir()
            for candidate in candidates:
                if candidate["severity"] != "HIGH":
                    continue
                (court_dir / f"{candidate['id']}.json").write_text(
                    json.dumps(
                        {
                            "candidate_id": candidate["id"],
                            "verdict": "VERIFIED",
                            "severity": "HIGH",
                            "cwe": "CWE-862",
                            "disproof_attempt": "Disproof failed on bytes.",
                            "basis": "static-reasoned",
                            "reach_basis": candidate["reach_basis"],
                            "fix": "Restore the missing control at the cited locus and add a test.",
                        }
                    ),
                    encoding="utf-8",
                )
            (run_dir / "COMPLETION.md").write_text(
                "# COMPLETION\nRECALL: EXTERNAL-PENDING\n", encoding="utf-8"
            )
            finalize(run_dir, workspace, results)
            recall = score_recall(run_dir, custody, workspace, results)
            self.assertEqual(recall["found"], 8)
            verdict = write_trial_verdict(run_dir, workspace, POLYGLOT, results, recall)
            self.assertEqual(verdict["status"], "PASS")

            # Below-bar: certification must refuse honestly.
            refused = generate_certification(
                run_dir, workspace, results, trial["run_id"], trial["started_at"]
            )
            self.assertFalse(refused["certified"])
            self.assertLess(min(unit_bounds(run_dir).values()), 0.95)

            # Recapture host: readers re-observe the full serious set (high
            # overlap), courts never needed (no new serious).
            class RecaptureHost:
                def run_agent(self, *, system, task, workspace, allow_edit=False, max_turns=60):
                    if task.startswith("LUCY READER") and "LENS=L1-auth" in task:
                        return "\n".join(json.dumps(serious_row(p)) for p in SERIOUS_PATHS)
                    if task.startswith("LUCY READER"):
                        return ""
                    raise AssertionError(f"unexpected task: {task[:40]}")

            receipt = run_recapture(RecaptureHost(), run_dir, workspace, results)
            self.assertTrue(receipt["closed"], receipt)
            self.assertGreaterEqual(min(receipt["final_bounds"].values()), 0.95)
            self.assertTrue((run_dir / "receipts" / "RECAPTURE.json").is_file())

            # Resume may clean-court unmatched candidates in planter-modified
            # files. Keep this pipeline test hermetic instead of invoking a
            # locally authenticated model host.
            class DispositionHost:
                def run_agent(self, *, task, **_kwargs):
                    candidate_id = next(
                        line.removeprefix("CANDIDATE_ID=")
                        for line in task.splitlines()
                        if line.startswith("CANDIDATE_ID=")
                    )
                    return json.dumps(
                        {
                            "candidate_id": candidate_id,
                            "clean_verdict": "PRESENT",
                            "basis": "scripted clean-target verdict for this test",
                        }
                    )

            from unittest.mock import patch

            # Host availability is a separate preflight contract; this
            # deterministic pipeline test must pass with either provider,
            # both, or neither installed.
            with (
                patch("lucy.runtime.trial.require_host_tools"),
                patch(
                    "lucy.runtime.host.ClaudeAgentHost",
                    return_value=DispositionHost(),
                ),
            ):
                code, verdict = resume_trial(results, trial["run_id"], certify=True)
            certification = verdict["certification"]
            self.assertTrue(certification["certified"], certification)
            self.assertRegex(
                certification["final_line"],
                r"^REVIEW-COMPLETE r-[0-9a-f]{12} [0-9a-f]{16} CERTIFIED$",
            )


if __name__ == "__main__":
    unittest.main()


class LaneDeathReconciliationTests(unittest.TestCase):
    """Orphan lane-dead receipts (command killed mid-retry) are reconciled
    only against evidence that the work was redone: a live superseding lane
    file, or a prior command's launcher-written lap record. This prevents
    stale death receipts from blocking C5 after evidenced recovery."""

    def test_reconciles_with_receipt_evidence_and_is_idempotent(self) -> None:
        import json
        import tempfile

        from lucy.runtime.recapture import reconcile_orphan_lane_deaths

        with tempfile.TemporaryDirectory() as tmp:
            run = Path(tmp)
            (run / "receipts").mkdir()
            (run / "staging").mkdir()
            (run / "receipts" / "LIVENESS.jsonl").write_text(
                json.dumps({"event": "lane-dead", "lane": "recap-pass9-L2-secrets-UNIT-001", "error": "budget"}) + "\n"
                + json.dumps({"event": "lane-dead", "lane": "recap-pass9-L1-auth-UNIT-002", "error": "budget"}) + "\n",
                encoding="utf-8",
            )
            (run / "receipts" / "RECAPTURE.json").write_text(
                json.dumps({"laps": [{"pass": 10, "units": ["UNIT-001"]}]}), encoding="utf-8"
            )
            self.assertEqual(1, reconcile_orphan_lane_deaths(run))
            self.assertEqual(0, reconcile_orphan_lane_deaths(run))
            rows = [
                json.loads(line)
                for line in (run / "receipts" / "LIVENESS.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            relaunched = [row for row in rows if row["event"] == "lane-relaunched"]
            self.assertEqual(1, len(relaunched))
            self.assertIn("reconciled", relaunched[0]["basis"])
            # UNIT-002 orphan has no evidence and must stay open.
            self.assertEqual(
                2, sum(1 for row in rows if row["event"] == "lane-dead")
            )
