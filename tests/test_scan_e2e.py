"""End-to-end scan pipeline test on the polyglot fixture.

Exercises prepare (fixture planter) -> simulated reader lanes -> merge ->
simulated courts -> finalize -> external recall scoring -> process verdict ->
report/seal/certification generation, with the REAL pinned gates arbitrating.
Only the Claude reviewer/planter processes are simulated; every deterministic
component runs for real.
"""

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
from lucy.runtime.seal import generate_certification  # noqa: E402
from lucy.runtime.trial import (  # noqa: E402
    assess_process_complete,
    prepare_fixture_trial,
    resume_trial,
    score_recall,
    write_trial_verdict,
)
from lucy.runtime.units import write_units  # noqa: E402

POLYGLOT = ROOT / "tests" / "fixtures" / "polyglot"

LENS_FOR_FAMILY = {
    "L1-auth": "L1-auth",
    "L2-secrets": "L2-secrets",
    "L3-injection": "L3-injection",
    "L4-infra": "L4-infra",
}
CATEGORY_FOR_FAMILY = {
    "L1-auth": "missing-authorization",
    "L2-secrets": "weakened-signature-validation",
    "L3-injection": "sql-injection",
    "L4-infra": "public-exposure",
}


class ScanEndToEndTests(unittest.TestCase):
    def setUp(self) -> None:
        self._original_custody_home = os.environ.get("LUCY_CUSTODY_HOME")

    def tearDown(self) -> None:
        if self._original_custody_home is None:
            os.environ.pop("LUCY_CUSTODY_HOME", None)
        else:
            os.environ["LUCY_CUSTODY_HOME"] = self._original_custody_home

    def test_full_pipeline_reaches_certified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
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

            # Simulated readers: every canary reported at its locus (with a
            # small line offset, as real readers do), plus one true-negative
            # LOW row and one serious row the court will refute.
            lane_rows = []
            for canary in answer["canaries"]:
                lane_rows.append(
                    {
                        "path": canary["path"],
                        "line": max(1, canary["line"] - 2),
                        "lens": LENS_FOR_FAMILY[canary["family"]],
                        "category": CATEGORY_FOR_FAMILY[canary["family"]],
                        "severity": "HIGH",
                        "title": f"Reader-observed defect matching: {canary['title']}",
                        "evidence": "kind-only evidence from workspace bytes",
                        "reach_basis": f"{canary['path']}:{canary['line']}",
                    }
                )
            lane_rows.append(
                {
                    "path": "deploy/Dockerfile",
                    "line": 10,
                    "lens": "L4-infra",
                    "category": "image-pinning",
                    "severity": "LOW",
                    "title": "Base image tag is pinned but not digest-pinned in the deploy Dockerfile.",
                    "evidence": "kind-only evidence",
                    "reach_basis": "deploy/Dockerfile:10",
                }
            )
            lane_rows.append(
                {
                    "path": "infra/iam.tf",
                    "line": 5,
                    "lens": "L4-infra",
                    "category": "iam-wildcard",
                    "severity": "HIGH",
                    "title": "A claimed IAM wildcard that the court will disprove on bytes.",
                    "evidence": "kind-only evidence",
                    "reach_basis": "infra/iam.tf:5",
                }
            )
            for pass_number in (1, 2, 3):
                for lens in ("L1-auth", "L2-secrets", "L3-injection", "L4-infra"):
                    rows = [row for row in lane_rows if row["lens"] == lens]
                    (staging / f"lane-pass{pass_number}-{lens}.jsonl").write_text(
                        "".join(json.dumps(row) + "\n" for row in rows),
                        encoding="utf-8",
                    )
            candidates = merge_candidates(run_dir, workspace, results)
            self.assertEqual(len(candidates), len(lane_rows))

            # Simulated courts: verify every serious row except the IAM claim.
            court_rows = []
            for candidate in candidates:
                if candidate["severity"] != "HIGH":
                    continue
                refute = candidate["path"] == "infra/iam.tf"
                court_rows.append(
                    {
                        "candidate_id": candidate["id"],
                        "verdict": "REFUTED" if refute else "VERIFIED",
                        "severity": "LOW" if refute else "HIGH",
                        "cwe": "CWE-732" if refute else "CWE-862",
                        "disproof_attempt": "IAM statements are scoped; claim does not hold."
                        if refute
                        else "Disproof failed; weakened control confirmed on bytes.",
                        "basis": "static-reasoned",
                        "reach_basis": candidate["reach_basis"],
                        "fix": "No code change required; the cited policy is already scoped."
                        if refute
                        else "Restore the removed control at the cited locus and add a regression test.",
                    }
                )
            (staging / "courts.jsonl").write_text(
                "".join(json.dumps(row) + "\n" for row in court_rows), encoding="utf-8"
            )
            # Orchestrator-proposed chains: one valid (two verified hops), one
            # touching the refuted row (must be dropped with a receipt).
            verified_ids = [
                row["candidate_id"] for row in court_rows if row["verdict"] == "VERIFIED"
            ][:2]
            refuted_id = next(
                row["candidate_id"] for row in court_rows if row["verdict"] == "REFUTED"
            )
            (staging / "chains.jsonl").write_text(
                json.dumps(
                    {
                        "id": "CHAIN-01",
                        "title": "Forged token reaches an unauthorized data read across services.",
                        "hops": verified_ids,
                    }
                )
                + "\n"
                + json.dumps(
                    {
                        "id": "CHAIN-02",
                        "title": "Chain through a refuted hop must be dropped.",
                        "hops": [verified_ids[0], refuted_id],
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            (run_dir / "COMPLETION.md").write_text(
                "# COMPLETION\nRECALL: EXTERNAL-PENDING\n", encoding="utf-8"
            )

            findings = finalize(run_dir, workspace, results)
            statuses = {row["status"] for row in findings}
            self.assertIn("refuted", statuses)
            self.assertFalse((run_dir / "staging").exists())
            self.assertTrue((run_dir / "receipts" / "CONSERVATION.json").is_file())
            self.assertTrue((run_dir / "receipts" / "PASS_HISTORY.json").is_file())

            recall = score_recall(run_dir, custody, workspace, results)
            self.assertEqual(recall["found"], 8)
            self.assertEqual(recall["status"], "PASS")

            verdict = write_trial_verdict(run_dir, workspace, POLYGLOT, results, recall)
            self.assertEqual(verdict["status"], "PASS")

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
            self.assertRegex(outcome["final_line"], r"^REVIEW-COMPLETE r-[0-9a-f]{12} [0-9a-f]{16} CERTIFIED$")
            self.assertTrue(Path(outcome["delivery_zip"]).is_file())
            report = json.loads(
                (run_dir / outcome["report"]).read_text(encoding="utf-8")
            )
            self.assertEqual(
                report["declared_counts"]["total"], len(report["findings"])
            )
            self.assertNotIn(
                "infra/iam.tf:5",
                {row["path"] for row in report["findings"]},
                "refuted rows must never enter the gated report",
            )
            self.assertEqual(report["declared_counts"]["chains"], 1)
            self.assertEqual(report["chains"][0]["id"], "CHAIN-01")
            self.assertEqual(report["chains"][0]["status"], "confirmed")
            self.assertTrue(
                (run_dir / "receipts" / "CHAINS_DROPPED.json").is_file(),
                "chain through a refuted hop must be dropped WITH a receipt",
            )

            # Resume after completion: no reviewer relaunch, but this test
            # called the gate directly and therefore deliberately retained
            # custody for rescoring. Simulate any clean-copy disposition
            # court; deterministic tests never depend on provider installs,
            # logins, or spend.
            def disposition_response(
                _host, *, system, task, workspace, allow_edit=False, max_turns=60
            ):
                del system, workspace, allow_edit, max_turns
                candidate_id = task.split("CANDIDATE_ID=", 1)[1].splitlines()[0]
                return json.dumps(
                    {
                        "candidate_id": candidate_id,
                        "clean_verdict": "PRESENT",
                        "basis": "fixture host confirmed the claim on clean bytes",
                    }
                )

            with (
                patch("lucy.runtime.trial.require_host_tools"),
                patch(
                    "lucy.runtime.host.ClaudeAgentHost.run_agent",
                    autospec=True,
                    side_effect=disposition_response,
                ),
            ):
                code, resumed = resume_trial(results, trial["run_id"], certify=False)
            self.assertEqual(code, 0)
            self.assertEqual(resumed["status"], "PASS")

    def test_priors_staged_run_reaches_certified_with_c4_active(self) -> None:
        priors_targets = [
            {
                "id": "HIST-001",
                "path": "apps/admin-ui/middleware.ts",
                "line": 10,
                "family": "L1-auth",
                "title": "JWT verification historically skipped issuer pinning.",
            },
            {
                "id": "HIST-002",
                "path": "infra/api_gateway.tf",
                "line": 30,
                "family": "L4-infra",
                "title": "A route historically shipped with authorization NONE.",
            },
            {
                "id": "HIST-003",
                "path": "apps/batch-worker/lib/settlement_service.rb",
                "line": 40,
                "family": "L3-injection",
                "title": "Batch job lookup historically interpolated identifiers into SQL.",
            },
            {
                "id": "HIST-004",
                "path": "shared/crypto-lib/src/cryptolib/aead.py",
                "line": 60,
                "family": "L2-secrets",
                "title": "AEAD historically reused nonces under one key.",
            },
            {
                "id": "HIST-005",
                "path": "no/such/file.py",
                "line": 1,
                "family": "L1-auth",
                "title": "A historical claim whose locus no longer exists anywhere.",
            },
        ]
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LUCY_CUSTODY_HOME"] = str(Path(tmp) / "custody-home")
            results = Path(tmp) / "results"
            priors_file = Path(tmp) / "priors.json"
            priors_file.write_text(
                json.dumps({"schema": "lucy-priors/oss-1", "targets": priors_targets}),
                encoding="utf-8",
            )
            from lucy.runtime.trial import prepare_trial

            trial = prepare_trial(
                POLYGLOT,
                results,
                custody_root=Path(tmp) / "custody",
                planter="fixture",
                priors_path=priors_file,
            )
            workspace = Path(trial["workspace"])
            run_dir = Path(trial["run_directory"])
            custody = Path(trial["_custody"])
            answer = json.loads(
                (custody.parent / "ANSWER_KEY.json").read_text(encoding="utf-8")
            )
            self.assertEqual(len(answer["canaries"]), 12)
            self.assertEqual(
                sum(1 for row in answer["canaries"] if row.get("historical")), 4
            )
            commitment = json.loads(
                (run_dir / "receipts" / "MINT_COMMITMENT.json").read_text(encoding="utf-8")
            )
            self.assertEqual(commitment["historical_canaries"], 4)
            self.assertEqual(commitment["plant_count"], 8)

            staging = run_dir / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            write_units(workspace, run_dir)
            # Simulated readers find every canary (planted AND historical).
            lane_rows = []
            for canary in answer["canaries"]:
                lane_rows.append(
                    {
                        "path": canary["path"],
                        "line": max(1, canary["line"] - 1),
                        "lens": canary["family"],
                        "category": CATEGORY_FOR_FAMILY[canary["family"]],
                        "severity": "HIGH",
                        "title": f"Reader-observed defect matching: {canary['title']}",
                        "evidence": "kind-only evidence",
                        "reach_basis": f"{canary['path']}:{canary['line']}",
                    }
                )
            for pass_number in (1, 2, 3):
                for lens in ("L1-auth", "L2-secrets", "L3-injection", "L4-infra"):
                    rows = [row for row in lane_rows if row["lens"] == lens]
                    (staging / f"lane-pass{pass_number}-{lens}.jsonl").write_text(
                        "".join(json.dumps(row) + "\n" for row in rows), encoding="utf-8"
                    )
            candidates = merge_candidates(run_dir, workspace, results)
            court_dir = staging / "courts"
            court_dir.mkdir()
            for candidate in candidates:
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
                            "fix": "Restore the weakened control at the cited locus and add a regression test.",
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
            self.assertEqual(recall["historical_found"], 4)
            verdict = write_trial_verdict(run_dir, workspace, POLYGLOT, results, recall)
            self.assertEqual(verdict["status"], "PASS")
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
            disposition = json.loads(
                (run_dir / "receipts" / "PRIORS_DISPOSITION.json").read_text(encoding="utf-8")
            )
            self.assertEqual(disposition["staged"], 5)
            self.assertEqual(disposition["refound"] + disposition["not_evidenced"], 5)
            cert_receipt = json.loads(
                (run_dir / "receipts" / "CERT_RECEIPT.json").read_text(encoding="utf-8")
            )
            self.assertEqual(cert_receipt["priors_staged"], 5)
            self.assertEqual(cert_receipt["canary_historical"], 4)
            card = (run_dir / "SEAL_CARD.md").read_text(encoding="utf-8")
            self.assertIn("CANARY-MIX: 4P+4H", card)
            self.assertIn("PRIORS: 5 loaded 5 refound-or-adjudicated", card)

    def test_finalize_refuses_uncourted_serious_rows(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            os.environ["LUCY_CUSTODY_HOME"] = str(Path(tmp) / "custody-home")
            results = Path(tmp) / "results"
            trial = prepare_fixture_trial(
                POLYGLOT, results, custody_root=Path(tmp) / "custody"
            )
            workspace = Path(trial["workspace"])
            run_dir = Path(trial["run_directory"])
            staging = run_dir / "staging"
            staging.mkdir(parents=True, exist_ok=True)
            (staging / "lane-pass1-L1-auth.jsonl").write_text(
                json.dumps(
                    {
                        "path": "apps/admin-ui/middleware.ts",
                        "line": 5,
                        "lens": "L1-auth",
                        "category": "missing-authorization",
                        "severity": "HIGH",
                        "title": "Serious row with no court verdict.",
                        "evidence": "kind-only",
                        "reach_basis": "apps/admin-ui/middleware.ts:5",
                    }
                )
                + "\n",
                encoding="utf-8",
            )
            merge_candidates(run_dir, workspace, results)
            with self.assertRaisesRegex(ValueError, "without a court verdict"):
                finalize(run_dir, workspace, results)


if __name__ == "__main__":
    unittest.main()
