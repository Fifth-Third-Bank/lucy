"""Tests for the measurement-channel calibration layer.

The collision fixture places two L3-injection plants four lines apart in
one file. Locus folding must not let one candidate satisfy two recall slots;
the preflight checks reject that mechanically unwinnable shape before a
model is dispatched.
"""

from __future__ import annotations

import json
import os
import signal
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch
from pathlib import Path

from lucy.runtime.planter import (
    check_placement_law,
    classify_plantable,
    plant_feasibility,
)
from lucy.runtime.preflight import oracle_replay, synthetic_rows


def _canary(slot, family, path, line):
    return {
        "slot": slot,
        "family": family,
        "path": path,
        "line": line,
        "title": f"plant {slot}",
        "reachability": "exercised by the app request path",
    }


def _key(rows):
    return {"schema": "lucy-answer-key/v1", "canaries": rows}


def _spread_key():
    return _key(
        [
            _canary(1, "L1-auth", "a/auth.java", 50),
            _canary(2, "L1-auth", "b/filter.java", 10),
            _canary(3, "L2-secrets", "c/app.yml", 100),
            _canary(4, "L2-secrets", "d/cfg.yml", 5),
            _canary(5, "L3-injection", "e/backup.py", 40),
            _canary(6, "L3-injection", "f/restore.py", 44),
            _canary(7, "L4-infra", "g/main.tf", 50),
            _canary(8, "L4-infra", "h/Dockerfile", 24),
        ]
    )


def _collision_key():
    """A synthetic collision: twin L3 plants four lines apart."""
    key = _spread_key()
    key["canaries"][5] = _canary(6, "L3-injection", "e/backup.py", 44)
    return key


class PlacementLawTests(unittest.TestCase):
    def test_same_family_same_file_rejected(self):
        with self.assertRaises(ValueError) as caught:
            check_placement_law(_collision_key()["canaries"])
        self.assertIn("placement law", str(caught.exception))
        self.assertIn("L3-injection", str(caught.exception))

    def test_spread_key_accepted(self):
        check_placement_law(_spread_key()["canaries"])

    def test_historical_rows_exempt(self):
        rows = _spread_key()["canaries"] + [
            {**_canary(9, "L1-auth", "a/auth.java", 200), "historical": True}
        ]
        check_placement_law(rows)

    def test_wired_into_validator(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "planter.py"
        ).read_text(encoding="utf-8")
        self.assertIn("check_placement_law(canaries)", source)
        # And the planter is TOLD the law (machine-enforced rules must be
        # spelled out in the prompt, per the forbidden-paths precedent).
        self.assertIn("placement_clause()", source)
        self.assertIn("DIFFERENT FILES", source)


class FeasibilityCensusTests(unittest.TestCase):
    def test_classification(self):
        # Input paths are reader-eligible by contract (they come from the
        # units census), so anything that is not config/IaC is code —
        # including extensionless shebang scripts. A suffix allowlist would
        # be narrower than the reader universe.
        self.assertIn("source", classify_plantable("app/src/Main.java"))
        self.assertIn("source", classify_plantable("bin/rotate-keys"))
        self.assertIn("config", classify_plantable("app/src/application.yml"))
        self.assertIn("iac", classify_plantable("infra/main.tf"))
        self.assertIn("iac", classify_plantable("svc/Dockerfile"))
        self.assertEqual(classify_plantable("tests/exploit.java"), set())

    def test_infeasible_when_a_family_lacks_two_files(self):
        report = plant_feasibility({"app/Main.java", "app/Other.java"})
        self.assertFalse(report["feasible"])
        self.assertIn("L4-infra", report["infeasible_families"])

    def test_feasible_estate(self):
        paths = {
            "a/Main.java", "b/Auth.java", "c/app.yml", "d/cfg.yml",
            "e/main.tf", "f/Dockerfile",
        }
        report = plant_feasibility(paths)
        self.assertTrue(report["feasible"])
        self.assertEqual(report["infeasible_families"], [])

    def test_census_runs_before_planter_spends(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn("plant_feasibility(baseline_reader_paths)", source)
        self.assertLess(
            source.index("plant_feasibility(baseline_reader_paths)"),
            source.index("answer_key = _plant_with_retries("),
        )

    def test_census_is_advisory_never_refuses(self):
        # The placement law is class-blind; the census predicts, so a
        # bucketing gap must never hard-stop a legitimate estate.
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        census_block = source.split("plant_feasibility(baseline_reader_paths)")[1]
        census_block = census_block.split("_plant_with_retries(")[0]
        self.assertNotIn("raise", census_block)
        self.assertIn("WARNING: plant feasibility census", census_block)


class OracleReplayTests(unittest.TestCase):
    def test_collision_key_fails_replay(self):
        report = oracle_replay(_collision_key())
        self.assertFalse(report["passed"])
        self.assertEqual(report["matched"], 7)
        self.assertEqual(report["missed_slots"], [6])

    def test_spread_key_passes_all_jitters(self):
        report = oracle_replay(_spread_key())
        self.assertTrue(report["passed"])
        self.assertEqual(report["matched"], 8)

    def test_historical_canaries_excluded(self):
        key = _spread_key()
        key["canaries"].append(
            {**_canary(9, "L1-auth", "z/legacy.java", 10), "historical": True}
        )
        self.assertEqual(len(synthetic_rows(key)), 8)
        self.assertTrue(oracle_replay(key)["passed"])

    def test_replay_uses_production_fold(self):
        # The replay must exercise the identical fold the live run uses —
        # a copied law would drift.
        preflight = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "preflight.py"
        ).read_text(encoding="utf-8")
        artifacts = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "artifacts.py"
        ).read_text(encoding="utf-8")
        self.assertIn("from lucy.runtime.artifacts import fold_rows", preflight)
        self.assertIn("from lucy.runtime.trial import match_canaries", preflight)
        self.assertIn("fold_candidate(by_key, fold_map, candidate)", artifacts)

    def test_prepare_trial_gates_on_replay(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_replay_or_raise(answer_key)", source)
        self.assertIn("PLANT_ATTEMPTS = 3", source)
        # Rejection resets the workspace so a failed plant never leaks
        # into the next key.
        self.assertIn('["git", "checkout", "-q", "--", "."]', source)
        self.assertIn('["git", "clean", "-qfd"]', source)
        self.assertIn("retry_hint=", source)


class ShadowDiagnosisTests(unittest.TestCase):
    def _finding(self, path, line, lens, fid="LUCY-aaaa"):
        return {
            "id": fid,
            "path": path,
            "line": line,
            "lens": lens,
            "category": "command-injection",
            "severity": "HIGH",
            "title": "shell injection",
        }

    def test_fold_shadow_detected_on_collision_shape(self):
        from lucy.runtime.trial import diagnose_recall_shadow

        findings = [self._finding("e/backup.py", 40, "L3-injection")]
        rows = diagnose_recall_shadow(_collision_key(), findings)
        row6 = next(row for row in rows if row["slot"] == 6)
        self.assertEqual(row6["mechanism"], "fold-shadow")
        self.assertEqual(row6["shadowed_by_slot"], 5)
        # Slot 5 claimed the lone folded candidate, so it is NOT missed.
        self.assertNotIn(5, [row["slot"] for row in rows])

    def test_claim_shadow_detected(self):
        from lucy.runtime.trial import diagnose_recall_shadow

        # Twin plants 30 apart (outside fold radius, inside match window):
        # one candidate claimed by the first slot starves the second.
        key = _spread_key()
        key["canaries"][5] = _canary(6, "L3-injection", "e/backup.py", 70)
        findings = [self._finding("e/backup.py", 42, "L3-injection")]
        rows = diagnose_recall_shadow(key, findings)
        row6 = next(row for row in rows if row["slot"] == 6)
        self.assertEqual(row6["mechanism"], "claim-shadow")

    def test_cold_miss(self):
        from lucy.runtime.trial import diagnose_recall_shadow

        findings = [self._finding("e/backup.py", 40, "L3-injection")]
        key = _spread_key()  # slot 6 lives in f/restore.py — nothing there
        rows = diagnose_recall_shadow(key, findings)
        row6 = next(row for row in rows if row["slot"] == 6)
        self.assertEqual(row6["mechanism"], "cold-miss")

    def test_ladder_skips_hopeless_laps_unless_operator_forces(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "recapture.py"
        ).read_text(encoding="utf-8")
        self.assertIn("operator_budget: bool = False", source)
        self.assertIn("diagnose_recall_shadow", source)
        self.assertIn('"recall_shadow": recall_shadow', source)
        self.assertIn(
            'all(row["mechanism"] == "fold-shadow" for row in recall_shadow)',
            source,
        )
        trial_source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn(
            "operator_budget=args.cure_lap_budget is not None", trial_source
        )

    def test_ending_never_advises_laps_for_fold_shadow(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "seal.py"
        ).read_text(encoding="utf-8")
        self.assertIn("recall_shadow", source)
        self.assertIn("structurally fold-shadowed", source)
        shadow_branch = source.split("structurally fold-shadowed")[1].split(
            "elif recall_short:"
        )[0]
        self.assertNotIn("--cure-lap-budget", shadow_branch)
        self.assertIn("--mint-error-slot", shadow_branch)
        # Both dead-end endings must point at the evidence tool before the
        # attestation flag (operator question: "is the adjudicator command
        # recommended on canary failures?" — it must be).
        self.assertIn("adjudicate_cmd", shadow_branch)
        exhausted_branch = source.split("blind cure budget exhausted")[1].split(
            'advice = "the recall self-test needs curing'
        )[0]
        self.assertIn("adjudicate_cmd", exhausted_branch)
        normal_branch = source.split(
            'advice = "the recall self-test needs curing'
        )[1].split("else:")[0]
        self.assertIn("adjudicate_cmd", normal_branch)


class LocusDriftTests(unittest.TestCase):
    def test_score_recall_rehashes_every_locus(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn("locus_drift_slots", source)
        self.assertIn('"locus_drift_slots": sorted(locus_drift_slots)', source)
        self.assertIn('canary.get("mutation_sha256")', source)

    def test_blocking_drift_invalidates_recall_status(self):
        # Recording invalid measurement bytes must never coexist with a
        # certificate. Mint-error-attested slots are exempt: the
        # attestation already excludes that slot's measurement.
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn('status = "INVALID"', source)
        self.assertIn("if blocking_drift:", source)
        self.assertIn('"locus_drift_blocking": sorted(blocking_drift)', source)
        block = source.split("blocking_drift = [")[1].split("if blocking_drift:")[0]
        self.assertIn('row.get("mint_error")', block)
        # INVALID (not FAIL) so the cure ladder never spends laps against
        # a corrupted workspace (recall_cure_needed checks == "FAIL").
        recapture_source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "recapture.py"
        ).read_text(encoding="utf-8")
        self.assertIn('recall.get("status") == "FAIL"', recapture_source)
        seal_source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "seal.py"
        ).read_text(encoding="utf-8")
        self.assertIn("locus_drift_blocking", seal_source)
        self.assertIn("recall measurement INVALID", seal_source)


class AdjudicateTests(unittest.TestCase):
    def _run_dir(self, base):
        run_dir = base / "runs" / "r-test"
        (run_dir / "receipts").mkdir(parents=True)
        return run_dir

    def test_brief_contains_diff_and_receipts(self):
        from lucy.runtime.adjudicate import build_brief

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            target = base / "target"
            workspace = base / "workspace"
            (target / "app").mkdir(parents=True)
            (workspace / "app").mkdir(parents=True)
            (target / "app" / "x.py").write_text("safe()\n", encoding="utf-8")
            (workspace / "app" / "x.py").write_text(
                "unsafe(shell=True)\n", encoding="utf-8"
            )
            run_dir = self._run_dir(base)
            (run_dir / "receipts" / "RECALL_RECEIPT.json").write_text(
                json.dumps({"status": "FAIL", "found": 7, "slots": []}),
                encoding="utf-8",
            )
            brief = build_brief(run_dir, target, workspace)
            self.assertIn("unsafe(shell=True)", brief)
            self.assertIn('"status": "FAIL"', brief)
            self.assertIn("Structural shadow diagnosis", brief)
            # Exact command context so verdicts end in copy-pasteable
            # commands (run id + results root, mint-error form included).
            self.assertIn("lucy recapture --run r-test", brief)
            self.assertIn("--mint-error-slot", brief)

    def test_post_verdict_only(self):
        from lucy.runtime.adjudicate import run_adjudication

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            run_dir = self._run_dir(base)
            with self.assertRaises(ValueError) as caught:
                run_adjudication(run_dir, base, base, host=None)
            self.assertIn("post-verdict only", str(caught.exception))
            (run_dir / "CERTIFICATION.json").write_text("{}", encoding="utf-8")
            (run_dir / "staging").mkdir()
            with self.assertRaises(ValueError) as caught:
                run_adjudication(run_dir, base, base, host=None)
            self.assertIn("staging", str(caught.exception))

    def test_preamble_chatter_stripped_from_verdict(self):
        from lucy.runtime.adjudicate import _verdict_text

        self.assertEqual(
            _verdict_text("All evidence is in. Composing now.\n\n# ADJUDICATION.md\n\n## Verdict\nFAIR MISS"),
            "# ADJUDICATION.md\n\n## Verdict\nFAIR MISS\n",
        )
        self.assertEqual(_verdict_text("# Clean\nbody"), "# Clean\nbody\n")
        self.assertEqual(_verdict_text("no heading at all"), "no heading at all\n")

    def test_refuses_moved_on_target(self):
        from lucy.runtime.adjudicate import run_adjudication

        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            run_dir = self._run_dir(base)
            (run_dir / "CERTIFICATION.json").write_text("{}", encoding="utf-8")
            (run_dir / "trial.json").write_text(
                json.dumps({"baseline_sha256": "0" * 64}), encoding="utf-8"
            )
            target = base / "target"
            target.mkdir()
            (target / "a.py").write_text("changed()\n", encoding="utf-8")
            with self.assertRaises(ValueError) as caught:
                run_adjudication(run_dir, target, base, host=None)
            self.assertIn("changed since the scan", str(caught.exception))

    def test_artifacts_go_through_redacting_sink(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "adjudicate.py"
        ).read_text(encoding="utf-8")
        self.assertIn("LocalResultsSink", source)
        self.assertNotIn("brief_path.write_text", source)
        self.assertNotIn("verdict_path.write_text", source)

    def test_advisory_never_attests(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "adjudicate.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn("_attest_mint_error", source)
        self.assertIn("ADVISORY ONLY", source)
        # The rubric is asymmetric on purpose.
        self.assertIn("When uncertain, the verdict is FAIR MISS", source)
        trial_source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"adjudicate"', trial_source)
        self.assertIn("advisory only", trial_source)


class CrashSafetyTests(unittest.TestCase):
    def test_sigterm_runs_finally_blocks(self):
        repo_root = str(Path(__file__).parents[1])
        driver = (
            "import os, sys\n"
            f"sys.path.insert(0, {repo_root!r})\n"
            "from lucy.runtime.trial import install_terminate_handler\n"
            "install_terminate_handler()\n"
            "import signal, time\n"
            "flag = sys.argv[1]\n"
            "try:\n"
            "    os.kill(os.getpid(), signal.SIGTERM)\n"
            "    time.sleep(5)\n"
            "finally:\n"
            "    open(flag, 'w').write('PRESERVED')\n"
        )
        with tempfile.TemporaryDirectory() as tmp:
            flag = Path(tmp) / "flag"
            result = subprocess.run(
                [sys.executable, "-c", driver, str(flag)],
                capture_output=True,
                text=True,
                timeout=30,
                check=False,
            )
            self.assertEqual(result.returncode, 128 + signal.SIGTERM)
            self.assertEqual(flag.read_text(), "PRESERVED")

    def test_main_installs_handler_first(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        body = source.split("def main() -> int:")[1]
        self.assertLess(
            body.index("install_terminate_handler()"),
            body.index("parse_args()"),
        )

    def test_orphaned_custody_adopted_on_resume(self):
        from lucy.runtime.trial import _adopt_orphaned_custody

        with tempfile.TemporaryDirectory() as tmp, patch.dict(
            os.environ, {"LUCY_CUSTODY_HOME": tmp}
        ):
            orphan = Path(tmp) / ".lucy-custody-abc123"
            orphan.mkdir()
            (orphan / "custody.json").write_text(
                json.dumps({"run_id": "r-killed"}), encoding="utf-8"
            )
            adopted = _adopt_orphaned_custody("r-killed")
            self.assertIsNotNone(adopted)
            self.assertTrue(
                (Path(tmp) / "runs" / "r-killed" / "custody.json").is_file()
            )
            self.assertFalse(orphan.exists())
            # Idempotent: nothing left to adopt, existing preserved
            # custody is never clobbered.
            self.assertIsNone(_adopt_orphaned_custody("r-killed"))

    def test_resume_wired_to_adoption(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn("_adopt_orphaned_custody(run_id)", source)


class ResumeEpilogueTests(unittest.TestCase):
    """The exact resume command must be the literal last line when a run
    ends unfinished so a later verdict dump cannot obscure it."""

    class _Args:
        results = Path("/tmp/results")
        log = Path("/tmp/scan.log")
        resume = None

    def _capture(self, receipt, run_id=None):
        import contextlib
        import io

        from lucy.runtime.trial import _print_resume_epilogue

        buffer = io.StringIO()
        with contextlib.redirect_stdout(buffer):
            _print_resume_epilogue(receipt, self._Args(), run_id)
        return buffer.getvalue()

    def test_failed_verdict_prints_exact_command_with_log(self):
        out = self._capture(
            {"schema": "lucy-trial-verdict/v1", "run_id": "r-abc", "status": "FAIL"}
        )
        self.assertIn(
            "lucy scan --resume r-abc --results /tmp/results --log /tmp/scan.log",
            out,
        )
        self.assertIn("never re-paid", out)
        self.assertIn("caffeinate", out)

    def test_silent_on_pass_and_on_certification_endings(self):
        self.assertEqual(self._capture({"run_id": "r-abc", "status": "PASS"}), "")
        # A finalized review has the state-aware certification ending;
        # the epilogue must not double-advise.
        self.assertEqual(
            self._capture(
                {"run_id": "r-abc", "status": "FAIL", "certification": {"certified": False}}
            ),
            "",
        )

    def test_explicit_run_id_wins_for_resume_path(self):
        out = self._capture({"status": "FAIL"}, run_id="r-resumed")
        self.assertIn("--resume r-resumed", out)

    def test_verdict_carries_run_id(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "trial.py"
        ).read_text(encoding="utf-8")
        self.assertIn('"run_id": run_directory.resolve().name', source)


class ProgressPassCounterTests(unittest.TestCase):
    def test_pass_number_is_live(self):
        source = (
            Path(__file__).parents[1] / "lucy" / "runtime" / "progress.py"
        ).read_text(encoding="utf-8")
        self.assertNotIn('"pass 1 done, will continue until quiet"', source)
        self.assertIn("pass {current_pass} running", source)
        self.assertIn('re.match(r"lane-pass(\\d+)", lane.name)', source)


if __name__ == "__main__":
    unittest.main()
