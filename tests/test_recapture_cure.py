"""Blind recall-cure lap regression tests."""

from __future__ import annotations

import json
from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class CureSemanticsTests(unittest.TestCase):
    def test_cure_ladder_is_bounded_blind_and_trusts_held_receipt_first(self) -> None:
        source = (ROOT / "lucy" / "runtime" / "recapture.py").read_text(encoding="utf-8")
        # Budget consumed only when a cure lap actually dispatches.
        cure_branch = source.split("if cure_lap_allowed(")[1]
        self.assertIn("cure_laps_used += 1", cure_branch.split("else:")[0])
        # Bounded ladder, cumulative across commands (decision + persistence
        # are extracted functions with their own behavioral tests).
        self.assertIn("CURE_LAP_BUDGET = 3", source)
        # Charge-before-dispatch (review P1): the budget is written to the
        # held receipt fail-closed BEFORE any lane launches.
        self.assertIn("charge_cure_lap(held_dir, cure_laps_prior, cure_laps_used)", source)
        charge_pos = source.find("charge_cure_lap(held_dir")
        dispatch_pos = source.find("cure_laps_used += 1")
        self.assertTrue(0 < charge_pos < dispatch_pos)
        # BLIND: no family- or unit-targeted dispatch anywhere; cure laps
        # cover all units at full width.
        self.assertNotIn("missing family", source)
        self.assertNotIn("family-targeted", source.replace("family-\n", ""))
        self.assertIn("below = sorted(bounds)", source)
        # Launcher-held receipt is consulted before the run-dir copy.
        held = source.find('held_dir / "RECALL_RECEIPT.json"')
        rundir = source.find('run_dir / "receipts" / "RECALL_RECEIPT.json"')
        self.assertTrue(0 < held < rundir)
        # Silent rescore stops the ladder the moment candidates cure.
        self.assertIn("_silent_recall_check", source)


class CensusRulesVersioningTests(unittest.TestCase):
    def test_units_record_rules_and_legacy_walk_excludes_shebang(self) -> None:
        import tempfile

        from lucy.runtime.units import CENSUS_RULES, compute_units

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            repo = root / "svc"
            repo.mkdir()
            (repo / "main.py").write_text("x = 1\n", encoding="utf-8")
            (repo / "runner").write_text("#!/bin/sh\nexec true\n", encoding="utf-8")
            current = compute_units(root)
            legacy = compute_units(root, census_rules="ext/v1")
            self.assertEqual(CENSUS_RULES, current["census_rules"])
            current_files = {f for u in current["units"] for f in u["files"]}
            legacy_files = {f for u in legacy["units"] for f in u["files"]}
            self.assertIn("svc/runner", current_files)
            self.assertNotIn("svc/runner", legacy_files)


class HistoricalDrawCoverageTests(unittest.TestCase):
    def test_uncovered_locus_is_skipped_not_drawn(self) -> None:
        import tempfile

        from lucy.runtime.priors import draw_historical_canaries

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            (root / "a.py").write_text("x\n" * 5, encoding="utf-8")
            (root / "hook").write_text("line\n" * 5, encoding="utf-8")
            priors = {
                "schema": "lucy-priors/oss-1",
                "targets": [
                    {"id": "H-1", "path": "a.py", "line": 2, "family": "L1-auth", "title": "t"},
                    {"id": "H-2", "path": "hook", "line": 2, "family": "L2-secrets", "title": "t"},
                ],
            }
            canaries, skipped = draw_historical_canaries(
                priors, root, covered_paths={"a.py"}
            )
            self.assertEqual(["a.py"], [c["path"] for c in canaries])
            self.assertIn("H-2", skipped)


if __name__ == "__main__":
    unittest.main()
