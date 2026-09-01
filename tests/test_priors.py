"""Launcher-side priors: schema, draw, disposition, and e2e certification."""

from __future__ import annotations

import json
from pathlib import Path
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lucy.runtime.priors import (  # noqa: E402
    draw_historical_canaries,
    load_priors,
    score_dispositions,
)

POLYGLOT = ROOT / "tests" / "fixtures" / "polyglot"


def make_priors(tmp: Path, targets: list[dict]) -> Path:
    path = tmp / "priors.json"
    path.write_text(
        json.dumps({"schema": "lucy-priors/oss-1", "targets": targets}), encoding="utf-8"
    )
    return path


VALID_TARGETS = [
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


class PriorsSchemaTests(unittest.TestCase):
    def test_valid_file_loads(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            priors = load_priors(make_priors(Path(tmp), VALID_TARGETS))
            self.assertEqual(len(priors["targets"]), 5)

    def test_rejects_bad_schema_duplicates_and_paths(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            base = Path(tmp)
            bad = base / "bad.json"
            bad.write_text(json.dumps({"schema": "other", "targets": []}), encoding="utf-8")
            with self.assertRaises(ValueError):
                load_priors(bad)
            with self.assertRaisesRegex(ValueError, "duplicate"):
                load_priors(make_priors(base, [VALID_TARGETS[0], VALID_TARGETS[0]]))
            escape = dict(VALID_TARGETS[0], path="../outside.py")
            with self.assertRaisesRegex(ValueError, "relative"):
                load_priors(make_priors(base, [escape]))


class HistoricalDrawTests(unittest.TestCase):
    def test_draw_is_deterministic_score_only_and_skips_unresolvable(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            priors = load_priors(make_priors(Path(tmp), VALID_TARGETS))
            first, skipped1 = draw_historical_canaries(priors, POLYGLOT)
            second, skipped2 = draw_historical_canaries(priors, POLYGLOT)
            self.assertEqual(first, second)
            self.assertEqual(len(first), 4)
            self.assertTrue(all(row["historical"] for row in first))
            drawn_ids = {row["priors_id"] for row in first}
            self.assertNotIn("HIST-005", drawn_ids)
            self.assertEqual(skipped1, skipped2)


class DispositionTests(unittest.TestCase):
    def test_refound_not_evidenced_and_conservation(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            priors = load_priors(make_priors(Path(tmp), VALID_TARGETS))
            findings = [
                {
                    "id": "LUCY-abc",
                    "path": "apps/admin-ui/middleware.ts",
                    "line": 12,
                    "lens": "L1-auth",
                    "category": "missing-authorization",
                    "title": "JWT verification lacks issuer pinning.",
                    "status": "verified",
                },
                {
                    "id": "LUCY-def",
                    "path": "infra/api_gateway.tf",
                    "line": 30,
                    "lens": "L4-infra",
                    "category": "public-exposure",
                    "title": "Route authorization weakened.",
                    "status": "refuted",
                },
            ]
            disposition = score_dispositions(priors, POLYGLOT, findings)
            self.assertEqual(disposition["staged"], 5)
            self.assertEqual(
                disposition["refound"] + disposition["not_evidenced"], disposition["staged"]
            )
            by_id = {row["id"]: row for row in disposition["rows"]}
            self.assertEqual(by_id["HIST-001"]["disposition"], "REFOUND")
            self.assertEqual(by_id["HIST-001"]["finding_status"], "verified")
            self.assertEqual(by_id["HIST-002"]["finding_status"], "refuted")
            self.assertEqual(by_id["HIST-005"]["sub_class"], "locus-not-found")
            self.assertEqual(by_id["HIST-003"]["sub_class"], "defect-not-present")
            self.assertEqual(
                disposition["not_evidenced_receipted"], disposition["not_evidenced"]
            )


if __name__ == "__main__":
    unittest.main()


class PriorsHeatTests(unittest.TestCase):
    def test_exclusion_radius_and_heat_files(self) -> None:
        from lucy.runtime.priors import heat_exclusions, write_heat_files
        import tempfile as _tempfile

        targets = VALID_TARGETS + [
            {
                "id": "HIST-006",
                "path": "apps/admin-ui/middleware.ts",  # same FILE as HIST-001
                "line": 60,
                "family": "L2-secrets",
                "title": "A second historical claim in the canary's file.",
            },
            {
                "id": "HIST-007",
                "path": "infra/alb.tf",  # same DIR + family as HIST-002
                "line": 12,
                "family": "L4-infra",
                "title": "A sibling infra claim in the canary's directory.",
            },
            {
                "id": "HIST-008",
                "path": "apps/notify-svc/main.go",  # unrelated -> heated
                "line": 20,
                "family": "L1-auth",
                "title": "An unrelated historical claim that should be heated.",
            },
        ]
        with _tempfile.TemporaryDirectory() as tmp:
            priors = load_priors(make_priors(Path(tmp), targets))
            canaries, _ = draw_historical_canaries(priors, POLYGLOT)
            heated, withheld = heat_exclusions(priors, canaries, POLYGLOT)
            withheld_reasons = {row["id"]: row["reason"] for row in withheld}
            drawn_ids = {row["priors_id"] for row in canaries}
            # Draw-agnostic guardrail assertions:
            for drawn in drawn_ids:
                self.assertEqual(withheld_reasons.get(drawn), "drawn-canary")
            heated_ids = {row["id"] for row in heated}
            self.assertTrue(drawn_ids.isdisjoint(heated_ids))
            self.assertEqual(withheld_reasons.get("HIST-005"), "locus-unresolved")
            # Every target is either heated or withheld, exactly once.
            all_ids = {target["id"] for target in targets}
            self.assertEqual(heated_ids | set(withheld_reasons), all_ids)
            self.assertFalse(heated_ids & set(withheld_reasons))
            # Radius neighbors of drawn canaries must be withheld.
            if "HIST-001" in drawn_ids:
                self.assertEqual(withheld_reasons.get("HIST-006"), "same-file-as-canary")
            if "HIST-002" in drawn_ids:
                self.assertEqual(
                    withheld_reasons.get("HIST-007"),
                    "same-directory-and-family-as-canary",
                )
            with _tempfile.TemporaryDirectory() as staging_tmp:
                staging = Path(staging_tmp)
                unit_files = [row["resolved_path"] for row in heated][:1] or ["none"]
                counts = write_heat_files(
                    heated, {"UNIT-001": unit_files}, staging
                )
                body = (staging / "UNIT-001-PRIORS.txt").read_text(encoding="utf-8")
                if heated:
                    self.assertIn(unit_files[0], body)
                    self.assertEqual(counts["UNIT-001"], 1)

    def test_dispositions_tag_briefed_and_blind(self) -> None:
        from lucy.runtime.priors import score_dispositions
        import tempfile as _tempfile

        with _tempfile.TemporaryDirectory() as tmp:
            priors = load_priors(make_priors(Path(tmp), VALID_TARGETS))
            findings = [
                {
                    "id": "LUCY-abc",
                    "path": "apps/admin-ui/middleware.ts",
                    "line": 12,
                    "lens": "L1-auth",
                    "category": "missing-authorization",
                    "title": "JWT verification lacks issuer pinning.",
                    "status": "verified",
                },
                {
                    "id": "LUCY-def",
                    "path": "infra/api_gateway.tf",
                    "line": 30,
                    "lens": "L4-infra",
                    "category": "public-exposure",
                    "title": "Route authorization weakened.",
                    "status": "verified",
                },
            ]
            disposition = score_dispositions(
                priors, POLYGLOT, findings, heated_ids={"HIST-002"}
            )
            by_id = {row["id"]: row for row in disposition["rows"]}
            self.assertTrue(by_id["HIST-002"]["briefed"])
            self.assertFalse(by_id["HIST-001"]["briefed"])
            self.assertTrue(disposition["heat_applied"])
            # Both refound, but only the un-briefed one counts as blind.
            self.assertEqual(disposition["refound"], 2)
            self.assertEqual(disposition["blind_refound"], 1)
