"""Cure-budget survival, disposition-aware gates, battery signal parsing,
and host-planter reachability regressions."""

from __future__ import annotations

import json
from pathlib import Path
import tempfile
import unittest

from lucy.runtime.trial import _battery_signal


ROOT = Path(__file__).parents[1]
FIXTURE = ROOT / "tests" / "fixtures" / "polyglot"


class BatterySignalTests(unittest.TestCase):
    def test_jsonl_nearby_far_other_file_and_malformed(self) -> None:
        nearby = json.dumps({"path": "a/b.py", "line": 110, "hit": "x"})
        far = json.dumps({"path": "a/b.py", "line": 500, "hit": "x"})
        other = json.dumps({"path": "a/c.py", "line": 101, "hit": "x"})
        malformed = 'a/b.py garbage without numbers'
        self.assertTrue(_battery_signal(nearby, "a/b.py", 100))
        # A same-file hit with a parseable FAR line is not a signal.
        self.assertFalse(_battery_signal(far, "a/b.py", 100))
        self.assertFalse(_battery_signal(other, "a/b.py", 100))
        self.assertFalse(_battery_signal(malformed, "a/b.py", 100))
        # Non-JSON fallback with colon-space still parses the number.
        self.assertTrue(_battery_signal("hit a/b.py: 112 weak-key", "a/b.py", 100))
        self.assertFalse(_battery_signal("hit a/b.py: 900 weak-key", "a/b.py", 100))


class CureBudgetAndDispositionTests(unittest.TestCase):
    def _fixture_run(self, directory: str):
        from lucy.runtime.trial import prepare_fixture_trial

        results = Path(directory) / "results"
        trial = prepare_fixture_trial(
            FIXTURE, results, custody_root=Path(directory) / "custody"
        )
        return trial, results

    def test_cure_laps_survive_rescoring_and_cap_attestation(self) -> None:
        import os
        from unittest import mock

        from lucy.runtime.trial import _attest_mint_error, custody_home, score_recall

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"LUCY_CUSTODY_HOME": str(Path(directory) / "home")}):
                trial, results = self._fixture_run(directory)
                run_dir = Path(trial["run_directory"])
                custody_path = Path(trial["_custody"])
                key = json.loads(
                    Path(json.loads(custody_path.read_text())["answer_key"]).read_text()
                )
                rows = [
                    {"path": c["path"], "line": c["line"], "severity": "HIGH", "title": c["title"]}
                    for c in key["canaries"][:7]
                ]
                (run_dir / "candidates.jsonl").write_text(
                    "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
                )
                (run_dir / "findings.jsonl").write_text("", encoding="utf-8")
                first = score_recall(run_dir, custody_path, Path(trial["workspace"]), results)
                self.assertEqual("FAIL", first["status"])
                held = custody_home() / "runs" / trial["run_id"] / "RECALL_RECEIPT.json"
                # Simulate two receipted cure laps, then rescore: the counter
                # must SURVIVE the receipt rewrite.
                from lucy.runtime.recapture import CURE_LAP_BUDGET

                doc = json.loads(held.read_text())
                doc["cure_laps"] = CURE_LAP_BUDGET
                held.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
                custody2 = custody_home() / "runs" / trial["run_id"] / "custody.json"
                second = score_recall(run_dir, custody2, Path(trial["workspace"]), results)
                self.assertEqual(CURE_LAP_BUDGET, second["cure_laps"])
                self.assertEqual(
                    CURE_LAP_BUDGET, json.loads(held.read_text()).get("cure_laps")
                )
                # Attestation of the missed PLANT now passes its precondition
                # and demands a concrete basis.
                missed = next(r["slot"] for r in second["slots"] if not r["found"] and not r["historical"])
                _attest_mint_error(trial["run_id"], [(missed, "semantically inert mutation: no caller invokes the weakened path")])
                doc = json.loads(held.read_text())
                row = next(r for r in doc["slots"] if r["slot"] == missed)
                self.assertTrue(row["mint_error"])
                self.assertIn("semantically inert", row["mint_error_basis"])
    def test_cold7_minterr1_certifies_through_both_pinned_gates(self) -> None:
        import os
        from unittest import mock

        from lucy.runtime.seal import generate_certification
        from lucy.runtime.trial import (
            _attest_mint_error,
            custody_home,
            score_recall,
            write_trial_verdict,
        )
        from lucy.runtime.artifacts import finalize, merge_candidates

        with tempfile.TemporaryDirectory() as directory:
            with mock.patch.dict(os.environ, {"LUCY_CUSTODY_HOME": str(Path(directory) / "home")}):
                trial, results = self._fixture_run(directory)
                run_dir = Path(trial["run_directory"])
                workspace = Path(trial["workspace"])
                custody_path = Path(trial["_custody"])
                key = json.loads(
                    Path(json.loads(custody_path.read_text())["answer_key"]).read_text()
                )
                staging = run_dir / "staging"
                staging.mkdir(parents=True, exist_ok=True)
                rows = [
                    {
                        "path": c["path"], "line": c["line"], "lens": c["family"],
                        "category": c["family"].split("-")[1], "severity": "MEDIUM",
                        "title": c["title"], "evidence": "kind-only", "reach_basis": "n/a",
                    }
                    for c in key["canaries"][:7]
                ]
                (staging / "lane-pass1-L1-auth-UNIT-001.jsonl").write_text(
                    "".join(json.dumps(r) + "\n" for r in rows), encoding="utf-8"
                )
                (staging / "lane-pass2-L1-auth-UNIT-001.jsonl").write_text("", encoding="utf-8")
                from lucy.runtime.units import compute_units

                plan = compute_units(workspace)
                receipts = run_dir / "receipts"
                receipts.mkdir(parents=True, exist_ok=True)
                (receipts / "UNITS.json").write_text(json.dumps(plan), encoding="utf-8")
                for index, unit in enumerate(plan["units"], 1):
                    (receipts / f"UNIT-{index:03d}.txt").write_text(
                        "\n".join(unit["files"]) + "\n", encoding="utf-8"
                    )
                merge_candidates(run_dir, workspace, results)
                finalize(run_dir, workspace, results)
                first = score_recall(run_dir, custody_path, workspace, results)
                self.assertEqual(7, first["found"])
                held = custody_home() / "runs" / trial["run_id"] / "RECALL_RECEIPT.json"
                doc = json.loads(held.read_text())
                doc["cure_laps"] = 2
                held.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n")
                missed = next(r["slot"] for r in first["slots"] if not r["found"] and not r["historical"])
                _attest_mint_error(trial["run_id"], [(missed, "semantically inert mutation: weakened guard has no caller")])
                custody2 = custody_home() / "runs" / trial["run_id"] / "custody.json"
                receipt = score_recall(run_dir, custody2, workspace, results)
                self.assertEqual((7, 0, 1, "PASS"),
                                 (receipt["cold"], receipt["cured"], receipt["mint_error"], receipt["status"]))
                write_trial_verdict(run_dir, workspace, FIXTURE, results, receipt)
                valid_dispositions = {
                    "schema": "lucy-dispositions/v1",
                    "planted_file_candidates": 7,
                    "dispositioned": 7,
                    "unresolved": 0,
                    "rows": [],
                }
                outcome = generate_certification(
                    run_dir, workspace, results, trial["run_id"], trial["started_at"],
                    recall_receipt=receipt, dispositions=valid_dispositions,
                )
                self.assertIn("SEAL-CARD: PASS", outcome["seal_gate"], outcome["seal_gate"])
                self.assertIn("CERTIFICATION: PASS", outcome["certification_gate"])
                self.assertTrue(outcome["certified"], outcome)
                card = (run_dir / "SEAL_CARD.md").read_text(encoding="utf-8")
                self.assertIn("MINT-ERROR:", card)
                self.assertIn("canaries 8 OPENED", card)


class CureBudgetBoundTests(unittest.TestCase):
    """The blind cure ladder is bounded CUMULATIVELY across commands: the
    counter accumulates through the launcher-held receipt, and once the
    budget is spent no further cure lap may dispatch in any later command."""

    def test_decision_and_accumulation_across_commands(self) -> None:
        import json as _json

        from lucy.runtime.recapture import (
            CURE_LAP_BUDGET,
            cure_lap_allowed,
            persist_cure_laps,
        )

        # Command 1: fresh run, recall failing — two laps allowed, third not.
        self.assertTrue(cure_lap_allowed(0, 0, True, False))
        self.assertTrue(cure_lap_allowed(0, 1, True, False))
        self.assertFalse(cure_lap_allowed(0, CURE_LAP_BUDGET, True, False))
        # Curing mid-command stops the ladder even with budget left.
        self.assertFalse(cure_lap_allowed(0, 0, True, True))
        self.assertFalse(cure_lap_allowed(0, 0, False, False))
        with tempfile.TemporaryDirectory() as directory:
            held_dir = Path(directory)
            (held_dir / "RECALL_RECEIPT.json").write_text(
                _json.dumps({"status": "FAIL", "found": 7, "total": 8, "slots": []}),
                encoding="utf-8",
            )
            # Command 1 dispatched the whole budget and persists the total.
            self.assertEqual(
                CURE_LAP_BUDGET, persist_cure_laps(held_dir, 0, CURE_LAP_BUDGET)
            )
            recorded = _json.loads((held_dir / "RECALL_RECEIPT.json").read_text())
            self.assertEqual(CURE_LAP_BUDGET, recorded["cure_laps"])
            # Command 2 loads prior=budget: NO lap may dispatch.
            self.assertFalse(cure_lap_allowed(recorded["cure_laps"], 0, True, False))
            # A no-dispatch command never inflates the counter.
            self.assertEqual(
                CURE_LAP_BUDGET, persist_cure_laps(held_dir, recorded["cure_laps"], 0)
            )
            self.assertEqual(
                CURE_LAP_BUDGET,
                _json.loads((held_dir / "RECALL_RECEIPT.json").read_text())["cure_laps"]
            )


class ChargeBeforeDispatchTests(unittest.TestCase):
    """A cure lap is charged to the held receipt BEFORE
    lanes launch, fail-closed, so a crash mid-command can never refund a
    dispatched lap and re-enable spending in the next command."""

    def test_crash_between_charge_and_finalize_keeps_the_charge(self) -> None:
        import json as _json

        from lucy.runtime.recapture import (
            CURE_LAP_BUDGET,
            charge_cure_lap,
            cure_lap_allowed,
        )

        with tempfile.TemporaryDirectory() as directory:
            held_dir = Path(directory)
            held = held_dir / "RECALL_RECEIPT.json"
            held.write_text(
                _json.dumps({"status": "FAIL", "found": 7, "total": 8, "slots": []}),
                encoding="utf-8",
            )
            # 1. fresh run: cure_laps starts absent (0)
            self.assertNotIn("cure_laps", _json.loads(held.read_text()))
            # 2. command 1 commits a lap: receipt says 1 IMMEDIATELY
            self.assertEqual(1, charge_cure_lap(held_dir, 0, 0))
            self.assertEqual(1, _json.loads(held.read_text())["cure_laps"])
            # 3. simulate a crash before merge/finalize: nothing else runs.
            # 4. command 2 reads prior=1 and may commit the second lap
            prior = _json.loads(held.read_text())["cure_laps"]
            self.assertEqual(1, prior)
            self.assertTrue(cure_lap_allowed(prior, 0, True, False))
            # 5. later commands keep charging until the budget is reached
            charged = prior
            while cure_lap_allowed(charged, 0, True, False):
                charged = charge_cure_lap(held_dir, charged, 0)
                self.assertEqual(charged, _json.loads(held.read_text())["cure_laps"])
            # 6. every later command refuses a lap past the budget
            final = _json.loads(held.read_text())["cure_laps"]
            self.assertEqual(CURE_LAP_BUDGET, final)
            self.assertFalse(cure_lap_allowed(final, 0, True, False))

    def test_charge_fails_closed_without_a_held_receipt(self) -> None:
        from lucy.runtime.recapture import charge_cure_lap

        with tempfile.TemporaryDirectory() as directory:
            with self.assertRaises(ValueError):
                charge_cure_lap(Path(directory), 0, 0)


class HostPlanterReachabilityTests(unittest.TestCase):
    def test_fake_host_planter_round_trip_requires_reachability(self) -> None:
        import subprocess

        from lucy.runtime.planter import launch_host_planter

        with tempfile.TemporaryDirectory() as directory:
            workspace = Path(directory) / "ws"
            (workspace / "src").mkdir(parents=True)
            for index in range(8):
                (workspace / "src" / f"file{index}.py").write_text("secure = True\n")
            subprocess.run(["git", "init", "-q"], cwd=workspace, check=True)
            subprocess.run(["git", "add", "--all"], cwd=workspace, check=True)
            subprocess.run(
                ["git", "-c", "user.name=t", "-c", "user.email=t@e.i", "commit", "-q", "-m", "b"],
                cwd=workspace, check=True,
            )
            families = ["L1-auth"] * 2 + ["L2-secrets"] * 2 + ["L3-injection"] * 2 + ["L4-infra"] * 2
            canaries = []
            for index, family in enumerate(families):
                (workspace / "src" / f"file{index}.py").write_text(f"secure = False_{index}\n")
                canaries.append({
                    "slot": index + 1, "family": family, "path": f"src/file{index}.py",
                    "line": 1, "title": f"m{index}",
                    "reachability": f"module import path exercises file{index} at startup",
                })
            answer = {"schema": "lucy-answer-key/v1", "canaries": canaries}

            class FakeHost:
                def run_agent(self, **kwargs):
                    # The task example must ADVERTISE reachability so a real
                    # host emits it (the schema demands it but
                    # the example omitted it).
                    assert "reachability" in kwargs["task"]
                    return json.dumps(answer)

            validated = launch_host_planter(workspace, ROOT / "lucy", FakeHost())
            self.assertEqual(8, len(validated["canaries"]))


if __name__ == "__main__":
    unittest.main()


class CleanTargetDispositionTests(unittest.TestCase):
    """Attribution is causation, not proximity: a plant at
    line 27, a duplicate description of that plant citing the far sink at
    line 87, and an unrelated genuine finding at line 35. Expected: the
    line-87 duplicate is synthetic (refuted on clean bytes) even though it
    is outside any window; the line-35 neighbor is genuine even though it
    is inside one."""

    def _scenario(self, tmp: str, responses: dict):
        import json as _json

        from lucy.runtime.dispositions import adjudicate_planted_candidates

        run_dir = Path(tmp) / "run"
        run_dir.mkdir()
        target = Path(tmp) / "target"
        target.mkdir()
        (target / "localtools.py").write_text("clean = True\n" * 100, encoding="utf-8")
        rows = [
            {"id": "LUCY-plant27", "path": "localtools.py", "line": 27,
             "category": "containment", "title": "resolve guard weakened", "severity": "HIGH"},
            {"id": "LUCY-dup87", "path": "localtools.py", "line": 87,
             "category": "traversal", "title": "write sink escapes workspace", "severity": "HIGH"},
            {"id": "LUCY-real35", "path": "localtools.py", "line": 35,
             "category": "scope", "title": "unit scope issue", "severity": "MEDIUM"},
        ]
        (run_dir / "candidates.jsonl").write_text(
            "".join(_json.dumps(r) + "\n" for r in rows), encoding="utf-8"
        )

        class FakeCleanCourt:
            def run_agent(self, **kwargs):
                for cid, verdict in responses.items():
                    if cid in kwargs["task"]:
                        if verdict is None:
                            return "garbage, no json"
                        return _json.dumps(
                            {"candidate_id": cid, "clean_verdict": verdict, "basis": "traced"}
                        )
                return "garbage"

        return adjudicate_planted_candidates(
            run_dir, target, {"localtools.py"}, {"LUCY-plant27"}, FakeCleanCourt(),
            copy_ignore=None, max_workers=2,
        ), run_dir

    def test_far_duplicate_synthetic_near_neighbor_genuine(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipt, _ = self._scenario(
                tmp, {"LUCY-dup87": "ABSENT", "LUCY-real35": "PRESENT"}
            )
            by_id = {r["candidate_id"]: r for r in receipt["rows"]}
            self.assertEqual("synthetic", by_id["LUCY-plant27"]["disposition"])
            self.assertIn("recall-matched", by_id["LUCY-plant27"]["basis"])
            self.assertEqual("synthetic", by_id["LUCY-dup87"]["disposition"])
            self.assertEqual("genuine", by_id["LUCY-real35"]["disposition"])
            self.assertEqual(3, receipt["dispositioned"])
            self.assertEqual(receipt["planted_file_candidates"], receipt["dispositioned"])
            self.assertEqual(0, receipt["unresolved"])

    def test_unparseable_court_is_unresolved_never_classified(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            receipt, _ = self._scenario(
                tmp, {"LUCY-dup87": None, "LUCY-real35": "PRESENT"}
            )
            by_id = {r["candidate_id"]: r for r in receipt["rows"]}
            self.assertEqual("unresolved", by_id["LUCY-dup87"]["disposition"])
            self.assertEqual(1, receipt["unresolved"])

    def test_apply_dispositions_rewrites_flags_both_directions(self) -> None:
        import json as _json

        from lucy.runtime.dispositions import apply_dispositions

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"; ws.mkdir(); (ws / "x.py").write_text("x\n")
            run_dir = root / "results" / "runs" / "r-t"
            run_dir.mkdir(parents=True)
            findings = [
                {"id": "LUCY-dup87", "path": "localtools.py", "line": 87, "severity": "HIGH",
                 "category": "traversal", "title": "t", "evidence": "e", "reach_basis": "r",
                 "status": "verified", "synthetic_canary": False},
                {"id": "LUCY-real35", "path": "localtools.py", "line": 35, "severity": "MEDIUM",
                 "category": "scope", "title": "t", "evidence": "e", "reach_basis": "r",
                 "status": "verified", "synthetic_canary": True},
            ]
            (run_dir / "findings.jsonl").write_text(
                "".join(_json.dumps(r) + "\n" for r in findings), encoding="utf-8"
            )
            receipt = {"rows": [
                {"candidate_id": "LUCY-dup87", "disposition": "synthetic"},
                {"candidate_id": "LUCY-real35", "disposition": "genuine"},
            ]}
            apply_dispositions(run_dir, ws, root / "results", receipt)
            rows = {r["id"]: r for r in map(_json.loads, (run_dir / "findings.jsonl").read_text().splitlines())}
            self.assertTrue(rows["LUCY-dup87"]["synthetic_canary"])   # leak closed
            self.assertFalse(rows["LUCY-real35"]["synthetic_canary"])  # suppression undone


class QuietMapArtifactLookupTests(unittest.TestCase):
    """Live reviews keep unit artifacts under staging/ until finalize;
    the quiet map must use them (staging wins, never blended)."""

    def _run_dir(self, tmp: str, where: str, loc: int = 30000, stale: bool = False):
        import json as _json

        run_dir = Path(tmp) / "run"
        (run_dir / "receipts").mkdir(parents=True, exist_ok=True)
        (run_dir / "staging").mkdir(parents=True, exist_ok=True)
        (run_dir / "receipts" / "PASS_HISTORY.json").write_text(
            _json.dumps({"passes": [
                {"pass": 1, "new_serious": ["LUCY-a"]},
                {"pass": 2, "new_serious": []},
                {"pass": 3, "new_serious": []},
            ]}), encoding="utf-8")
        (run_dir / "candidates.jsonl").write_text(
            _json.dumps({"id": "LUCY-a", "path": "svc/a.py", "severity": "HIGH"}) + "\n",
            encoding="utf-8")
        target = run_dir / where
        (target / "UNIT-001.txt").write_text("svc/a.py\n", encoding="utf-8")
        (target / "UNITS.json").write_text(
            _json.dumps({"units": [{"id": "UNIT-001", "loc": loc}]}), encoding="utf-8")
        if stale:
            # stale finalized artifacts from a previous invocation: a bogus
            # second unit that must NOT appear when staging is live
            (run_dir / "receipts" / "UNIT-001.txt").write_text("old/other.py\n", encoding="utf-8")
            (run_dir / "receipts" / "UNIT-099.txt").write_text("old/gone.py\n", encoding="utf-8")
            (run_dir / "receipts" / "UNITS.json").write_text(
                _json.dumps({"units": [{"id": "UNIT-099", "loc": 1}]}), encoding="utf-8")
        return run_dir

    def test_live_staging_produces_nonempty_quiet(self) -> None:
        from lucy.runtime.artifacts import unit_quiet_map

        with tempfile.TemporaryDirectory() as tmp:
            quiet = unit_quiet_map(self._run_dir(tmp, "staging"))
            self.assertEqual({"UNIT-001": True}, quiet)

    def test_finalized_receipts_fallback_matches(self) -> None:
        from lucy.runtime.artifacts import unit_quiet_map

        with tempfile.TemporaryDirectory() as tmp_a, tempfile.TemporaryDirectory() as tmp_b:
            live = unit_quiet_map(self._run_dir(tmp_a, "staging"))
            finalized = unit_quiet_map(self._run_dir(tmp_b, "receipts"))
            self.assertEqual(live, finalized)

    def test_staging_wins_over_stale_receipts(self) -> None:
        from lucy.runtime.artifacts import unit_quiet_map

        with tempfile.TemporaryDirectory() as tmp:
            quiet = unit_quiet_map(self._run_dir(tmp, "staging", stale=True))
            self.assertEqual({"UNIT-001": True}, quiet)
            self.assertNotIn("UNIT-099", quiet)


class DispositionVerdictParsingTests(unittest.TestCase):
    """parse_clean_verdict reads the verdict however the court formats it;
    the decision contract (exact candidate_id + PRESENT/ABSENT) is unchanged."""

    CID = "LUCY-deadbeef01234567"

    def _doc(self, verdict="ABSENT", basis="traced guards on clean bytes"):
        return {"candidate_id": self.CID, "clean_verdict": verdict, "basis": basis}

    def _parse(self, text):
        from lucy.runtime.dispositions import parse_clean_verdict

        return parse_clean_verdict(text, self.CID)

    def test_single_line_contract_still_parses(self):
        verdict, basis = self._parse(json.dumps(self._doc()))
        self.assertEqual("ABSENT", verdict)
        self.assertEqual("traced guards on clean bytes", basis)

    def test_pretty_printed_multiline_parses(self):
        verdict, _ = self._parse(json.dumps(self._doc("PRESENT"), indent=2))
        self.assertEqual("PRESENT", verdict)

    def test_fenced_block_parses(self):
        text = "```json\n" + json.dumps(self._doc(), indent=2) + "\n```"
        verdict, _ = self._parse(text)
        self.assertEqual("ABSENT", verdict)

    def test_prose_wrapped_block_parses(self):
        text = (
            "I examined the clean file.\n\n"
            + json.dumps(self._doc(), indent=4)
            + "\n\nThat is my verdict."
        )
        verdict, _ = self._parse(text)
        self.assertEqual("ABSENT", verdict)

    def test_braces_inside_basis_string_parse(self):
        doc = self._doc(basis="the guard `if cfg { return }` exists on clean bytes")
        verdict, basis = self._parse(json.dumps(doc, indent=2))
        self.assertEqual("ABSENT", verdict)
        self.assertIn("cfg", basis)

    def test_wrong_candidate_id_stays_unresolved(self):
        doc = dict(self._doc(), candidate_id="LUCY-0000000000000000")
        verdict, basis = self._parse(json.dumps(doc, indent=2))
        self.assertIsNone(verdict)
        self.assertIn("no parseable verdict", basis)

    def test_invalid_enum_stays_unresolved(self):
        verdict, _ = self._parse(json.dumps(self._doc("MAYBE"), indent=2))
        self.assertIsNone(verdict)

    def test_garbage_stays_unresolved(self):
        verdict, basis = self._parse("the defect is probably absent, hard to say")
        self.assertIsNone(verdict)
        self.assertIn("no parseable verdict", basis)


class DispositionBoundedRetryTests(unittest.TestCase):
    """A court that returns no verdict is asked again, up to
    DISPOSITION_RETRIES more times; silence after every allowed ask stays
    unresolved. Courts that answered are never re-run."""

    def _scenario(self, tmp: str, host):
        import json as _json

        from lucy.runtime.dispositions import adjudicate_planted_candidates

        run_dir = Path(tmp) / "run"
        run_dir.mkdir()
        target = Path(tmp) / "target"
        target.mkdir()
        (target / "app.py").write_text("clean = True\n" * 50, encoding="utf-8")
        rows = [
            {"id": "LUCY-flaky", "path": "app.py", "line": 10,
             "category": "auth", "title": "guard missing", "severity": "HIGH"},
            {"id": "LUCY-steady", "path": "app.py", "line": 20,
             "category": "auth", "title": "other claim", "severity": "MEDIUM"},
        ]
        (run_dir / "candidates.jsonl").write_text(
            "".join(_json.dumps(r) + "\n" for r in rows), encoding="utf-8"
        )
        return adjudicate_planted_candidates(
            run_dir, target, {"app.py"}, set(), host,
            copy_ignore=None, max_workers=2,
        )

    class CountingHost:
        """Silent for `silent_calls` asks per candidate, then answers."""

        def __init__(self, silent_calls: dict):
            import threading

            self.silent_calls = dict(silent_calls)
            self.calls: dict = {}
            self._lock = threading.Lock()

        def run_agent(self, **kwargs):
            import json as _json

            for cid in ("LUCY-flaky", "LUCY-steady"):
                if cid in kwargs["task"]:
                    with self._lock:
                        self.calls[cid] = self.calls.get(cid, 0) + 1
                        seen = self.calls[cid]
                    if seen <= self.silent_calls.get(cid, 0):
                        return "…the court stopped before its verdict"
                    return _json.dumps(
                        {"candidate_id": cid, "clean_verdict": "ABSENT", "basis": "traced"}
                    )
            return "garbage"

    def test_silent_court_resolved_on_retry(self) -> None:
        host = self.CountingHost({"LUCY-flaky": 3})
        with tempfile.TemporaryDirectory() as tmp:
            receipt = self._scenario(tmp, host)
        by_id = {r["candidate_id"]: r for r in receipt["rows"]}
        self.assertEqual(0, receipt["unresolved"])
        self.assertEqual("synthetic", by_id["LUCY-flaky"]["disposition"])
        self.assertTrue(by_id["LUCY-flaky"].get("retried"))
        self.assertNotIn("retried", by_id["LUCY-steady"])
        self.assertEqual(4, host.calls["LUCY-flaky"])   # answered on the final allowed ask
        self.assertEqual(1, host.calls["LUCY-steady"])  # answered courts never re-run

    def test_twice_silent_court_stays_unresolved(self) -> None:
        host = self.CountingHost({"LUCY-flaky": 99})
        with tempfile.TemporaryDirectory() as tmp:
            receipt = self._scenario(tmp, host)
        by_id = {r["candidate_id"]: r for r in receipt["rows"]}
        self.assertEqual(1, receipt["unresolved"])
        self.assertEqual("unresolved", by_id["LUCY-flaky"]["disposition"])
        from lucy.runtime.dispositions import DISPOSITION_RETRIES

        self.assertEqual(1 + DISPOSITION_RETRIES, host.calls["LUCY-flaky"])  # bounded: no further asks


class LocusFoldLensKeyTests(unittest.TestCase):
    """Fold key is (file, ±10 lines, machine-set lens) — never the free-text
    category: rewordings of one defect must not mint new serious ids and
    re-open quiet after convergence."""

    def _merge(self, tmp: str, rows_by_lane: dict):
        import json as _json

        from lucy.runtime.artifacts import merge_candidates

        root = Path(tmp)
        ws = root / "ws"; ws.mkdir(); (ws / "x.py").write_text("x\n")
        run_dir = root / "results" / "runs" / "r-t"
        (run_dir / "staging").mkdir(parents=True)
        for lane, rows in rows_by_lane.items():
            (run_dir / "staging" / lane).write_text(
                "".join(_json.dumps(r) + "\n" for r in rows), encoding="utf-8"
            )
        merge_candidates(run_dir, ws, root / "results")
        cands = [
            _json.loads(l)
            for l in (run_dir / "candidates.jsonl").read_text().splitlines()
            if l.strip()
        ]
        history = _json.loads((run_dir / "receipts" / "PASS_HISTORY.json").read_text())
        return cands, history

    @staticmethod
    def _row(line, category, lens="L2-secrets", severity="HIGH", title="t"):
        return {"path": "scripts/start", "line": line, "lens": lens,
                "category": category, "severity": severity, "title": title,
                "evidence": "e", "reach_basis": "r"}

    def test_reworded_category_same_lens_folds(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cands, history = self._merge(tmp, {
                "lane-pass1-L2-secrets-UNIT-001.jsonl": [
                    self._row(53, "secrets-management")],
                "lane-pass2-L2-secrets-UNIT-001.jsonl": [
                    self._row(55, "token-lifecycle", title="reworded")],
            })
        self.assertEqual(1, len(cands))
        new_by_pass = [len(p["new"]) for p in history["passes"]]
        self.assertEqual([1, 0], new_by_pass)

    def test_same_locus_different_lens_stays_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cands, _ = self._merge(tmp, {
                "lane-pass1-L2-secrets-UNIT-001.jsonl": [
                    self._row(53, "secrets-management")],
                "lane-pass1-L1-auth-UNIT-001.jsonl": [
                    self._row(53, "auth-bypass", lens="L1-auth")],
            })
        self.assertEqual(2, len(cands))

    def test_beyond_radius_same_lens_stays_distinct(self) -> None:
        with tempfile.TemporaryDirectory() as tmp:
            cands, _ = self._merge(tmp, {
                "lane-pass1-L2-secrets-UNIT-001.jsonl": [
                    self._row(53, "secrets-management"),
                    self._row(80, "secrets-management", title="other defect")],
            })
        self.assertEqual(2, len(cands))


class FoldIdentityUniquenessTests(unittest.TestCase):
    """Two rows hashing to one id (same path+line+category, any lens) fold
    into one candidate: the id is the report's primary key and gate R06
    refuses duplicates."""

    def test_cross_lens_same_id_folds(self) -> None:
        import json as _json

        from lucy.runtime.artifacts import merge_candidates

        with tempfile.TemporaryDirectory() as tmp:
            root = Path(tmp)
            ws = root / "ws"; ws.mkdir(); (ws / "x.py").write_text("x\n")
            run_dir = root / "results" / "runs" / "r-t"
            (run_dir / "staging").mkdir(parents=True)
            base = {"path": "app/Login.java", "line": 25, "category": "open-redirect",
                    "severity": "MEDIUM", "evidence": "e", "reach_basis": "r"}
            (run_dir / "staging" / "lane-pass1-L1-auth-UNIT-001.jsonl").write_text(
                _json.dumps(dict(base, lens="L1-auth", title="unvalidated redirect")) + "\n")
            (run_dir / "staging" / "lane-pass1-L3-injection-UNIT-001.jsonl").write_text(
                _json.dumps(dict(base, lens="L3-injection", title="open redirect")) + "\n")
            merge_candidates(run_dir, ws, root / "results")
            cands = [_json.loads(l) for l in (run_dir / "candidates.jsonl").read_text().splitlines() if l.strip()]
        self.assertEqual(1, len(cands))
        ids = [c["id"] for c in cands]
        self.assertEqual(len(ids), len(set(ids)))


class PulseCoverageLawTests(unittest.TestCase):
    """The PRODUCTION ordered reducer (reduce_pulse_ledger) — shared by seal
    generation and orphan reconciliation. Closures consume only prior
    outstanding deaths on their own lane; over-closure is receipted noise;
    invalid lane labels fail closed. Ordering prevents both false refusal
    after reconciliation and a later death being hidden by an earlier
    benign closure."""

    @staticmethod
    def _reduce(pairs):
        from lucy.runtime.recapture import reduce_pulse_ledger

        return reduce_pulse_ledger([{"event": e, "lane": l} for l, e in pairs])

    def test_no_events_passes(self) -> None:
        self.assertEqual(0, self._reduce([])["unreconciled"])

    def test_dead_only_fails(self) -> None:
        self.assertEqual(1, self._reduce([("a", "lane-dead")])["unreconciled"])

    def test_dead_then_relaunched_passes(self) -> None:
        r = self._reduce([("a", "lane-dead"), ("a", "lane-relaunched")])
        self.assertEqual(0, r["unreconciled"])
        self.assertEqual(0, r["over_closures"])

    def test_dead_then_adopted_passes(self) -> None:
        r = self._reduce([("a", "lane-dead"), ("a", "lane-adopted-empty")])
        self.assertEqual(0, r["unreconciled"])

    def test_double_closure_is_receipted_noise(self) -> None:
        r = self._reduce([("a", "lane-dead"), ("a", "lane-relaunched"),
                          ("a", "lane-adopted-empty")])
        self.assertEqual(0, r["unreconciled"])
        self.assertEqual(1, r["over_closures"])

    def test_dead_relaunched_dead_fails(self) -> None:
        r = self._reduce([("a", "lane-dead"), ("a", "lane-relaunched"),
                          ("a", "lane-dead")])
        self.assertEqual(1, r["unreconciled"])

    def test_closure_before_death_never_offsets(self) -> None:
        self.assertEqual(
            1, self._reduce([("a", "lane-relaunched"), ("a", "lane-dead")])["unreconciled"]
        )

    def test_duplicate_early_closures_never_offset_later_death(self) -> None:
        r = self._reduce([("a", "lane-dead"), ("a", "lane-relaunched"),
                          ("a", "lane-relaunched"), ("a", "lane-dead")])
        self.assertEqual(1, r["unreconciled"])
        self.assertEqual(1, r["over_closures"])

    def test_closure_on_other_lane_does_not_cover(self) -> None:
        self.assertEqual(
            1, self._reduce([("a", "lane-dead"), ("b", "lane-relaunched")])["unreconciled"]
        )

    def test_missing_or_empty_lane_label_fails_closed(self) -> None:
        from lucy.runtime.recapture import reduce_pulse_ledger

        r = reduce_pulse_ledger([{"event": "lane-dead"},
                                 {"event": "lane-relaunched", "lane": "  "},
                                 {"event": "lane-adopted-empty", "lane": None}])
        self.assertEqual(3, r["unreconciled"])
        self.assertEqual(3, r["invalid_rows"])

    def test_reconciled_ledger_with_extra_closures_passes(self) -> None:
        pairs = [("pass3-L4-infra-UNIT-001", "lane-dead"),
                 ("pass3-L4-infra-UNIT-001", "lane-relaunched")]
        for lens in ("L1-auth", "L2-secrets", "L3-injection", "L4-infra"):
            pairs += [(f"sweep-{lens}", "lane-dead"),
                      (f"sweep-{lens}", "lane-relaunched"),
                      (f"sweep-{lens}", "lane-adopted-empty")]
        r = self._reduce(pairs)
        self.assertEqual(0, r["unreconciled"])
        self.assertEqual(4, r["over_closures"])

    def test_seal_consumes_the_shared_reducer(self) -> None:
        import inspect

        from lucy.runtime import seal

        source = inspect.getsource(seal)
        self.assertIn("reduce_pulse_ledger", source)
        self.assertIn("lane_deaths_unreconciled", source)

    def test_current_command_lap_reconciles_orphan_in_one_invocation(self) -> None:
        import json as _json

        from lucy.runtime.recapture import (
            reconcile_orphan_lane_deaths,
            reduce_pulse_ledger,
        )

        with tempfile.TemporaryDirectory() as tmp:
            run_dir = Path(tmp)
            receipts = run_dir / "receipts"
            receipts.mkdir()
            (run_dir / "staging").mkdir()  # empty: finalize already deleted lane files
            (receipts / "LIVENESS.jsonl").write_text(
                _json.dumps({"event": "lane-dead",
                             "lane": "recap-pass9-L2-secrets-UNIT-001"}) + "\n",
                encoding="utf-8",
            )
            appended = reconcile_orphan_lane_deaths(
                run_dir, current_laps=[{"pass": 10, "units": ["UNIT-001"]}]
            )
            self.assertEqual(1, appended)
            events = [_json.loads(l) for l in
                      (receipts / "LIVENESS.jsonl").read_text().splitlines()]
            self.assertEqual(0, reduce_pulse_ledger(events)["unreconciled"])
            self.assertIn("this command", events[-1]["basis"])
            # idempotent: a second reconciliation appends nothing
            self.assertEqual(
                0, reconcile_orphan_lane_deaths(
                    run_dir, current_laps=[{"pass": 10, "units": ["UNIT-001"]}]
                )
            )


class CureLapBudgetPolicyTests(unittest.TestCase):
    """--cure-lap-budget is operator policy: it widens the blind ladder,
    never the claims. Default bound unchanged."""

    def test_default_budget_is_three(self) -> None:
        from lucy.runtime.recapture import CURE_LAP_BUDGET, cure_lap_allowed

        self.assertEqual(3, CURE_LAP_BUDGET)
        self.assertTrue(cure_lap_allowed(2, 0, True, False))
        self.assertFalse(cure_lap_allowed(3, 0, True, False))

    def test_raised_budget_allows_more_blind_laps(self) -> None:
        from lucy.runtime.recapture import cure_lap_allowed

        self.assertTrue(cure_lap_allowed(2, 0, True, False, budget=6))
        self.assertTrue(cure_lap_allowed(2, 3, True, False, budget=6))
        self.assertFalse(cure_lap_allowed(2, 4, True, False, budget=6))

    def test_budget_never_overrides_blindness_or_cure_state(self) -> None:
        from lucy.runtime.recapture import cure_lap_allowed

        self.assertFalse(cure_lap_allowed(0, 0, True, True, budget=99))
        self.assertFalse(cure_lap_allowed(0, 0, False, False, budget=99))

    def test_cli_exposes_flag_and_passes_max_laps(self) -> None:
        import inspect

        from lucy.runtime import trial

        source = inspect.getsource(trial)
        self.assertIn("--cure-lap-budget", source)
        self.assertIn("cure_lap_budget=(", source)
        # regression: --max-laps was parsed but never passed to run_recapture
        self.assertIn("max_laps=args.max_laps", source)
