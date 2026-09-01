from datetime import datetime, timezone
from pathlib import Path
import tempfile
import unittest

from lucy.runtime.run_state import PHASES, RunState, compute_run_id
from lucy.runtime.results import LocalResultsSink


STARTED_AT = datetime(2026, 8, 21, 12, 34, 56, tzinfo=timezone.utc)


class RunStateTests(unittest.TestCase):
    def create_state(self) -> RunState:
        return RunState.create(
            target=Path("."),
            head_sha="a" * 40,
            model="session-default",
            started_at=STARTED_AT,
            session_id="0123456789abcdef",
        )

    def test_run_id_uses_utc_minute_and_session(self) -> None:
        first = compute_run_id("a" * 40, STARTED_AT, "session-one")
        same_minute = compute_run_id(
            "a" * 40,
            datetime(2026, 8, 21, 12, 34, 1, tzinfo=timezone.utc),
            "session-one",
        )
        different_session = compute_run_id("a" * 40, STARTED_AT, "session-two")
        self.assertEqual(first, same_minute)
        self.assertNotEqual(first, different_session)
        self.assertRegex(first, r"^r-[0-9a-f]{12}$")

    def test_phase_progress_is_ordered_and_idempotent(self) -> None:
        state = self.create_state()
        state.advance(PHASES[0])
        state.advance(PHASES[1])
        with self.assertRaisesRegex(ValueError, "cannot advance"):
            state.advance(PHASES[3])

    def test_claude_code_run_can_finish_certified_after_emit(self) -> None:
        state = self.create_state()
        for phase in PHASES[1:]:
            state.advance(phase)
        state.finish("CERTIFIED", "all gates passed", STARTED_AT)
        self.assertEqual("CERTIFIED", state.status)
        self.assertEqual("claude-code", state.platform)

    def test_state_round_trips_through_atomic_receipt(self) -> None:
        state = self.create_state()
        state.advance("census")
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            sink = LocalResultsSink.create(base / "results", target)
            path = state.save_to_sink(sink)
            loaded = RunState.load(path)
        self.assertEqual(state, loaded)


if __name__ == "__main__":
    unittest.main()