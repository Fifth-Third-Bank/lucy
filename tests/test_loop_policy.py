import unittest

from lucy.runtime.loop_policy import (
    DispatchPermission,
    MAX_WIDTH,
    SOFT_START_WIDTH,
    lane_is_dead,
    limiter_width,
    ramp_width,
    unit_is_quiet,
)


class LoopPolicyTests(unittest.TestCase):
    def test_soft_start_ramps_by_four_to_twenty(self) -> None:
        width = SOFT_START_WIDTH
        self.assertEqual(10, ramp_width(width))
        self.assertEqual(18, ramp_width(width, clean_intervals=3))
        self.assertEqual(MAX_WIDTH, ramp_width(width, clean_intervals=4))

    def test_limiter_wave_halves_then_ramp_resumes(self) -> None:
        reduced = limiter_width(20)
        self.assertEqual(10, reduced)
        self.assertEqual(14, ramp_width(reduced))

    def test_lane_dies_after_two_stalled_sweeps(self) -> None:
        self.assertFalse(lane_is_dead(1))
        self.assertTrue(lane_is_dead(2))

    def test_quiet_requires_two_consecutive_bounded_passes(self) -> None:
        self.assertFalse(unit_is_quiet([1]))
        self.assertFalse(unit_is_quiet([3, 1]))
        self.assertTrue(unit_is_quiet([3, 2, 1]))

    def test_dispatch_requires_wake_and_mint_receipt(self) -> None:
        with self.assertRaisesRegex(ValueError, "wake must be armed"):
            DispatchPermission(False, True, active_lanes=0, width=6).validate()
        with self.assertRaisesRegex(ValueError, "mint receipt"):
            DispatchPermission(True, False, active_lanes=0, width=6).validate()
        DispatchPermission(True, True, active_lanes=5, width=6).validate()


if __name__ == "__main__":
    unittest.main()

class DensityQuietThresholdTests(unittest.TestCase):
    """The quiet bar scales with unit size so the residual-density standard
    is uniform instead of applying the same absolute count to very different
    unit sizes."""

    def test_floor_and_scaling(self) -> None:
        from lucy.runtime.loop_policy import quiet_threshold

        self.assertEqual(2, quiet_threshold(0))
        self.assertEqual(2, quiet_threshold(12000))
        self.assertEqual(2, quiet_threshold(50000))
        self.assertEqual(3, quiet_threshold(75000))
        self.assertEqual(5, quiet_threshold(130000))

    def test_unit_is_quiet_uses_unit_loc(self) -> None:
        from lucy.runtime.loop_policy import unit_is_quiet

        # 4 new serious per pass: loud for a 50K unit, quiet for a 130K one.
        self.assertFalse(unit_is_quiet([4, 4], unit_loc=50000))
        self.assertTrue(unit_is_quiet([4, 4], unit_loc=130000))
        self.assertFalse(unit_is_quiet([4, 9], unit_loc=130000))
