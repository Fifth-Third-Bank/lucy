"""Binding policy for the Claude Code autonomous review loop."""

from __future__ import annotations

from dataclasses import dataclass
import os


MAX_WIDTH = 20


def lane_cap() -> int:
    """Machine- and operator-aware concurrency cap for agent lanes.

    Order of precedence: LUCY_MAX_LANES env (operator override, clamped to
    the platform's 20-subagent limit) > conservative auto-default sized to
    the host: min(12, max(6, cpu_count)). Lanes are API-bound, so the
    default deliberately sits below the platform cap to stay gentle on both
    the machine and API rate limits; operators with headroom raise it."""
    override = os.environ.get("LUCY_MAX_LANES", "").strip()
    if override:
        try:
            return max(1, min(MAX_WIDTH, int(override)))
        except ValueError:
            pass
    return min(12, max(6, os.cpu_count() or 8))


SOFT_START_WIDTH = max(4, lane_cap() // 2)
RAMP_STEP = max(2, lane_cap() // 3)
CLEAN_INTERVAL_SECONDS = 5 * 60
LIVENESS_INTERVAL_SECONDS = 15 * 60
IDLE_WAKE_INTERVAL_SECONDS = 5 * 60
DEAD_AFTER_STALLED_SWEEPS = 2
QUIET_CONSECUTIVE_PASSES = 2
QUIET_MAX_NEW_SERIOUS_PER_UNIT = 2  # floor; see quiet_threshold()
QUIET_DENSITY_LOC = 25000


def quiet_threshold(unit_loc: int) -> int:
    """Density-scaled quiet bar: a unit is quiet when a pass adds at most
    max(2, unit_LOC/25K) new serious candidates. The quiet law's question is
    'is the well empty?', and the honest measure is residual DENSITY, not an
    absolute count. A fixed threshold applies inconsistent residual-density
    standards across differently sized units. The floor of 2 keeps every
    cap-sized-or-smaller unit on the original bar, so existing certification
    semantics are unchanged.
    The per-unit threshold is recorded in CERT_RECEIPT.json for audit."""
    return max(QUIET_MAX_NEW_SERIOUS_PER_UNIT, round(int(unit_loc) / QUIET_DENSITY_LOC))


def ramp_width(current_width: int, clean_intervals: int = 1) -> int:
    """Increase width after clean lane-start intervals, capped at 20."""
    _validate_width(current_width)
    if clean_intervals < 0:
        raise ValueError("clean_intervals cannot be negative")
    return min(MAX_WIDTH, current_width + RAMP_STEP * clean_intervals)


def limiter_width(current_width: int) -> int:
    """Halve width after a limiter wave without dropping below one lane."""
    _validate_width(current_width)
    return max(1, current_width // 2)


def lane_is_dead(stalled_sweeps: int) -> bool:
    if stalled_sweeps < 0:
        raise ValueError("stalled_sweeps cannot be negative")
    return stalled_sweeps >= DEAD_AFTER_STALLED_SWEEPS


def unit_is_quiet(new_serious_counts: list[int], unit_loc: int = 0) -> bool:
    """Require the last two passes to stay within the unit's density-scaled
    serious bound (quiet_threshold; unit_loc=0 keeps the floor of 2)."""
    if any(count < 0 for count in new_serious_counts):
        raise ValueError("new finding counts cannot be negative")
    if len(new_serious_counts) < QUIET_CONSECUTIVE_PASSES:
        return False
    recent = new_serious_counts[-QUIET_CONSECUTIVE_PASSES:]
    return all(count <= quiet_threshold(unit_loc) for count in recent)


@dataclass(frozen=True)
class DispatchPermission:
    wake_armed: bool
    mint_receipt_present: bool
    active_lanes: int
    width: int

    def validate(self) -> None:
        _validate_width(self.width)
        if not self.wake_armed:
            raise ValueError("wake must be armed before dispatch")
        if not self.mint_receipt_present:
            raise ValueError("mint receipt is required before pass-one dispatch")
        if self.active_lanes < 0:
            raise ValueError("active_lanes cannot be negative")
        if self.active_lanes >= self.width:
            raise ValueError("no dispatch slot is available")


def _validate_width(width: int) -> None:
    if not 1 <= width <= MAX_WIDTH:
        raise ValueError(f"width must be between 1 and {MAX_WIDTH}")
