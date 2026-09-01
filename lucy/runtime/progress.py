"""Launcher-side progress reporting and output teeing.

Progress is derived from the run directory's staging receipts — the ground
truth — never from model narration (a print-mode reviewer buffers its text
until exit, so its stdout is not a liveness signal). Lines go to stderr (and
the tee log when configured) only when the observed state changes.
"""

from __future__ import annotations

import re
import sys
import threading
import time
from pathlib import Path
from typing import IO, Any


def brand_code(rgb: tuple[int, int, int], fallback: str) -> str:
    """ANSI SGR for a brand color: 24-bit where the terminal declares support,
    else the nearest basic color. Palette: Opal #0064D1 (primary/blue),
    Emerald #26D07C (success), Topaz #78C8F9 (emphasis readable on dark
    backgrounds; Azurite/Lapis are print/web tones that vanish on terminals)."""
    import os

    if "truecolor" in os.environ.get("COLORTERM", "").lower() or "24bit" in os.environ.get("COLORTERM", "").lower():
        r, g, b = rgb
        return f"38;2;{r};{g};{b}"
    return fallback


OPAL = brand_code((0, 100, 209), "34")
EMERALD = brand_code((38, 208, 124), "32")
TOPAZ = brand_code((120, 200, 249), "36")


class Tee:
    """Duplicate a stream to a log file (line-buffered, best-effort).

    The log side is REDACTED: the tee persists reviewer output derived from
    scanned code, so it needs the same pre-write redaction as every other
    sink-written file.
    The console side stays verbatim."""

    def __init__(self, stream: IO[str], log: IO[str] | None) -> None:
        self.stream = stream
        self.log = log

    def write(self, text: str) -> int:
        self.stream.write(text)
        if self.log is not None:
            from lucy.runtime.results import redact_text

            self.log.write(redact_text(text)[0])
            self.log.flush()
        return len(text)

    def flush(self) -> None:
        self.stream.flush()
        if self.log is not None:
            self.log.flush()

    def isatty(self) -> bool:
        # The certification summary asks stdout whether color is safe; a Tee
        # without this crashed at the very end of every --log run.
        return bool(getattr(self.stream, "isatty", lambda: False)())


class ProgressReporter:
    """Poll a run directory and print phase milestones on change."""

    def __init__(
        self,
        run_directory: Path,
        *,
        interval_seconds: float = 20.0,
        quiet: bool = False,
        out: IO[str] | None = None,
    ) -> None:
        self.run_directory = run_directory
        self.interval = interval_seconds
        self.quiet = quiet
        self.out = out or sys.stderr
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._started = time.monotonic()
        self._last = ""

    LEGEND = (
        "LUCY progress - lines print only when state changes\n"
        "\n"
        "  phases      preflight -> reading -> courts -> finalize -> certify\n"
        "\n"
        "  units       code partitions (~50K lines); read by 4 lenses per pass\n"
        "  quiet       units whose last two passes found almost nothing new\n"
        "  lanes       completed reader lanes (pass-1 total = units x 4;\n"
        "              later passes repeat until quiet)\n"
        "  sweeps      cross-repo pattern lanes (dispatch after pass 1)\n"
        "  courts      verdicts delivered / serious findings requiring one\n"
        "              (refuted = claims disproven, kept on purpose)\n"
        "  candidates  merged findings so far (+new since the last line)\n"
        "\n"
    )

    # -- state observation ------------------------------------------------
    def _observe(self) -> str:
        staging = self.run_directory / "staging"
        # An active staging dir wins over run-level artifacts: a recapture of
        # a previously refused run starts with a stale CERTIFICATION.json on
        # disk; active staging means the recapture is still in progress.
        if (self.run_directory / "CERTIFICATION.json").is_file() and not staging.exists():
            return f"{'certify':<10} complete"
        if (self.run_directory / "receipts" / "RECALL_RECEIPT.json").is_file() and not staging.exists():
            return f"{'certify':<10} recall scored \u00b7 gates running"
        if (self.run_directory / "findings.jsonl").is_file() and not staging.exists():
            return f"{'finalize':<10} awaiting external recall scoring"
        if not staging.exists():
            return f"{'preparing':<10} workspace copy + canary planting"
        lanes = len(list(staging.glob("lane-pass*")))
        pass1_lanes = len(list(staging.glob("lane-pass1-*")))
        later_lanes = lanes - pass1_lanes
        sweeps = len(list(staging.glob("lane-sweep-*")))
        court_dir = staging / "courts"
        courts = len(list(court_dir.glob("*.json"))) if court_dir.is_dir() else 0
        units = len(list(staging.glob("UNIT-*.txt"))) - len(
            list(staging.glob("UNIT-*-BATTERY.txt"))
        ) - len(list(staging.glob("UNIT-*-PRIORS.txt")))
        units = max(units, 0)
        # Fractions only where the denominator is honestly knowable;
        # commentary goes at the very end of the line.
        commentary = ""
        if units and later_lanes == 0:
            lanes_text = f"lanes {pass1_lanes}/{units * 4} (pass 1)"
        else:
            lanes_text = f"lanes {lanes}"
            # Report the highest pass number dispatched so progress advances
            # throughout the run.
            pass_numbers = [
                int(match.group(1))
                for lane in staging.glob("lane-pass*")
                if (match := re.match(r"lane-pass(\d+)", lane.name))
            ]
            current_pass = max(pass_numbers, default=1)
            commentary = f"pass {current_pass} running, continues until quiet"
        sweeps_text = f"sweeps {sweeps}/4" if sweeps else "sweeps 0"
        tallies = self._candidate_tallies()
        court_stats = self._court_tallies(court_dir)
        if tallies is not None:
            serious = tallies["serious"]
            courts_text = f"courts {courts}/{serious}"
        else:
            courts_text = f"courts {courts}"
        if court_stats and courts:
            courts_text += (
                f" ({court_stats['verified']} verified · "
                f"{court_stats['conditional']} conditional · "
                f"{court_stats['refuted']} refuted)"
            )
        candidates_text = ""
        if tallies is not None:
            candidates_text = f"candidates {tallies['total']}{tallies['delta']}"
        quiet_text = ""
        quiet = self._quiet_units()
        if quiet is not None:
            quiet_text = f"quiet {quiet[0]}/{quiet[1]}"
        if courts:
            phase = "courts"
        elif lanes:
            phase = "reading"
        else:
            phase = "preflight"
        parts = [f"units {units}"]
        if quiet_text:
            parts.append(quiet_text)
        parts.extend([lanes_text, sweeps_text, courts_text])
        if candidates_text:
            parts.append(candidates_text)
        if commentary:
            parts.append(commentary)
        return f"{phase:<10} " + " · ".join(parts)

    def _candidate_tallies(self) -> dict[str, Any] | None:
        """Merged-candidate total with the delta since the previous
        observation. Counts only — never titles or paths (progress must not
        become an unredacted findings channel)."""
        candidates = self.run_directory / "candidates.jsonl"
        if not candidates.is_file():
            return None
        import json

        serious_tiers = {"PRIORITIZED_CRITICAL", "CRITICAL", "HIGH"}
        total = 0
        serious = 0
        try:
            for line in candidates.read_text(encoding="utf-8").splitlines():
                if not line.strip():
                    continue
                row = json.loads(line)
                total += 1
                if str(row.get("severity", "")).upper() in serious_tiers:
                    serious += 1
        except (OSError, json.JSONDecodeError):
            return None
        previous = getattr(self, "_last_candidate_total", None)
        self._last_candidate_total = total
        delta = f" (+{total - previous} new)" if previous is not None and total > previous else ""
        return {"total": total, "delta": delta, "serious": serious}

    def _court_tallies(self, court_dir: Path) -> dict[str, Any] | None:
        """Live verdict outcomes from the per-verdict files. Refuted counts
        are shown deliberately: disproven claims are the tool's credibility
        record, not an embarrassment."""
        if not court_dir.is_dir():
            return None
        import json

        outcomes = {"VERIFIED": 0, "CONDITIONAL": 0, "REFUTED": 0}
        try:
            for verdict_file in court_dir.glob("*.json"):
                row = json.loads(verdict_file.read_text(encoding="utf-8"))
                verdict = str(row.get("verdict", "")).upper()
                if verdict in outcomes:
                    outcomes[verdict] += 1
        except (OSError, json.JSONDecodeError):
            return None
        return {
            "verified": outcomes["VERIFIED"],
            "conditional": outcomes["CONDITIONAL"],
            "refuted": outcomes["REFUTED"],
        }

    def _quiet_units(self) -> tuple[int, int] | None:
        """Per-unit countdown from the one production convergence reducer."""
        import json

        if not (self.run_directory / "receipts" / "PASS_HISTORY.json").is_file():
            return None
        try:
            from lucy.runtime.artifacts import unit_quiet_map

            quiet = unit_quiet_map(self.run_directory)
            if not quiet:
                return None
            return sum(quiet.values()), len(quiet)
        except (OSError, ValueError, json.JSONDecodeError, KeyError):
            return None

    def _paint(self, text: str, code: str) -> str:
        if bool(getattr(self.out, "isatty", lambda: False)()):
            return f"\033[{code}m{text}\033[0m"
        return text

    def _tick(self) -> None:
        state = self._observe()
        if state != self._last:
            elapsed = int((time.monotonic() - self._started) / 60)
            prefix = self._paint(f"[lucy +{elapsed}m]", OPAL)
            # Phase-completion chapter lines: announce the transition before
            # the first line of the new phase.
            new_phase = state.split(None, 1)[0]
            old_phase = self._last.split(None, 1)[0] if self._last else ""
            if old_phase and new_phase != old_phase:
                self.out.write(f"{prefix} {self._paint(f'── {old_phase} complete ──', f'1;{TOPAZ}')}\n")
            self.out.write(f"{prefix} {state}\n")
            self.out.flush()
            self._last = state

    # -- lifecycle ---------------------------------------------------------
    def start(self) -> "ProgressReporter":
        if self.quiet:
            return self
        self.out.write(self.LEGEND)
        self.out.flush()
        def loop() -> None:
            while not self._stop.wait(self.interval):
                try:
                    self._tick()
                except Exception:
                    continue
        self._tick()
        self._thread = threading.Thread(target=loop, name="lucy-progress", daemon=True)
        self._thread.start()
        return self

    def stop(self) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout=2)
        if not self.quiet:
            try:
                self._tick()
            except Exception:
                pass

    def __enter__(self) -> "ProgressReporter":
        return self.start()

    def __exit__(self, *_: Any) -> None:
        self.stop()


_ESCAPE_BYTES = __import__("re").compile(r"\x1b\[[0-9;?]*[A-Za-z]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)|[\x00-\x08\x0b\x0c\x0e-\x1f]")


def pump_subprocess(process: Any, sinks: list[IO[str]]) -> None:
    """Stream a subprocess's combined output line-by-line to every sink —
    anything the reviewer does emit reaches the console (and log) live
    instead of sitting in a buffer until exit. Escape/control sequences are
    stripped: reviewer output is shaped by hostile repo bytes, and a raw OSC/
    CSI passthrough can rewrite the operator's screen or spoof verdict lines."""
    assert process.stdout is not None
    for line in iter(process.stdout.readline, ""):
        line = _ESCAPE_BYTES.sub("", line)
        for sink in sinks:
            sink.write(line)
            sink.flush()
    process.stdout.close()
