"""Recapture laps: reopen reading for below-bar units on a finalized run.

The seal gate's closure standard (STANDARD-095) demands per-unit coverage
bounds >= 0.95. When a finalized run falls short, the lawful cure is more
comparable capture — not card edits. This module:

1. restores staging from the run's receipts (unit files, battery seeds, and
   per-pass lane data reconstructed from PASS_HISTORY + candidates.jsonl);
2. dispatches full four-lens recapture laps for every below-bar unit via an
   AgentHost (fresh reader agents, same static brief);
3. re-merges, re-courts any new serious candidates (existing verdicts are
   reconstructed from finalized findings, never re-litigated);
4. re-finalizes, then certification re-runs on the updated receipts.

Stops when every unit clears the bar, or when a lap neither lifts any bound
by >= 0.02 nor finds new serious candidates (receipted stagnation — the
honest "keep mining or end PROCESS-COMPLETE" outcome).
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
from typing import Any

from lucy.runtime.artifacts import SERIOUS, finalize, merge_candidates, read_jsonl
from lucy.runtime.host import AgentHost
from lucy.runtime.orchestrator import LENSES, READER_SYSTEM, READER_TASK, _jsonl_only
from lucy.runtime.seal import _chapman_bound


CLOSURE_BAR = 0.95
MIN_IMPROVEMENT = 0.02


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}



CURE_LAP_BUDGET = 3


def cure_lap_allowed(
    prior_laps: int,
    used_this_command: int,
    cure_needed: bool,
    already_cured: bool,
    budget: int = CURE_LAP_BUDGET,
) -> bool:
    """Pure cure-ladder decision: a blind cure lap may dispatch only while
    recall still needs curing, the current candidate set has not already
    cured it, and the CUMULATIVE budget (prior commands + this command)
    is not exhausted. The budget is OPERATOR POLICY (--cure-lap-budget):
    every lap stays fully blind and every cure is receipted with its lap
    count on the seal card, so a larger budget widens spend, never claims.
    Extracted so the bound is testable behaviorally."""
    if not cure_needed or already_cured:
        return False
    return prior_laps + used_this_command < max(0, int(budget))


def charge_cure_lap(held_dir: Path, prior_laps: int, used_this_command: int) -> int:
    """Charge ONE cure lap to the launcher-held receipt BEFORE dispatch,
    fail-closed. A crash between dispatch and end-of-command bookkeeping
    must never refund the lap or the next command could dispatch it again
    and defeat the cumulative bound.
    Raises — never silently continues — when the held receipt is missing,
    corrupt, or unwritable: no charge, no dispatch. A lap consumed by a
    post-charge crash is the safe, honest failure mode."""
    held = held_dir / "RECALL_RECEIPT.json"
    if not held.is_file():
        raise ValueError(
            "cure lap refused: launcher-held recall receipt is missing — "
            "cannot charge the cumulative budget, so no cure lap may dispatch"
        )
    doc = json.loads(held.read_text(encoding="utf-8"))
    total = prior_laps + used_this_command + 1
    doc["cure_laps"] = total
    held.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    recorded = json.loads(held.read_text(encoding="utf-8")).get("cure_laps")
    if recorded != total:
        raise ValueError("cure lap refused: budget charge did not persist")
    return total


def persist_cure_laps(held_dir: Path, prior_laps: int, used_this_command: int) -> int:
    """Accumulate the cure-lap counter into the launcher-held receipt so the
    budget survives across commands. Returns the recorded total."""
    held = held_dir / "RECALL_RECEIPT.json"
    total = prior_laps + used_this_command
    if used_this_command and held.is_file():
        try:
            doc = json.loads(held.read_text(encoding="utf-8"))
            doc["cure_laps"] = total
            held.write_text(json.dumps(doc, indent=2, sort_keys=True) + "\n", encoding="utf-8")
        except (OSError, ValueError, json.JSONDecodeError):
            pass
    return total

def restore_staging(run_dir: Path) -> None:
    """Rebuild staging from receipts so merge reproduces the finalized state.

    Per-pass lane files are reconstructed by joining PASS_HISTORY's observed
    candidate ids with the full rows in candidates.jsonl — merge then yields
    byte-identical candidate ids and an extended pass history.
    """
    receipts = run_dir / "receipts"
    staging = run_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    for receipt in receipts.glob("UNIT-*.txt"):
        (staging / receipt.name).write_text(
            receipt.read_text(encoding="utf-8"), encoding="utf-8"
        )
    for name in ("BATTERY.txt", "CENSUS.txt", "UNITS.json"):
        source = receipts / name
        if source.is_file():
            (staging / name).write_text(source.read_text(encoding="utf-8"), encoding="utf-8")
    rows_by_id = {row["id"]: row for row in read_jsonl(run_dir / "candidates.jsonl")}
    passes = _read_json(receipts / "PASS_HISTORY.json").get("passes", [])
    for entry in passes:
        # Same traversal guard as restore_courts: a tampered receipt's pass
        # value must not steer the filename.
        if entry.get("phase") != "sweep" and not isinstance(entry.get("pass"), int):
            raise ValueError(f"PASS_HISTORY entry has non-integer pass: {entry.get('pass')!r}")
        rows = [rows_by_id[cid] for cid in entry.get("observed", []) if cid in rows_by_id]
        # Sweep slots restore as sweep lanes so merge re-derives the same
        # history shape (a sweep entry shares its pass number with pass 1).
        name = (
            "lane-sweep-restored.jsonl"
            if entry.get("phase") == "sweep"
            else f"lane-pass{entry['pass']}-restored.jsonl"
        )
        (staging / name).write_text(
            "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
            encoding="utf-8",
        )


def restore_courts(run_dir: Path) -> None:
    """Reconstruct per-verdict court files from finalized findings.

    Existing verdicts are never re-litigated; only NEW serious candidates go
    to fresh courts.
    """
    court_dir = run_dir / "staging" / "courts"
    court_dir.mkdir(parents=True, exist_ok=True)
    verdict_map = {"verified": "VERIFIED", "refuted": "REFUTED", "conditional-court": "CONDITIONAL"}
    for row in read_jsonl(run_dir / "findings.jsonl"):
        verdict = verdict_map.get(str(row.get("status", "")))
        if verdict is None:
            continue
        # The id becomes a filename: a tampered findings row must not be able
        # to traverse out of the courts directory.
        if not re.fullmatch(r"[A-Za-z0-9._-]{1,80}", str(row.get("id", ""))):
            raise ValueError(f"findings row carries an unsafe id: {row.get('id')!r}")
        (court_dir / f"{row['id']}.json").write_text(
            json.dumps(
                {
                    "candidate_id": row["id"],
                    "verdict": verdict,
                    "severity": row["severity"],
                    "cwe": row.get("cwe", "CWE-693"),
                    "disproof_attempt": row.get("disproof_attempt", ""),
                    "basis": row.get("verification_basis", "static-reasoned"),
                    "reach_basis": row.get("reach_basis", ""),
                    "fix": row.get("fix", "Review the cited locus."),
                }
            ),
            encoding="utf-8",
        )


def _unit_listings(receipts: Path) -> dict[str, set[str]]:
    listings = {}
    for listing in sorted(receipts.glob("UNIT-*.txt")):
        if listing.name.endswith(("-BATTERY.txt", "-PRIORS.txt")):
            continue
        listings[listing.stem] = {
            line for line in listing.read_text(encoding="utf-8").splitlines() if line.strip()
        }
    return listings


def unit_quiet(run_dir: Path) -> dict[str, bool]:
    """Delegates to THE single quiet arithmetic (artifacts.unit_quiet_map)."""
    from lucy.runtime.artifacts import unit_quiet_map

    return unit_quiet_map(run_dir)


def unit_bounds(run_dir: Path) -> dict[str, float]:
    receipts = run_dir / "receipts"
    passes = _read_json(receipts / "PASS_HISTORY.json").get("passes", [])
    candidates = read_jsonl(run_dir / "candidates.jsonl")
    serious_ids = {row["id"] for row in candidates if row["severity"] in SERIOUS}
    paths_by_id = {row["id"]: row["path"] for row in candidates}
    bounds: dict[str, float] = {}
    for listing in sorted(receipts.glob("UNIT-*.txt")):
        if listing.name.endswith(("-BATTERY.txt", "-PRIORS.txt")):
            continue
        unit_files = {
            line for line in listing.read_text(encoding="utf-8").splitlines() if line.strip()
        }
        unit_ids = {
            cid for cid in serious_ids if paths_by_id.get(cid) in unit_files
        }
        bounds[listing.stem] = _chapman_bound(passes, unit_ids)
    return bounds


COURT_TASK = """LUCY COURT
CANDIDATE_ID={id}
CLAIM={title}
LOCUS={path}:{line}
CATEGORY={category}
PROPOSED_SEVERITY={severity}

Attempt to disprove this claim from workspace bytes. Return exactly one JSON
object and no markdown:
{{"candidate_id":"{id}","verdict":"VERIFIED|CONDITIONAL|REFUTED","severity":"PRIORITIZED_CRITICAL|CRITICAL|HIGH|MEDIUM|LOW","cwe":"CWE-N","disproof_attempt":"...","basis":"static-reasoned","reach_basis":"...","fix":"specific imperative remediation or No code change required; reason"}}"""

COURT_SYSTEM = (Path(__file__).parents[1] / "agents" / "lucy-court.md").read_text(
    encoding="utf-8"
).split("---", 2)[-1].strip()


def _court_one(host: AgentHost, workspace: Path, court_dir: Path, candidate: dict[str, Any]) -> None:
    response = host.run_agent(
        system=COURT_SYSTEM,
        task=COURT_TASK.format(**candidate),
        workspace=workspace,
    )
    body = _jsonl_only(response).strip() or json.dumps(
        {
            "candidate_id": candidate["id"],
            "verdict": "CONDITIONAL",
            "severity": candidate["severity"],
            "cwe": "CWE-693",
            "disproof_attempt": "court returned no parseable verdict; retained at worst-plausible",
            "basis": "static-reasoned",
            "reach_basis": candidate["reach_basis"],
            "fix": "Review the cited locus manually.",
        }
    )
    (court_dir / f"{candidate['id']}.json").write_text(body, encoding="utf-8")



_LANE_LABEL = re.compile(r"^(?:recap-)?pass(\d+)-(L\d-[a-z]+)-(UNIT-\d+)$")


PULSE_EVENTS = {"lane-dead", "lane-relaunched", "lane-adopted-empty"}


def reduce_pulse_ledger(events: "list[dict]") -> dict:
    """ORDERED per-lane reduction of the pulse ledger — the single C5 law.

    - lane-dead opens one outstanding obligation for that lane.
    - lane-relaunched / lane-adopted-empty consumes one ALREADY-outstanding
      obligation for the same lane. A closure with no outstanding death is
      over-closure noise: receipted, never an offset for a LATER death
      (aggregate counting let an earlier benign adoption mask a later
      unclosed death — a false-certify hole).
    - A relevant event with a missing/empty/non-string lane label fails
      closed: it counts as unreconciled.

    Returns {"unreconciled", "over_closures", "invalid_rows",
    "outstanding_by_lane"}. Used by BOTH seal generation and orphan
    reconciliation so the two paths cannot disagree.
    """
    outstanding: dict[str, int] = {}
    over_closures = 0
    invalid_rows = 0
    for row in events:
        event = row.get("event") if isinstance(row, dict) else None
        if event not in PULSE_EVENTS:
            continue
        lane = row.get("lane")
        if not isinstance(lane, str) or not lane.strip():
            invalid_rows += 1
            continue
        if event == "lane-dead":
            outstanding[lane] = outstanding.get(lane, 0) + 1
        elif outstanding.get(lane, 0) > 0:
            outstanding[lane] -= 1
        else:
            over_closures += 1
    return {
        "unreconciled": sum(outstanding.values()) + invalid_rows,
        "over_closures": over_closures,
        "invalid_rows": invalid_rows,
        "outstanding_by_lane": {k: v for k, v in outstanding.items() if v > 0},
    }


def reconcile_orphan_lane_deaths(
    run_dir: Path, current_laps: "list[dict] | None" = None
) -> int:
    """Balance the pulse ledger with EVIDENCE, never narration.

    A lane guard writes lane-dead, retries, then lane-relaunched, but a
    command killed mid-retry can strand lane-dead receipts with no closure, and
    the append-only ledger then never balances, blocking C5 forever.
    Reconciliation rule: an orphan death is receipted as relaunched ONLY
    with proof the dead lane's work was actually redone — a completed lane
    file for the same lens and unit at a same-or-later pass, THIS command's
    validated lap records (current_laps, passed in after merge/finalize
    succeeded — staging is deleted by finalize, so the caller must hand the
    evidence over rather than have it re-scanned), or a prior command's
    receipted laps. Outstanding deaths come from the same ordered reducer
    the seal uses (reduce_pulse_ledger), so an earlier benign closure can
    never mask a later death here either. Returns receipts appended."""
    liveness_path = run_dir / "receipts" / "LIVENESS.jsonl"
    staging = run_dir / "staging"
    if not liveness_path.is_file():
        return 0
    events = []
    for line in liveness_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        try:
            events.append(json.loads(line))
        except json.JSONDecodeError:
            continue
    outstanding = reduce_pulse_ledger(events)["outstanding_by_lane"]
    appended = 0
    with liveness_path.open("a", encoding="utf-8") as handle:
        for label, orphans in sorted(outstanding.items()):
            if orphans <= 0:
                continue
            match = _LANE_LABEL.match(label)
            if not match:
                continue
            pass_number, lens, unit = int(match.group(1)), match.group(2), match.group(3)
            # Evidence source 1: live lane files from THIS command's laps.
            superseding = sorted(
                lane.name
                for lane in staging.glob(f"lane-pass*-{lens}-{unit}.jsonl")
                if (m := re.match(r"lane-pass(\d+)-", lane.name))
                and int(m.group(1)) >= pass_number
            )
            # Evidence source 2: THIS command's validated lap records,
            # handed in by the caller after merge/finalize accepted them.
            if not superseding and current_laps:
                for lap in current_laps:
                    try:
                        lap_pass = int(lap.get("pass", -1))
                    except (TypeError, ValueError):
                        continue
                    if lap_pass >= pass_number and unit in (lap.get("units") or []):
                        superseding = [f"validated lap pass {lap_pass} over {unit} (this command)"]
                        break
            # Evidence source 3: a PRIOR command's launcher-written lap
            # record (staging lane files do not survive finalize; restored
            # staging uses -restored names, so a later recapture must look
            # at receipts/RECAPTURE.json to see that the dead lane's unit
            # was fully re-lapped at the same-or-later pass — recapture
            # laps are always full four-lens width).
            if not superseding:
                prior = run_dir / "receipts" / "RECAPTURE.json"
                if prior.is_file():
                    try:
                        for lap in json.loads(prior.read_text(encoding="utf-8")).get("laps", []):
                            if int(lap.get("pass", -1)) >= pass_number and unit in lap.get("units", []):
                                superseding = [f"receipted lap pass {lap['pass']} over {unit}"]
                                break
                    except (json.JSONDecodeError, ValueError, TypeError):
                        pass
            if not superseding:
                continue
            for _ in range(orphans):
                handle.write(
                    json.dumps(
                        {
                            "event": "lane-relaunched",
                            "lane": label,
                            "basis": f"reconciled: superseded by {superseding[0]}",
                        }
                    )
                    + "\n"
                )
                appended += 1
    return appended


def run_recapture(
    host: AgentHost,
    run_dir: Path,
    workspace: Path,
    results_root: Path,
    *,
    max_laps: int | None = None,
    width: int | None = None,
    cure_lap_budget: int = CURE_LAP_BUDGET,
    operator_budget: bool = False,
) -> dict[str, Any]:
    """max_laps=None (default) is UNCAPPED: recall is the priority, so laps
    continue until every unit is closed AND quiet, or until receipted
    stagnation. A numeric cap is a fidelity trade-off the caller opts into.
    width=None resolves to the machine/operator lane cap (LUCY_MAX_LANES)."""
    if width is None:
        from lucy.runtime.loop_policy import lane_cap

        width = lane_cap()
    staging = run_dir / "staging"
    restore_staging(run_dir)
    restore_courts(run_dir)
    laps: list[dict[str, Any]] = []
    bounds = unit_bounds(run_dir)
    # BLIND CURE LADDER. Recall scoring is launcher-only and never
    # discloses a missed canary's unit, locus, or family to the model —
    # every cure lap is a full-width blind read of ALL units (family-
    # targeted dispatch is deliberately rejected: even a family-level leak
    # taints the experiment). The ladder is BOUNDED (default 2 cure laps
    # per command, cumulative across commands via the held receipt's
    # cure_laps counter) and each lap is followed by a SILENT launcher-side
    # rescore against custody: the moment the candidate set cures recall,
    # cure lapping stops. Exhausting the ladder ends in adjudication (CANARY-CURE
    # for refound slots; MINT-ERROR only by operator attestation), never
    # in unbounded grinding.
    from lucy.runtime.trial import custody_home, match_canaries

    run_id_name = run_dir.name
    held_dir = custody_home() / "runs" / run_id_name
    recall_cure_needed = False
    cure_laps_prior = 0
    for receipt_path in (
        held_dir / "RECALL_RECEIPT.json",
        run_dir / "receipts" / "RECALL_RECEIPT.json",
    ):
        if not receipt_path.is_file():
            continue
        try:
            recall = _read_json(receipt_path)
            recall_cure_needed = (
                recall.get("status") == "FAIL"
                and int(recall.get("found", 0)) + int(recall.get("mint_error", 0) or 0)
                < int(recall.get("total", 0))
            )
            cure_laps_prior = int(recall.get("cure_laps", 0) or 0)
        except (OSError, ValueError, TypeError):
            recall_cure_needed = False
        break
    cure_laps_used = 0

    # SHADOW DIAGNOSIS before any lap is charged: when every missed slot is
    # fold-shadowed (a sibling same-family plant inside the fold radius owns
    # the only mintable candidate), blind laps have no RELIABLE cure path —
    # every accurate re-report folds into the claimed candidate; only an
    # off-lens or mis-cited report could escape, so further laps would depend
    # on citation error rather than new evidence. Skip the ladder and receipt the
    # mechanism instead of vending hopeless laps.
    # An operator who EXPLICITLY set --cure-lap-budget overrides the skip
    # (spend autonomy is theirs); the diagnosis is receipted either way.
    recall_shadow: list[dict[str, Any]] = []
    if recall_cure_needed:
        try:
            key = json.loads(
                (held_dir / "ANSWER_KEY.json").read_text(encoding="utf-8")
            )
            from lucy.runtime.trial import diagnose_recall_shadow

            recall_shadow = diagnose_recall_shadow(
                key, read_jsonl(run_dir / "candidates.jsonl")
            )
        except (OSError, ValueError, json.JSONDecodeError):
            recall_shadow = []
        if (
            recall_shadow
            and all(row["mechanism"] == "fold-shadow" for row in recall_shadow)
            and not operator_budget
        ):
            recall_cure_needed = False

    def _silent_recall_check() -> bool:
        """True when the CURRENT candidate set already cures recall.
        Reads custody only; writes nothing; prints nothing."""
        key_path = held_dir / "ANSWER_KEY.json"
        if not key_path.is_file():
            return False
        try:
            key = json.loads(key_path.read_text(encoding="utf-8"))
            rows = read_jsonl(run_dir / "candidates.jsonl")
            slots = match_canaries(key, rows)
            plants = [s for s in slots if not s["historical"]]
            return all(s["found"] for s in plants)
        except (OSError, ValueError, json.JSONDecodeError):
            return False

    def reader_lane(pass_number: int, lens: str, unit_id: str) -> None:
        unit_files = (staging / f"{unit_id}.txt").read_text(encoding="utf-8")
        battery_path = run_dir / "receipts" / f"{unit_id}-BATTERY.txt"
        battery = battery_path.read_text(encoding="utf-8") if battery_path.is_file() else "none"
        heat_path = run_dir / "receipts" / f"{unit_id}-PRIORS.txt"
        priors_heat = heat_path.read_text(encoding="utf-8") if heat_path.is_file() else "none"
        response = host.run_agent(
            system=READER_SYSTEM,
            task=READER_TASK.format(
                pass_number=pass_number,
                lens=lens,
                unit_files=unit_files,
                battery=battery,
                priors_heat=priors_heat,
            ),
            workspace=workspace,
        )
        (staging / f"lane-pass{pass_number}-{lens}-{unit_id}.jsonl").write_text(
            _jsonl_only(response), encoding="utf-8"
        )

    lap_count = 0
    stagnant_laps = 0
    while max_laps is None or lap_count < max_laps:
        lap_count += 1
        quiet = unit_quiet(run_dir)
        below = sorted(
            unit
            for unit, bound in bounds.items()
            if bound < CLOSURE_BAR or not quiet.get(unit, False)
        )
        if not below:
            if cure_lap_allowed(
                cure_laps_prior, cure_laps_used, recall_cure_needed,
                _silent_recall_check(), budget=cure_lap_budget,
            ):
                # Charge BEFORE dispatch, fail-closed: any persistence
                # failure raises here and nothing launches.
                charge_cure_lap(held_dir, cure_laps_prior, cure_laps_used)
                # All units, full width, no disclosure of any kind. The
                # budget is consumed ONLY when a cure lap actually
                # dispatches, and it is cumulative across commands (the
                # counter rides in the held receipt) so repeated commands
                # cannot become an unbounded grind.
                below = sorted(bounds)
                cure_laps_used += 1
                blind_recall_cure = True
            else:
                break
        else:
            blind_recall_cure = False
        if blind_recall_cure is False and recall_cure_needed and _silent_recall_check():
            # Recall already cured by earlier laps' candidates — no reason
            # to keep dispatching for recall; coverage laps proceed only if
            # units genuinely demand them.
            recall_cure_needed = False
        existing = [
            int(match.group(1))
            for lane in staging.glob("lane-pass*-*")
            if (match := re.match(r"lane-pass(\d+)-", lane.name))
        ]
        pass_number = max(existing, default=0) + 1
        pre_candidates = {row["id"] for row in read_jsonl(run_dir / "candidates.jsonl")}
        lanes = [(pass_number, lens, unit) for unit in below for lens in LENSES]
        from lucy.runtime.orchestrator import _lane_guarded

        with ThreadPoolExecutor(max_workers=width) as pool:
            list(pool.map(lambda lane: _lane_guarded(run_dir, f"recap-pass{lane[0]}-{lane[1]}-{lane[2]}", lambda lane=lane: reader_lane(*lane)), lanes))
        candidates = merge_candidates(run_dir, workspace, results_root)
        # Court every serious candidate lacking a verdict file — not just new
        # ids: a recapture lane can UPGRADE an existing candidate's severity
        # (same id, higher tier), and finalize fails closed on any uncourted
        # serious row.
        court_dir_check = staging / "courts"
        new_serious = [
            row
            for row in candidates
            if row["severity"] in SERIOUS
            and not (court_dir_check / f"{row['id']}.json").is_file()
        ]
        newly_observed = [row for row in new_serious if row["id"] not in pre_candidates]
        new_bounds = unit_bounds(run_dir)
        improvement = max(
            (new_bounds.get(unit, 0.0) - bounds.get(unit, 0.0) for unit in below),
            default=0.0,
        )
        if blind_recall_cure and _silent_recall_check():
            recall_cure_needed = False
        laps.append(
            {
                "pass": pass_number,
                "units": below,
                "recall_cure": blind_recall_cure,
                "new_serious": len(newly_observed),
                "uncourted_serious": len(new_serious),
                "bounds_before": {unit: bounds[unit] for unit in below},
                "bounds_after": {unit: new_bounds[unit] for unit in below},
            }
        )
        bounds = new_bounds

        if new_serious:
            court_dir = staging / "courts"
            with ThreadPoolExecutor(max_workers=width) as pool:
                list(
                    pool.map(
                        lambda candidate: _court_one(host, workspace, court_dir, candidate),
                        new_serious,
                    )
                )
        if not newly_observed and improvement < MIN_IMPROVEMENT:
            # A clean lap while quiet is still pending is PROGRESS, not
            # stagnation — it is the confirming pass the quiet law needs.
            # Only stop after two
            # consecutive stagnant laps with quiet still unreachable.
            stagnant_laps += 1
            if all(unit_quiet(run_dir).values()) or stagnant_laps >= 2:
                laps[-1]["stopped"] = (
                    "stagnation: no new serious and bound improvement < 0.02"
                    + ("" if stagnant_laps < 2 else " (two consecutive stagnant laps)")
                )
                break
        else:
            stagnant_laps = 0

    # Safety net before finalize: court any serious row still lacking a
    # verdict (covers upgrades from the FINAL lap, which the per-lap sweep
    # above only handles for earlier laps).
    court_dir_final = staging / "courts"
    candidates = read_jsonl(run_dir / "candidates.jsonl")
    leftovers = [
        row
        for row in candidates
        if row["severity"] in SERIOUS
        and not (court_dir_final / f"{row['id']}.json").is_file()
    ]
    if leftovers:
        with ThreadPoolExecutor(max_workers=width) as pool:
            list(
                pool.map(
                    lambda candidate: _court_one(host, workspace, court_dir_final, candidate),
                    leftovers,
                )
            )

    findings = finalize(run_dir, workspace, results_root)
    lap_capped = bool(
        max_laps is not None
        and lap_count >= max_laps
        and laps
        and "stopped" not in laps[-1]
    )
    if lap_capped:
        laps[-1]["stopped"] = (
            f"LAP CAP REACHED (max_laps={max_laps}): recall may be incomplete — "
            "the run stopped on an operator limit, not on convergence"
        )
    reconciled = reconcile_orphan_lane_deaths(run_dir, current_laps=laps)
    # Cumulative cure-lap accounting rides in the launcher-held recall
    # receipt (tamper-proof) so the budget survives across commands.
    # Cure laps are charged at dispatch time (charge_cure_lap); no
    # end-of-command write needed — a crash mid-command keeps the charge.
    receipt = {
        "schema": "lucy-recapture/v1",
        "cure_laps": cure_laps_used,
        "recall_shadow": recall_shadow,
        "reconciled_lane_deaths": reconciled,
        "laps": laps,
        "final_bounds": bounds,
        "closed": all(bound >= CLOSURE_BAR for bound in bounds.values()),
        "lap_capped": lap_capped,
        "findings_emitted": sum(1 for row in findings if row["status"] != "refuted"),
    }
    (run_dir / "receipts" / "RECAPTURE.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return receipt
