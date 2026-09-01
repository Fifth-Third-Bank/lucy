"""Deterministic review orchestrator for launcher-driven model hosts.

Claude's default path remains the Claude Code skill session. This module is
the mechanically equivalent scheduler for hosts such as saved-login Codex and
the direct OpenAI API adapter: models only perform isolated reader/court
lanes; Python owns passes, quiet convergence, sweeps, liveness, and courts.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import re
import subprocess
import sys
import threading
from typing import Any, Callable

from lucy.runtime.artifacts import (
    SERIOUS,
    SEVERITIES,
    finalize,
    merge_candidates,
    read_jsonl,
    unit_convergence_map,
)
from lucy.runtime.host import AgentHost
from lucy.runtime.loop_policy import SOFT_START_WIDTH, lane_cap, ramp_width
from lucy.runtime.units import write_units


READER_SYSTEM = (Path(__file__).parents[1] / "agents" / "lucy-reader.md").read_text(
    encoding="utf-8"
).split("---", 2)[-1].strip()
COURT_SYSTEM = (Path(__file__).parents[1] / "agents" / "lucy-court.md").read_text(
    encoding="utf-8"
).split("---", 2)[-1].strip()

READER_TASK = """LUCY READER PASS={pass_number} LENS={lens}
UNIT_FILE contents (read every listed file per your contract; rows naming any
other path are mechanically rejected):
{unit_files}

BATTERY candidates for this unit (start deep reading at these loci):
{battery}

HISTORICAL heat for this unit (verify each on current bytes; a historical
claim is a lead, never a conclusion):
{priors_heat}

Return JSONL only, one object per candidate, using exactly:
{{"path":"relative/path","line":1,"lens":"{lens}","category":"...","severity":"HIGH","title":"...","evidence":"kind-only evidence; never literal secrets or PII","reach_basis":"file:line or stated absence"}}
Return no markdown. An empty result is valid."""

SWEEP_TASK = """LUCY SWEEP LENS={lens}
Cross-repository sweep. You receive no battery or historical heat by design —
sweeps stay cold so their discoveries are independent evidence. Coverage is
already proven; do NOT open every file. Search ONLY the allowed reader files
below. Rows naming any other path are mechanically rejected.
ALLOWED READER FILES:
{allowed_files}

Grep the allowed files for your lens's signature patterns, then deep-read at
most 30 of them: the strongest cross-repository signals (same secret/idiom/
config in 2+ top-level directories, trust relationships between services).
Report only NEW cross-repo candidates. Return JSONL only in the reader schema
with lens "{lens}". An empty result is valid."""

COURT_TASK = """LUCY COURT
CANDIDATE_ID={id}
CLAIM={title}
LOCUS={path}:{line}
CATEGORY={category}
PROPOSED_SEVERITY={severity}

Attempt to disprove this claim from workspace bytes. Return exactly one JSON
object and no markdown:
{{"candidate_id":"{id}","verdict":"VERIFIED|CONDITIONAL|REFUTED","severity":"PRIORITIZED_CRITICAL|CRITICAL|HIGH|MEDIUM|LOW","cwe":"CWE-N","disproof_attempt":"...","basis":"static-reasoned","reach_basis":"...","fix":"specific imperative remediation or No code change required; reason"}}"""

LENSES = ("L1-auth", "L2-secrets", "L3-injection", "L4-infra")
MAX_PASSES = 6
COURT_BATCH_MAX = 16
COURT_FIRST_MULTIPLIER = 2
_LIVENESS_LOCK = threading.Lock()


def _jsonl_only(text: str) -> str:
    lines = []
    for line in text.splitlines():
        line = line.strip().strip("`")
        if line.startswith("{") and line.endswith("}"):
            lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")


def scoped_jsonl(text: str, allowed_paths: set[str]) -> tuple[str, int]:
    """Keep model rows inside the deterministic reader universe."""
    kept: list[str] = []
    rejected = 0
    for line in _jsonl_only(text).splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            kept.append(line)
            continue
        if str(row.get("path", "")) not in allowed_paths:
            rejected += 1
            continue
        kept.append(line)
    return "\n".join(kept) + ("\n" if kept else ""), rejected


def write_scope_receipt(run_dir: Path, lane: str, rejected: int) -> None:
    if rejected <= 0:
        return
    receipts = run_dir / "receipts"
    receipts.mkdir(parents=True, exist_ok=True)
    safe_lane = re.sub(r"[^A-Za-z0-9_.-]", "_", lane)
    (receipts / f"SCOPE_REJECT-{safe_lane}.json").write_text(
        json.dumps(
            {
                "schema": "lucy-scope-reject/v1",
                "lane": lane,
                "rejected_rows": rejected,
                "basis": "path absent from computed reader-unit set",
            },
            indent=2,
            sort_keys=True,
        )
        + "\n",
        encoding="utf-8",
    )


def _atomic_text(path: Path, text: str) -> None:
    temporary = path.with_name(f".{path.name}.tmp")
    temporary.write_text(text, encoding="utf-8")
    temporary.replace(path)


def _write_json_atomic(path: Path, value: dict[str, Any]) -> None:
    _atomic_text(path, json.dumps(value, indent=2, sort_keys=True) + "\n")


def _run_toolbox(script: str, workspace: Path, output: Path) -> None:
    from lucy.runtime.assets import verify_asset

    toolbox = Path(__file__).parents[1] / "toolbox" / script
    verify_asset(toolbox)
    result = subprocess.run(
        [sys.executable, str(toolbox), str(workspace)],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise RuntimeError(
            f"{script} failed: {(result.stderr or result.stdout).strip()[:300]}"
        )
    _atomic_text(output, result.stdout)


def _liveness_path(run_dir: Path) -> Path:
    return run_dir / "receipts" / "LIVENESS.jsonl"


def _open_deaths(run_dir: Path, label: str) -> int:
    path = _liveness_path(run_dir)
    if not path.is_file():
        return 0
    open_count = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("lane") != label:
            continue
        if row.get("event") == "lane-dead":
            open_count += 1
        elif row.get("event") in {"lane-relaunched", "lane-adopted-empty"} and open_count:
            open_count -= 1
    return open_count


def _append_liveness(run_dir: Path, row: dict[str, Any]) -> None:
    path = _liveness_path(run_dir)
    with _LIVENESS_LOCK:
        path.parent.mkdir(parents=True, exist_ok=True)
        with path.open("a", encoding="utf-8") as handle:
            handle.write(json.dumps(row, sort_keys=True) + "\n")


def _lane_guarded(run_dir: Path, label: str, work: Callable[[], None]) -> None:
    """Retry once and close every prior orphan only after output is accepted."""
    orphaned = _open_deaths(run_dir, label)
    failures = 0
    try:
        work()
    except Exception as error:  # noqa: BLE001 - receipted, retried, fail-closed
        failures = 1
        _append_liveness(
            run_dir,
            {"event": "lane-dead", "lane": label, "error": str(error)[:200]},
        )
        work()
    for index in range(orphaned + failures):
        _append_liveness(
            run_dir,
            {
                "event": "lane-relaunched",
                "lane": label,
                "basis": "accepted replacement output"
                + (" after command resume" if index < orphaned else ""),
            },
        )


def _severity_rank(value: str) -> int:
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
        "PRIORITIZED_CRITICAL": 5,
    }.get(str(value).upper(), 0)


def court_needs_dispatch(candidate: dict[str, Any], verdict_file: Path) -> bool:
    """Missing, malformed, wrong-id, or stale-severity verdicts need court."""
    if not verdict_file.is_file():
        return True
    docs = []
    for line in verdict_file.read_text(encoding="utf-8").splitlines():
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(row, dict):
            docs.append(row)
    if not docs:
        return True
    verdict = max(docs, key=len)
    if verdict.get("candidate_id") != candidate.get("id"):
        return True
    if str(verdict.get("verdict", "")).upper() not in {
        "VERIFIED",
        "CONDITIONAL",
        "REFUTED",
    }:
        return True
    if str(verdict.get("severity", "")).upper() not in SEVERITIES:
        return True
    proposed = verdict.get("proposed_severity")
    if proposed is None:
        return False
    return _severity_rank(candidate.get("severity", "")) > _severity_rank(str(proposed))


def normalized_court_verdict(
    docs: list[dict[str, Any]], candidate: dict[str, Any]
) -> dict[str, Any]:
    """Accept one contract-valid verdict or conservatively retain the claim.

    A parseable but wrong-id/off-enum object must not enter an infinite
    dispatch loop, and it must never be allowed to refute a different claim.
    Falling back to CONDITIONAL at the proposed severity is fail-safe: the
    candidate stays in the report at worst-plausible severity.
    """
    verdict = max(docs, key=len) if docs else None
    valid = bool(
        verdict
        and verdict.get("candidate_id") == candidate.get("id")
        and str(verdict.get("verdict", "")).upper()
        in {"VERIFIED", "CONDITIONAL", "REFUTED"}
        and str(verdict.get("severity", "")).upper() in SEVERITIES
    )
    if valid:
        normalized = dict(verdict or {})
        normalized["verdict"] = str(normalized["verdict"]).upper()
        normalized["severity"] = str(normalized["severity"]).upper()
    else:
        normalized = {
            "candidate_id": candidate["id"],
            "verdict": "CONDITIONAL",
            "severity": candidate["severity"],
            "cwe": "CWE-693",
            "disproof_attempt": (
                "court returned no contract-valid verdict; retained at "
                "worst-plausible severity"
            ),
            "basis": "static-reasoned",
            "reach_basis": candidate["reach_basis"],
            "fix": "Review the cited locus manually.",
        }
    normalized["proposed_severity"] = candidate["severity"]
    return normalized


def _typical_serious_yield(run_dir: Path) -> int:
    path = run_dir / "receipts" / "PASS_HISTORY.json"
    if not path.is_file():
        return 1
    entries = json.loads(path.read_text(encoding="utf-8")).get("passes", [])
    yields = [
        len(entry.get("new_serious", []))
        for entry in entries
        if entry.get("phase") != "sweep"
        and "full" in set((entry.get("unit_modes") or {}).values() or ["full"])
    ]
    if not yields:
        return 1
    ordered = sorted(yields)
    return max(1, ordered[len(ordered) // 2])


def run_review(
    host: AgentHost,
    workspace: Path,
    run_dir: Path,
    results_root: Path,
    *,
    width: int = SOFT_START_WIDTH,
    max_lanes: int | None = None,
) -> dict[str, Any]:
    """Run or resume the launcher-owned review using Claude's written laws."""
    staging = run_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    if not (staging / "CENSUS.txt").is_file():
        _run_toolbox("census.py", workspace, staging / "CENSUS.txt")
    if not (staging / "BATTERY.txt").is_file():
        _run_toolbox("detector_battery_v3_3_1.py", workspace, staging / "BATTERY.txt")
    if not (staging / "UNITS.json").is_file():
        units_summary = write_units(workspace, run_dir)
    else:
        units_summary = json.loads((staging / "UNITS.json").read_text(encoding="utf-8"))
    unit_ids = [unit["id"] for unit in units_summary["units"]]
    unit_files_map = {
        unit_id: {
            path
            for path in (staging / f"{unit_id}.txt").read_text(encoding="utf-8").splitlines()
            if path.strip()
        }
        for unit_id in unit_ids
    }
    all_reader_files = set().union(*unit_files_map.values()) if unit_files_map else set()
    repo_count = len({path.split("/")[0] for path in all_reader_files})
    effective_cap = max(1, min(20, max_lanes if max_lanes is not None else lane_cap()))
    current_width = max(1, min(effective_cap, width))

    def reader_lane(pass_number: int, lens: str, unit_id: str) -> None:
        unit_files = "\n".join(sorted(unit_files_map[unit_id])) + "\n"
        battery_path = staging / f"{unit_id}-BATTERY.txt"
        battery = battery_path.read_text(encoding="utf-8") if battery_path.is_file() else "none"
        heat_path = staging / f"{unit_id}-PRIORS.txt"
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
        payload, rejected = scoped_jsonl(response, unit_files_map[unit_id])
        output = staging / f"lane-pass{pass_number}-{lens}-{unit_id}.jsonl"
        _atomic_text(output, payload)
        write_scope_receipt(run_dir, f"pass{pass_number}-{lens}-{unit_id}", rejected)

    def sweep_lane(lens: str) -> None:
        response = host.run_agent(
            system=READER_SYSTEM,
            task=SWEEP_TASK.format(
                lens=lens, allowed_files="\n".join(sorted(all_reader_files))
            ),
            workspace=workspace,
        )
        payload, rejected = scoped_jsonl(response, all_reader_files)
        _atomic_text(staging / f"lane-sweep-{lens}.jsonl", payload)
        write_scope_receipt(run_dir, f"sweep-{lens}", rejected)

    def court_lane(candidate: dict[str, Any]) -> None:
        response = host.run_agent(
            system=COURT_SYSTEM,
            task=COURT_TASK.format(**candidate),
            workspace=workspace,
        )
        docs = []
        for line in _jsonl_only(response).splitlines():
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue
            if isinstance(row, dict):
                docs.append(row)
        verdict = normalized_court_verdict(docs, candidate)
        court_dir = staging / "courts"
        court_dir.mkdir(exist_ok=True)
        _atomic_text(
            court_dir / f"{candidate['id']}.json",
            json.dumps(verdict, sort_keys=True) + "\n",
        )

    def candidate_map() -> dict[str, dict[str, Any]]:
        path = run_dir / "candidates.jsonl"
        return {row["id"]: row for row in read_jsonl(path)} if path.is_file() else {}

    def output_for(item: dict[str, Any]) -> Path:
        if item["kind"] == "reader":
            return staging / f"lane-pass{item['pass']}-{item['lens']}-{item['unit']}.jsonl"
        if item["kind"] == "sweep":
            return staging / f"lane-sweep-{item['lens']}.jsonl"
        return staging / "courts" / f"{item['candidate_id']}.json"

    def item_complete(item: dict[str, Any], candidates: dict[str, dict[str, Any]]) -> bool:
        output = output_for(item)
        if item["kind"] != "court":
            return output.is_file()
        candidate = candidates.get(item["candidate_id"])
        return candidate is not None and not court_needs_dispatch(candidate, output)

    def perform(item: dict[str, Any], candidates: dict[str, dict[str, Any]]) -> None:
        if item_complete(item, candidates):
            return
        if item["kind"] == "reader":
            label = f"pass{item['pass']}-{item['lens']}-{item['unit']}"
            work = lambda: reader_lane(item["pass"], item["lens"], item["unit"])
        elif item["kind"] == "sweep":
            label = f"sweep-{item['lens']}"
            work = lambda: sweep_lane(item["lens"])
        else:
            candidate = candidates[item["candidate_id"]]
            label = f"court-{candidate['id']}"
            work = lambda: court_lane(candidate)
        _lane_guarded(run_dir, label, work)

    wave_path = staging / "CURRENT_WAVE.json"

    def execute_wave(items: list[dict[str, Any]], *, wave_width: int) -> None:
        nonlocal current_width
        _write_json_atomic(
            wave_path,
            {"schema": "lucy-dispatch-wave/v1", "width": wave_width, "items": items},
        )
        candidates = candidate_map()
        with ThreadPoolExecutor(max_workers=max(1, min(effective_cap, wave_width))) as pool:
            list(pool.map(lambda item: perform(item, candidates), items))
        wave_path.unlink(missing_ok=True)
        current_width = min(effective_cap, ramp_width(current_width))

    def resume_wave_if_present() -> bool:
        if not wave_path.is_file():
            return False
        wave = json.loads(wave_path.read_text(encoding="utf-8"))
        items = list(wave.get("items", []))
        wave_width = max(1, min(effective_cap, int(wave.get("width", current_width))))
        execute_wave(items, wave_width=wave_width)
        if any(item.get("kind") in {"reader", "sweep"} for item in items):
            merge_candidates(run_dir, workspace, results_root)
        return True

    resume_wave_if_present()

    pass_numbers = [
        int(match.group(1))
        for path in staging.glob("lane-pass*-*.jsonl")
        if (match := re.match(r"lane-pass(\d+)-", path.name))
    ]
    pass_number = max(pass_numbers, default=0)

    if not (run_dir / "candidates.jsonl").is_file():
        pass_number = max(1, pass_number)
        initial = [
            {"kind": "reader", "pass": pass_number, "lens": lens, "unit": unit_id}
            for unit_id in unit_ids
            for lens in LENSES
        ]
        execute_wave(initial, wave_width=current_width)
        merge_candidates(run_dir, workspace, results_root)

    # Resume seam: an interrupted pass-one wave is merged by
    # resume_wave_if_present(), so candidates.jsonl may already exist even
    # though the required multi-repo sweeps never dispatched. Backfill any
    # missing sweep here, after pass one and before convergence accounting.
    if pass_number >= 1 and repo_count >= 2:
        sweeps = [{"kind": "sweep", "lens": lens} for lens in LENSES]
        if any(not output_for(item).is_file() for item in sweeps):
            execute_wave(sweeps, wave_width=current_width)
            merge_candidates(run_dir, workspace, results_root)

    def missing_courts() -> list[dict[str, Any]]:
        court_dir = staging / "courts"
        return [
            row
            for row in candidate_map().values()
            if row["severity"] in SERIOUS
            and court_needs_dispatch(row, court_dir / f"{row['id']}.json")
        ]

    while pass_number < MAX_PASSES:
        convergence = unit_convergence_map(run_dir)
        active = [unit_id for unit_id in unit_ids if convergence.get(unit_id) != "quiet"]
        if not active:
            break
        courts = missing_courts()
        typical_yield = _typical_serious_yield(run_dir)
        if len(courts) > COURT_FIRST_MULTIPLIER * typical_yield:
            execute_wave(
                [
                    {"kind": "court", "candidate_id": row["id"]}
                    for row in courts[:COURT_BATCH_MAX]
                ],
                wave_width=current_width,
            )
            continue

        pass_number += 1
        readers: list[dict[str, Any]] = []
        history_path = run_dir / "receipts" / "PASS_HISTORY.json"
        history = (
            json.loads(history_path.read_text(encoding="utf-8")).get("passes", [])
            if history_path.is_file()
            else []
        )
        prior_confirm_lenses = {
            unit_id: {
                lens
                for entry in history
                if (entry.get("unit_modes") or {}).get(unit_id) == "confirm"
                for lens in (entry.get("unit_lenses") or {}).get(unit_id, [])
            }
            for unit_id in unit_ids
        }
        for unit_id in active:
            if convergence.get(unit_id) == "confirm":
                used = prior_confirm_lenses[unit_id]
                lens = next((value for value in LENSES if value not in used), LENSES[pass_number % 4])
                readers.append(
                    {"kind": "reader", "pass": pass_number, "lens": lens, "unit": unit_id}
                )
            else:
                readers.extend(
                    {"kind": "reader", "pass": pass_number, "lens": lens, "unit": unit_id}
                    for lens in LENSES
                )
        court_items = [
            {"kind": "court", "candidate_id": row["id"]}
            for row in courts[:COURT_BATCH_MAX]
        ]
        execute_wave(court_items + readers, wave_width=current_width)
        merge_candidates(run_dir, workspace, results_root)

    while True:
        courts = missing_courts()
        if not courts:
            break
        execute_wave(
            [
                {"kind": "court", "candidate_id": row["id"]}
                for row in courts[:COURT_BATCH_MAX]
            ],
            wave_width=current_width,
        )

    candidates = read_jsonl(run_dir / "candidates.jsonl")
    serious_rows = [row for row in candidates if row["severity"] in SERIOUS]
    findings = finalize(run_dir, workspace, results_root)
    convergence = unit_convergence_map(run_dir)
    quiet_units = sum(state == "quiet" for state in convergence.values())
    (run_dir / "COMPLETION.md").write_text(
        "# COMPLETION\n"
        f"Passes: {pass_number} · units: {len(unit_ids)} · candidates: {len(candidates)} · "
        f"serious courted: {len(serious_rows)} · emitted: "
        f"{sum(1 for row in findings if row['status'] != 'refuted')} · refuted: "
        f"{sum(1 for row in findings if row['status'] == 'refuted')}\n"
        "RECALL: EXTERNAL-PENDING\n",
        encoding="utf-8",
    )
    return {
        "passes": pass_number,
        "units": len(unit_ids),
        "quiet_units": quiet_units,
        "candidates": len(candidates),
        "courted": len(serious_rows),
    }
