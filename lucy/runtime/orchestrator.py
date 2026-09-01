"""Deterministic review orchestrator for API-driven hosts.

Replaces the Claude Code skill session: passes, the quiet law, sweeps, and
courts are CODE here, not prompt prose — the model is used only inside reader
and court agent loops (see host.py). Writes the exact staging layout the
existing merge/finalize/scoring/seal machinery consumes, so everything
downstream of reading is shared with the Claude host, byte for byte.
"""

from __future__ import annotations

from concurrent.futures import ThreadPoolExecutor
import json
from pathlib import Path
import subprocess
import sys
from typing import Any

from lucy.runtime.artifacts import merge_candidates, finalize, read_jsonl, SERIOUS
from lucy.runtime.host import AgentHost
from lucy.runtime.loop_policy import (
    MAX_WIDTH,
    QUIET_MAX_NEW_SERIOUS_PER_UNIT,
    SOFT_START_WIDTH,
    lane_cap,
    unit_is_quiet,
)
from lucy.runtime.units import write_units


READER_SYSTEM = (Path(__file__).parents[1] / "agents" / "lucy-reader.md").read_text(
    encoding="utf-8"
).split("---", 2)[-1].strip()
COURT_SYSTEM = (Path(__file__).parents[1] / "agents" / "lucy-court.md").read_text(
    encoding="utf-8"
).split("---", 2)[-1].strip()

READER_TASK = """LUCY READER PASS={pass_number} LENS={lens}
UNIT_FILE contents (read every listed file per your contract):
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
already proven; do NOT open every file.
Grep the whole workspace for your lens's signature patterns, then deep-read at
most 30 files: the strongest cross-repository signals (same secret/idiom/
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


def _jsonl_only(text: str) -> str:
    lines = []
    for line in text.splitlines():
        line = line.strip().strip("`")
        if line.startswith("{") and line.endswith("}"):
            lines.append(line)
    return "\n".join(lines) + ("\n" if lines else "")


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
    output.write_text(result.stdout, encoding="utf-8")


def _lane_guarded(run_dir: Path, label: str, work) -> None:
    """Run one lane; on abnormal end, receipt the death, relaunch once, and
    receipt the relaunch for the seal card's deaths==redispatched ledger. A second failure
    propagates - a lost lane must fail the run loudly, never count as a
    clean quiet pass."""
    import json as _json

    try:
        work()
        return
    except Exception as error:  # noqa: BLE001 - receipted and retried once
        liveness = run_dir / "receipts" / "LIVENESS.jsonl"
        liveness.parent.mkdir(parents=True, exist_ok=True)
        with liveness.open("a", encoding="utf-8") as handle:
            handle.write(_json.dumps({"event": "lane-dead", "lane": label, "error": str(error)[:200]}) + "\n")
        work()
        with liveness.open("a", encoding="utf-8") as handle:
            handle.write(_json.dumps({"event": "lane-relaunched", "lane": label}) + "\n")


def run_review(
    host: AgentHost,
    workspace: Path,
    run_dir: Path,
    results_root: Path,
    *,
    width: int = SOFT_START_WIDTH,
) -> dict[str, Any]:
    staging = run_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    _run_toolbox("census.py", workspace, staging / "CENSUS.txt")
    _run_toolbox("detector_battery_v3_3_1.py", workspace, staging / "BATTERY.txt")
    units_summary = write_units(workspace, run_dir)
    unit_ids = [unit["id"] for unit in units_summary["units"]]
    repo_count = len(
        {
            path.split("/")[0]
            for unit_id in unit_ids
            for path in (staging / f"{unit_id}.txt").read_text(encoding="utf-8").splitlines()
            if path.strip()
        }
    )

    def reader_lane(pass_number: int, lens: str, unit_id: str) -> None:
        unit_files = (staging / f"{unit_id}.txt").read_text(encoding="utf-8")
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
        (staging / f"lane-pass{pass_number}-{lens}-{unit_id}.jsonl").write_text(
            _jsonl_only(response), encoding="utf-8"
        )

    def sweep_lane(lens: str) -> None:
        response = host.run_agent(
            system=READER_SYSTEM,
            task=SWEEP_TASK.format(lens=lens),
            workspace=workspace,
        )
        (staging / f"lane-sweep-{lens}.jsonl").write_text(
            _jsonl_only(response), encoding="utf-8"
        )

    # Pass loop under the quiet law (per-unit independence).
    unit_new_serious: dict[str, list[int]] = {unit_id: [] for unit_id in unit_ids}
    seen_serious: dict[str, set[str]] = {unit_id: set() for unit_id in unit_ids}
    unit_files_map = {
        unit_id: set(
            (staging / f"{unit_id}.txt").read_text(encoding="utf-8").splitlines()
        )
        for unit_id in unit_ids
    }
    active_units = list(unit_ids)
    pass_number = 0
    while active_units and pass_number < MAX_PASSES:
        pass_number += 1
        lanes = [(pass_number, lens, unit_id) for unit_id in active_units for lens in LENSES]
        pool_width = SOFT_START_WIDTH if pass_number == 1 else min(lane_cap(), width * 3)
        with ThreadPoolExecutor(max_workers=pool_width) as pool:
            list(pool.map(lambda lane: _lane_guarded(run_dir, f"pass{lane[0]}-{lane[1]}-{lane[2]}", lambda lane=lane: reader_lane(*lane)), lanes))
        if pass_number == 1 and repo_count >= 2:
            with ThreadPoolExecutor(max_workers=min(4, MAX_WIDTH)) as pool:
                list(pool.map(lambda lens: _lane_guarded(run_dir, f"sweep-{lens}", lambda lens=lens: sweep_lane(lens)), LENSES))
        candidates = merge_candidates(run_dir, workspace, results_root)
        for unit_id in list(active_units):
            files = unit_files_map[unit_id]
            serious_now = {
                row["id"]
                for row in candidates
                if row["severity"] in SERIOUS and row["path"] in files
            }
            new = serious_now - seen_serious[unit_id]
            seen_serious[unit_id] |= serious_now
            unit_new_serious[unit_id].append(len(new))
            if unit_is_quiet(unit_new_serious[unit_id]):
                active_units.remove(unit_id)

    # Courts: one fresh agent per serious candidate, per-verdict files.
    candidates = read_jsonl(run_dir / "candidates.jsonl")
    court_dir = staging / "courts"
    court_dir.mkdir(exist_ok=True)

    def court_lane(candidate: dict[str, Any]) -> None:
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

    serious_rows = [row for row in candidates if row["severity"] in SERIOUS]
    with ThreadPoolExecutor(max_workers=min(lane_cap() + 4, 16)) as pool:
        list(pool.map(lambda row: _lane_guarded(run_dir, f"court-{row['id']}", lambda row=row: court_lane(row)), serious_rows))

    findings = finalize(run_dir, workspace, results_root)
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
        "quiet_units": len(unit_ids) - len(active_units),
        "candidates": len(candidates),
        "courted": len(serious_rows),
    }
