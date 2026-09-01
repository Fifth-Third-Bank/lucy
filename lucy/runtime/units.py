#!/usr/bin/env python3
"""Deterministic unit partitioning for scan mode.

Reuses the pinned toolbox census constants and extends their filename rules
with extensionless shebang scripts.  Executable wrappers are security-critical
source even when archives or package installs do not preserve executable mode.
Units are cut repo-first-fit-decreasing at the census cap and written as
UNIT-NNN.txt file lists for reader lanes.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import sys


def _load_census_module():
    import warnings

    toolbox = Path(__file__).parents[1] / "toolbox" / "census.py"
    from lucy.runtime.assets import verify_asset

    verify_asset(toolbox)
    spec = importlib.util.spec_from_file_location("lucy_census", toolbox)
    module = importlib.util.module_from_spec(spec)
    with warnings.catch_warnings():
        # Keep warning handling local to this imported command-line asset so
        # a future interpreter warning cannot alter the caller's policy.
        warnings.simplefilter("ignore", SyntaxWarning)
        spec.loader.exec_module(module)  # type: ignore[union-attr]
    return module


def _has_shebang(path: Path) -> bool:
    """Recognize extensionless scripts by bytes, not executable mode."""
    try:
        with path.open("rb") as handle:
            return handle.read(2) == b"#!"
    except OSError:
        return False


CENSUS_RULES = "ext+shebang/v2"  # recorded per run; certification replays the run's own rules


def compute_units(workspace: Path, *, census_rules: str = CENSUS_RULES) -> dict:
    census = _load_census_module()
    repos, zones, lock_loc, raw, suspects, staging_loc, staging_files = census.census(
        str(workspace)
    )
    code_ext = census.CODE_EXT
    code_names = census.CODE_NAMES
    lockfiles = census.LOCKFILES
    zone_names = set(census.ZONES)
    per_repo_files: dict[str, list[str]] = {}
    shebang_loc: dict[str, int] = {}
    shebang_files: dict[str, int] = {}
    for path in sorted(workspace.rglob("*")):
        if path.is_symlink() or not path.is_file():
            continue
        relative = path.relative_to(workspace)
        parts = relative.parts
        if ".git" in parts or parts[0] in zone_names:
            continue
        if len(parts) == 1 and parts[0].startswith("PRIORS_"):
            continue
        name = path.name
        if name in lockfiles:
            continue
        named_source = path.suffix.lower() in code_ext or name in code_names
        shebang_source = (
            census_rules != "ext/v1" and not named_source and _has_shebang(path)
        )
        if named_source or shebang_source:
            repo = parts[0] if len(parts) > 1 else "(root)"
            per_repo_files.setdefault(repo, []).append(relative.as_posix())
            if shebang_source:
                shebang_loc[repo] = shebang_loc.get(repo, 0) + census.count_lines(path)
                shebang_files[repo] = shebang_files.get(repo, 0) + 1

    # The pinned census predates shebang discovery. Add only the newly
    # recognized lines here so partition size, estimates, and fresh C1 walks
    # agree with the actual reader file lists without double counting.
    for repo, loc in shebang_loc.items():
        data = repos.setdefault(repo, {"loc": 0, "files": 0, "biggest": (0, "")})
        data["loc"] += loc
        data["files"] += shebang_files[repo]
    raw += sum(shebang_loc.values())
    suspect_loc = {repo: lines for repo, _path, lines in suspects}
    sized = sorted(
        ((max(data["loc"] - suspect_loc.get(repo, 0), 0), repo) for repo, data in repos.items()),
        key=lambda item: (-item[0], item[1]),
    )
    scannable = sum(loc for loc, _ in sized)
    cap = max(50000, -(-scannable // 40))
    units: list[list] = []
    for loc, repo in sized:
        placed = False
        for unit in units:
            if unit[0] + loc <= cap:
                unit[0] += loc
                unit[1].append(repo)
                placed = True
                break
        if not placed:
            units.append([loc, [repo]])

    unit_rows = []
    total_files = 0
    for index, (loc, repo_list) in enumerate(units, 1):
        files: list[str] = []
        for repo in repo_list:
            files.extend(per_repo_files.get(repo, []))
        files.sort()
        total_files += len(files)
        unit_rows.append(
            {"id": f"UNIT-{index:03d}", "loc": loc, "repos": repo_list, "files": files}
        )
    return {
        "schema": "lucy-units/v1",
        "census_rules": census_rules,
        "cap": cap,
        "scannable_loc": scannable,
        "raw_loc": raw,
        "total_files": total_files,
        "mass_suspects": [
            {"repo": repo, "path": path, "lines": lines} for repo, path, lines in suspects
        ],
        "units": unit_rows,
    }


def write_units(workspace: Path, run_dir: Path) -> dict:
    plan = compute_units(workspace)
    staging = run_dir / "staging"
    staging.mkdir(parents=True, exist_ok=True)
    battery_hits = _battery_hits_by_path(staging / "BATTERY.txt")
    for unit in plan["units"]:
        (staging / f"{unit['id']}.txt").write_text(
            "\n".join(unit["files"]) + "\n", encoding="utf-8"
        )
        # Deterministic battery seed per unit: injected into reader briefs
        # MECHANICALLY (never orchestrator prose), restoring the source
        # method's battery-seeded briefs without a canary-leak channel.
        unit_hits = [hit for hit in battery_hits if hit.split(":", 1)[0] in set(unit["files"])]
        (staging / f"{unit['id']}-BATTERY.txt").write_text(
            ("\n".join(unit_hits) + "\n") if unit_hits else "no battery candidates\n",
            encoding="utf-8",
        )
    # Priors heat (when the launcher staged it): distributed per unit like
    # battery seeds — mechanical, never orchestrator-composed. Sweep lanes
    # receive no heat file by design.
    heat_doc = run_dir / "receipts" / "PRIORS_HEATED.json"
    if heat_doc.is_file():
        from lucy.runtime.priors import write_heat_files

        heated = json.loads(heat_doc.read_text(encoding="utf-8")).get("heated", [])
        write_heat_files(
            heated,
            {unit["id"]: unit["files"] for unit in plan["units"]},
            staging,
        )
    summary = {
        key: value for key, value in plan.items() if key != "units"
    }
    summary["units"] = [
        {"id": unit["id"], "loc": unit["loc"], "repos": unit["repos"], "files": len(unit["files"])}
        for unit in plan["units"]
    ]
    (staging / "UNITS.json").write_text(
        json.dumps(summary, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )
    return summary


def _battery_hits_by_path(battery_path: Path) -> list[str]:
    """Parse detector-battery JSONL into 'path:line detector' seed lines."""
    if not battery_path.is_file():
        return []
    hits = []
    for line in battery_path.read_text(encoding="utf-8", errors="replace").splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            row = json.loads(line)
        except json.JSONDecodeError:
            continue
        if row.get("path"):
            hits.append(f"{row['path']}:{row.get('line', 1)} {row.get('detector', 'detector')}")
    return hits


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--workspace", type=Path, required=True)
    parser.add_argument("--run-dir", type=Path, required=True)
    args = parser.parse_args()
    try:
        # Same cross-run confinement as lucy-merge/finalize: honor the
        # launcher's session pin when present.
        import os

        pinned = os.environ.get("LUCY_RUN_DIR")
        if pinned and Path(pinned).resolve() != args.run_dir.resolve():
            raise ValueError(
                f"--run-dir {args.run_dir} is not this session's pinned run ({pinned})"
            )
        summary = write_units(args.workspace.resolve(), args.run_dir.resolve())
    except (OSError, ValueError) as error:
        print(f"unit partitioning failed: {error}", file=sys.stderr)
        return 1
    print(json.dumps(summary, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
