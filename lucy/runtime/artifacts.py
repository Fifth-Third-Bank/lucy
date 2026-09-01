#!/usr/bin/env python3
"""Merge lane/court staging data into redacted trial artifacts."""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import sys
from typing import Any

from lucy.runtime.results import LocalResultsSink


SEVERITIES = {"PRIORITIZED_CRITICAL", "CRITICAL", "HIGH", "MEDIUM", "LOW"}
SERIOUS = {"PRIORITIZED_CRITICAL", "CRITICAL", "HIGH"}
_PASS_RE = re.compile(r"lane-pass(\d+)-")
_PASS_LANE_RE = re.compile(
    r"lane-pass(\d+)-(L[1-4]-[A-Za-z0-9_-]+)(?:-(UNIT-\d+))?\.jsonl$"
)


def read_jsonl(path: Path) -> list[dict[str, Any]]:
    rows = []
    for line_number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if not line.strip():
            continue
        try:
            value = json.loads(line)
        except json.JSONDecodeError as error:
            raise ValueError(f"{path}:{line_number}: invalid JSON: {error}") from error
        if not isinstance(value, dict):
            raise ValueError(f"{path}:{line_number}: row must be an object")
        rows.append(value)
    return rows


def normalize_candidate(row: dict[str, Any]) -> dict[str, Any]:
    required = ("path", "line", "lens", "category", "severity", "title", "evidence", "reach_basis")
    missing = [field for field in required if field not in row]
    if missing:
        raise ValueError(f"candidate missing fields: {', '.join(missing)}")
    path = str(row["path"])
    line = row["line"]
    severity = str(row["severity"]).upper()
    if Path(path).is_absolute() or ".." in Path(path).parts:
        raise ValueError("candidate path must be relative")
    if not isinstance(line, int) or isinstance(line, bool) or line < 1:
        raise ValueError("candidate line must be a positive integer")
    if severity not in SEVERITIES:
        raise ValueError(f"invalid severity: {severity}")
    normalized = {
        "path": path,
        "line": line,
        "lens": str(row["lens"]),
        "category": str(row["category"]),
        "severity": severity,
        "title": str(row["title"]),
        "evidence": str(row["evidence"]),
        "reach_basis": str(row["reach_basis"]),
    }
    material = "\0".join([path, str(line), normalized["category"].lower()])
    normalized["id"] = "LUCY-" + hashlib.sha256(material.encode()).hexdigest()[:16]
    return normalized


def fold_candidate(
    by_key: dict[tuple[str, int, str], dict[str, Any]],
    fold_map: dict[str, str],
    candidate: dict[str, Any],
) -> None:
    """Fold one normalized candidate into the accumulator (THE fold law).

    LOCUS FOLDING: nearby citations of one weakness are one finding.
    Readers re-cite known weaknesses a few lines off on every pass;
    exact-line identity minted each offset as a NEW serious id,
    re-opening quiet and adding a court per offset. Folding radius 10
    lines, same file+LENS — never
    the category: category is reader free text, and rewordings of
    one defect can mint fresh serious ids every pass, making quiet
    unreachable at the minimum bar. Lens is machine-set by
    the lane. The recall match window is +/-40, so a folded row
    still scores its plant. Passes stay blind — the fold is
    bookkeeping, not a hint.

    Extracted from merge_candidates so oracle replay exercises the
    IDENTICAL fold the live run uses. Reimplementing the law for replay can
    drift and fail to expose a structurally unmatchable recall slot."""
    key = (candidate["path"], candidate["line"], candidate["lens"])
    existing = by_key.get(key)
    if existing is None:
        # IDENTITY LAW: two rows that hash to the same id (same
        # path+line+category) are one finding even across lenses —
        # the id is the report's primary key and gate R06 refuses
        # duplicates, even when separate lenses report the same root cause.
        for other_key, other in by_key.items():
            if other["id"] == candidate["id"]:
                key = other_key
                existing = other
                break
    if existing is None:
        for (other_path, other_line, other_lens), other in by_key.items():
            if (
                other_path == candidate["path"]
                and other_lens == candidate["lens"]
                and abs(other_line - candidate["line"]) <= 10
            ):
                key = (other_path, other_line, other_lens)
                existing = other
                break
    if existing is None or _severity_rank(candidate["severity"]) > _severity_rank(existing["severity"]):
        folded = dict(candidate)
        if existing is not None:
            # Keep the established locus/id; adopt the stronger grade.
            folded.update({
                "path": existing["path"], "line": existing["line"],
                "id": existing["id"], "lens": existing["lens"],
                "category": existing["category"],
            })
            folded["severity"] = candidate["severity"]
        by_key[key] = folded
        fold_map[candidate["id"]] = folded["id"]
    else:
        fold_map[candidate["id"]] = existing["id"]


def fold_rows(rows: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """Run raw candidate rows through the production fold (identity law +
    locus law) without touching a run directory. Used by oracle replay."""
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    fold_map: dict[str, str] = {}
    for raw in rows:
        fold_candidate(by_key, fold_map, normalize_candidate(raw))
    return sorted(
        by_key.values(), key=lambda row: (row["path"], row["line"], row["id"])
    )


def merge_candidates(run_directory: Path, workspace: Path, results_root: Path) -> list[dict[str, Any]]:
    sink = LocalResultsSink.create(results_root, workspace)
    run_directory = run_directory.resolve()
    staging = run_directory / "staging"
    files = sorted(staging.glob("lane-*.jsonl"))
    if not files:
        raise ValueError("no lane staging files found")
    by_key: dict[tuple[str, int, str], dict[str, Any]] = {}
    fold_map: dict[str, str] = {}
    quarantined: list[dict[str, Any]] = []
    for path in files:
        for raw in read_jsonl(path):
            try:
                candidate = normalize_candidate(raw)
            except ValueError as error:
                # One nonconforming lane row must not kill the run. The row is
                # quarantined with its reason — receipted, never silently
                # coerced into a valid tier. Only structural fields are
                # receipted; free text stays out of receipts (they bypass
                # the redaction sink).
                fields = raw if isinstance(raw, dict) else {}
                quarantined.append(
                    {
                        "lane_file": path.name,
                        "reason": str(error),
                        "row": {
                            key: fields.get(key)
                            for key in ("path", "line", "severity", "category")
                        },
                    }
                )
                continue
            fold_candidate(by_key, fold_map, candidate)
    if quarantined:
        receipts_dir = run_directory / "receipts"
        receipts_dir.mkdir(parents=True, exist_ok=True)
        with (receipts_dir / "QUARANTINED.jsonl").open("a", encoding="utf-8") as handle:
            for entry in quarantined:
                handle.write(json.dumps(entry, sort_keys=True) + "\n")
    candidates = sorted(by_key.values(), key=lambda row: (row["path"], row["line"], row["id"]))
    payload = "".join(json.dumps(row, sort_keys=True) + "\n" for row in candidates)
    relative = str((run_directory / "candidates.jsonl").relative_to(sink.root))
    sink.write_text(relative, payload)

    # Pass-history receipt: per-pass observed candidate ids (for quiet-law
    # accounting and capture-recapture coverage bounds at seal time).
    # SWEEP LANES COUNT: estate-wide sweeps dispatch after pass 1, so their
    # observations form a distinct history slot ordered right after pass 1.
    # Without this, a serious sweep finding lands in the ledger but stays
    # invisible to the quiet law — C2 could certify a quiet that is no longer
    # true (creator-review finding: sweeps must re-open a unit exactly as a
    # confirmation-lane finding does).
    passes: dict[int, set[str]] = {}
    pass_severity: dict[int, dict[str, str]] = {}
    sweep_ids: set[str] = set()
    sweep_severity: dict[str, str] = {}
    unit_listings = [
        listing
        for listing in sorted(staging.glob("UNIT-*.txt"))
        if not listing.name.endswith(("-BATTERY.txt", "-PRIORS.txt"))
    ]
    unit_files = {
        listing.stem: {
            line
            for line in listing.read_text(encoding="utf-8").splitlines()
            if line.strip()
        }
        for listing in unit_listings
    }
    pass_unit_lenses: dict[int, dict[str, set[str]]] = {}

    def remember_severity(store: dict[str, str], candidate_id: str, severity: str) -> None:
        previous = store.get(candidate_id)
        if previous is None or _severity_rank(severity) > _severity_rank(previous):
            store[candidate_id] = severity

    for path in files:
        if path.name.startswith("lane-sweep-"):
            for raw in read_jsonl(path):
                try:
                    normalized = normalize_candidate(raw)
                except ValueError:
                    continue
                raw_id = normalized["id"]
                candidate_id = fold_map.get(raw_id, raw_id)
                sweep_ids.add(fold_map.get(raw_id, raw_id))
                remember_severity(sweep_severity, candidate_id, normalized["severity"])
            continue
        match = _PASS_RE.match(path.name)
        if not match:
            continue
        number = int(match.group(1))
        ids = passes.setdefault(number, set())
        severity_by_id = pass_severity.setdefault(number, {})
        lane_match = _PASS_LANE_RE.fullmatch(path.name)
        if lane_match:
            lens = lane_match.group(2)
            unit_id = lane_match.group(3)
            if unit_id is None and len(unit_files) == 1:
                unit_id = next(iter(unit_files))
            if unit_id in unit_files:
                pass_unit_lenses.setdefault(number, {}).setdefault(unit_id, set()).add(lens)
        elif path.name.endswith("-restored.jsonl"):
            # Recapture restores one aggregate file per historical pass. Those
            # source passes were full-width; retain that fact so rebuilding
            # staging cannot erase convergence state.
            for unit_id in unit_files:
                pass_unit_lenses.setdefault(number, {}).setdefault(unit_id, set()).update(
                    {"restored-1", "restored-2", "restored-3", "restored-4"}
                )
        for raw in read_jsonl(path):
            try:
                normalized = normalize_candidate(raw)
            except ValueError:
                continue
            raw_id = normalized["id"]
            candidate_id = fold_map.get(raw_id, raw_id)
            ids.add(candidate_id)
            remember_severity(severity_by_id, candidate_id, normalized["severity"])
    seen: set[str] = set()
    highest_seen: dict[str, str] = {}
    history = []

    def append_entry(
        number: int,
        observed: set[str],
        severity_by_id: dict[str, str],
        phase: str | None = None,
    ) -> None:
        nonlocal seen, highest_seen
        new_serious = []
        for candidate_id in observed:
            previous = highest_seen.get(candidate_id, "")
            current = severity_by_id.get(candidate_id, "")
            if _severity_rank(previous) < _severity_rank("HIGH") <= _severity_rank(current):
                new_serious.append(candidate_id)
        entry = {
            "pass": number,
            "observed": sorted(observed),
            "new": sorted(observed - seen),
            "new_serious": sorted(new_serious),
        }
        if phase:
            entry["phase"] = phase
        if phase != "sweep":
            lenses_by_unit = pass_unit_lenses.get(number, {})
            if lenses_by_unit:
                entry["unit_lenses"] = {
                    unit_id: sorted(lenses)
                    for unit_id, lenses in sorted(lenses_by_unit.items())
                }
                entry["unit_modes"] = {
                    unit_id: (
                        "confirm" if len(lenses) == 1 else "full" if len(lenses) >= 4 else "partial"
                    )
                    for unit_id, lenses in sorted(lenses_by_unit.items())
                }
        history.append(entry)
        seen |= observed
        for candidate_id, severity in severity_by_id.items():
            previous = highest_seen.get(candidate_id)
            if previous is None or _severity_rank(severity) > _severity_rank(previous):
                highest_seen[candidate_id] = severity

    ordered = sorted(passes)
    if not ordered and sweep_ids:
        append_entry(1, sweep_ids, sweep_severity, phase="sweep")
    for number in ordered:
        append_entry(number, passes[number], pass_severity.get(number, {}))
        if number == ordered[0] and sweep_ids:
            append_entry(number, sweep_ids, sweep_severity, phase="sweep")
    sink.write_json(
        str((run_directory / "receipts" / "PASS_HISTORY.json").relative_to(sink.root)),
        {"schema": "lucy-pass-history/v1", "passes": history},
    )
    return candidates


def render_findings_markdown(findings: list[dict[str, Any]]) -> str:
    """Human-readable findings view. Synthetic recall canaries (annotated by
    the launcher after external scoring) are moved out of the main list into
    their own labeled section — they are LUCY's planted test mutations, not
    vulnerabilities in the target."""
    markdown = ["# LUCY Findings", ""]
    real = [row for row in findings if row["status"] != "refuted" and not row.get("synthetic_canary")]
    synthetic = [row for row in findings if row["status"] != "refuted" and row.get("synthetic_canary")]
    for finding in real:
        markdown.extend(
            [
                f"## {finding['severity']}: {finding['title']}",
                "",
                f"- Location: `{finding['path']}:{finding['line']}`",
                f"- Category: `{finding['category']}`",
                f"- Status: `{finding['status']}`",
                "",
                finding["evidence"],
                "",
            ]
        )
    if synthetic:
        markdown.extend(
            [
                "# Synthetic recall canaries (planted by LUCY for the recall test — not real findings)",
                "",
            ]
        )
        for finding in synthetic:
            markdown.extend(
                [
                    f"## SYNTHETIC ({finding['severity']}): {finding['title']}",
                    "",
                    f"- Location: `{finding['path']}:{finding['line']}`",
                    "",
                ]
            )
    refuted_rows = [row for row in findings if row["status"] == "refuted"]
    if refuted_rows:
        markdown.extend(["# Refutations (credibility record — claims disproven by court)", ""])
        for finding in refuted_rows:
            markdown.extend(
                [
                    f"## REFUTED: {finding['title']}",
                    "",
                    f"- Location: `{finding['path']}:{finding['line']}`",
                    f"- Disproof: {finding['disproof_attempt']}",
                    "",
                ]
            )
    return "\n".join(markdown)


def finalize(run_directory: Path, workspace: Path, results_root: Path) -> list[dict[str, Any]]:
    """Fail-closed finalization with ledger conservation.

    Every serious candidate MUST carry a court verdict; refuted rows are
    retained (never silently dropped); candidates == verified + conditional
    + refuted, checked mechanically and receipted.
    """
    sink = LocalResultsSink.create(results_root, workspace)
    run_directory = run_directory.resolve()
    candidates = read_jsonl(run_directory / "candidates.jsonl")
    courts: dict[str, dict[str, Any]] = {}
    court_path = run_directory / "staging" / "courts.jsonl"
    if court_path.exists():
        courts.update({str(row.get("candidate_id")): row for row in read_jsonl(court_path)})
    court_dir = run_directory / "staging" / "courts"
    if court_dir.is_dir():
        for verdict_file in sorted(court_dir.glob("*.json")):
            # A court may emit more than one JSONL line. Parse per line and
            # keep the richest valid object.
            docs = []
            for court_line in verdict_file.read_text(encoding="utf-8").splitlines():
                if not court_line.strip():
                    continue
                try:
                    parsed = json.loads(court_line)
                except json.JSONDecodeError:
                    continue
                if isinstance(parsed, dict):
                    docs.append(parsed)
            if not docs:
                raise ValueError(f"unparseable court verdict file: {verdict_file}")
            row = max(docs, key=len)
            if row.get("candidate_id"):
                courts[str(row["candidate_id"])] = row
    uncourted = [
        candidate["id"]
        for candidate in candidates
        if candidate["severity"] in SERIOUS and candidate["id"] not in courts
    ]
    if uncourted:
        raise ValueError(
            "finalize refused: serious candidates without a court verdict: "
            + ", ".join(sorted(uncourted))
        )
    findings = []
    for candidate in candidates:
        court = courts.get(candidate["id"])
        row = dict(candidate)
        if candidate["severity"] in SERIOUS:
            verdict = str(court.get("verdict", "")).upper()
            if verdict not in {"VERIFIED", "CONDITIONAL", "REFUTED"}:
                raise ValueError(
                    f"finalize refused: court verdict for {candidate['id']} must be "
                    f"VERIFIED, CONDITIONAL, or REFUTED, got {verdict!r}"
                )
            status = {
                "VERIFIED": "verified",
                # Court-CONDITIONAL: mechanism verified, a stated precondition
                # unresolved. Severity stays uncapped (worst-plausible tier);
                # the report carries status conditional and the seal counts it
                # in TIER-WP instead of conflating it with a true MEDIUM.
                "CONDITIONAL": "conditional-court",
                "REFUTED": "refuted",
            }[verdict]
            court_severity = str(court.get("severity", candidate["severity"])).upper()
            if court_severity not in SEVERITIES:
                # Fail closed: an off-enum severity would silently drop the
                # row from the gated report while conservation still balances.
                raise ValueError(
                    f"court verdict for {candidate['id']} carries off-enum "
                    f"severity {court_severity!r}"
                )
            row.update(
                {
                    "status": status,
                    "severity": court_severity,
                    "reach_basis": str(court.get("reach_basis", candidate.get("reach_basis", ""))),
                    "cwe": str(court.get("cwe", "CWE-000")),
                    "disproof_attempt": str(court.get("disproof_attempt", "")),
                    "verification_basis": str(court.get("basis", "static-reasoned")),
                    "fix": str(court.get("fix", "No code change required; refuted claim.")),
                }
            )
        else:
            row["status"] = "conditional"
        findings.append(row)
    emitted = sum(
        1 for row in findings if row["status"] in {"verified", "conditional", "conditional-court"}
    )
    refuted = sum(1 for row in findings if row["status"] == "refuted")
    if emitted + refuted != len(candidates):
        raise ValueError(
            f"ledger conservation failed: {emitted} emitted + {refuted} refuted "
            f"!= {len(candidates)} candidates"
        )
    sink.write_json(
        str((run_directory / "receipts" / "CONSERVATION.json").relative_to(sink.root)),
        {
            "schema": "lucy-conservation/v1",
            "candidates": len(candidates),
            "emitted": emitted,
            "refuted": refuted,
        },
    )
    findings.sort(key=lambda row: (-_severity_rank(row["severity"]), row["path"], row["line"]))
    jsonl = "".join(json.dumps(row, sort_keys=True) + "\n" for row in findings)
    sink.write_text(str((run_directory / "findings.jsonl").relative_to(sink.root)), jsonl)
    sink.write_text(
        str((run_directory / "FINDINGS.md").relative_to(sink.root)),
        render_findings_markdown(findings),
    )
    _finalize_chains(sink, run_directory, findings)
    _preserve_staging_receipts(sink, run_directory)
    shutil.rmtree(run_directory / "staging", ignore_errors=True)
    return findings


def _finalize_chains(
    sink: LocalResultsSink, run_directory: Path, findings: list[dict[str, Any]]
) -> None:
    """Validate orchestrator-proposed chains against finalized findings.

    A chain (staging/chains.jsonl: {id, title, hops:[candidate ids]}) survives
    only when every hop exists and none is refuted; it is `confirmed` when
    every hop is court-verified, else `conditional`. Dropped chains are
    receipted, never silently discarded.
    """
    chains_path = run_directory / "staging" / "chains.jsonl"
    if not chains_path.exists():
        return
    status_by_id = {row["id"]: row["status"] for row in findings}
    kept, dropped = [], []
    for chain in read_jsonl(chains_path):
        chain_id = str(chain.get("id", "")).strip()
        title = str(chain.get("title", "")).strip()
        hops = chain.get("hops")
        if not chain_id or not title or not isinstance(hops, list) or len(hops) < 2:
            dropped.append({"id": chain_id or "?", "reason": "malformed chain row"})
            continue
        hop_ids = [str(hop) for hop in hops]
        missing = [hop for hop in hop_ids if hop not in status_by_id]
        refuted = [hop for hop in hop_ids if status_by_id.get(hop) == "refuted"]
        if missing or refuted:
            dropped.append(
                {"id": chain_id, "reason": f"missing={missing} refuted={refuted}"}
            )
            continue
        kept.append(
            {
                "id": chain_id,
                "title": title,
                "status": "confirmed"
                if all(status_by_id[hop] == "verified" for hop in hop_ids)
                else "conditional",
                "hops": [{"finding_id": hop} for hop in hop_ids],
            }
        )
    sink.write_text(
        str((run_directory / "chains.jsonl").relative_to(sink.root)),
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in kept),
    )
    if dropped:
        sink.write_json(
            str((run_directory / "receipts" / "CHAINS_DROPPED.json").relative_to(sink.root)),
            {"schema": "lucy-chains-dropped/v1", "dropped": dropped},
        )


# Staging members preserved into receipts/ before staging is destroyed —
# the seal/certification generator derives coverage, liveness, and timeline
# facts from these. Lane JSONL and court JSONL stay out (their content
# already lives in candidates/findings).
_PRESERVED_STAGING = ("CENSUS.txt", "BATTERY.txt", "UNITS.json", "WAKE.jsonl", "LIVENESS.jsonl")


def _preserve_staging_receipts(sink: LocalResultsSink, run_directory: Path) -> None:
    staging = run_directory / "staging"
    timeline: dict[str, Any] = {"schema": "lucy-timeline/v1"}
    lane_mtimes = sorted(
        path.stat().st_mtime for path in staging.glob("lane-pass1-*.jsonl") if path.is_file()
    )
    court_path = staging / "courts.jsonl"
    if lane_mtimes:
        timeline["first_pass1_lane_mtime"] = lane_mtimes[0]
        timeline["last_pass1_lane_mtime"] = lane_mtimes[-1]
    if court_path.is_file():
        timeline["courts_mtime"] = court_path.stat().st_mtime
    for name in _PRESERVED_STAGING:
        source = staging / name
        if source.is_file():
            sink.write_text(
                str((run_directory / "receipts" / name).relative_to(sink.root)),
                source.read_text(encoding="utf-8", errors="replace"),
            )
    unit_names = sorted(path.name for path in staging.glob("UNIT-*.txt"))
    timeline["unit_files"] = unit_names
    for name in unit_names:
        sink.write_text(
            str((run_directory / "receipts" / name).relative_to(sink.root)),
            (staging / name).read_text(encoding="utf-8", errors="replace"),
        )
    sink.write_json(
        str((run_directory / "receipts" / "TIMELINE.json").relative_to(sink.root)), timeline
    )


def _severity_rank(severity: str) -> int:
    return {
        "LOW": 1,
        "MEDIUM": 2,
        "HIGH": 3,
        "CRITICAL": 4,
        "PRIORITIZED_CRITICAL": 5,
    }.get(severity, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("merge", "finalize"):
        command = subparsers.add_parser(name)
        command.add_argument("--run-dir", type=Path, required=True)
        command.add_argument("--workspace", type=Path, required=True)
        command.add_argument("--results", type=Path, required=True)
    return parser.parse_args()


def _enforce_run_pin(run_dir: Path) -> None:
    """When the launcher pinned this session to one run (LUCY_RUN_DIR in the
    reviewer environment), refuse any other --run-dir: the Bash prefix grants
    are argument-blind, so this is the wrappers' cross-run confinement.
    Operator invocations without the pin are free."""
    pinned = os.environ.get("LUCY_RUN_DIR")
    if pinned and Path(pinned).resolve() != run_dir.resolve():
        raise ValueError(
            f"--run-dir {run_dir} is not this session's pinned run ({pinned})"
        )


def unit_convergence_map(run_directory: Path) -> dict[str, str]:
    """Return ``loud``, ``confirm``, or ``quiet`` for every reader unit.

    This is THE convergence reducer. A full pass at or below the density bar
    earns a light confirmation; one fresh confirmation lane must then add zero
    new serious candidates. For compatibility with receipts produced before
    light confirmations existed, a second bounded full pass also closes the
    unit. Sweep discoveries are added to pass one's yield and can reopen it,
    but a sweep can never serve as the confirming read.
    """
    from lucy.runtime.loop_policy import quiet_threshold

    receipts = run_directory / "receipts"
    passes: list[dict[str, Any]] = []
    history = receipts / "PASS_HISTORY.json"
    if history.is_file():
        passes = json.loads(history.read_text(encoding="utf-8")).get("passes", [])
    rows = read_jsonl(run_directory / "candidates.jsonl") if (run_directory / "candidates.jsonl").is_file() else []
    row_by_id = {row["id"]: row for row in rows}
    # ACTIVE STAGING WINS: during a live review the unit listings and
    # UNITS.json live under staging/ and only move to receipts/ at finalize
    # — reading receipts alone made merge emit an EMPTY quiet map exactly
    # when the orchestrator needed it, risking redundant passes (external
    # review). Never blend the two directories: current staging listings
    # must not mix with stale finalized ones.
    staging = run_directory / "staging"
    def _unit_listings_in(directory: Path) -> list[Path]:
        return [
            listing for listing in sorted(directory.glob("UNIT-*.txt"))
            if not listing.name.endswith(("-BATTERY.txt", "-PRIORS.txt"))
        ]
    unit_dir = staging if _unit_listings_in(staging) else receipts
    unit_loc: dict[str, int] = {}
    units_meta = unit_dir / "UNITS.json"
    if units_meta.is_file():
        unit_loc = {
            unit.get("id"): int(unit.get("loc", 0) or 0)
            for unit in json.loads(units_meta.read_text(encoding="utf-8")).get("units", [])
        }
    convergence: dict[str, str] = {}
    for listing in _unit_listings_in(unit_dir):
        files = {line for line in listing.read_text(encoding="utf-8").splitlines() if line.strip()}
        bar = quiet_threshold(unit_loc.get(listing.stem, 0))
        cycles: list[dict[str, Any]] = []
        for entry in passes:
            count = sum(
                1
                for candidate_id in entry.get("new_serious", [])
                if row_by_id.get(candidate_id, {}).get("path") in files
            )
            if entry.get("phase") == "sweep":
                if cycles:
                    cycles[-1]["count"] += count
                continue
            modes = entry.get("unit_modes") or {}
            mode = modes.get(listing.stem)
            if mode is None:
                # Legacy histories predate per-unit lane-mode receipts. A
                # numbered pass was full-width under that contract.
                mode = "full"
            if mode != "partial":
                cycles.append({"mode": mode, "count": count})

        state = "loud"
        for cycle in cycles:
            mode, count = cycle["mode"], int(cycle["count"])
            if mode == "confirm":
                state = "quiet" if state == "confirm" and count == 0 else "loud"
                continue
            if count > bar:
                state = "loud"
            elif state == "quiet":
                state = "quiet"
            elif state == "confirm":
                # Legacy second full-width bounded pass.
                state = "quiet"
            else:
                state = "confirm"
        convergence[listing.stem] = state
    return convergence


def unit_quiet_map(run_directory: Path) -> dict[str, bool]:
    """Boolean view of :func:`unit_convergence_map` for gates and display."""
    return {
        unit_id: state == "quiet"
        for unit_id, state in unit_convergence_map(run_directory).items()
    }


def main() -> int:
    args = parse_args()
    try:
        _enforce_run_pin(args.run_dir)
        if args.command == "merge":
            rows = merge_candidates(args.run_dir.resolve(), args.workspace, args.results)
        else:
            rows = finalize(args.run_dir.resolve(), args.workspace, args.results)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        print(f"artifact processing failed: {error}", file=sys.stderr)
        return 1
    # Quiet verdicts ride on merge output so the orchestrator TRUSTS this
    # arithmetic instead of recomputing its own (single source of truth).
    quiet = unit_quiet_map(args.run_dir.resolve()) if args.command == "merge" else {}
    print(json.dumps({"rows": len(rows), **({"quiet": quiet} if quiet else {})}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
