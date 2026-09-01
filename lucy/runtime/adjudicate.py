"""Post-verdict recall adjudication: an advisory agent, never a grader.

When a run ends PROCESS-COMPLETE with recall short, someone must judge
the miss: fair plant the readers should have caught, or a defective
measurement? The deterministic layers answer most of it first (oracle
replay prevents unpassable keys; the recapture ladder receipts shadow
mechanisms; score_recall receipts locus drift). This module packages the
residual judgment call for a bounded, read-only agent.

Integrity constraints (deliberate, do not weaken):
- POST-VERDICT ONLY: refuses to run unless the run is finalized. It can
  never steer a live review.
- NO CUSTODY: the brief is built from the workspace-vs-target diff (the
  plants are visible as diffs once the run is over), findings, court
  records, and receipts. The custody deny-wall stays intact.
- ADVISORY ONLY: it writes ADJUDICATION.md with a recommendation and an
  evidence chain. The --mint-error-slot attestation remains something
  only the operator types; this tool never executes it.
- BIASED BRIEF: its two errors are not symmetric. A wrong "mint error"
  inflates a certification; a wrong "fair plant" costs one recapture.
  The rubric demands mechanical evidence for a mint-error recommendation
  and defaults to "fair miss".
"""

from __future__ import annotations

import difflib
import json
from pathlib import Path
from typing import Any

# Workspace files the launcher adds; not plants.
_WORKSPACE_ARTIFACTS = {
    "PLANT_NOTICE.txt",
    "CMDB_ID.txt",
    "CLAUDE-SECURITY.md",
    ".git",
}

ADJUDICATOR_SYSTEM = """You are a recall adjudicator for a completed LUCY \
security-scan certification run. The run planted defects, the scanner missed \
at least one, and the operator must now decide between three paths: run more \
blind recapture laps, attest a defective measurement (mint error), or accept \
the honest non-certified ending.

Your job: for each MISSED plant in the brief, judge whether it was FINDABLE.

Rules of judgment (asymmetric on purpose):
- Recommend MINT-ERROR only on MECHANICAL evidence that the measurement is
  invalid: the planted mutation is semantically inert, unreachable from any
  caller, structurally unmatchable (e.g. fold-shadowed by a sibling plant,
  already receipted), or the planted line no longer matches its recorded
  hash (locus drift). Cite the exact evidence.
- If the plant is a real, reachable defect a competent reader could report,
  the verdict is FAIR MISS even if it is subtle. Recommend recapture or
  acceptance, never mint-error, for a fair miss.
- If a finding or court record already DESCRIBES the planted defect (even
  inside another finding's prose), say so explicitly and quote it — that is
  evidence of detection that the operator needs.
- When uncertain, the verdict is FAIR MISS. A wrong mint-error inflates a
  certification; a wrong fair-miss only costs one more recapture.

Write your verdict as ADJUDICATION.md in markdown with sections:
## Verdict (one line per missed slot: FAIR MISS or MINT-ERROR CANDIDATE)
## Evidence (per slot: what the diff shows, what findings/courts say, quotes)
## Recommended next command (exactly one, copy-pasteable)
Do not modify any file except by returning this markdown as your final
message. You have read-only tools."""


def _plant_hunks(target: Path, workspace: Path, limit: int = 12) -> list[str]:
    """Unified diffs of every workspace file that differs from the target
    (the plants, visible post-verdict). Pure computation, no custody."""
    hunks: list[str] = []
    for path in sorted(workspace.rglob("*")):
        if not path.is_file():
            continue
        relative = path.relative_to(workspace)
        if any(part in _WORKSPACE_ARTIFACTS for part in relative.parts):
            continue
        counterpart = target / relative
        if not counterpart.is_file():
            continue
        try:
            before = counterpart.read_text(encoding="utf-8", errors="replace")
            after = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        if before == after:
            continue
        diff = "".join(
            difflib.unified_diff(
                before.splitlines(keepends=True),
                after.splitlines(keepends=True),
                fromfile=f"target/{relative.as_posix()}",
                tofile=f"workspace/{relative.as_posix()}",
                n=3,
            )
        )
        if diff:
            hunks.append(diff)
        if len(hunks) >= limit:
            break
    return hunks


def _findings_near(findings: list[dict[str, Any]], path: str) -> list[dict[str, Any]]:
    return [row for row in findings if str(row.get("path", "")) == path][:20]


def build_brief(run_dir: Path, target: Path, workspace: Path) -> str:
    """Deterministic launcher-side brief. Everything in it is post-verdict
    information the operator could assemble by hand."""
    receipts = run_dir / "receipts"
    recall: dict[str, Any] = {}
    try:
        recall = json.loads(
            (receipts / "RECALL_RECEIPT.json").read_text(encoding="utf-8")
        )
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    shadow: list[Any] = []
    try:
        shadow = list(
            json.loads(
                (receipts / "RECAPTURE.json").read_text(encoding="utf-8")
            ).get("recall_shadow")
            or []
        )
    except (OSError, ValueError, json.JSONDecodeError):
        pass
    findings: list[dict[str, Any]] = []
    findings_path = run_dir / "findings.jsonl"
    if findings_path.is_file():
        for line in findings_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                try:
                    findings.append(json.loads(line))
                except json.JSONDecodeError:
                    continue
    hunks = _plant_hunks(target, workspace)
    run_id = run_dir.name
    results_root = run_dir.parents[1]
    sections = [
        "# Recall adjudication brief (post-verdict; launcher-generated)",
        "",
        "## Command context (use these EXACT forms in 'Recommended next command')",
        (
            f"- one more blind cure lap: `lucy recapture --run {run_id} "
            f"--results {results_root} --cure-lap-budget <current laps + 1>`"
        ),
        (
            "- mint-error attestation (ONLY with mechanical evidence): "
            f"`lucy recapture --run {run_id} --results {results_root} "
            '--mint-error-slot <N>:"<your verified basis, >=12 chars>"`'
        ),
        "- accept the honest ending: no command; the findings report is delivered.",
        "",
        "## Recall receipt (per slot)",
        "```json",
        json.dumps(
            {
                "status": recall.get("status"),
                "found": recall.get("found"),
                "cure_laps": recall.get("cure_laps"),
                "locus_drift_slots": recall.get("locus_drift_slots"),
                "slots": recall.get("slots"),
            },
            indent=1,
            sort_keys=True,
        ),
        "```",
        "",
        "## Structural shadow diagnosis (mechanical, from the cure ladder)",
        "```json",
        json.dumps(shadow, indent=1, sort_keys=True),
        "```",
        "",
        "## Planted mutations (workspace vs pristine target)",
    ]
    for hunk in hunks:
        sections += ["```diff", hunk.rstrip("\n"), "```", ""]
    sections.append("## Emitted findings in each planted file")
    planted_paths = sorted(
        {
            hunk.splitlines()[1].split("workspace/", 1)[1]
            for hunk in hunks
            if len(hunk.splitlines()) > 1 and "workspace/" in hunk.splitlines()[1]
        }
    )
    for path in planted_paths:
        rows = _findings_near(findings, path)
        sections += [
            f"### {path}",
            "```json",
            json.dumps(
                [
                    {
                        key: row.get(key)
                        for key in (
                            "id",
                            "line",
                            "lens",
                            "category",
                            "severity",
                            "title",
                            "disproof_attempt",
                        )
                    }
                    for row in rows
                ],
                indent=1,
                sort_keys=True,
            ),
            "```",
            "",
        ]
    return "\n".join(sections) + "\n"


def run_adjudication(
    run_dir: Path, target: Path, workspace: Path, host: Any
) -> Path:
    """Build the brief, run the read-only adjudicator, write ADJUDICATION.md."""
    if not (run_dir / "CERTIFICATION.json").is_file():
        raise ValueError(
            "adjudication is post-verdict only: this run has no "
            "CERTIFICATION.json yet — finish or resume the run first"
        )
    if (run_dir / "staging").exists():
        raise ValueError(
            "adjudication is post-verdict only: staging/ still exists, "
            "so a review or recapture is (or was) in flight"
        )
    _verify_target_baseline(run_dir, target)
    brief = build_brief(run_dir, target, workspace)
    # Both artifacts carry planted-mutation bytes (which can include
    # literal planted secrets) — they must go through the mandatory
    # pre-write redaction sink like every other results artifact, never
    # a raw write.
    from lucy.runtime.results import LocalResultsSink

    sink = LocalResultsSink.create(run_dir.parents[1], workspace)
    brief_path = sink.write_text(
        str((run_dir / "ADJUDICATION_BRIEF.md").relative_to(sink.root)), brief
    )
    response = host.run_agent(
        system=ADJUDICATOR_SYSTEM,
        task=(
            "Adjudicate the missed recall slot(s) described in this brief. "
            "Follow the asymmetric rules of judgment exactly.\n\n"
            + brief_path.read_text(encoding="utf-8")
        ),
        workspace=workspace,
    )
    return sink.write_text(
        str((run_dir / "ADJUDICATION.md").relative_to(sink.root)),
        _verdict_text(response),
    )


def _verify_target_baseline(run_dir: Path, target: Path) -> None:
    """Refuse a diff oracle against a target that moved on since the scan.

    Development continuing after the run would present unrelated changes
    as plants and the adjudicator would judge phantoms. The recorded
    baseline_sha256 is authoritative; a missing
    record (older runs) is noted in the brief path rather than guessed."""
    try:
        recorded = json.loads(
            (run_dir / "trial.json").read_text(encoding="utf-8")
        ).get("baseline_sha256")
    except (OSError, ValueError, json.JSONDecodeError):
        recorded = None
    if not recorded:
        return
    from lucy.runtime.trial import content_hash

    if content_hash(target.resolve()) != recorded:
        raise ValueError(
            "target has changed since the scan (content hash no longer "
            "matches the recorded baseline_sha256) — the diff oracle would "
            "present unrelated development as plants; pass --target with a "
            "pristine copy of the scanned revision"
        )


def _verdict_text(response: str) -> str:
    """Drop agent preamble chatter before the first markdown heading."""
    text = response.strip()
    index = text.find("# ")
    if index > 0:
        text = text[index:]
    return text + "\n"
