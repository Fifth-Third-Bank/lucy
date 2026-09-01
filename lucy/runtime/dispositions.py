"""Clean-target adjudication of candidates in planter-modified files.

The synthetic/genuine question is CAUSATION, not proximity: a finding that
describes a planted defect can cite a sink far from the mutated line, and a
genuine pre-existing defect can sit right beside a plant. A line window alone
cannot classify either reliably.

Law: every candidate whose file the planter modified receives a disposition.
- A candidate matched one-to-one to a canary slot IS the plant: synthetic,
  basis "recall-matched", no court needed.
- Every other candidate in a planted file is re-adjudicated by a court lane
  against a FRESH CLEAN COPY of the original target: if the claimed defect
  survives on clean bytes it is genuine; if it is refuted on clean bytes it
  exists only because of the plant — synthetic.
- Certification fails closed unless every planted-file candidate carries a
  disposition (completeness is receipted into CERT_RECEIPT.json).
"""

from __future__ import annotations

import json
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
import shutil
import tempfile
from typing import Any


# A silent court gets up to this many additional asks before its candidate
# is receipted unresolved (which blocks certification).
DISPOSITION_RETRIES = 3

DISPOSITION_TASK = """LUCY CLEAN-TARGET DISPOSITION COURT
CANDIDATE_ID={id}
CLAIM={title}
LOCUS={path}:{line}
CATEGORY={category}

You are examining the ORIGINAL, UNMODIFIED codebase. Determine whether the
claimed defect exists in THIS code as it stands. Trace the actual guards,
callers, and data flow — do not assume the claim is true. Return exactly one
JSON object and no markdown:
{{"candidate_id":"{id}","clean_verdict":"PRESENT|ABSENT","basis":"what you traced on these bytes"}}"""


def parse_clean_verdict(response: str, candidate_id: str) -> tuple[str | None, str]:
    """Extract the court's verdict for candidate_id from its response text.

    Courts may deliver the SAME JSON document pretty-printed across lines or
    inside a fence, which a single-line scan would misread as no verdict.
    Reading is lenient; the DECISION
    contract is not: the document must name this exact candidate_id and say
    PRESENT or ABSENT, else the court stays unresolved (fail-closed).
    """
    text = str(response)

    def accept(doc: Any) -> tuple[str, str] | None:
        if (
            isinstance(doc, dict)
            and doc.get("candidate_id") == candidate_id
            and doc.get("clean_verdict") in {"PRESENT", "ABSENT"}
        ):
            return doc["clean_verdict"], str(doc.get("basis", ""))[:400]
        return None

    for line in text.splitlines():
        line = line.strip()
        if not line.startswith("{"):
            continue
        try:
            found = accept(json.loads(line))
        except json.JSONDecodeError:
            continue
        if found:
            return found
    try:
        found = accept(json.loads(text.strip()))
        if found:
            return found
    except json.JSONDecodeError:
        pass
    depth = 0
    start = None
    for index, char in enumerate(text):
        if char == "{":
            if depth == 0:
                start = index
            depth += 1
        elif char == "}" and depth:
            depth -= 1
            if depth == 0 and start is not None:
                try:
                    found = accept(json.loads(text[start : index + 1]))
                except json.JSONDecodeError:
                    found = None
                if found:
                    return found
    return None, "court returned no parseable verdict"


def adjudicate_planted_candidates(
    run_directory: Path,
    target: Path,
    planted_files: set[str],
    matched_candidate_ids: set[str],
    host: Any,
    *,
    copy_ignore: Any,
    max_workers: int = 8,
) -> dict[str, Any]:
    """Adjudicate every candidate in a planted file; return the receipt.

    The clean copy is made fresh from the TARGET (never the workspace) with
    the same ignore rules as trial preparation, and destroyed afterward.
    """
    candidates = []
    candidates_path = run_directory / "candidates.jsonl"
    if candidates_path.is_file():
        for line in candidates_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                candidates.append(json.loads(line))
    in_planted = [row for row in candidates if str(row.get("path")) in planted_files]
    rows: list[dict[str, Any]] = []
    to_court: list[dict[str, Any]] = []
    for row in in_planted:
        if str(row.get("id")) in matched_candidate_ids:
            rows.append(
                {
                    "candidate_id": row["id"],
                    "disposition": "synthetic",
                    "clean_verdict": None,
                    "basis": "recall-matched: this candidate is the plant's scored find",
                }
            )
        else:
            to_court.append(row)

    if to_court:
        clean_dir = Path(tempfile.mkdtemp(prefix="lucy-clean-"))
        clean_copy = clean_dir / "clean"
        try:
            shutil.copytree(
                target, clean_copy, ignore=copy_ignore, symlinks=True,
                ignore_dangling_symlinks=True,
            )

            def adjudicate(row: dict[str, Any]) -> dict[str, Any]:
                response = host.run_agent(
                    system=(
                        "You are an independent verification court with a fresh "
                        "context. Read-only. Judge only from the bytes in front "
                        "of you."
                    ),
                    task=DISPOSITION_TASK.format(
                        id=row["id"], title=row["title"], path=row["path"],
                        line=row["line"], category=row["category"],
                    ),
                    workspace=clean_copy,
                )
                verdict, basis = parse_clean_verdict(str(response), row["id"])
                if verdict is None:
                    disposition = "unresolved"
                elif verdict == "PRESENT":
                    disposition = "genuine"
                else:
                    disposition = "synthetic"
                return {
                    "candidate_id": row["id"],
                    "disposition": disposition,
                    "clean_verdict": verdict,
                    "basis": basis,
                }

            with ThreadPoolExecutor(max_workers=max_workers) as pool:
                courted = list(pool.map(adjudicate, to_court))
                # Bounded retries, only for courts that ended without a
                # verdict: a court that stops before its verdict line is
                # noise, not a judgment. Silence after
                # every allowed ask stays unresolved — fail-closed, never
                # classified. Answered courts are never re-run.
                candidate_by_id = {str(row["id"]): row for row in to_court}
                for _ in range(DISPOSITION_RETRIES):
                    retry = [
                        candidate_by_id[row["candidate_id"]]
                        for row in courted
                        if row["disposition"] == "unresolved"
                    ]
                    if not retry:
                        break
                    reasked = {
                        row["candidate_id"]: dict(row, retried=True)
                        for row in pool.map(adjudicate, retry)
                    }
                    courted = [
                        reasked.get(row["candidate_id"], row)
                        if row["disposition"] == "unresolved"
                        else row
                        for row in courted
                    ]
                rows.extend(courted)
        finally:
            shutil.rmtree(clean_dir, ignore_errors=True)

    receipt = {
        "schema": "lucy-dispositions/v1",
        "planted_files": sorted(planted_files),
        "planted_file_candidates": len(in_planted),
        "dispositioned": len(rows),
        "synthetic": sum(1 for row in rows if row["disposition"] == "synthetic"),
        "genuine": sum(1 for row in rows if row["disposition"] == "genuine"),
        # unresolved > 0 blocks certification: an unparseable clean-court
        # response must never silently classify in either direction.
        "unresolved": sum(1 for row in rows if row["disposition"] == "unresolved"),
        "rows": sorted(rows, key=lambda row: row["candidate_id"]),
    }
    return receipt


def apply_dispositions(
    run_directory: Path, workspace: Path, results_root: Path, receipt: dict[str, Any]
) -> None:
    """Rewrite findings synthetic flags from dispositions (replacing the old
    proximity-window annotation) and regenerate FINDINGS.md."""
    from lucy.runtime.artifacts import render_findings_markdown
    from lucy.runtime.results import LocalResultsSink

    findings_path = run_directory / "findings.jsonl"
    if not findings_path.is_file():
        return
    synthetic_ids = {
        row["candidate_id"] for row in receipt.get("rows", []) if row["disposition"] == "synthetic"
    }
    rows = []
    changed = False
    for line in findings_path.read_text(encoding="utf-8").splitlines():
        if not line.strip():
            continue
        row = json.loads(line)
        should = row.get("id") in synthetic_ids
        if bool(row.get("synthetic_canary")) != should:
            row["synthetic_canary"] = should
            changed = True
        rows.append(row)
    if not changed:
        return
    sink = LocalResultsSink.create(results_root, workspace)
    findings_path = findings_path.resolve()
    sink.write_text(
        str(findings_path.relative_to(sink.root)),
        "".join(json.dumps(row, sort_keys=True) + "\n" for row in rows),
    )
    sink.write_text(
        str((run_directory.resolve() / "FINDINGS.md").relative_to(sink.root)),
        render_findings_markdown(rows),
    )
