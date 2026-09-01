"""Launcher-side priors: historical refind accounting and score-only canaries.

Priors NEVER enter the scanned repository or the reviewer's context. The
launcher loads a priors file from outside the target, draws historical
canaries deterministically into answer-key custody as SCORE-ONLY entries (no
edits — they are real defects already on the estate bytes), and after
finalization diffs every staged target against findings.jsonl with tolerant
path matching. The reviewer stays cold: no watchlist injection, no hints.

Schema (lucy-priors/oss-1):
{
  "schema": "lucy-priors/oss-1",
  "targets": [
    {"id": "HIST-001", "path": "repo/src/file.py", "line": 10,
     "family": "L1-auth", "title": "..."}
  ]
}
"""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

FAMILIES = ("L1-auth", "L2-secrets", "L3-injection", "L4-infra")
HISTORICAL_CANARY_COUNT = 4


def load_priors(priors_path: Path) -> dict[str, Any]:
    document = json.loads(priors_path.read_text(encoding="utf-8"))
    if document.get("schema") != "lucy-priors/oss-1":
        raise ValueError("unsupported priors schema (want lucy-priors/oss-1)")
    targets = document.get("targets")
    if not isinstance(targets, list) or not targets:
        raise ValueError("priors file has no targets")
    seen_ids: set[str] = set()
    for target in targets:
        if not isinstance(target, dict):
            raise ValueError("priors targets must be objects")
        for field in ("id", "path", "title"):
            if not isinstance(target.get(field), str) or not target[field].strip():
                raise ValueError(f"priors target missing {field}")
        if target["id"] in seen_ids:
            raise ValueError(f"duplicate priors id: {target['id']}")
        seen_ids.add(target["id"])
        if target.get("family") not in FAMILIES:
            raise ValueError(f"priors target {target['id']}: family must be one of {FAMILIES}")
        if Path(target["path"]).is_absolute() or ".." in Path(target["path"]).parts:
            raise ValueError(f"priors target {target['id']}: path must be normalized relative")
    return document


def resolve_locus(workspace: Path, relative: str) -> str | None:
    """Tolerant path matching: exact, then unique suffix, then unique basename."""
    if (workspace / relative).is_file():
        return relative
    candidates = [
        path.relative_to(workspace).as_posix()
        for path in workspace.rglob("*")
        if path.is_file() and ".git" not in path.parts
    ]
    suffix_hits = [c for c in candidates if c.endswith(relative)]
    if len(suffix_hits) == 1:
        return suffix_hits[0]
    base = Path(relative).name
    base_hits = [c for c in candidates if Path(c).name == base]
    if len(base_hits) == 1:
        return base_hits[0]
    return None


def draw_historical_canaries(
    priors: dict[str, Any], workspace: Path, covered_paths: set[str] | None = None
) -> tuple[list[dict[str, Any]], list[str]]:
    """Deterministic sha256-ascending draw of score-only historical canaries.

    Only targets whose locus resolves on workspace bytes AND (when the
    caller supplies the reader-unit set) sits inside reader coverage are
    eligible — a canary in a file no reader ever receives is unfindable by
    construction and would score as a silent miss (the same class the
    planted-canary coverage validation closes). Returns (canaries,
    skipped_ids); coverage-skipped targets are receipted like unresolved
    ones, never silently dropped.
    """
    ranked = sorted(
        priors["targets"], key=lambda t: hashlib.sha256(str(t["id"]).encode()).hexdigest()
    )
    canaries: list[dict[str, Any]] = []
    skipped: list[str] = []
    for target in ranked:
        if len(canaries) == HISTORICAL_CANARY_COUNT:
            break
        resolved = resolve_locus(workspace, target["path"])
        if resolved is None or (covered_paths is not None and resolved not in covered_paths):
            skipped.append(target["id"])
            continue
        canaries.append(
            {
                "slot": 8 + len(canaries) + 1,
                "family": target["family"],
                "path": resolved,
                "line": int(target.get("line", 1) or 1),
                "title": target["title"],
                "historical": True,
                "priors_id": target["id"],
            }
        )
    return canaries, skipped


def heat_exclusions(
    priors: dict[str, Any],
    canaries: list[dict[str, Any]],
    workspace: Path,
) -> tuple[list[dict[str, Any]], list[dict[str, Any]]]:
    """Split priors into brief-heat targets and withheld targets.

    Withheld (never briefed): the drawn canaries themselves, plus any prior
    within the EXCLUSION RADIUS of a canary — same file, or same directory AND
    same family. Correlated neighbors would let a briefed target walk a reader
    into a canary, inflating the blind refind score. Deterministic; receipted
    by the caller.
    """
    canary_ids = {row.get("priors_id") for row in canaries}
    canary_keys = []
    for row in canaries:
        path = Path(str(row["path"]))
        canary_keys.append((path.as_posix(), path.parent.as_posix(), row.get("family")))
    heated, withheld = [], []
    for target in priors["targets"]:
        resolved = resolve_locus(workspace, target["path"])
        if resolved is None:
            withheld.append({"id": target["id"], "reason": "locus-unresolved"})
            continue
        path = Path(resolved)
        reason = None
        if target["id"] in canary_ids:
            reason = "drawn-canary"
        else:
            for canary_path, canary_dir, canary_family in canary_keys:
                if path.as_posix() == canary_path:
                    reason = "same-file-as-canary"
                    break
                if path.parent.as_posix() == canary_dir and target["family"] == canary_family:
                    reason = "same-directory-and-family-as-canary"
                    break
        if reason:
            withheld.append({"id": target["id"], "reason": reason})
        else:
            heated.append(dict(target, resolved_path=path.as_posix()))
    return heated, withheld


def write_heat_files(
    heated: list[dict[str, Any]],
    unit_listings: dict[str, list[str]],
    staging: Path,
) -> dict[str, int]:
    """Write per-unit UNIT-NNN-PRIORS.txt heat files (battery-style: injected
    into reader briefs MECHANICALLY, never composed by the orchestrator).
    Sweep lanes stay cold by design — they get no heat file."""
    counts: dict[str, int] = {}
    for unit_id, files in unit_listings.items():
        file_set = set(files)
        lines = [
            f"{target['resolved_path']}:{target.get('line', 1)} {target['family']} {target['title']}"
            for target in heated
            if target["resolved_path"] in file_set
        ]
        (staging / f"{unit_id}-PRIORS.txt").write_text(
            ("\n".join(lines) + "\n") if lines else "no historical heat for this unit\n",
            encoding="utf-8",
        )
        counts[unit_id] = len(lines)
    return counts


def score_dispositions(
    priors: dict[str, Any],
    workspace: Path,
    findings: list[dict[str, Any]],
    heated_ids: set[str] | None = None,
) -> dict[str, Any]:
    """REFOUND / NOT-EVIDENCED accounting for every staged target.

    Matches against ALL finalized rows including court-refuted ones — a
    historical claim disproven by a court is REFOUND->refuted (the honest
    disposition), never silently NOT-EVIDENCED.

    HONEST ACCOUNTING GUARDRAIL: when brief heat was applied, every row is
    tagged briefed/blind — refinding a briefed target proves little (the
    reader was handed the address); only blind refinds evidence scanner power.
    """
    rows = []
    refound = 0
    for target in priors["targets"]:
        resolved = resolve_locus(workspace, target["path"])
        if resolved is None:
            rows.append(
                {
                    "id": target["id"],
                    "disposition": "NOT-EVIDENCED",
                    "sub_class": "locus-not-found",
                    "receipt": f"tolerant match (exact/suffix/basename) found no file for {target['path']}",
                }
            )
            continue
        matches = [
            row
            for row in findings
            if row.get("path") == resolved
            and _family_compatible(str(target.get("family", "")), row)
        ]
        matches.sort(key=lambda row: 0 if row.get("status") == "verified" else 1)
        if matches:
            refound += 1
            rows.append(
                {
                    "id": target["id"],
                    "disposition": "REFOUND",
                    "finding_id": matches[0]["id"],
                    "finding_status": matches[0]["status"],
                }
            )
        else:
            rows.append(
                {
                    "id": target["id"],
                    "disposition": "NOT-EVIDENCED",
                    "sub_class": "defect-not-present",
                    "receipt": f"{resolved} present; no {target.get('family')} finding at locus on current bytes",
                }
            )
    if heated_ids is not None:
        for row in rows:
            row["briefed"] = row["id"] in heated_ids
    not_evidenced = len(rows) - refound
    blind_refound = sum(
        1
        for row in rows
        if row["disposition"] == "REFOUND" and not row.get("briefed", False)
    )
    return {
        "schema": "lucy-priors-disposition/v1",
        "staged": len(rows),
        "refound": refound,
        "blind_refound": blind_refound,
        "not_evidenced": not_evidenced,
        "not_evidenced_receipted": sum(
            1 for row in rows if row["disposition"] == "NOT-EVIDENCED" and row.get("receipt")
        ),
        "heat_applied": heated_ids is not None,
        "rows": rows,
    }


_FAMILY_KEYWORDS = {
    "L1-auth": ("auth", "authz", "access", "session", "token", "role", "tenant", "ownership", "idor", "permission"),
    "L2-secrets": ("secret", "credential", "key", "crypto", "password", "tls", "certificate", "signature", "hash"),
    "L3-injection": ("injection", "sql", "command", "path", "traversal", "ssrf", "deserial", "template", "xss", "parser"),
    "L4-infra": ("infra", "config", "iam", "ingress", "container", "privilege", "pipeline", "supply", "exposure", "network"),
}


def _family_compatible(family: str, finding: dict[str, Any]) -> bool:
    if str(finding.get("lens", "")) == family:
        return True
    text = (str(finding.get("category", "")) + " " + str(finding.get("title", ""))).lower()
    return any(keyword in text for keyword in _FAMILY_KEYWORDS.get(family, ()))
