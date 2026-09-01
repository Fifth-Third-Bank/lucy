"""Pre-lane calibration of the recall measurement channel.

The certification gates audit the SCANNER, but the RULER also needs a check:
the planted answer key must remain passable through the production fold and
1:1 scoring pipeline by a perfect reader. In particular, nearby same-family
canaries can fold into one candidate and leave a slot structurally
unmatchable.

Oracle replay closes that hole for zero model dollars: synthesize the
rows a perfect reader would emit — plus jittered variants, because real
readers cite a few lines off — and push them through the IDENTICAL code
path a live run uses (artifacts.fold_candidate via fold_rows, then
trial.match_canaries). Anything short of a full score means the key must
be replanted, not read.

Custody note: this module handles the answer key launcher-side only,
before any reader exists. Nothing here writes to the run directory or
prints plant loci.
"""

from __future__ import annotations

from typing import Any

# Real readers cite the sink a few lines off; the fold radius is 10 and
# the match window is 40, so replay must stay honest inside both.
REPLAY_JITTERS = (0, -3, 3, -9, 9)


def synthetic_rows(answer_key: dict[str, Any], jitter: int = 0) -> list[dict[str, Any]]:
    """The rows a perfect reader would emit for the planted canaries."""
    rows = []
    for canary in answer_key.get("canaries", []):
        if canary.get("historical"):
            continue
        family = str(canary.get("family", ""))
        rows.append(
            {
                "path": str(canary.get("path", "")),
                "line": max(1, int(canary.get("line", 1)) + jitter),
                "lens": family,
                "category": f"{family} oracle probe slot {canary.get('slot')}",
                "severity": "HIGH",
                "title": str(canary.get("title") or "oracle replay probe"),
                "evidence": "oracle replay synthetic row (never leaves the launcher)",
                "reach_basis": str(canary.get("reachability") or "oracle replay"),
            }
        )
    return rows


def oracle_replay(answer_key: dict[str, Any]) -> dict[str, Any]:
    """Score a perfect reader against the key through the production
    pipeline; report the WORST jitter case (the channel must tolerate
    ordinary citation imprecision, not just exact lines)."""
    from lucy.runtime.artifacts import fold_rows
    from lucy.runtime.trial import match_canaries

    worst: dict[str, Any] | None = None
    for jitter in REPLAY_JITTERS:
        folded = fold_rows(synthetic_rows(answer_key, jitter))
        slots = match_canaries(answer_key, folded)
        plants = [slot for slot in slots if not slot["historical"]]
        matched = sum(1 for slot in plants if slot["found"])
        report = {
            "jitter": jitter,
            "matched": matched,
            "total": len(plants),
            "missed_slots": sorted(slot["slot"] for slot in plants if not slot["found"]),
        }
        if worst is None or report["matched"] < worst["matched"]:
            worst = report
    assert worst is not None
    worst["passed"] = worst["matched"] == worst["total"] and worst["total"] > 0
    return worst
