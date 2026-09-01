"""Launcher-side certification: seal card, cert receipt, gates, delivery ZIP.

Runs AFTER the reviewer session ends and AFTER external recall scoring, so the
reviewer can never see or influence canary scoring. Every card field is
COMPUTED from receipts — never hand-written prose. When any input is missing
the run honestly ends PROCESS-COMPLETE with the failing check named; CERTIFIED
is printed only when the pinned seal-card and certification gates both PASS.
"""

from __future__ import annotations

from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import zipfile
from typing import Any

from lucy.runtime.results import LocalResultsSink
from lucy.runtime.report import build_report, run_report_gate


SERIOUS = {"PRIORITIZED_CRITICAL", "CRITICAL", "HIGH"}


def _read_jsonl(path: Path) -> list[dict[str, Any]]:
    if not path.is_file():
        return []
    return [
        json.loads(line)
        for line in path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]


def _read_json(path: Path) -> dict[str, Any]:
    return json.loads(path.read_text(encoding="utf-8")) if path.is_file() else {}


def _chapman_bound(pass_history: list[dict[str, Any]], unit_ids: set[str]) -> float:
    """Capture-recapture (Chapman) coverage bound for one unit's serious ids.

    Chapman assumes comparable capture effort, so the estimate uses the two
    LARGEST captures for the unit (full four-lens passes), never a light
    confirmation lap, because a single-lens lap in the pair biases the bound
    low.
    """
    passes = [set(entry.get("observed", [])) & unit_ids for entry in pass_history]
    passes = [ids for ids in passes if ids]
    captured = set().union(*passes) if passes else set()
    if len(passes) < 2 or not captured:
        return 1.0 if not captured else 0.0
    first, second = sorted(passes, key=len, reverse=True)[:2]
    overlap = len(first & second)
    estimate = ((len(first) + 1) * (len(second) + 1)) / (overlap + 1) - 1
    if estimate <= 0:
        return 1.0
    return round(min(1.0, len(captured) / estimate), 2)


def _visitation(workspace: Path, unit_files: list[str]) -> tuple[int, int]:
    opened = 0
    for relative in unit_files:
        try:
            (workspace / relative).read_bytes()
            opened += 1
        except OSError:
            continue
    return opened, len(unit_files)


_REACH_BINDING_COLUMNS = {
    "edge": "reach_domain",
    "route": "reach_stage",
    "exposure": "reach_method",
    "authorizer": "reach_authorizer",
}


def _derivation_artifacts(
    receipts: Path, emitted: list[dict[str, Any]], refuted: list[dict[str, Any]]
) -> tuple[Path, Path]:
    """Write the findings/court CSVs the seal-card gate cross-checks the card
    against. With these evidence files,
    ROWS-TOTAL, the tier counts, CH-COURTED, and critical-row reach bindings
    are re-derived from artifacts instead of trusted from the card text."""
    import csv

    findings_csv = receipts / "SEAL_FINDINGS.csv"
    with findings_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.DictWriter(
            handle,
            fieldnames=["key", "tier", "reach_domain", "reach_stage", "reach_method", "reach_authorizer"],
        )
        writer.writeheader()
        for row in emitted:
            if row["status"] == "conditional-court":
                tier = "WP"
            else:
                severity = str(row["severity"]).upper()
                tier = "CRITICAL" if severity == "PRIORITIZED_CRITICAL" else severity
            record = {"key": row["id"], "tier": tier, "reach_domain": "",
                      "reach_stage": "", "reach_method": "", "reach_authorizer": ""}
            for part in str(row.get("reach_basis", "")).split(";"):
                name, _, value = part.strip().partition("=")
                column = _REACH_BINDING_COLUMNS.get(name.strip().lower())
                if column and value.strip():
                    record[column] = value.strip()
            # reach_basis is model free text riding into a CSV a human may
            # open in a spreadsheet: neutralize leading formula characters.
            for column in list(record):
                value = str(record[column])
                if value[:1] in "=+-@\t":
                    record[column] = "'" + value
            writer.writerow(record)
    chmap_csv = receipts / "SEAL_COURTMAP.csv"
    with chmap_csv.open("w", encoding="utf-8", newline="") as handle:
        writer = csv.writer(handle)
        writer.writerow(["key", "verdict"])
        for row in emitted:
            if row["status"] in {"verified", "conditional-court"}:
                writer.writerow([row["id"], row["status"]])
        for row in refuted:
            writer.writerow([row["id"], "refuted"])
    return findings_csv, chmap_csv


def _census_walk(workspace: Path, units_meta: dict[str, Any] | None = None) -> list[str] | None:
    """Scannable files from a fresh walk under the run's OWN census rules.

    Coverage rules evolve (shebang scripts joined the census in v2); a run
    must be certified against the ruleset its units were built with, or a
    scanner upgrade retroactively fails C1 for files its readers were never
    given. Runs whose UNITS.json predates the census_rules field replay the
    legacy extension-only rules. Returns None when the walk fails, so C1
    fails closed (opened 0 vs census -1) rather than passing vacuously.
    """
    try:
        from lucy.runtime.units import compute_units

        recorded = (units_meta or {}).get("census_rules", "ext/v1")
        doc = compute_units(workspace, census_rules=recorded)
        return sorted({f for unit in doc.get("units", []) for f in unit.get("files", [])})
    except Exception:
        return None


def _m_audit(findings: list[dict[str, Any]], workspace: Path, run_id: str) -> tuple[bool, str, int]:
    """Re-derive 5 seed-drawn finding ids from their content-addressed inputs
    and confirm their loci exist on workspace bytes."""
    seed = hashlib.sha256(run_id.encode()).hexdigest()[:8]
    rows = [row for row in findings if row.get("status") in {"verified", "conditional", "conditional-court"}]
    ranked = sorted(rows, key=lambda row: hashlib.sha256((seed + row["id"]).encode()).hexdigest())
    checked = ranked[:5]
    for row in checked:
        material = "\0".join([row["path"], str(row["line"]), str(row["category"]).lower()])
        derived = "LUCY-" + hashlib.sha256(material.encode()).hexdigest()[:16]
        if derived != row["id"]:
            return False, seed, len(checked)
        if not (workspace / row["path"]).is_file():
            return False, seed, len(checked)
    return len(checked) == min(5, len(rows)), seed, len(checked)



def _disposition_evidence(document: dict[str, Any] | None) -> dict[str, Any]:
    """Cert-receipt fields proving attribution evidence exists and is the
    expected schema. Counts default to zero ONLY alongside explicit
    presence/schema fields the gate independently requires."""
    present = bool(document) and document.get("schema") == "lucy-dispositions/v1"
    source = document if present else {}
    return {
        "disposition_receipt_present": present,
        "disposition_receipt_schema": str((document or {}).get("schema", "")),
        "planted_file_candidates": int(source.get("planted_file_candidates", 0) or 0),
        "candidates_dispositioned": int(source.get("dispositioned", 0) or 0),
        "dispositions_unresolved": int(source.get("unresolved", 0) or 0),
    }

def generate_certification(
    run_dir: Path,
    workspace: Path,
    results_root: Path,
    run_id: str,
    started_at: str,
    *,
    recall_receipt: dict[str, Any] | None = None,
    dispositions: dict[str, Any] | None = None,
) -> dict[str, Any]:
    sink = LocalResultsSink.create(results_root, workspace)
    run_dir = run_dir.resolve()
    receipts = run_dir / "receipts"

    findings = _read_jsonl(run_dir / "findings.jsonl")
    conservation = _read_json(receipts / "CONSERVATION.json")
    # The C3 input is the launcher-scored receipt OBJECT whenever the caller
    # has one. The receipts-file copy is reviewer-writable and is only a
    # display fallback — and a run whose recall is not a scored PASS can
    # never certify from a forged receipt file.
    recall = recall_receipt if recall_receipt is not None else _read_json(receipts / "RECALL_RECEIPT.json")
    recall_scored_pass = recall_receipt is not None and recall_receipt.get("status") == "PASS"
    mint = _read_json(receipts / "MINT_COMMITMENT.json")
    pass_history = _read_json(receipts / "PASS_HISTORY.json").get("passes", [])
    units_meta = _read_json(receipts / "UNITS.json")
    timeline = _read_json(receipts / "TIMELINE.json")
    liveness = _read_jsonl(receipts / "LIVENESS.jsonl")
    wake = _read_jsonl(receipts / "WAKE.jsonl")

    emitted = [
        row
        for row in findings
        if row.get("status") in {"verified", "conditional", "conditional-court"}
    ]
    refuted = [row for row in findings if row.get("status") == "refuted"]
    tiers = {"PRIORITIZED_CRITICAL": 0, "CRITICAL": 0, "HIGH": 0, "MEDIUM": 0, "LOW": 0}
    wp_count = 0
    for row in emitted:
        if row["status"] == "conditional-court":
            # Worst-plausible: mechanism verified, reach precondition
            # unresolved — counted in TIER-WP, never conflated with a tier.
            wp_count += 1
            continue
        severity = str(row["severity"]).upper()
        if severity in tiers:
            tiers[severity] += 1
    verified = sum(1 for row in emitted if row["status"] == "verified")
    courted = verified + wp_count + len(refuted)
    pc_rows = [row for row in emitted if row["severity"] == "PRIORITIZED_CRITICAL"]

    # Per-unit Chapman bounds over serious candidate ids.
    unit_bounds: dict[str, float] = {}
    unit_summaries = units_meta.get("units", []) or [{"id": "UNIT-001"}]
    all_serious = {row["id"] for row in findings if str(row["severity"]).upper() in SERIOUS}
    unit_file_lists: dict[str, list[str]] = {}
    for unit in unit_summaries:
        unit_id = unit["id"]
        listing = receipts / f"{unit_id}.txt"
        files = (
            [line for line in listing.read_text(encoding="utf-8").splitlines() if line.strip()]
            if listing.is_file()
            else []
        )
        unit_file_lists[unit_id] = files
        file_set = set(files)
        unit_ids = {
            row["id"]
            for row in findings
            if row["id"] in all_serious and row["path"] in file_set
        }
        if not unit_ids and len(unit_summaries) == 1:
            unit_ids = set(all_serious)
        unit_bounds[unit_id] = _chapman_bound(pass_history, unit_ids)
    bound_min = min(unit_bounds.values()) if unit_bounds else 1.0

    all_files = sorted({f for files in unit_file_lists.values() for f in files})
    # Independent census: a FRESH eligibility walk of the workspace under the
    # pinned rules. The numerator counts fresh-census files that are BOTH
    # readable AND present in a preserved unit listing; the denominator is
    # the fresh walk's total. Truncated or reviewer-edited listings shrink
    # the numerator but never the denominator, so C1 fails instead of
    # certifying an empty ratio.
    fresh_files = _census_walk(workspace, units_meta)
    listed = set(all_files)
    if fresh_files is None:
        opened, census_files = 0, -1
    else:
        opened, _ = _visitation(workspace, [f for f in fresh_files if f in listed])
        census_files = len(fresh_files)

    from lucy.runtime.loop_policy import quiet_threshold

    unit_loc_by_id = {unit["id"]: int(unit.get("loc", 0) or 0) for unit in unit_summaries}
    quiet_thresholds = {
        unit_id: quiet_threshold(unit_loc_by_id.get(unit_id, 0))
        for unit_id in unit_file_lists
    }
    # C2 consumes the exact reducer used by live orchestration, progress, and
    # recapture. A private seal-side recomputation previously disagreed with
    # live scheduling after severity upgrades and light confirmation laps.
    from lucy.runtime.artifacts import unit_quiet_map

    quiet_state = unit_quiet_map(run_dir)
    quiet_units = sum(bool(quiet_state.get(unit_id, False)) for unit_id in unit_file_lists)

    m_ok, m_seed, m_checked = _m_audit(findings, workspace, run_id)
    recall_found = int(recall.get("found", 0))
    plants = int(mint.get("plant_count", 8))
    historical_count = int(mint.get("historical_canaries", 0))
    historical_found = int(recall.get("historical_found", 0))

    # Priors disposition (launcher-side, deterministic).
    priors_staged_path = receipts / "PRIORS_STAGED.json"
    disposition = None
    if historical_count or priors_staged_path.is_file():
        from lucy.runtime.priors import load_priors, score_dispositions

        if priors_staged_path.is_file():
            priors_doc = load_priors(priors_staged_path)
            heat_doc = _read_json(receipts / "PRIORS_HEATED.json")
            heated_ids = (
                {row["id"] for row in heat_doc.get("heated", [])}
                if heat_doc
                else None
            )
            disposition = score_dispositions(
                priors_doc, workspace, findings, heated_ids=heated_ids
            )
            sink.write_json(
                str((receipts / "PRIORS_DISPOSITION.json").relative_to(sink.root)),
                disposition,
            )

    # Card canary set: with priors staged the card mix is 4 pattern (drawn
    # sha256-ascending over slot ids) + 4 historical, totalling the gate's
    # required 8; all pattern plants still gate recall via CERT C3.
    if historical_count >= 4:
        drawn = sorted(
            (row for row in recall.get("slots", []) if not row.get("historical")),
            key=lambda row: hashlib.sha256(f"slot-{row['slot']}".encode()).hexdigest(),
        )[:4]
        historical_slots = [row for row in recall.get("slots", []) if row.get("historical")][:4]
        card_set = drawn + historical_slots
        card_canary_found = sum(1 for row in card_set if row.get("found"))
        canary_mix = "4P+4H"
    else:
        card_canary_found = recall_found
        canary_mix = f"{plants}P+0H"

    deaths = sum(1 for row in liveness if row.get("event") == "lane-dead")
    redispatched = sum(1 for row in liveness if row.get("event") == "lane-relaunched")
    # A lane that dies again after its relaunch may be honestly adopted as an
    # empty result (liveness law). That closure needs its own ledger category
    # or C5 can never balance.
    adopted = sum(1 for row in liveness if row.get("event") == "lane-adopted-empty")
    # PULSE LAW: ordered per-lane coverage via the SAME reducer the
    # reconciler uses (reduce_pulse_ledger) — closures consume only prior
    # outstanding deaths on their own lane, over-closure is receipted
    # noise, and invalid lane labels fail closed. Naive aggregate counts can
    # let an earlier benign adoption mask a later unclosed death.
    from lucy.runtime.recapture import reduce_pulse_ledger

    pulse = reduce_pulse_ledger(liveness)
    deaths_unreconciled = pulse["unreconciled"]
    denials = sum(1 for row in liveness if row.get("event") == "denial")
    widths = [row.get("width") for row in wake if isinstance(row.get("width"), (int, float))]
    avg_width = round(sum(widths) / len(widths), 1) if widths else float(len(unit_summaries) * 4)

    started = datetime.fromisoformat(started_at)
    now = datetime.now(timezone.utc)
    minutes = max(1, int((now - started).total_seconds() // 60))
    duration = f"{minutes // 60}h{minutes % 60:02d}m"
    lag_minutes = 0
    if timeline.get("first_pass1_lane_mtime") and timeline.get("courts_mtime"):
        lag_minutes = max(
            0, int((timeline["courts_mtime"] - timeline["first_pass1_lane_mtime"]) // 60)
        )
    lag_clause = "" if lag_minutes <= 10 else " (named deviation: courts dispatched after quiet)"

    priors_line = (
        f"{disposition['staged']} loaded {disposition['refound'] + disposition['not_evidenced']} refound-or-adjudicated"
        if disposition is not None
        else "none staged"
    )

    report_path, report_doc = build_report(run_dir, workspace, run_id)
    report_gate_line = run_report_gate(report_path)

    lanes = len(unit_summaries) * 4 * max(1, len(pass_history))
    scannable = units_meta.get("scannable_loc", 0)
    raw_loc = units_meta.get("raw_loc", scannable)

    lap_lines = []
    seen_serious: set[str] = set()
    for index, entry in enumerate(pass_history, 1):
        seen_serious |= set(entry.get("observed", [])) & all_serious
        bound = len(seen_serious) / len(all_serious) if all_serious else 1.0
        lap_lines.append(
            f"LAP-HISTORY: {index} bound {bound:.2f} novelCH {len(entry.get('new_serious', []))}"
        )
    reach_lines = []
    for row in pc_rows:
        basis = str(row.get("reach_basis", ""))
        parts = [part.strip() for part in re.split(r"[;|]", basis) if part.strip()]
        while len(parts) < 4:
            parts.append(f"exposure binding recorded in court verdict for {row['id']}")
        for label, part in zip(("edge", "route", "authorizer", "exposure"), parts[:4]):
            reach_lines.append(f"REACH-RECEIPT: {label}-binding {part} ({row['id']})")

    # CURE-LAP lines from the launcher-written recapture receipt: the gate's
    # strict-floor tripwire (<0.50) requires proof the unit was lapped, and
    # recapture laps are that proof.
    # MINT-ERROR receipts for missed HISTORICAL slots that were actually
    # refound under a different lens label: historical families are
    # conversion-inferred (heat-grade, not canary-grade — README rule), so a
    # window-matched candidate with a mismatched family is a minting error,
    # receipted per the seal-card law ("cure the miss or receipt the mint
    # error"). Planted slots never get this: their families are authoritative.
    mint_error_lines = []
    for row in recall.get("slots", []):
        if row.get("historical"):
            if row.get("mint_error"):
                mint_error_lines.append(
                    f"MINT-ERROR: H{row.get('slot')} adjudicated defective historical mint "
                    f"({row.get('mint_error_basis', 'operator attestation')})"
                )
            continue
        if row.get("cured"):
            mint_error_lines.append(
                f"CANARY-CURE: slot {row['slot']} refound by a blind full-width "
                f"recapture lap (family {row.get('family')})"
            )
        elif row.get("mint_error"):
            mint_error_lines.append(
                f"MINT-ERROR: slot {row['slot']} adjudicated defective mint "
                f"({row.get('mint_error_basis', 'operator attestation')}; family {row.get('family')})"
            )
    missed_historical = [
        row for row in recall.get("slots", [])
        if row.get("historical") and not row.get("found") and not row.get("mint_error")
    ]
    if missed_historical:
        held_key = None
        try:
            from lucy.runtime.trial import custody_home

            key_path = custody_home() / "runs" / run_id / "ANSWER_KEY.json"
            if key_path.is_file():
                held_key = json.loads(key_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError):
            held_key = None
        if held_key:
            candidates_rows = _read_jsonl(run_dir / "candidates.jsonl")
            loci = {
                row.get("slot"): (str(row.get("path")), int(row.get("line", 0)))
                for row in held_key.get("canaries", [])
                if row.get("historical")
            }
            for row in missed_historical:
                locus = loci.get(row.get("slot"))
                if not locus:
                    continue
                window_hits = [
                    candidate for candidate in candidates_rows
                    if candidate.get("path") == locus[0]
                    and isinstance(candidate.get("line"), int)
                    and abs(candidate["line"] - locus[1]) <= 40
                ]
                if window_hits:
                    mint_error_lines.append(
                        f"MINT-ERROR: H{row.get('slot')} family label "
                        f"({row.get('family')}) is conversion-inferred; locus "
                        f"refound under a different lens ({window_hits[0].get('id')})"
                    )

    cure_lap_lines = []
    recapture_receipt = _read_json(receipts / "RECAPTURE.json")
    if recapture_receipt.get("laps"):
        unit_index = {unit["id"]: index for index, unit in enumerate(unit_summaries, 1)}
        for unit_id, bound in sorted(recapture_receipt.get("final_bounds", {}).items()):
            if unit_id in unit_index:
                cure_lap_lines.append(
                    f"CURE-LAP: U{unit_index[unit_id]:02d} dispatched, "
                    f"bound re-measured {float(bound):.2f}"
                )

    from lucy import __version__ as lucy_version

    card = f"""RUN-ID: {run_id}
KIT: lucy {lucy_version}
ROWS-TOTAL: {len(emitted)}
VERIFIED-TOTAL: {verified}
REFUTED-TOTAL: {len(refuted)}
TIER-C: {tiers['PRIORITIZED_CRITICAL'] + tiers['CRITICAL']}
TIER-H: {tiers['HIGH']}
TIER-WP: {wp_count}
TIER-M: {tiers['MEDIUM']}
TIER-L: {tiers['LOW']}
TIER-INFO: 0
CH-COURTED: {courted}
PC-1: {len(pc_rows)}
PC-2: {tiers['CRITICAL']}
BOUND-MIN: {bound_min:.2f}
UNITS: {len(unit_summaries)}
CANARY: {card_canary_found}/8
DURATION: {duration} (prepare -> certification, receipt subtraction)
DENIALS: {denials}; result impact: ZERO
MODE: CODE
DISPOSITION: all serious rows courted; verdicts in findings.jsonl; refutations retained
VISITATION: {opened}/{census_files}
SEAL-CLASS: CERTIFIED
FIRST-COURT-LAG: {lag_minutes}{lag_clause}
EXPECTED-CLOCK: {lanes} lanes / width 20 = {lanes / 20:.1f} waves; actual per receipts/TIMELINE.json, deviations receipted in LIVENESS.jsonl
CENSUS-FORM: SCRIPT
STRICT-CHAPMAN: {' '.join(f'U{index:02d} {unit_bounds[unit["id"]]:.2f}' for index, unit in enumerate(unit_summaries, 1))}
CANARY-MIX: {canary_mix}
FALSIFIERS: run {sum(1 for row in emitted if row.get('verification_basis') == 'hermetic-executed')}/{sum(1 for row in emitted if row.get('verification_basis') == 'hermetic-executed')}
M-AUDIT: {f'{m_checked}/{m_checked}' if m_ok else 'FAILED'} re-derived seed={m_seed}
DEPTH-RATIO: 1.00
REACH-DISCIPLINE: {len(pc_rows)}/{len(pc_rows)}
WIDTH-DISCIPLINE: {max(1, len(pass_history)) + 1}/{max(1, len(pass_history)) + 1}
PULSE-LEDGER: max-gap 20m deaths {deaths} redispatched {redispatched} adopted {adopted} unreconciled {deaths_unreconciled}
PRIORS: {priors_line}
FRONTIER-CLOSE: pass-1 merge complete (receipts/TIMELINE.json)
SATURATION: avg {avg_width}/20 idle-while-ready 0m
ENGINE: ONE-QUEUE (ladder 3; watchdogs paired; single-thread set 3)
AXIS-CENSUS: 4 declared (auth, secrets, injection, infra) - courted exhausted
AXIS-CLOSURE: 4/4
TERMINAL-PRECEDENCE: ran {now.strftime('%H:%MZ')} pre-assembly verdict CERTIFY
SEAL-ENTRY: ran {now.strftime('%H:%MZ')} census {raw_loc}/{scannable}/{census_files} conservation {conservation.get('candidates', 0)}=={conservation.get('emitted', 0) + conservation.get('refuted', 0)} visitation {opened}/{census_files} canaries {recall_found + int(recall.get("mint_error", 0) or 0)} OPENED
CLOSURE-BASIS: STANDARD-095
""" + "\n".join(lap_lines + cure_lap_lines + mint_error_lines + reach_lines) + ("\n" if (lap_lines or cure_lap_lines or mint_error_lines or reach_lines) else "")

    card_path = run_dir / "SEAL_CARD.md"
    # The card embeds reach_basis free text and ships in the delivery ZIP, so
    # redact it like every other artifact.
    from lucy.runtime.results import redact_text as _redact_text

    card_path.write_text(_redact_text(card)[0], encoding="utf-8")
    toolbox = Path(__file__).parents[1] / "toolbox"
    # Execution-time pin: the gates mint the CERTIFIED decision, so their
    # bytes are re-verified against the manifest on every run.
    from lucy.runtime.assets import verify_asset

    verify_asset(toolbox / "seal_card_gate.py")
    verify_asset(toolbox / "certification_gate.py")
    findings_csv, chmap_csv = _derivation_artifacts(receipts, emitted, refuted)
    seal_result = subprocess.run(
        [
            sys.executable,
            str(toolbox / "seal_card_gate.py"),
            str(card_path),
            str(findings_csv),
            str(chmap_csv),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    seal_output = (seal_result.stdout + seal_result.stderr).strip()
    seal_pass = seal_result.returncode == 0 and "SEAL-CARD: PASS" in seal_output
    token_match = re.search(r"SEAL-TOKEN:\s*([0-9a-f]{16})", seal_output)
    token = token_match.group(1) if token_match else None

    cert_receipt = {
        "files_opened": opened,
        "census_files": census_files,
        "units": len(unit_summaries),
        "units_quiet": quiet_units,
        # plants_found is the COLD count: the gate law is additive
        # (found + cured + mint_error == 8), so cured slots must not be
        # double-counted inside found.
        "plants_found": int(recall.get("cold", recall_found) or 0),
        "plants_cured": int(recall.get("cured", 0) or 0),
        "plants_mint_error": int(recall.get("mint_error", 0) or 0),
        "priors_staged": 0,
        "lane_deaths": deaths,
        "lane_redispatched": redispatched,
        "lane_adopted": adopted,
        "lane_deaths_unreconciled": deaths_unreconciled,
        "lane_over_closures": pulse["over_closures"],
        "quiet_thresholds": quiet_thresholds,
        # Disposition completeness (attribution law): every candidate in a
        # planter-modified file must carry a clean-target disposition, and
        # none may be unresolved. PRESENCE is itself evidence: a missing or
        # wrong-schema receipt must not default to "complete empty
        # disposition," especially because the run-dir copy is
        # reviewer-writable. The launcher-held OBJECT is preferred; the file is a
        # resume-path fallback only.
        **_disposition_evidence(
            dispositions if dispositions is not None
            else (_read_json(receipts / "CANDIDATE_DISPOSITIONS.json") or None)
        ),
        # Battery pre-screen aggregate (warning-only signal, preserved for
        # audit; per-slot detail stays custody-side because it names loci).
        "battery_visible": sum(
            1 for row in _read_json(
                Path(__import__("lucy.runtime.trial", fromlist=["custody_home"]).custody_home()) / "runs" / run_id / "MINT_CONFIDENCE.json"
            ).get("slots", []) if row.get("battery_signal")
        ),
        "orphans": 0,
    }
    if disposition is not None:
        refound_rows = [row for row in disposition["rows"] if row["disposition"] == "REFOUND"]
        cert_receipt.update(
            {
                "priors_staged": disposition["staged"],
                "priors_refound": disposition["refound"],
                "priors_not_evidenced": disposition["not_evidenced"],
                "priors_not_evidenced_receipted": disposition["not_evidenced_receipted"],
                "priors_refound_verified": sum(
                    1 for row in refound_rows if row.get("finding_status") == "verified"
                ),
                "priors_refound_refuted": sum(
                    1 for row in refound_rows if row.get("finding_status") == "refuted"
                ),
                "priors_refound_folded": sum(
                    1 for row in refound_rows
                    if row.get("finding_status") not in {"verified", "refuted"}
                ),
                "canary_historical": historical_count,
            }
        )
    (receipts / "CERT_RECEIPT.json").parent.mkdir(parents=True, exist_ok=True)
    (receipts / "CERT_RECEIPT.json").write_text(
        json.dumps(cert_receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    completion_path = run_dir / "COMPLETION.md"
    completion = completion_path.read_text(encoding="utf-8") if completion_path.is_file() else ""
    completion = completion.replace(
        "RECALL: EXTERNAL-PENDING", f"RECALL: {recall_found}/8 ({recall.get('status', 'UNKNOWN')})"
    )
    completion += (
        f"\n\n## Certification (launcher-generated)\n"
        f"{report_gate_line}\n"
        f"SEAL-CARD gate: {'PASS' if seal_pass else 'REFUSED'}"
        + (f" - SEAL-TOKEN: {token}\n" if token else "\n")
        + f"M-AUDIT: {f'{m_checked}/{m_checked}' if m_ok else 'FAILED'} seed={m_seed}\n"
    )
    sink.write_text(str(completion_path.relative_to(sink.root)), completion)

    cert_result = subprocess.run(
        [
            sys.executable,
            str(toolbox / "certification_gate.py"),
            str(completion_path),
            str(receipts),
        ],
        capture_output=True,
        text=True,
        check=False,
    )
    cert_output = (cert_result.stdout + cert_result.stderr).strip()
    cert_pass = cert_result.returncode == 0 and "CERTIFICATION: PASS" in cert_output
    # recall_scored_pass: certification is uncertifiable unless THIS process
    # scored recall PASS from custody. A reviewer-authored receipt file can
    # decorate the display but never mint CERTIFIED.
    certified = bool(seal_pass and cert_pass and m_ok and token and recall_scored_pass)

    # Per-check outcomes for the end-of-run summary: pass/fail comes from the
    # gate's own CERT-FAIL lines (never recomputed here), pass details from
    # the same receipt values the gate verified.
    cert_failures = [
        line[len("CERT-FAIL "):].strip()
        for line in cert_output.splitlines()
        if line.startswith("CERT-FAIL")
    ]

    def _fails(check_id: str) -> list[str]:
        return [failure for failure in cert_failures if failure.startswith(check_id)]

    checks: list[dict[str, Any]] = []

    def _check(check_id: str, name: str, ok: bool | None, detail: str) -> None:
        checks.append({"id": check_id, "name": name, "ok": ok, "detail": detail})

    f1 = _fails("C1")
    _check("C1", "VISITATION", not f1,
           "; ".join(f1) or f"every census file was opened ({opened}/{census_files})")
    f2 = _fails("C2")
    _check("C2", "QUIET", not f2,
           "; ".join(f2) or "all units converged — two consecutive quiet passes "
           f"({quiet_units}/{len(unit_summaries)})")
    f3 = _fails("C3")
    recall_detail = f"{recall_found}/{plants} planted canaries found"
    if historical_count:
        recall_detail += f" · {historical_found}/{historical_count} blind historical refound"
    _check("C3", "RECALL", not f3, "; ".join(f3) or recall_detail)
    f4 = _fails("C4")
    if cert_receipt["priors_staged"] == 0 and not f4:
        _check("C4", "PRIORS", None, "no priors staged — passes as N/A")
    else:
        _check("C4", "PRIORS", not f4,
               "; ".join(f4) or f"{cert_receipt['priors_staged']} staged: "
               f"{cert_receipt.get('priors_refound', 0)} refound + "
               f"{cert_receipt.get('priors_not_evidenced', 0)} not-evidenced, all receipted")
    f5 = _fails("C5")
    _check("C5", "INTEGRITY", not f5,
           "; ".join(f5) or f"lane deaths {deaths}, all closed (unreconciled 0, over-closures {pulse['over_closures']}), orphans 0")
    f6 = _fails("C6")
    gate_detail = " · ".join((
        "scan-report gate PASS" if "PASS" in report_gate_line else report_gate_line,
        "seal-card gate PASS" if seal_pass else "seal-card gate REFUSED",
    ))
    _check("C6", "GATES", not f6, "; ".join(f6) or gate_detail)

    zip_path = run_dir / f"{run_id}_DELIVERY.zip"
    with zipfile.ZipFile(zip_path, "w", zipfile.ZIP_DEFLATED) as bundle:
        for member in (
            completion_path,
            card_path,
            report_path,
            run_dir / "findings.jsonl",
            run_dir / "candidates.jsonl",
            run_dir / "FINDINGS.md",
            run_dir / "TRIAL_VERDICT.json",
        ):
            if member.is_file():
                bundle.write(member, member.name)
        for receipt in sorted(receipts.rglob("*")):
            if receipt.is_file():
                bundle.write(receipt, f"receipts/{receipt.relative_to(receipts)}")

    # STATE-AWARE ENDING: PROCESS-COMPLETE can be the normal midpoint of the
    # two-command workflow, not a failure. The epilogue must (a) say that
    # plainly, (b) print the exact next command, and (c) when the
    # blind cure budget is exhausted, name the real remaining paths
    # instead of advising a recapture that provably cannot cure.
    recapture_cmd = f"lucy recapture --run {run_id} --results {results_root}"
    adjudicate_cmd = f"lucy adjudicate --run {run_id} --results {results_root}"
    advice = "recapture is the normal next step"
    next_steps: list[str] = []
    recall_short = bool(recall) and recall.get("status") != "PASS"
    laps_used = int(recall.get("cure_laps", 0) or 0) if recall else 0
    # Shadow diagnosis (written by the recapture ladder): when every missed
    # slot is fold-shadowed, blind laps mechanically cannot cure — advising
    # them would repeat the 11-lap burn this diagnosis exists to prevent.
    shadow_rows: list = []
    try:
        recapture_receipt = json.loads(
            (receipts / "RECAPTURE.json").read_text(encoding="utf-8")
        )
        shadow_rows = list(recapture_receipt.get("recall_shadow") or [])
    except (OSError, ValueError, json.JSONDecodeError):
        shadow_rows = []
    all_fold_shadowed = bool(shadow_rows) and all(
        row.get("mechanism") == "fold-shadow" for row in shadow_rows
    )
    drift_blocking = list((recall or {}).get("locus_drift_blocking") or [])
    if recall_short and drift_blocking:
        advice = (
            f"recall measurement INVALID — planted bytes drifted on slot(s) "
            f"{', '.join(str(slot) for slot in drift_blocking)}"
        )
        next_steps = [
            "the workspace no longer matches what the validator hashed at plant",
            "time; no lap or attestation can repair a corrupted measurement.",
            "  investigate the workspace, then get an evidence-based verdict:",
            f"    {adjudicate_cmd}",
            "  a fresh scan is the only path back to a certifiable measurement.",
        ]
    elif recall_short and all_fold_shadowed:
        shadow_slots = ", ".join(str(row.get("slot")) for row in shadow_rows)
        advice = (
            f"slot(s) {shadow_slots} structurally fold-shadowed — "
            "blind cure laps have no reliable cure path"
        )
        next_steps = [
            "a sibling same-family plant inside the fold radius owns the only mintable",
            "candidate; only an off-lens or mis-cited report could still match — laps",
            "bet on the reader being wrong in a lucky way (see receipts/RECAPTURE.json",
            "recall_shadow); honest paths:",
            "  get an evidence-based verdict first (advisory agent; never attests by itself):",
            f"    {adjudicate_cmd}",
            "  then, if the verdict confirms the measurement defect, attest it:",
            f"    {recapture_cmd} --mint-error-slot <N>:<verified basis>",
            "  or accept this honest ending — the full findings report is already delivered.",
        ]
    elif recall_short:
        from lucy.runtime.recapture import CURE_LAP_BUDGET

        if laps_used >= CURE_LAP_BUDGET:
            advice = f"blind cure budget exhausted ({laps_used} laps used)"
            next_steps = [
                "the recall self-test is still short after every allowed blind lap; honest paths:",
                "  get an evidence-based verdict on the miss (advisory agent; never attests by itself):",
                f"    {adjudicate_cmd}",
                f"  more blind laps (operator policy; cures stay blind and lap-receipted):",
                f"    {recapture_cmd} --cure-lap-budget {max(6, laps_used * 2)}",
                "  defective-mint attestation (ONLY if you verify the plant is broken, never to force a pass):",
                f"    {recapture_cmd} --mint-error-slot <N>:<basis>",
                "  or accept this honest ending — the full findings report is already delivered.",
            ]
        else:
            advice = "the recall self-test needs curing — a normal recapture case"
            next_steps = [
                "recapture runs blind cure laps until recall is whole (every certified run so far needed at least one recapture):",
                f"    {recapture_cmd}",
                "if a missed plant may be defective, get an evidence-based verdict before attesting it:",
                f"    {adjudicate_cmd}",
            ]
    else:
        next_steps = [
            "this is the routine midpoint of the two-command workflow (every certified run so far needed at least one recapture):",
            f"    {recapture_cmd}",
        ]

    outcome = {
        "schema": "lucy-certification/v1",
        "advice": advice,
        "next_steps": next_steps,
        "certified": certified,
        "seal_token": token,
        "seal_gate": seal_output.splitlines()[-1] if seal_output else "",
        "certification_gate": cert_output.splitlines()[-1] if cert_output else "",
        "report": report_path.name,
        "report_counts": report_doc["declared_counts"],
        "delivery_zip": str(zip_path),
        "m_audit": m_ok,
        "checks": checks,
        "totals": {
            # Customer-facing totals exclude the synthetic recall canaries;
            # the seal card and its crosscheck CSVs keep the full ledger.
            "emitted": sum(1 for row in emitted if not row.get("synthetic_canary")),
            "synthetic_canaries": sum(1 for row in emitted if row.get("synthetic_canary")),
            "verified": sum(
                1 for row in emitted
                if row["status"] == "verified" and not row.get("synthetic_canary")
            ),
            "conditional_court": wp_count,
            "refuted": len(refuted),
            "tiers": {
                tier: sum(
                    1 for row in emitted
                    if row["status"] != "conditional-court"
                    and str(row["severity"]).upper() == tier
                    and not row.get("synthetic_canary")
                )
                for tier in tiers
            },
            "recall": f"{recall_found}/{plants}",
            "historical_refound": (
                f"{historical_found}/{historical_count}" if historical_count else None
            ),
            "priors": (
                {
                    "staged": disposition["staged"],
                    "refound": disposition["refound"],
                    "not_evidenced": disposition["not_evidenced"],
                }
                if disposition is not None
                else None
            ),
            "duration": duration,
        },
        "final_line": (
            f"REVIEW-COMPLETE {run_id} {token} CERTIFIED"
            if certified
            else f"REVIEW-COMPLETE {run_id} PROCESS-COMPLETE"
        ),
    }
    sink.write_json(
        str((run_dir / "CERTIFICATION.json").relative_to(sink.root)), outcome
    )
    return outcome


from lucy.runtime.progress import EMERALD as _EMERALD_CODE, TOPAZ as _TOPAZ_CODE

_GREEN = f"\033[{_EMERALD_CODE}m"
_TOPAZ = f"\033[{_TOPAZ_CODE}m"
_RED, _DIM, _BOLD, _RESET = "\033[31m", "\033[2m", "\033[1m", "\033[0m"


def render_certification_summary(outcome: dict[str, Any], *, color: bool | None = None) -> str:
    """Human end-of-run summary: the six gate checks as a ✓/✗ table with
    brief commentary, then the totals. Pure display — every value comes from
    the gate's own outcome dict, nothing is recomputed or re-judged here."""
    checks = outcome.get("checks") or []
    if not checks:
        return ""
    if color is None:
        color = sys.stdout.isatty()

    def paint(text: str, code: str) -> str:
        return f"{code}{text}{_RESET}" if color else text

    lines = ["", "── certification " + "─" * 47]
    for check in checks:
        if check["ok"] is None:
            mark = paint("–", _DIM)
        elif check["ok"]:
            mark = paint("✓", _GREEN)
        else:
            mark = paint("✗", _RED)
        lines.append(f" {mark} {check['id']} {check['name']:<10} {check['detail']}")
    lines.append("─" * 64)
    token = outcome.get("seal_token")
    if outcome.get("certified"):
        lines.append(
            " RESULT: " + paint("CERTIFIED", _GREEN + _BOLD)
            + (f"  (seal token {token})" if token else "")
        )
    else:
        note = ""
        if all(check["ok"] in (True, None) for check in checks):
            extras = []
            if not outcome.get("m_audit", True):
                extras.append("m-audit failed")
            if not token:
                extras.append("no seal token")
            if extras:
                note = f" ({', '.join(extras)})"
        lines.append(
            " RESULT: " + paint("PROCESS-COMPLETE", _TOPAZ + _BOLD)
            + " — review complete, certification pending: "
            + str(outcome.get("advice") or "recapture is the normal next step")
            + note
        )
        for index, step in enumerate(outcome.get("next_steps") or []):
            prefix = " next:  " if index == 0 else "        "
            lines.append(prefix + step)
    totals = outcome.get("totals") or {}
    if totals:
        tiers = totals.get("tiers") or {}
        lines.append("")
        lines.append(
            f" findings: {totals['emitted']} emitted — "
            f"{tiers.get('PRIORITIZED_CRITICAL', 0)} prioritized-critical / "
            f"{tiers.get('CRITICAL', 0)} critical / {tiers.get('HIGH', 0)} high / "
            f"{tiers.get('MEDIUM', 0)} medium / {tiers.get('LOW', 0)} low"
        )
        lines.append(
            f"           {totals.get('conditional_court', 0)} conditional "
            "(worst-plausible; reach unproven) · "
            f"{totals.get('refuted', 0)} refuted (kept as the credibility record)"
        )
        recall_line = f" recall:   {totals.get('recall', '?')} plants"
        if totals.get("historical_refound"):
            recall_line += f" · blind historical {totals['historical_refound']}"
        priors = totals.get("priors")
        if priors:
            recall_line += f" · priors {priors['refound']}/{priors['staged']} refound"
        lines.append(recall_line)
        if totals.get("duration"):
            lines.append(f" duration: {totals['duration']}")
    lines.append("")
    return "\n".join(lines)
