"""Assemble the authoritative gated scan report from finalized findings.

Consumes ``findings.jsonl`` (verified + conditional + refuted rows written by
:mod:`lucy.runtime.artifacts`), emits ``<CMDB>_SCAN_REPORT.json`` in the source
contract (schema_version 2.0), and validates it with the pinned toolbox gate.
Refuted rows never enter the report; they remain in findings.jsonl and the
completion record as the credibility ledger.
"""

from __future__ import annotations

from lucy import __version__ as lucy_version

from datetime import datetime, timezone
import json
from pathlib import Path
import re
import subprocess
import sys
from typing import Any


TIER_KEY = {
    "PRIORITIZED_CRITICAL": "pc",
    "CRITICAL": "critical",
    "HIGH": "high",
    "MEDIUM": "medium",
    "LOW": "low",
}

# Category-keyword -> canonical CWE for rows the courts never graded
# (MEDIUM/LOW conditional rows). Ordered: first match wins.
CATEGORY_CWE = (
    (("sql",), "CWE-89"),
    (("command", "exec"), "CWE-78"),
    (("path", "traversal"), "CWE-22"),
    (("ssrf",), "CWE-918"),
    (("deserial",), "CWE-502"),
    (("template",), "CWE-1336"),
    (("xss",), "CWE-79"),
    (("xxe", "parser"), "CWE-611"),
    (("redirect",), "CWE-601"),
    (("authz", "authorization", "idor", "ownership", "tenant"), "CWE-862"),
    (("authn", "authentication", "auth"), "CWE-306"),
    (("session",), "CWE-613"),
    (("credential", "hardcoded", "secret", "password", "key"), "CWE-798"),
    (("crypto", "cipher", "hash"), "CWE-327"),
    (("tls", "certificate", "hostname"), "CWE-295"),
    (("log", "pii", "sensitive"), "CWE-532"),
    (("privilege", "container", "root"), "CWE-250"),
    (("iam", "policy", "permission"), "CWE-732"),
    (("ingress", "exposure", "public", "network"), "CWE-668"),
    (("pipeline", "supply", "dependency", "pinning"), "CWE-829"),
    (("debug",), "CWE-489"),
    (("cors",), "CWE-942"),
)
DEFAULT_CWE = "CWE-693"  # protection mechanism failure


def _category_cwe(category: str, title: str) -> str:
    text = f"{category} {title}".lower()
    for keywords, cwe in CATEGORY_CWE:
        if any(keyword in text for keyword in keywords):
            return cwe
    return DEFAULT_CWE


def _identity(workspace: Path, run_dir: Path | None = None) -> dict[str, str]:
    estate = workspace.name
    if run_dir is not None:
        trial_doc = run_dir / "trial.json"
        if trial_doc.is_file():
            target = json.loads(trial_doc.read_text(encoding="utf-8")).get("target")
            if target:
                estate = Path(target).name
    cmdb_id, app_name = estate, estate
    tag = workspace / "CMDB_ID.txt"
    if tag.is_file():
        first = tag.read_text(encoding="utf-8", errors="replace").splitlines()[:1]
        if first and "|" in first[0]:
            left, right = first[0].split("|", 1)
            # CMDB_ID.txt is untrusted repo content and the id becomes the
            # report filename: constrain it to a safe basename charset so it
            # can never traverse out of the run directory.
            if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,63}", left.strip()) and right.strip():
                cmdb_id, app_name = left.strip(), right.strip()
    cmdb_id = re.sub(r"[^A-Za-z0-9._-]", "-", cmdb_id)[:64].strip(".") or "APP"
    # app_name is equally untrusted repo text headed for the report, so apply
    # the same character and length constraints used for the identifier.
    app_name = re.sub(r"[^A-Za-z0-9 ._-]", "-", app_name)[:64].strip() or cmdb_id
    return {"cmdb_id": cmdb_id, "app_name": app_name, "estate": estate}


def _split_locus(path: str, estate: str) -> tuple[str, str]:
    parts = path.split("/")
    if len(parts) > 1:
        return parts[0], "/".join(parts[1:])
    return estate, path


def _conditional_fix(category: str, path: str, line: int) -> str:
    return (
        f"Review the {category} weakness at {path}:{line} and apply the "
        "family-standard control (validate/bind/parameterize or remove the "
        "weakened setting); not yet independently verified."
    )


def build_report(run_dir: Path, workspace: Path, run_id: str) -> tuple[Path, dict[str, Any]]:
    findings_path = run_dir / "findings.jsonl"
    rows = [
        json.loads(line)
        for line in findings_path.read_text(encoding="utf-8").splitlines()
        if line.strip()
    ]
    identity = _identity(workspace, run_dir)
    report_rows = []
    tally = {key: 0 for key in TIER_KEY.values()}
    for row in rows:
        if row.get("status") == "refuted":
            continue
        # Synthetic recall canaries (launcher-annotated after external
        # scoring) never enter the customer report — they are LUCY's own
        # planted test mutations, cured on workspace disposal.
        if row.get("synthetic_canary"):
            continue
        severity = str(row["severity"]).upper()
        if severity not in TIER_KEY:
            continue
        repo, rel = _split_locus(str(row["path"]), identity["estate"])
        title = str(row["title"]).rstrip()
        if title.endswith(("...", "…")):
            title = title.rstrip(".…") + "."
        cwe = str(row.get("cwe", "")).strip()
        if not re.fullmatch(r"CWE-[1-9][0-9]*", cwe):
            cwe = _category_cwe(str(row.get("category", "")), title)
        fix = str(row.get("fix", "")).strip()
        if len(fix) < 20 and not fix.startswith("No code change required;"):
            fix = _conditional_fix(str(row.get("category", "issue")), rel, int(row["line"]))
        entry: dict[str, Any] = {
            "id": str(row["id"]),
            "severity": severity,
            "repo": repo,
            "path": f"{rel}:{int(row['line'])}",
            "title": title,
            "cwe_canonical": cwe,
            "fix": fix,
            # Legacy contract carries two statuses; court-CONDITIONAL rows
            # (mechanism verified, precondition unresolved) map to conditional
            # at their uncapped severity.
            "status": "verified" if row.get("status") == "verified" else "conditional",
        }
        if severity == "PRIORITIZED_CRITICAL":
            reason = str(row.get("disproof_attempt", "")).strip() or str(
                row.get("reach_basis", "")
            )
            entry["pc_reason"] = reason or (
                "All four PC-1 clauses evidenced by the verification court; "
                "see court verdict in findings.jsonl."
            )
        report_rows.append(entry)
        tally[TIER_KEY[severity]] += 1

    report_ids = {row["id"] for row in report_rows}
    chains = []
    chains_path = run_dir / "chains.jsonl"
    if chains_path.is_file():
        for line in chains_path.read_text(encoding="utf-8").splitlines():
            if not line.strip():
                continue
            chain = json.loads(line)
            if all(hop["finding_id"] in report_ids for hop in chain.get("hops", [])):
                chains.append(chain)

    document = {
        "schema_version": "2.0",
        "app": {
            **identity,
            "scan_run": f"lucy {run_id}",
            "scanner_version": lucy_version,
            "sealed_date": datetime.now(timezone.utc).strftime("%Y-%m-%d"),
        },
        "declared_counts": {"total": sum(tally.values()), **tally, "chains": len(chains)},
        "findings": report_rows,
        "chains": chains,
    }
    out_path = run_dir / f"{identity['cmdb_id']}_SCAN_REPORT.json"
    # The gated report carries reviewer-authored finding text and repo-
    # derived identity fields into the delivery ZIP, so redact it at the
    # same write boundary as every other sink artifact.
    from lucy.runtime.results import redact_text as _redact_text

    out_path.write_text(_redact_text(json.dumps(document, indent=2, sort_keys=False))[0] + "\n", encoding="utf-8")
    return out_path, document


def run_report_gate(report_path: Path) -> str:
    from lucy.runtime.assets import verify_asset

    gate = Path(__file__).parents[1] / "toolbox" / "scan_report_gate.py"
    verify_asset(gate)
    result = subprocess.run(
        [sys.executable, str(gate), str(report_path)],
        capture_output=True,
        text=True,
        check=False,
    )
    output = (result.stdout + result.stderr).strip()
    if result.returncode != 0 or "SCAN-REPORT GATE: PASS" not in output:
        raise ValueError(f"scan-report gate refused:\n{output}")
    return output
