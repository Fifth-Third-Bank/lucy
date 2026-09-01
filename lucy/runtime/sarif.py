"""Derived SARIF 2.1.0 export from the gated scan report.

The gated ``<CMDB>_SCAN_REPORT.json`` remains the authoritative artifact; this
export is generated FROM it after its gate passes, never instead of it, and it
never carries refuted-row content (those live in findings.jsonl/COMPLETION.md).
"""

from __future__ import annotations

from lucy import __version__ as lucy_version

import argparse
import json
from pathlib import Path
import sys


SEVERITY_LEVEL = {
    "PRIORITIZED_CRITICAL": "error",
    "CRITICAL": "error",
    "HIGH": "error",
    "MEDIUM": "warning",
    "LOW": "note",
}
SEVERITY_RANK = {
    "PRIORITIZED_CRITICAL": "9.8",
    "CRITICAL": "9.0",
    "HIGH": "7.5",
    "MEDIUM": "5.0",
    "LOW": "2.5",
}


def to_sarif(report: dict) -> dict:
    rules = {}
    results = []
    for finding in report.get("findings", []):
        cwe = finding["cwe_canonical"]
        rule_id = f"lucy/{cwe}"
        rules.setdefault(
            rule_id,
            {
                "id": rule_id,
                "name": cwe.replace("-", ""),
                "shortDescription": {"text": cwe},
                "helpUri": f"https://cwe.mitre.org/data/definitions/{cwe.split('-')[1]}.html",
            },
        )
        path, _, line = finding["path"].rpartition(":")
        results.append(
            {
                "ruleId": rule_id,
                "level": SEVERITY_LEVEL[finding["severity"]],
                "message": {"text": finding["title"] + " Fix: " + finding["fix"]},
                "partialFingerprints": {"lucyId": finding["id"]},
                "properties": {
                    "severity": finding["severity"],
                    "security-severity": SEVERITY_RANK[finding["severity"]],
                    "status": finding.get("status", "verified"),
                },
                "locations": [
                    {
                        "physicalLocation": {
                            "artifactLocation": {
                                "uri": f"{finding['repo']}/{path}",
                                "uriBaseId": "SRCROOT",
                            },
                            "region": {"startLine": int(line) if line.isdigit() else 1},
                        }
                    }
                ],
            }
        )
    scanner_version = report.get("app", {}).get("scanner_version")
    return {
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [
            {
                "tool": {
                    "driver": {
                        "name": "LUCY",
                        # informationUri is added once the public mirror URL
                        # is finalized; a fictional placeholder repo is worse
                        # than no link for SARIF consumers.
                        # Provenance lives in the artifact: driver.version
                        # is the version recorded by the scan that PRODUCED
                        # the report, and is OMITTED for artifacts that
                        # predate scanner_version — a converter must never
                        # claim a scanner version it cannot know (external
                        # review, round 3). The converter identifies itself
                        # in the property bag either way.
                        **(
                            {"version": scanner_version}
                            if scanner_version
                            else {}
                        ),
                        "properties": {"converterVersion": lucy_version},
                        "rules": sorted(rules.values(), key=lambda rule: rule["id"]),
                    }
                },
                # The scan-run identifier is run metadata, not a tool
                # version (GitHub code scanning renders driver.version).
                "automationDetails": {
                    "id": report.get("app", {}).get("scan_run", ""),
                },
                "results": results,
            }
        ],
    }


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("report", type=Path, help="gated <CMDB>_SCAN_REPORT.json")
    parser.add_argument("--output", type=Path, default=None)
    args = parser.parse_args()
    report = json.loads(args.report.read_text(encoding="utf-8"))
    sarif = to_sarif(report)
    output = args.output or args.report.with_suffix(".sarif")
    output.write_text(json.dumps(sarif, indent=2, sort_keys=False) + "\n", encoding="utf-8")
    print(str(output))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
