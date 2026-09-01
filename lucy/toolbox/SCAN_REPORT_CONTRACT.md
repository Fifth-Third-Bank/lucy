# SCAN REPORT CONTRACT — one JSON file per app (schema_version 2.0)

The run's findings hand off to the operator as ONE file on the run
branch: `<CMDB>_SCAN_REPORT.json`. Everything downstream is built from
it, so it must land clean. `SCAN_REPORT_TEMPLATE.json` beside this file
is the blank skeleton; `scan_report_gate.py` checks the machine-verifiable
rules below deterministically and downstream validation runs the identical
gate on the pushed file — a report that fails the gate here fails there too.
Confidential handling and review requirements remain operator
responsibilities.

## Identity

`app.cmdb_id`, `app.app_name`, `app.estate` are required. If the
repository root contains `CMDB_ID.txt` (an operator-committed file:
first line `<CMDB> | <App Name>`, e.g. `APP001 | Example
Service`), use it. Otherwise use the repository/estate slug as
`cmdb_id` and the best available name — the gate accepts any non-empty
non-placeholder values, and the operator reconciles ids on collection.
Name the file `<cmdb_id>_SCAN_REPORT.json` exactly.

## Severity enum and PC-1s

Tier assignment follows SEVERITY_RUBRIC.md beside this file: readers
propose, the verification COURT assigns the final tier from the
rubric's decision table, and the court evaluates EVERY CRITICAL
against the PC-1 four clauses with the outcome recorded in its
verdict row.

Five tiers only: `PRIORITIZED_CRITICAL` · `CRITICAL` · `HIGH` ·
`MEDIUM` · `LOW`. INFO does not exist in this contract — do not emit
INFO rows. A `PRIORITIZED_CRITICAL` (PC-1) is a critical that meets
ALL FOUR clauses, stated in its required `pc_reason`:
(1) INTERNET-REACHABLE — the vulnerable surface is reachable from the
internet, with the evidence named; (2) YIELD AT SCALE — exploitation
yields protected data or privileged functions across an affected
population, not a single subject; (3) LIVE
CREDENTIAL IN-CHAIN — an attacker can actually hold the credential or
token the chain needs; (4) NO COMPENSATING CONTROL on estate bytes —
name what's absent. Ordinary criticals carry no `pc_reason`. Zero
PC-1s is a valid outcome (`pc: 0`, no `pc_reason` anywhere).

## Per finding (required unless marked optional)

- `id` — unique, non-empty, never `...`
- `severity` — the enum above
- `repo` — first path segment (the repository)
- `path` — the rest, repo-relative, ending `:line` (e.g. `src/A.java:83`)
- `title` — the FULL claim sentence, verbatim, untruncated, no
  trailing ellipsis
- `cwe_canonical` — a real `CWE-NNN`, never `CWE-0`/`none`
- `fix` — REQUIRED: 1-2 imperative sentences specific to THIS finding
  (the concrete change, named); the only null-equivalent is exactly
  "No code change required; <reason>". The gate refuses hollow fixes
- `pc_reason` — PC-1 rows only (required there, forbidden elsewhere)
- `status` — optional (`verified`/`conditional`); rides along, the
  operator's process never drops a row because of it

## Counts (the drift check — the single most important rule)

`declared_counts.total` MUST equal `pc + critical + high + medium +
low`, each tier count MUST equal its `findings[]` tally, and `chains`
MUST equal the number of entries in `chains[]`. If the headline counts
do not match the rows, the report is not ready — fix the ROWS or the
COUNTS to reflect reality, never pad either.

## Chains

A chain is 2+ linked findings: `id`, `title`,
`status` (`confirmed`|`conditional`), and `hops[]` where every
`finding_id` exists in `findings[].id`. No narrative-only chains.

## Include / exclude

INCLUDE every finding at every tier (no severity floor), verdicts
AS-IS from the verified ledger (refuted rows stay out; the operator's
context filter does its own re-scoring — never elevate, never
pre-filter). EXCLUDE: INFO rows; literal secret or personal-data VALUES
anywhere (reference by kind only, including test fixtures); scan-tooling
loci (`.claude/`, `CLAUDE*.md`); absolute paths; fabricated CWEs;
truncated ids or titles.

Automated masking is defense in depth for recognized credential forms,
email addresses, and formatted U.S. SSNs; it is not comprehensive PII
anonymization or DLP. Treat the gated report and delivery archive as
confidential and review them before sharing outside the source-data access
boundary.

## Hand-off

Run `python3 <toolbox>/scan_report_gate.py <CMDB>_SCAN_REPORT.json`.
It must print `SCAN-REPORT GATE: PASS` before the file is committed as
final. Commit the file at the run-branch root beside COMPLETION.md.

## Multi-site (systemic) findings
One row may represent a defect repeated across files ONLY if its
also_affects array lists EVERY other affected repo/path:line. A
court-verified serious finding may fold into another row only when
its locus appears in that row's also_affects — otherwise it must be
its own row. This makes two honest reports of the same estate
locus-comparable regardless of packaging style; the coverage
instrument expands also_affects when scoring.

## Staged priors are run inputs
No report row may carry a PRIORS_* locus (gate-refused). Anything a
sweep finds inside staged priors files is recorded in COMPLETION.md
as a STAGING-INPUT note for the operator, never in the report.
