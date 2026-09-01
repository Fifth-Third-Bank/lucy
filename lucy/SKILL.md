---
name: lucy
description: Run a Claude Code-only verified source review using unit-partitioned independent reader lenses, independent courts, quiet convergence, receipts, and externally scored recall tests. Use only in a workspace prepared by the lucy launcher.
compatibility: Claude Code 2.1.245+ and Python 3.10+.
allowed-tools: Read, Grep, Glob, Write, Agent(lucy-reader), Agent(lucy-court), ScheduleWakeup, Bash(git status *), Bash(git rev-parse *), Bash(git ls-files *), Bash(lucy-units *), Bash(lucy-merge *), Bash(lucy-finalize *), Bash(lucy-toolbox *)
disable-model-invocation: true
---

# LUCY Verified Review

Run the prepared workspace in `$ARGUMENTS` to `PROCESS-COMPLETE`. You are the
orchestrator, not a reader, planter, or recall grader. Recall scoring, report
assembly, the seal card, and certification all happen OUTSIDE this session in
the launcher after you exit — your successful ending is always
`PROCESS-COMPLETE`; never claim `CERTIFIED`.

## Binding Boundaries

- Work only in the current prepared workspace and the supplied `--run-dir`.
- Never search outside those two roots.
- Never search for an answer key, custody record, canary definition, planter,
  or hidden trial metadata.
- Never inspect source to find vulnerabilities yourself. Delegate every read to
  fresh `lucy-reader` agents using the static brief below.
- Never add canary hints, hot-file hints, prior findings, or your own source
  observations to a reader brief.
- Never create, modify, or commit `.claude/settings.json`.
- Never create a branch, commit, push, fetch, open an issue, or create a PR.
- Never run application code, builds, package managers, network tools, or live
  endpoints. The only executable scanner commands are the installed pinned
  wrappers: `lucy-units`, `lucy-merge`, `lucy-finalize`, `lucy-toolbox`.
- Write only staging data beneath `<run-dir>/staging` and, at the end,
  `<run-dir>/COMPLETION.md`. The launcher's permission rules enforce exactly
  that surface; receipts are wrapper-written. Final artifacts are produced by
  the runtime, which applies best-effort masking for recognized credential,
  email, and formatted U.S. SSN patterns.

## Arguments

Parse `$ARGUMENTS` for these required values:

```text
--run-id <r-...> --run-dir <absolute-path>
```

The launcher adds `--noninteractive` only for print-mode runs. In that mode,
do not call `ScheduleWakeup`; use completion-notification fallback.

`RUN_DIR` must be outside the current Git repository. Refuse any other shape.

Set `TARGET` = current working directory.

## Phase 0: Preflight

1. Run `git status --short`. The prepared workspace must contain modified
   existing source/config files plus `PLANT_NOTICE.txt`. Read the external
   `MINT_COMMITMENT.json` only to verify `plant_count=8`, family counts are
   2/2/2/2, and `historical_canaries=0`. It contains no loci. Do not open the
   notice beyond confirming temporary recall edits exist.
2. Run `lucy-toolbox census.py "$TARGET"` and write stdout to
   `<run-dir>/staging/CENSUS.txt`.
3. Run `lucy-toolbox detector_battery_v3_3_1.py "$TARGET"` and write stdout to
   `<run-dir>/staging/BATTERY.txt`.
4. Run `lucy-units --workspace "$TARGET" --run-dir "$RUN_DIR"`. This writes
   `staging/UNITS.json` and one `staging/UNIT-NNN.txt` file list per unit.
   Read UNITS.json for the unit count; never edit these files.
5. Print exactly:
   `REVIEW STARTED · verified-review · RUN-ID <run-id>`

If a required step fails twice, write `<run-dir>/RESUME.md`, print
`REVIEW BLOCKED <run-id> <cause>`, and stop.

## Static Reader Brief

For every reader invocation, use this exact task shape. Substitute only PASS,
LENS, TARGET, UNIT_FILE, BATTERY_FILE, and PRIORS_FILE (the unit's
`UNIT-NNN-BATTERY.txt` and `UNIT-NNN-PRIORS.txt` written by `lucy-units` —
mechanical artifacts; never compose or edit seed content yourself; when no
`UNIT-NNN-PRIORS.txt` exists, substitute the literal word `none`). Do not add
prose.

```text
LUCY READER PASS={PASS} LENS={LENS}
TARGET={TARGET}
UNIT_FILE={UNIT_FILE}
BATTERY_FILE={BATTERY_FILE}
PRIORS_FILE={PRIORS_FILE}

Read the files listed in UNIT_FILE. BATTERY_FILE lists deterministic detector
candidates for this unit (path:line detector) — start your deep reading at
those loci. PRIORS_FILE lists historical findings for this unit
(path:line family description) — verify each on current bytes and treat its
neighborhood as hot; a historical claim is a lead, never a conclusion. Then
follow your agent's fixed lens contract.
Open every listed file. Do not read files outside TARGET. Do not read other
agents' output, prior pass output, staging files, PLANT_NOTICE.txt, or scanner
metadata. Return JSONL only, one object per candidate, using exactly:
{"path":"relative/path","line":1,"lens":"L1-auth","category":"...","severity":"HIGH","title":"...","evidence":"kind-only evidence; never literal secrets or PII","reach_basis":"file:line or stated absence"}
Return no markdown. An empty result is valid.
```

The four `LENS` values are `L1-auth`, `L2-secrets`, `L3-injection`,
`L4-infra`.

## Phase 1: Discovery And Loop

Before every interactive fan-out, arm a wake for 15 minutes and re-arm it as
the first action on every wake. Record each arming (and the current dispatch
width) as one JSON line in `<run-dir>/staging/WAKE.jsonl`:
`{"event":"wake-armed","width":<lanes-now-dispatching>}`. In noninteractive
mode do not call `ScheduleWakeup`; record
`{"event":"completion-notification-fallback"}` instead and rely on subagent
completion notifications; never pretend a timer was armed.

Dispatch reader lanes as fresh `lucy-reader` agents, one lane per
(unit x lens). Pacing law: the launcher supplies `--max-lanes` (machine-
and operator-sized; LUCY_MAX_LANES overrides, platform hard cap 20; treat 12
as the value if the argument is absent). Soft-start at half that cap, add a
third of it after each clean interval up to the cap, halve on a platform
limiter wave, and always ramp back up. COURT-FIRST law: whenever uncourted serious candidates exceed
twice a typical pass's serious yield, drain courts (batches of 12-16) before
dispatching the next full pass — finalize cannot run until every serious row
has a verdict, so an unchecked docket can become the wall-clock bottleneck.
Save each lane's final response unchanged as:

```text
<run-dir>/staging/lane-pass{N}-{LENS}-{UNIT}.jsonl
```

(Single-unit estates may omit `-{UNIT}`.) After every full pass, run:

```bash
lucy-merge --run-dir "$RUN_DIR" --workspace "$TARGET" --results "<results-root>"
```

`<results-root>` is the ancestor of `RUN_DIR` immediately above `runs/`.

Quiet law (per unit, source-method form): `lucy-merge` prints the
authoritative per-unit quiet verdicts in its output JSON (`"quiet"`);
TRUST THEM and never recompute quiet yourself — a divergent private
recomputation can launch a redundant pass that certification has already
judged unnecessary. A full four-lens pass that adds at most the
unit's quiet threshold in new serious candidates is that unit's FIRST
quiet pass. The threshold is DENSITY-SCALED: max(2, unit_LOC/25000),
computed from the unit's recorded LOC in UNITS.json — the question is
whether the well is empty, and the honest measure is residual density, not
an absolute count; a fixed threshold applies inconsistent residual-density
standards across differently sized units. Units at or under ~50K LOC keep the
original bar of 2.
"New serious" is scored mechanically from the merged pass history: any
candidate id first observed in that pass whose merged severity is serious
COUNTS, including a severity escalation at a previously known locus — never
reclassify an escalation as "not new" in your own accounting; receipts are
authoritative.
Its CONFIRMING quiet pass runs at LIGHT width — one fresh lane under a lens
the unit has not yet had in a confirmation role, same static brief — and must
add zero new serious candidates. Any new serious candidate in a confirmation
lane re-escalates the unit to full-width passes immediately. Units are
independent: a quiet unit stops while noisy units keep lapping. Never stop a
unit after only one quiet pass, and never run a second full-width pass where
the light confirmation suffices.

If a lane fails or stalls across two liveness sweeps, record
`{"event":"lane-dead","lane":...}` in `<run-dir>/staging/LIVENESS.jsonl`,
relaunch the same static brief with a fresh agent, and record
`{"event":"lane-relaunched","lane":...}` ONLY AFTER the replacement lane
has returned and its output was accepted — a mere dispatch never closes a
death (the replacement can die too). If the relaunched lane dies again and
you adopt its partial or empty output instead of relaunching a second
time, record `{"event":"lane-adopted-empty","lane":...}`. The pulse ledger
law is ORDERED PER-LANE COVERAGE: every `lane-dead` must be followed
(later in the ledger, same exact lane label) by a `lane-relaunched` or
`lane-adopted-empty`; a closure never covers an earlier lane, another
lane, or a later death; every event needs its exact lane label. Any death
left unclosed blocks certification. Record platform permission denials as
`{"event":"denial","command":"..."}`. Do not alter the brief.

## Phase 1.5: Estate-Wide Sweeps (multi-repo estates)

AFTER PASS 1 COMPLETES (source-method timing — sweep findings must feed the
quiet law, not arrive after it), and whenever the estate holds two or more
top-level repositories (check `git ls-files`; unit count is irrelevant — a
small two-repo estate can be one unit), dispatch FOUR estate-wide sweep lanes
— one per lens, fresh `lucy-reader` agents. Sweeps are PATTERN CHASERS, not
coverage lanes: unit
lanes already opened every file, so a sweep must NOT open every file; doing so
duplicates coverage work and can prevent the sweep from completing. Use this
sweep brief instead of the static unit brief, substituting only LENS, TARGET,
and RUN_DIR:

```text
LUCY SWEEP LENS={LENS}
TARGET={TARGET}

Cross-repository sweep. Coverage is already proven; do NOT open every file.
Grep the whole target for your lens's signature patterns, then deep-read at
most 30 files: the strongest cross-repository signals (same secret/idiom/
config in 2+ top-level directories, trust relationships between services).
Report only NEW cross-repo candidates: shared credentials, copy-pasted
vulnerable idioms, one service trusting another's weakened control. You
receive no battery or historical heat by design — sweeps stay cold so their
cross-repo discoveries are independent evidence. Follow your agent's fixed
lens contract and JSONL output schema exactly. An empty result is valid.
Budget: finish within roughly 15 minutes of reading.
```

Save results as `<run-dir>/staging/lane-sweep-{LENS}.jsonl` and rerun
`lucy-merge`. Serious sweep candidates go to courts like any other.

CHAINS: when court-bound candidates link into one attack path spanning 2+
findings, append one JSON line to `<run-dir>/staging/chains.jsonl`:
`{"id":"CHAIN-01","title":"one-line attack story","hops":["<candidate-id>",
"<candidate-id>"]}`. Use only candidate ids from candidates.jsonl. Finalize
validates every hop and drops (with receipt) any chain touching a refuted or
missing hop — propose chains from evidence, never pad them.

## Resume

If `$ARGUMENTS` contains `--resume`, the run was interrupted: staging may
already contain lane files, merges, court output, and receipts. Adopt them —
count existing `lane-pass{N}-*` files to determine the last completed pass,
rerun `lucy-merge` to rebuild candidates, and continue from the first
incomplete step (missing lenses in the current pass, uncourted serious rows,
or finalize). Never redo completed passes; never re-dispatch courts for
candidate ids already present in `staging/courts.jsonl`.

## Phase 2: Independent Courts

Read `candidates.jsonl`. Every `HIGH`, `CRITICAL`, or `PRIORITIZED_CRITICAL`
candidate gets one fresh `lucy-court` invocation. Courts must not receive
reader derivation, reader identity, pass number, other findings, or canary
context.

Use this exact task shape, substituting only candidate fields:

```text
LUCY COURT
TARGET={TARGET}
CANDIDATE_ID={id}
CLAIM={title}
LOCUS={path}:{line}
CATEGORY={category}
PROPOSED_SEVERITY={severity}

Attempt to disprove this claim from target bytes. Follow your fixed court
contract. Return exactly one JSON object and no markdown:
{"candidate_id":"...","verdict":"VERIFIED|CONDITIONAL|REFUTED","severity":"PRIORITIZED_CRITICAL|CRITICAL|HIGH|MEDIUM|LOW","cwe":"CWE-N","disproof_attempt":"...","basis":"hermetic-executed|static-reasoned","reach_basis":"...","fix":"specific imperative remediation or No code change required; reason"}
For a PRIORITIZED_CRITICAL verdict, reach_basis MUST contain four
semicolon-separated bindings: edge=<file:line>; route=<file:line>;
authorizer=<file:line>; exposure=<file:line>.
```

Run courts in parallel batches up to the `--max-lanes` cap (courts are
small-context and cheap — never trickle them). Save
each court's single JSON object response as its own file —
`<run-dir>/staging/courts/{candidate_id}.json` — never a shared file (a
shared file rewritten per batch can lose earlier verdicts). `lucy-finalize` collects the
directory.

## Phase 3: Finalize

Run:

```bash
lucy-finalize --run-dir "$RUN_DIR" --workspace "$TARGET" --results "<results-root>"
```

Finalize FAILS CLOSED if any serious candidate lacks a court verdict — dispatch
the missing courts and rerun rather than dropping rows. Confirm `FINDINGS.md`,
`findings.jsonl`, `candidates.jsonl`, and redaction receipts exist and staging
was deleted. Do not open or infer the answer key. Do not score recall. Do not
assemble the report or seal card — the launcher does that after external
recall scoring.

Write `<run-dir>/COMPLETION.md` containing run ID, census summary, pass count,
quiet-pass counts, captured/verified/refuted totals, model shown by `/status`,
and `RECALL: EXTERNAL-PENDING`. Do not include source literals.

Final line, exactly:

```text
REVIEW-COMPLETE <run-id> EXTERNAL-RECALL PROCESS-COMPLETE
```

There is no other successful ending for this skill.
