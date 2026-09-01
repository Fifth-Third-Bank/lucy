# Courts, Gates, and Certification

LUCY never asks you to trust a model's claim that the work was done. Every
serious finding is adversarially verified, and the run's completion claim is
checked by deterministic gates that anyone holding the delivery can re-run.

## Courts: adversarial verification

Recall-first discovery through the [four reading lenses](lenses.md)
deliberately over-collects, so every serious candidate goes before an
independent court agent that never sees the
discovering reader's reasoning. The court attempts to DISPROVE the claim
from the code alone: does the cited path exist, is it reachable, can
attacker-controlled input influence it, is authentication enforced
elsewhere, does a compensating control block exploitation, does the
evidence support the severity.

Three verdicts exist:

- **VERIFIED** - the defect holds on the target bytes and its reach is
  evidenced.
- **CONDITIONAL** - the defect mechanism holds, but exploitation rests on a
  precondition the code alone cannot settle (deployment state, external
  reachability). These findings keep the severity they would carry IF the
  precondition holds, and are reported in a separate worst-plausible tier
  (TIER-WP). Unproven reachability never downgrades a finding; only a
  proven compensating control does.
- **REFUTED** - the claim does not hold. Refuted claims are published in
  the final report as their own section, never silently deleted. A review
  tool's disproven claims are its credibility record.

Ledger conservation is enforced mechanically: candidates in must equal
findings emitted plus claims refuted, and finalization fails closed if any
serious finding lacks a verdict.

## The three gates

A run may print CERTIFIED only when three deterministic gates pass on the
run's own receipts, never on its prose:

1. **Scan-report gate** - validates the findings artifact against the report
   contract's machine-verifiable schema and counts, with placeholder and
   selected credential-pattern checks in finding narrative fields.
2. **Seal-card gate** - validates a 43-field summary computed entirely from
   receipts, including per-unit
   [capture-recapture](https://en.wikipedia.org/wiki/Mark_and_recapture)
   coverage bounds (a
   [Chapman lower bound](https://en.wikipedia.org/wiki/Mark_and_recapture#Chapman_estimator)
   of at least 0.95 per unit, computed from the two largest comparable
   passes).
3. **Certification gate** - six checks, each verified from receipts:

| Check | Requirement |
| --- | --- |
| C1 VISITATION | Every file found eligible by an independent census walk was assigned to a reading unit and remains readable |
| C2 QUIET | Every unit shows two consecutive quiet passes; the per-unit bar is density-scaled — max(2, unit LOC / 25K) — so the residual-density standard is uniform across estate sizes, and each unit's computed threshold is recorded in the certification receipt |
| C3 RECALL | Cold finds + blind-recapture cures + adjudicated mint errors account for all 8 plants, each disposition receipted on the seal card |
| C4 PRIORS | Every staged historical finding adjudicated, with receipts for every NOT-EVIDENCED verdict (N/A when no prior findings are staged) |
| C5 INTEGRITY | Every reader lane that died was relaunched; no orphaned work |
| C6 GATES | The report and seal-card gates themselves passed |

## Canaries: recall measured on every run

Before any reading begins, a separate isolated planter process hides eight
synthetic vulnerabilities (two per [lens](lenses.md)) in the disposable
workspace. The
answer key goes into launcher-side custody and never enters any model's
context; the reviewer sees only a hash commitment. Recall is scored
externally after the reviewer exits. When prior findings are supplied, blind
historical refind targets join the canary set, so detection is also tested
against real historical defects.

Synthetic-versus-genuine attribution is adjudicated by CAUSATION, never
proximity: after external scoring, every candidate in a planter-modified
file is re-examined by an independent court against a fresh clean copy of
the original target — a defect that survives on clean bytes is genuine; one
that exists only in the planted workspace is synthetic. Every such
candidate must carry a disposition (receipted with its basis in
CANDIDATE_DISPOSITIONS.json) and none may be unresolved, or certification
refuses. Recall matching is one-to-one — a single candidate can never
satisfy two canary slots — and each slot's matched candidate id is recorded
in the trusted recall receipt.

A missed plant has exactly three honest endings, each receipted on the
seal card. A **cold find** means the normal protocol found it. A
**CANARY-CURE** means a bounded budget of fully blind recapture laps
(full width, all units — the launcher never discloses a missed plant's
unit, file, or family to any model) re-read the code and a fresh lane
found it; the external rescore then counts it as cured, never as cold.
A **MINT-ERROR** means the plant itself was adjudicated defective
(semantically inert, on an unreachable path, or — for historical slots —
a stale or out-of-scope converted locus); mint errors are never inferred
by the scanner. Planted-slot mint errors require the cure budget to be
exhausted first plus an explicit operator attestation carrying a concrete
auditable basis; historical-slot mint errors require the attested basis
(they are conversion-quality adjudications, so the cure-lap precondition
does not apply). The defective slot is adjudicated in place and accounted
on the seal card — it is not re-minted mid-run. The
certification law is cold + cured + mint-error = 8, and the seal card
shows the split. At mint time a deterministic detector battery
pre-screens every plant for detectability (warning-only: requiring
battery-visibility would select for shallow plants), and the planter
must record, per plant, the concrete caller or route that makes the
defect real — auditable at adjudication.

## The seal token

When everything passes, the seal-card gate mints a seal token: a truncated
hash of the exact seal-card contents plus the verdict class. The token is
the run's tamper-evident fingerprint. Anyone holding the delivery ZIP
(findings, seal card, every receipt) can re-run the gates and either
reproduce the token or not. Change any number after the fact and the token
no longer reproduces. Trust in the model is not required, and the
receipts themselves are tamper-evident. One boundary is stated plainly:
a MINT-ERROR disposition is an operator adjudication — the gates prove
its basis was receipted and never altered, but not that the operator's
semantic judgment was correct. A seal over a run containing mint errors
therefore certifies the process plus a labeled, auditable operator
call, and the card always shows exactly how many (cold + cured +
mint-error are printed separately, never blended).

## Honest endings

A run that falls short does not pretend otherwise. It ends
PROCESS-COMPLETE with the full report delivered and the failing check
named. `lucy scan --resume` adopts all completed work after a crash or
network drop; `lucy recapture` re-reads only the units below the coverage
bar and re-seals. That is the honest path from PROCESS-COMPLETE to
CERTIFIED.

Certification does not mean the application is vulnerability-free. It
means the code you pointed it at was reviewed through a measurable, repeatable,
independently checkable process.
