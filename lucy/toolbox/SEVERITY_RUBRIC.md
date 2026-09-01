# SEVERITY RUBRIC v1.3 — courts assign tiers from THIS table

Independent reviewers can agree on a finding while differing at tier
boundaries. Readers propose a tier; the VERIFICATION COURT assigns the final tier
from this table and records the rule it applied. No INFO tier exists
in the hand-off report.

## PRIORITIZED_CRITICAL (PC-1)
A CRITICAL that meets ALL FOUR clauses, each documented with evidence
in pc_reason: (1) INTERNET-REACHABLE — the vulnerable surface is
reachable from the internet (name the route/edge evidence);
(2) YIELD AT SCALE — exploitation yields protected data or privileged
functions across an affected population, not a single subject; (3) LIVE CREDENTIAL
IN-CHAIN — any credential/token the chain needs is obtainable by the
attacker (self-registration, committed secret, none needed);
(4) NO COMPENSATING CONTROL in estate bytes — name what is absent.
**MANDATORY: the court evaluates every CRITICAL against these four
clauses and records the outcome (promoted, or which clause failed) in
its verdict row.** Zero PC-1s is a valid outcome.

## CRITICAL
Direct compromise of sensitive data, high-impact transactions, authentication,
or code execution, exploitable WITHOUT unrealistic preconditions:
unauthenticated sensitive endpoints; committed live production
credentials or key material (especially when it decrypts other
committed material); complete authn/authz bypass on a deployed
surface; RCE/deserialization on reachable input.

## HIGH
Serious defect requiring ONE realistic precondition (an authenticated
low-privilege foothold, internal network position, or a leaked log):
cross-tenant/IDOR with auth; privilege escalation; secrets or PII
written to logs at production levels; injection needing an
authenticated route; security control bypass with a second factor
still standing.

## MEDIUM
Real weakness with meaningful preconditions or bounded yield:
defense-in-depth failures where a compensating control demonstrably
stands; fail-open behavior gated by unlikely states; scoped
disclosure; weak crypto on non-critical data; missing hardening that
enables other attacks but yields nothing alone.

## LOW
Hygiene and least-privilege polish with minimal direct yield: verbose
errors without secrets; outdated-but-unexploited dependencies (no
reachable sink); test-only credentials clearly unused in deploy
paths; missing headers on non-sensitive responses. If a row would be
"informational" — it does not enter the report at all.

## Reach basis, per row
Every serious verdict row records its TWO rubric inputs: the defect
class, and the REACH BASIS — the byte evidence of attacker
reachability (file:line of the exposing route/config) or the stated
absence of such evidence. A severity capped down by a compensating
control cites that control byte-for-byte (reason code REACH-CAP). A
tier without a recorded reach basis is a defect in the verdict, not
a style choice — two independent runs must be checkable row against
row.

## Execution over argument (when locally possible)
Where a serious finding admits a LOCAL falsifier test — parsing,
regex, logic, crypto misuse, path handling on pinned workbench
copies, never deployed systems and never the network — the
re-verifier writes the test and EXECUTES it under the toolbox's
hermetic runner, recording rc and output. Executed rows carry
verification basis "hermetic-executed"; rows that cannot execute
carry "static-reasoned" with the per-row cause. An execution error
is evidence, never a refutation by itself; a platform denial routes
the row back to static reasoning without blocking anything.

## Downgrade discipline
Reviewers can diverge when a downgrade rests on an assumed control or
an unsupported reach argument. The following rules bind every verdict:
1. A serious proposal (CRITICAL or HIGH by mechanism) may be placed
   BELOW HIGH only when the compensating control is NAMED and CITED
   byte-for-byte in the DEPLOYED path — the control demonstrably
   wired in production provisioning (config, route table, filter
   chain, authorizer binding) — never assumed from convention or
   architecture diagrams.
2. Provability is asymmetric: an unevidenced ATTACK precondition
   drops the row one tier (the existing tie-breaker below); an
   unevidenced DEFENSE never lowers a tier. Doubt about a defense
   resolves UPWARD.
3. If after the evidence pass the verdict cannot decide between HIGH
   and MEDIUM, HIGH stands, and the row records BOUNDARY-HIGH plus
   the single piece of evidence that would settle it.
4. REACH-CAP remains available exactly as defined — with its
   byte-for-byte citation per row; capping a batch of rows without
   per-row citations is void.

## Tie-breakers
- Provability beats vibes: a tier that depends on a claim the court
  could not evidence drops one tier.
- Reachability decides between CRITICAL and HIGH; preconditions
  decide between HIGH and MEDIUM; yield decides between MEDIUM and
  LOW.
- When two lanes propose different tiers for the same locus, the
  court resolves with this table and cites the deciding rule.

## Obtainability standard
Personal identifiers that are commonly exposed, traded, or publicly
discoverable count as ATTACKER-OBTAINABLE for tier
purposes. Consequences: (a) PC-1 clause 3 (obtainable credential /
prerequisite in chain) is MET by a prerequisite of this class;
(b) the unevidenced-precondition tie-breaker ("one realistic but
unevidenced attack precondition drops one tier") does NOT apply to
preconditions of this class — needing a commonly obtainable personal
identifier is not an unevidenced precondition in an identity-abuse
threat model. Secrets the ESTATE must supply (its own
keys, tokens, internal endpoints) are unchanged: those still require
byte evidence.
