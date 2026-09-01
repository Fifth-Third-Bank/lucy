# LENS BRIEFS v1.7 — the four specialist reading lenses

Independent readers have different blind spots, so coverage improves
when their perspectives are deliberately varied. This file makes those
differences explicit.
Every reader lane is dispatched WITH ONE lens below; the lane reads
every file in its unit but hunts its lens's list first and deepest.

## L1 — AUTHENTICATION & AUTHORIZATION
Hunt: missing/disabled authn on endpoints, controllers, filters,
gateways; authorization checks absent, inverted, or client-supplied
(IDs, roles, headers, tokens trusted from the request); ownership /
tenant binding absent; session and token lifecycle (issuance,
validation, audience, expiry, revocation); MFA/step-up bypass; admin
and actuator surfaces; security-config classes and route tables
end-to-end; login-as/impersonation flows; API gateway authorizers and
their failure modes (fail-open).

## L2 — SECRETS, CRYPTO & KEY MATERIAL
Hunt: committed credentials, tokens, keys, keystores, cryptograms
(and whether committed material decrypts other committed material —
prove it when found); hardcoded or default encryption keys; weak or
misused crypto (ECB, static IVs, non-constant-time comparisons, MD5/
SHA1 for auth, homegrown crypto); key derivation and storage; vault/
KMS/HSM integration and its fallbacks; secrets in build/deploy files,
container definitions, test fixtures; certificate and TLS validation
(hostname verification, trust-all managers).

## L3 — INJECTION & DATA FLOW
WALK ORDER: SINK-FIRST —
start from the dangerous sinks (exec/process spawns, deserializers,
SQL assembly, detokenize/vault clients, queue publishers, file
writes) and trace BACKWARD to attacker reachability; findings cite
the reach chain, not only the sink.
Hunt: SQL/NoSQL/LDAP/command/expression injection — trace
attacker-reachable input to sinks, do not pattern-match only;
deserialization of untrusted data; path traversal and file handling;
SSRF and attacker-influenced routing/URLs; template injection;
XXE/parser configuration; request smuggling primitives; encoding/
normalization defeats of security decisions (the decision made on a
different string than the one used); sensitive data written to logs
(trace values into log sinks, including error serializers).

## L4 — INFRASTRUCTURE, CONFIG & SUPPLY CHAIN
Hunt: IaC exposure (open security groups, public buckets/queues,
authorization=NONE routes, wildcard IAM); deploy profiles and
per-environment config drift (controls off in prod-provisioned
paths); network policy and TLS termination; container privilege and
image provenance; CI/CD pipelines executing untrusted input;
dependency floors and known-dangerous versions; feature flags gating
security controls; fail-open designs in listeners, filters, sidecars.

## Surface duties (L1 + L4 jointly)
1. ENTRY-POINT CENSUS: enumerate every input surface of the unit —
   HTTP routes/handlers, queue and topic consumers, scheduled/file/
   cron intakes. Every surface is dispositioned: walked with its
   access-control binding cited (file:line), or an ABSENCE-OF-CONTROL
   finding is emitted. Presence is proven; absence is therefore
   findable. The per-unit disposition receipt is committed.
2. CARVED-MASS SWEEP: any file carved from the reading denominator as
   data/vendored/generated mass is still swept — detector battery +
   secret patterns — with a receipt, BEFORE the carve is accepted.
   Excluded, generated, and test artifacts can still contain secret
   material, so carving never replaces this sweep.

## Speed rules (coverage-preserving economies; the coverage gate grades them)
A. BATTERY-SEEDED BRIEFS: the detector battery runs first and each
   reader brief carries its unit's battery candidates up front — deep
   reading starts where the signal already is. (Same information,
   better sequence; costs nothing.)
B. AFFINITY DEPTH: every lane still OPENS every file of its unit, but
   DEEP reading follows affinity — L4 deep on IaC/config/pipelines
   (tf, yaml, Dockerfiles, CI), L1 deep on controllers, routes,
   security config and auth flows, L3 deep on parsers, DAOs,
   serializers, exec and file handling, L2 deep on key material,
   crypto call sites, vaults and certs; files outside a lane's
   affinity get a targeted pass (its lens hunt-list against the
   file), not a line-by-line read. Rotation transfers DEEP ownership
   across passes, so every file gets different deep eyes over the
   run. No file is ever unopened; no file keeps the same deep reader
   twice.
C. LIGHT CONFIRMATION LAP: a unit's FIRST quiet pass runs at full
   width. Its CONFIRMING quiet pass (the second consecutive one the
   quiet law requires) runs as ONE lane under a lens that unit has
   not yet had, emphasizing entry points and previously-hot files.
   ANY new serious finding in a confirmation lap re-escalates that
   unit to full-width passes immediately. The confirmation lap is a
   tripwire, not permission to stop after a productive pass.

## Priors (operator-staged only; never assumed)
If, and only if, the operator staged prior findings (the optional
priors upload at the repository root), use them. The current pack is
one structured file per app — PRIORS_<app>_<CMDB>.json, schema
lucy-priors/1.1 — whose sections carry these duties (an older or
free-form priors upload is treated as section 1 only):
1. refind_targets: a REFIND list. Verify each row on the current
   bytes and account every row in COMPLETION.md as REFOUND or
   NOT-EVIDENCED-ON-BYTES (sub-class: defect-not-present, or
   locus-not-found). EVIDENCE RULE: every NOT-EVIDENCED verdict
   carries a one-line receipt (the tolerant-match attempts made and
   what the bytes showed); path matching MUST be tolerant before
   declaring locus-not-found (basename and path-suffix attempts, not
   exact-string only). On a frozen one-time copy, NOT-EVIDENCED
   NEVER means remediated — it means the historical row does not
   hold; never use remediation language ("fixed", "patched",
   "remediated") in any summary of a frozen-copy run. Refound rows re-enter the normal pipeline — proposed,
   independently re-verified, re-graded from the severity rubric —
   exactly as if newly discovered. Historical severity labels in the
   file carry NO authority over today's tier.
2. watchlist: historical medium/low heat by file. Extra reading
   targets only; no per-row accounting.
3. chains: attempt to re-establish each chain on current bytes via
   its hop rows; report chains that still stand.
4. qna_files: application-team questions and answers with evidence. Extract
   the concrete checkable claims and verify them against the bytes.
   A claim is NEVER grounds to lower a tier or drop a finding unless
   the claimed control is proven in estate bytes (the rubric's
   standing rule); a claimed control the bytes contradict is itself
   finding-worthy. Count claims confirmed / contradicted /
   undetermined in COMPLETION.md.
5. retired (lucy-priors/1.1): rows a prior review has already
   disproven on bytes or retired as malformed, each with its own
   evidence receipt. They are NOT duties — do not adjudicate them and
   do not count them in the staged total. A genuine finding at a
   retired locus is reportable like any other discovery.
CANARY MINT LAW: the canary plan is COMPUTED, not chosen —
run mint_canaries.py at mint time (BEFORE any reader dispatch) with
the staged priors file (or NONE) and commit its receipt. It fixes
the 8 pattern-plant family spread and, when priors are staged, the
4 historical canaries by deterministic sha256 draw. Historical
canaries are real historical defects scored blind (found during
review, or a COLD RE-READ receipt per the card template) — never
planted edits. A missing or mix-violating mint receipt at pass-1
dispatch is a BOOT-STOP: fix the mint before dispatch, never discover
it at the seal.
HISTORICAL DISPOSITION TABLE (mandatory in COMPLETION.md): one row
per staged refind target with its fate — REFOUND->verified <rowid> /
REFOUND->refuted <receipt> / REFOUND->folded-into <rowid> /
NOT-EVIDENCED (<sub-class>, <receipt>). The table MUST sum to the
staged total; the certification gate checks the arithmetic. This is
how a recipient traces every historical finding into (or honestly
out of) the new report without desk archaeology.
STAGED FILES ARE RUN INPUTS, NOT ESTATE CODE: the census script
excludes root PRIORS_* files from the denominator; sweep them for
secrets exactly like carved mass, but record anything found ONLY in
COMPLETION.md as STAGING-INPUT notes — never as report rows (the
report gate refuses PRIORS_ loci). If files for OTHER apps are
present, use only the matching app's file and note the extras.
Priors NEVER narrow the scan, never substitute for the cold recall
plants (which remain the recall measure), and their absence changes
nothing — a cold estate runs exactly the rules above.

## Pacing (soft-start and ramp-up)
1. SOFT-START: never ignite the full lane budget at once. Begin at
   6 concurrent lanes; after each ~5-minute interval in which every
   lane start survived, add 4 lanes, up to the full budget.
2. LIMITER WAVE: on a burst of lane deaths at startup, halve the
   current width, record a PULSE ledger entry (deaths, redispatch
   plan), let running lanes drain, redispatch dead lanes at the
   reduced width after a short cool-down.
3. RAMP-UP IS MANDATORY, NOT OPTIONAL: after any reduction, resume
   the soft-start climb (add lanes after each clean interval) until
   back at full budget. Staying reduced after starts are surviving
   is an idling defect — the same defect as an idle deck.
4. Every width change is one receipt line (old -> new, cause).
5. WAKE-BEFORE-DISPATCH:
   arm the scheduled wake BEFORE dispatching any wave of lanes, and
   re-arm it as the FIRST act of every wake — there must never be a
   moment with lanes in flight and no guaranteed future wake. Record
   each arming as a one-line receipt (id + interval). This guarantees
   a future liveness check even if every dispatched lane fails.
6. LIVENESS SWEEP (mandatory cadence): every ~15 minutes, or once per
   finished lap, whichever comes first, verify byte growth for EVERY
   in-flight lane (output file size vs the previous sweep). A lane
   with no growth across two sweeps is presumed dead RIGHT THEN:
   redispatch it from its partial with a receipt (lane, last-write
   age, restart point). Never wait for an external prompt to discover a
   dead lane.

## Ceremony overlap (finishing-tail law)
While the FINAL confirming lap runs, a drafting lane MAY pre-build
as DRAFTS: the scan report, the seal card's lap-independent fields,
COMPLETION.md's skeleton, and the delivery zip's finished members.
The post-revert re-grade of plant-affected findings MAY run early
against committed HEAD copies (HEAD == post-revert bytes); after the
actual revert, verify working copies match HEAD (empty diff) and
adopt the verdicts — re-judge on any non-empty diff. UNCHANGED: the
quiet decision comes only from lap results; the recall key opens
only after quiet; plants are reverted before the report is final;
both gates run only on FINAL artifacts.

## Dispatch and rotation rules
1. Pass 1: every unit gets ALL FOUR lenses (four lanes per unit).
2. Re-sweep passes: each unit's lanes take lenses they have NOT yet
   held on that unit (rotate), so every pass is new eyes by design.
3. After pass 1, additionally dispatch one ESTATE-WIDE sweep lane per
   lens: it ignores unit boundaries and chases its lens's cross-repo
   patterns (shared keys, common gateways, copy-pasted configs).
4. Keep the full concurrency budget saturated: a freed slot always
   pulls the next (unit × lens) or sweep lane from the queue.
5. Recall plants are minted ACROSS the four lens families so the
   recall score measures every lens's blind spot, not one idiom.
