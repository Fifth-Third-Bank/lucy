SEAL CARD (fixed form v2.1 — every field mandatory and in gate order;
seal_card_gate v2.7 refuses a card missing any of the 43 fields below.
The template mirrors the gate's REQ list and binds every terminal:
CERTIFIED, BLOCKED-UNCERTIFIED, and ASSESSMENT.)
RUN-ID: <id>
KIT: <version>
ROWS-TOTAL: <int — every captured row once, all tiers, no carve-outs>
VERIFIED-TOTAL: <int — court-verified rows across all tiers; THE HEADLINE NUMBER>
REFUTED-TOTAL: <int — rows refuted with receipts; a credibility asset, always shown>
TIER-C: <int>
TIER-H: <int>
TIER-WP: <int — worst-plausible: every row whose reach fact is unresolved>
TIER-M: <int>
TIER-L: <int>
TIER-INFO: <int>
CH-COURTED: <int — must equal the CH court map>
PC-1: <int — each claim carries 4 REACH-RECEIPT lines below>
PC-2: <int>
BOUND-MIN: <lowest per-unit bound>
UNITS: <int>
CANARY: <n>/8  <n<8 requires one CANARY-CURE/MINT-ERROR line per miss>
DURATION: <boot→seal, git subtraction>
DENIALS: <n>; result impact: ZERO
MODE: <CODE|TEXT|MIXED + one clause>
DISPOSITION: <per-instrument summary or pointer>
VISITATION: <opened>/<census — WHOLE for CERTIFIED and for any dead-yield block>
SEAL-CLASS: <CERTIFIED | BLOCKED-UNCERTIFIED — the only terminal classes; ASSESSMENT appears only on INTERIM (NOT-A-SEAL) reports>
FIRST-COURT-LAG: <minutes, first lane landing → first docket; >10 is a named deviation>
EXPECTED-CLOCK: <the boot-printed wave math + one clause: actual vs expected, every deviation named>
CENSUS-FORM: <SCRIPT | SCRATCHPAD-COPY | FLAT-PIPELINE — the only three lawful denominators>
STRICT-CHAPMAN: U01 <0.xx> U02 <0.xx> ... <every unit; any <0.50 requires a CURE-LAP line>
CANARY-MIX: <n>P+<n>H  <total 8; >=4 historical when priors staged; 8P+0H lawful only with PRIORS: none staged>
FALSIFIERS: <run n/m | hermetic-off (<named cause>)>
M-AUDIT: 5/5 re-derived seed=<sha256(RUN-ID)[:8]>
DEPTH-RATIO: <bytes-read / scannable bytes; diagnostic>
REACH-DISCIPLINE: <n>/<n — R0/R1 rows fully receipted / R0/R1 rows total; must be whole>
WIDTH-DISCIPLINE: <n>/<n — phases at-width-or-receipted / shardable phases; must be whole>
PULSE-LEDGER: max-gap <N>m deaths <N> redispatched <N> adopted <N> unreconciled <0 — per-lane coverage law: every death has a closure; over-closure is receipted noise>
PRIORS: <none staged | N loaded N refound-or-adjudicated>
FRONTIER-CLOSE: <elapsed when the risk frontier was dual-read complete + receipts ref>
SATURATION: avg <W>/<cap> idle-while-ready <N>m  <over 5m is refused>
ENGINE: ONE-QUEUE (<ladder depth; watchdogs paired; single-thread set 3>)
AXIS-CENSUS: <N> declared (<axis list>) - courted exhausted
AXIS-CLOSURE: <n>/<N — must be whole and equal the census>
TERMINAL-PRECEDENCE: ran <hh:mmZ> pre-assembly verdict <CERTIFY|BLOCK|ASSESS — a card after CONTINUE is a contradiction>
SEAL-ENTRY: ran <hh:mmZ> census <raw/scannable/files> conservation <n>==<n> visitation <d>/<d> canaries <k> OPENED  <the printed pre-assembly gate; k must be 8 for a seal>
CLOSURE-BASIS: <STANDARD-095 | EXHAUSTIVE-SATURATED — the certification door used; ES requires ES-RECEIPTS 6/6 + RECAPTURE + dead novelty>

SUPPLEMENTAL LINES (appended below the fixed form as facts require):
ES-RECEIPTS: 6/6 (<visitation-closure · per-axis-recompute · recapture · conservation · frontier+entrypoints · courts+falsifiers>)   <EXHAUSTIVE-SATURATED only>
RECAPTURE: U<nn> <recapture laps + bound movement + novelCH>   <per below-bar unit>
LAP-HISTORY: <n> bound <0.xx> novelCH <m>   <one per lap, append-only>
CURE-LAP: U<nn> <dispatched + re-measured bound>   <per strict-floor trip>
CANARY-CURE: <miss id + re-laned unit + rescored HIT>   <per cured miss>
<CANARY-MIX CURE (lawful post-quiet): if the mint
 violated the >=4-historical rule, the card composition MAY be
 repaired without touching plants, key hash, or any finding —
 deterministic sha256 draw of 4 pattern plants + 4 historical
 targets; each historical canary scored by a COLD RE-READ receipt
 (one fresh lane, NO priors context, single file, independent
 re-find); record a MINT-ERROR line + one CANARY-CURE line per
 cold-scored canary. The current mint_canaries.py contract makes this
 unnecessary by fixing the mix at mint time; the boot check stops a bad mix
 before dispatch.>
MINT-ERROR: <miss id + receipted basis>   <per mint defect; adjudicated in place: a concrete independently attested or mechanically derived basis is receipted on the card and in the recall receipt — reminting is not performed (the defective slot is accounted, never replaced mid-run)>
REACH-RECEIPT: <edge|route|authorizer|exposure binding, file:line>   <4 per PC-1 claim>
BLOCK-RECEIPT: <DISPATCH-DENIED | LAP-YIELD-COLLAPSE>   <BLOCKED cards only>
DENIAL-QUOTE: <the quoted persistent denial + time>   <DISPATCH-DENIED only>
OPERATOR-TARGET: ASSESSMENT (<the operator's edited target line, quoted>)   <ASSESSMENT only>
UNCONTROLLABLE: <the named uncontrollable limit + receipt>   <ASSESSMENT only>
