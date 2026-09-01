# How a Scan Works, End to End

One page, three diagrams: the pipeline, what happens to a finding, and what
CERTIFIED actually requires.

## The pipeline

```mermaid
flowchart TD
    S1["1 - Cost estimate<br/>census the code, print a dollar range<br/>(no spend yet)"]
    S1 --> S2["2 - Copy<br/>your code goes into a disposable workspace<br/>(the original is never touched)"]
    S2 --> S3["3 - Plant<br/>an isolated planter hides 8 synthetic bugs;<br/>the answer key stays with the launcher -<br/>the reviewer can't see it"]
    S3 --> S4["4 - Read<br/>code split into units, each read through<br/>4 lenses (auth / secrets / injection / infra),<br/>up to 20 readers at a time"]
    S4 --> Q{"still finding<br/>new problems?"}
    Q -->|yes - another pass<br/>+ cross-repo sweeps| S4
    Q -->|no - quiet| S5["5 - Courts<br/>an independent agent per serious finding<br/>tries to DISPROVE it"]
    S5 --> S6["6 - Check and seal<br/>launcher verifies the 8 hidden bugs were found,<br/>builds the report, runs the certification gates,<br/>bundles the delivery ZIP"]
    S6 -->|gates pass| C["CERTIFIED + seal token"]
    S6 -->|any gate fails| P["PROCESS-COMPLETE<br/>full report, failing check named,<br/>curable with resume / recapture"]
```

Key points that are easy to miss:

- The reviewer never sees the answer key. A separate process plants the
  bugs, the key is held by the launcher, and recall is scored after the
  reviewer exits.
- Reading is not one pass. Lanes repeat until each unit goes quiet, and
  independent passes double as the samples for the coverage estimate below.
- The battery runs first so the AI spends its attention on judgment calls,
  not on things a deterministic check can catch. Battery hits go through
  courts like everything else.

## What happens to a finding

```mermaid
flowchart LR
    R["Reader proposes<br/>a finding"] --> M["Merged + deduplicated"]
    M -->|"serious<br/>(critical / high)"| C["Court:<br/>independent agent,<br/>never sees reader reasoning"]
    M -->|"medium / low"| REP["Report"]
    C -->|VERIFIED| REP
    C -->|"CONDITIONAL<br/>(real bug, reachability<br/>not provable from code)"| WP["Report:<br/>worst-plausible tier"]
    C -->|REFUTED| REF["Report:<br/>refuted section<br/>(published, not deleted)"]
```

The court asks: does the cited code exist, is it reachable, can an attacker
influence it, does something else block it, does the evidence support the
severity. Three outcomes:

- **VERIFIED** - holds up, reach evidenced.
- **CONDITIONAL** - the bug is real in the code, but exploitation depends on
  something the code alone can't settle (deployment config, network
  reachability). Severity is kept at what it would be IF reachable - an
  unproven precondition never downgrades a finding; only a proven
  compensating control does.
- **REFUTED** - doesn't hold up. Kept in the report as its own section.
  The count must balance: every candidate is either emitted or refuted.

## What CERTIFIED requires

Three deterministic gates run in order, and anyone holding the delivery
ZIP can re-run all three:

```mermaid
flowchart TD
    G1["Gate 1 - report gate<br/>findings artifact passes machine-verifiable contract checks"]
    G1 --> G2["Gate 2 - seal-card gate<br/>43 receipt-computed fields, including per-unit<br/>coverage bound of at least 0.95"]
    G2 --> G3["Gate 3 - certification gate: six checks<br/>C1 every file opened<br/>C2 every unit quiet<br/>C3 all 8 hidden bugs found<br/>C4 every prior finding adjudicated<br/>C5 no lost lanes<br/>C6 gates 1-2 passed"]
    G3 -->|all pass| T["Seal token minted:<br/>hash of the exact seal card + verdict<br/>= tamper-evident fingerprint"]
    G3 -->|any fail| P["PROCESS-COMPLETE<br/>honest, named, curable"]
```

The coverage bound comes from [capture-recapture](https://en.wikipedia.org/wiki/Mark_and_recapture), the technique ecologists
use to estimate a fish population: if a second, independent reading pass
mostly rediscovers what the first pass found, most of what's findable has
been found. If it keeps surfacing new things, the review isn't done, and
the number says so.

CERTIFIED does not mean bug-free. It means: every file was opened, reading
continued until it stopped producing, detection was spot-checked against
hidden bugs, every serious claim survived a disproof attempt or was
published as refuted, and all of that is checkable by re-running the gates
yourself.

## Where to go deeper

- [Building a super-repo](super-repo.md)
- [The four lenses](lenses.md)
- [Courts](certification.md#courts-adversarial-verification) and [gates](certification.md#the-three-gates)
- [Threat model](threat-model.md)
