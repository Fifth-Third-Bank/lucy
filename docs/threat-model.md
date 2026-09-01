# LUCY Tool Threat Model

## Assets

- scanned source code;
- vulnerability findings and court verdicts;
- temporary recall-test answer keys;
- historical priors (excluded from the initial trial);
- Claude Code credentials and local tool permissions;
- deterministic toolbox and gate integrity.

## Trust Boundaries

The scanned repository is untrusted input. It must not supply LUCY prompts,
skills, settings, hooks, plugins, priors, or scanner executables. The installed
skill and hash-verified toolbox are trusted code. Claude reader/court contexts
are untrusted judgment components whose output is structurally validated;
selected finalized artifacts then receive best-effort masking for recognized
patterns.

The trial launcher is the recall-test custodian. A separate ephemeral Claude
process plants canaries before the reviewer starts. The launcher validates the
diff and answer-key schema, gives the orchestrator only a commitment, scores
after the reviewer exits, and destroys custody. The orchestrator is never
trusted with loci or planter context.

## Primary Threats And Controls

| Threat | Control |
| --- | --- |
| Repository prompt injection | Static installed skill/agents; fixture disclosure files removed; no target instructions loaded intentionally. |
| Findings published to target remote | External local sink is default; no branch, commit, fetch, push, issue, or PR permission in the skill. |
| Priors disclose standing vulnerabilities | No real priors ship or load in the initial trial; historical priors are out of scope. |
| Literal secret or personal data in narrative and report artifacts | Agent contracts prohibit literal values; finalization applies best-effort masking for recognized credentials, email addresses, and formatted U.S. SSNs, and the report gate rejects selected recognized credential patterns. Outputs remain confidential; this is not comprehensive PII anonymization or DLP. |
| Canary leakage from orchestrator to readers | Separate no-history planter process, marker-free source, static briefs, fresh agents, no key/locus in run state. |
| Orchestrator reads answer key early | Custody under ~/.lucy/custody (0700), outside workspace and results, not passed in prompt or environment, external post-session scoring. |
| Planter exceeds its role | Claude safe mode; custom system prompt; only Read/Edit/Grep/Glob; no shell/network/skills/agents; structured output; deterministic diff, path, syntax, family, and marker validation. |
| Toolbox tampering | Allowlisted imports, per-file SHA-256 manifest, startup consistency check (integrity against accidental drift, not a signature: an attacker who can rewrite the toolbox can rewrite the manifest), shipped self-tests. |
| Claude executes application or reaches network | Skill forbids builds, package managers, services, endpoints, WebFetch/WebSearch, and target-provided tools. |
| Broad persistent permissions | No generated/committed target settings; trial uses Claude manual permission mode. |
| Claude local history or memory retains source | Launcher disables auto-memory, all CLAUDE.md loading, prompt history, and print-mode session persistence. |
| Partial or malformed lane output | Deterministic JSONL validation, fingerprints, merge, court references, and fail-closed finalization. |

## Residual Risks

- Claude runs under the user's operating-system identity; filesystem policy is
  ultimately enforced by Claude Code permissions and the host OS.
- Local incognito controls do not change provider-side retention policies,
  terminal scrollback, shell history, or the intentional external results sink.
- A malicious repository can contain instruction-shaped source text. Reader
  agents are directed to treat repository content as data, but model behavior
  is not a security boundary.
- The planter is model-driven and receives the lens contracts and severity
  rubric as method documents (they contain no scoring information, so
  reviewer blindness is unaffected). Mechanical validation proves shape,
  custody, syntax, reader-unit coverage, and the presence of a per-plant
  reachability rationale; a deterministic detector battery pre-screens
  detectability (warning-only). None of this proves exploitability - a
  defective mint is adjudicated post-run as a receipted MINT-ERROR
  requiring operator attestation, never inferred by the scanner.
- Recall rescoring during recapture is launcher-only and silent: it reads
  custody, writes nothing to the run directory, and is never displayed
  mid-run. Cure dispatch is fully blind - no family-, unit-, or
  file-targeted lanes exist.
- The private results tree contains an unredacted working copy and may contain
  transient raw staging data until finalization or after an interrupted run.
  Receipts, logs, delivery archives, and SARIF exports can also contain
  source-derived identifiers. Keep all of these within the source-data access
  boundary; staging is not encrypted at rest.
- The 18 toolbox assets in this repository are the sanitized public set
  (identifier examples replaced, golden selftests preserved) and are
  byte-pinned in `lucy/toolbox/assets.json`. One legacy reference is
  retained by explicit release decision: the census's scanner-state
  directory exclusion list (see the zone map at the top of
  `lucy/toolbox/census.py`) keeps one legacy generation-named entry —
  removing it would change census counts on repositories that contain such
  directories, and it carries no identifier or customer data. The pins are verified at
  install time and re-verified at every execution site (the `lucy-toolbox`
  wrapper and each launcher gate/census call).
- The certification gates run in production on every scan: the launcher
  executes the pinned seal-card and certification gates after external
  recall scoring, cross-checks them against derived artifacts, and prints
  CERTIFIED only when both pass alongside a launcher-scored recall PASS. A
  run that does not clear the gates ends PROCESS-COMPLETE and must not be
  represented as certified.
- Court verdicts on the Claude host are transcribed into staging by the
  orchestrator session (courts themselves are read-only agents). Verdict
  authenticity therefore rests on the orchestrator's conduct; refuted
  counts are always displayed as a detection surface for fabricated
  refutations. This is an accepted residual of the single-session
  architecture.
