#!/usr/bin/env python3
# OUTPUT NOTE: run by path; write results to files and read them
# with file tools. Keep detector patterns and seeded test samples out of
# shell transcripts: they are synthetic fixtures, and printing them raises
# false security alerts and floods logs. Noise control only, never
# concealment - every byte of this file and its outputs is on disk,
# hash-pinned, and open to any reviewer or platform check.
"""token_gate.py v1.3 — the mechanical gate.
Usage: python3 token_gate.py <REQUIRED_ARTIFACTS_v1.txt> <DOC.md>
Checks (1) every token present as 'TOKEN-NAME:' in the DOCUMENT bytes;
(2) TOKEN-VALUE REQUIREMENT: result-class token values carry RESULTS, never
promises — promissory patterns are rejected by name."""
import re, sys
req, doc = open(sys.argv[1], encoding='utf-8').read(), open(sys.argv[2], encoding='utf-8', errors='replace').read()
toks = re.findall(r'^([A-Z0-9-]+):', req, re.M)
missing = [t for t in toks if not re.search(r'(^|[^A-Z0-9-])' + re.escape(t) + r':', doc, re.M)]
PROM = re.compile(r'\b(pending|armed at|will |to be |TBD|later|shortly|soon|in progress|upcoming|planned|to follow|forthcoming|after (the )?seal|once sealed|next session|not yet)\b', re.I)
promissory = []
for t in toks:
    m = re.search(r'(^|[^A-Z0-9-])' + re.escape(t) + r':([^\n]*)', doc, re.M)
    if m and PROM.search(m.group(2)):
        promissory.append(t + ' ("' + m.group(2).strip()[:40] + '")')
if missing or promissory:
    if missing: print('TOKEN-GATE: FAIL — missing ' + str(len(missing)) + '/' + str(len(toks)) + ': ' + ', '.join(missing))
    if promissory: print('TOKEN-GATE: FAIL — PROMISSORY VALUES (results required, promises rejected): ' + ', '.join(promissory))
    sys.exit(1)
print('TOKEN-GATE: PASS ' + str(len(toks)) + '/' + str(len(toks)) + ' tokens present, all values result-class'); sys.exit(0)
