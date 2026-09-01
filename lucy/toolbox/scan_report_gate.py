#!/usr/bin/env python3
"""scan_report_gate.py v1.3 — deterministic validator for the per-app
scan report (<CMDB>_SCAN_REPORT.json, schema_version 2.0).

Usage:
    python3 scan_report_gate.py <path/to/CMDB_SCAN_REPORT.json>
    python3 scan_report_gate.py --selftest

Checks the machine-verifiable portions of the operator's handoff contract
(see SCAN_REPORT_CONTRACT.md beside this script). Prints every failure with
its rule name; prints "SCAN-REPORT GATE: PASS <file>" and exits 0 only when
those checks pass. Downstream validation runs this same gate on the pushed
report, so a report that fails here fails there identically. All checks are
offline and deterministic — no network, no clock."""
import json, os, re, sys

SEVS = ('PRIORITIZED_CRITICAL', 'CRITICAL', 'HIGH', 'MEDIUM', 'LOW')

# R18 values-by-kind law at the report layer: a report names the KIND
# of a credential and cites its locus; it never carries the value.
_PW = re.compile(r'(?i)(?:password|passwd|pwd|secret|api[_-]?key|token)\s*[=:]\s*["\']?([A-Za-z0-9!@#$%^&*_+-]{6,})')
_PW_PLACEHOLDER = re.compile(r'(?i)(?:x+|\*+|change.?me|placeholder|redacted|password|secret|value|dummy|example|test\w*|none|null|true|false|vault\w*|env\w*)$')
_TOKENS = (re.compile(r'eyJ[A-Za-z0-9_-]{10,}\.eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}'),
           re.compile(r'AKIA[0-9A-Z]{16}'),
           re.compile(r'-----BEGIN [A-Z ]*PRIVATE KEY-----'))


def _value_like(v):
    # real credential values carry digits, symbols or mixed case; a
    # pure lower/upper dictionary word is prose, not a value
    # underscore/hyphen alone are identifier chars (base_env, my-var)
    return (any(c.isdigit() or (not c.isalnum() and c not in '_-') for c in v)
            or (v != v.lower() and v != v.upper()))


def _leaks(text):
    for m in _PW.finditer(text):
        if m.group(1)[0] in '$+':   # $VAR reference / '+var code concat
            continue
        if _value_like(m.group(1)) and not _PW_PLACEHOLDER.fullmatch(m.group(1)):
            return 'credential value after %r' % m.group(0)[:16]
    for t in _TOKENS:
        if t.search(text):
            return 'token/key material (%s...)' % t.pattern[:12]
    return None
TIER_KEY = {'PRIORITIZED_CRITICAL': 'pc', 'CRITICAL': 'critical',
            'HIGH': 'high', 'MEDIUM': 'medium', 'LOW': 'low'}


def check(doc, fname='report.json'):
    """Return a list of failure strings (empty == PASS)."""
    F = []
    if not isinstance(doc, dict):
        return ['R00 top-level: not a JSON object']
    if doc.get('schema_version') != '2.0':
        F.append('R01 schema_version: must be exactly "2.0", got %r'
                 % doc.get('schema_version'))
    app = doc.get('app')
    if not isinstance(app, dict):
        F.append('R02 app: block missing')
        app = {}
    for k in ('cmdb_id', 'app_name', 'estate', 'scanner_version'):
        v = app.get(k)
        if not isinstance(v, str) or not v.strip():
            F.append('R02 app.%s: required non-empty string' % k)
        elif v.strip().startswith('<'):
            F.append('R02 app.%s: template placeholder not filled in (%r)' % (k, v))
    cm = app.get('cmdb_id')
    if isinstance(cm, str) and cm.strip() and not cm.startswith('<'):
        want = cm.strip() + '_SCAN_REPORT.json'
        if os.path.basename(fname) != want:
            F.append('R03 filename: must be %r, got %r' % (want, os.path.basename(fname)))
    dc = doc.get('declared_counts')
    if not isinstance(dc, dict):
        F.append('R04 declared_counts: block missing')
        dc = {}
    for k in ('total', 'pc', 'critical', 'high', 'medium', 'low'):
        if not isinstance(dc.get(k), int) or dc.get(k, -1) < 0:
            F.append('R04 declared_counts.%s: required non-negative integer' % k)
    finds = doc.get('findings')
    if not isinstance(finds, list) or not finds:
        F.append('R05 findings: required non-empty array')
        finds = []
    ids, tally = [], {k: 0 for k in TIER_KEY.values()}
    for i, f in enumerate(finds):
        tag = 'findings[%d]' % i
        if not isinstance(f, dict):
            F.append('R05 %s: not an object' % tag); continue
        fid = f.get('id')
        if not isinstance(fid, str) or not fid.strip() or '...' in fid:
            F.append('R06 %s.id: required, non-empty, never "..."' % tag)
        else:
            if fid in ids:
                F.append('R06 %s.id: duplicate id %r' % (tag, fid))
            ids.append(fid)
        sev = f.get('severity')
        if sev == 'INFO':
            F.append('R07 %s.severity: INFO findings are excluded by contract' % tag)
        elif sev not in SEVS:
            F.append('R07 %s.severity: %r not in the five-tier enum' % (tag, sev))
        else:
            tally[TIER_KEY[sev]] += 1
        for k in ('repo', 'path'):
            v = f.get(k)
            if not isinstance(v, str) or not v.strip():
                F.append('R08 %s.%s: required non-empty string' % (tag, k))
        path = f.get('path')
        if isinstance(path, str) and path.strip():
            if path.startswith('/'):
                F.append('R08 %s.path: absolute paths are excluded (%r)' % (tag, path))
            if not re.search(r':[0-9]+$', path):
                F.append('R08 %s.path: must end with :line (e.g. File.java:83), got %r'
                         % (tag, path))
        loci = '%s %s' % (f.get('repo', ''), f.get('path', ''))
        if '.claude' in loci or 'CLAUDE' in loci:
            F.append('R09 %s: scan-tooling loci are excluded from reports' % tag)
        if 'PRIORS_' in loci:
            F.append('R09 %s: operator-staged priors are RUN INPUTS - their loci are '
                     'excluded from reports (route observations to COMPLETION.md '
                     'staging notes)' % tag)
        aa = f.get('also_affects')
        if aa is not None:
            if not isinstance(aa, list) or not aa:
                F.append('R16 %s.also_affects: must be a non-empty array when present' % tag)
            else:
                for j, a in enumerate(aa):
                    bad = (not isinstance(a, str) or not a.strip()
                           or a.startswith('/') or 'PRIORS_' in a or '.claude' in a
                           or '/' not in a)
                    if bad:
                        F.append('R16 %s.also_affects[%d]: each entry is a relative '
                                 'repo/path[:line] estate locus, got %r' % (tag, j, a))
        title = f.get('title')
        if not isinstance(title, str) or not title.strip():
            F.append('R10 %s.title: required non-empty (the full claim sentence)' % tag)
        elif title.rstrip().endswith('...') or title.rstrip().endswith('…'):
            F.append('R10 %s.title: truncated (trailing ellipsis)' % tag)
        cwe = f.get('cwe_canonical')
        if not isinstance(cwe, str) or not re.fullmatch(r'CWE-[1-9][0-9]*', cwe.strip()):
            F.append('R11 %s.cwe_canonical: must be a real CWE-NNN (never CWE-0/none), got %r'
                     % (tag, cwe))
        fx = f.get('fix')
        fx_ok = (isinstance(fx, str) and not fx.strip().startswith('<')
                 and (fx.strip().startswith('No code change required;')
                      or len(fx.strip()) >= 20))
        if not fx_ok:
            F.append('R17 %s.fix: REQUIRED — 1-2 imperative sentences specific to this '
                     'finding, or "No code change required; <reason>" (got %r)'
                     % (tag, fx if not isinstance(fx, str) else fx[:40]))
        pr = f.get('pc_reason')
        has_pr = isinstance(pr, str) and pr.strip()
        if sev == 'PRIORITIZED_CRITICAL' and not has_pr:
            F.append('R12 %s: PRIORITIZED_CRITICAL requires a pc_reason' % tag)
        if sev != 'PRIORITIZED_CRITICAL' and has_pr:
            F.append('R12 %s: pc_reason is only allowed on PRIORITIZED_CRITICAL rows' % tag)
        for k in ('title', 'fix', 'pc_reason'):
            v = f.get(k)
            if isinstance(v, str):
                leak = _leaks(v)
                if leak:
                    F.append('R18 %s.%s: literal %s - reports name the KIND and '
                             'cite the locus, never the value (values-by-kind law)'
                             % (tag, k, leak))
    if isinstance(dc.get('total'), int):
        s = sum(tally.values())
        parts = sum(dc.get(k, 0) for k in ('pc', 'critical', 'high', 'medium', 'low')
                    if isinstance(dc.get(k), int))
        if dc['total'] != parts:
            F.append('R13 counts: total (%d) != pc+critical+high+medium+low (%d)'
                     % (dc['total'], parts))
        if dc['total'] != s:
            F.append('R13 counts: total (%d) != number of findings by tier (%d)'
                     % (dc['total'], s))
    for k in ('pc', 'critical', 'high', 'medium', 'low'):
        if isinstance(dc.get(k), int) and dc[k] != tally[k]:
            F.append('R13 counts: declared %s=%d but findings tally %d' % (k, dc[k], tally[k]))
    chains = doc.get('chains', [])
    if chains is None:
        chains = []
    if not isinstance(chains, list):
        F.append('R14 chains: must be an array when present'); chains = []
    if 'chains' in dc and isinstance(dc.get('chains'), int) and dc['chains'] != len(chains):
        F.append('R14 counts: declared chains=%d but chains[] holds %d'
                 % (dc['chains'], len(chains)))
    for i, c in enumerate(chains):
        tag = 'chains[%d]' % i
        if not isinstance(c, dict):
            F.append('R14 %s: not an object' % tag); continue
        for k in ('id', 'title'):
            if not isinstance(c.get(k), str) or not c.get(k, '').strip():
                F.append('R14 %s.%s: required non-empty string' % (tag, k))
        if c.get('status') not in ('confirmed', 'conditional'):
            F.append('R14 %s.status: must be confirmed|conditional, got %r'
                     % (tag, c.get('status')))
        hops = c.get('hops')
        if not isinstance(hops, list) or len(hops) < 2:
            F.append('R15 %s.hops: a chain is 2+ linked findings with structured hops' % tag)
            hops = hops if isinstance(hops, list) else []
        for j, h in enumerate(hops):
            hid = h.get('finding_id') if isinstance(h, dict) else None
            if hid not in ids:
                F.append('R15 %s.hops[%d].finding_id: %r does not exist in findings[]'
                         % (tag, j, hid))
    return F


def _good():
    return {
        'schema_version': '2.0',
        'app': {'cmdb_id': 'APP001', 'app_name': 'Example Service', 'estate': 'example-service', 'scanner_version': '1.0.0'},
        'declared_counts': {'total': 3, 'pc': 1, 'critical': 1, 'high': 1,
                            'medium': 0, 'low': 0, 'chains': 1},
        'findings': [
            {'id': 'F-0001', 'severity': 'PRIORITIZED_CRITICAL', 'repo': 'svc-a',
             'path': 'src/A.java:10', 'title': 'Full claim sentence one.',
             'cwe_canonical': 'CWE-639', 'pc_reason': 'All four clauses met: 1..2..3..4.',
             'fix': 'Derive identity from the authenticated token and enforce ownership server-side.'},
            {'id': 'F-0002', 'severity': 'CRITICAL', 'repo': 'svc-b',
             'path': 'src/B.js:20', 'title': 'Full claim sentence two.',
             'cwe_canonical': 'CWE-862',
             'fix': 'Enforce an entitlement check on the reset endpoint before acting.'},
            {'id': 'F-0003', 'severity': 'HIGH', 'repo': 'svc-c',
             'path': 'conf/c.yaml:3', 'title': 'Full claim sentence three.',
             'cwe_canonical': 'CWE-532',
             'fix': 'No code change required; the field is masked upstream by the tokenizer.'},
        ],
        'chains': [{'id': 'CHAIN-01', 'title': 'two-hop story', 'status': 'confirmed',
                    'hops': [{'finding_id': 'F-0002'}, {'finding_id': 'F-0001'}]}],
    }


def selftest():
    import copy
    n, ok = 0, 0
    def t(name, doc, fname, want_pass):
        nonlocal n, ok
        n += 1
        fails = check(doc, fname)
        good = (not fails) == want_pass
        ok += good
        print('%-4s selftest %02d %s%s' % ('PASS' if good else 'FAIL', n, name,
              '' if good else ' — ' + '; '.join(fails[:2])))
    g = _good()
    t('clean report passes', g, 'APP001_SCAN_REPORT.json', True)
    b = copy.deepcopy(g); b['declared_counts']['total'] = 4
    t('total != tier sum refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['declared_counts']['high'] = 0; b['declared_counts']['total'] = 2
    t('tier count != tally refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][1]['severity'] = 'INFO'
    t('INFO tier refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][1]['id'] = 'F-0001'
    t('duplicate id refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][2]['cwe_canonical'] = 'CWE-0'
    t('CWE-0 refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][2]['cwe_canonical'] = 'none'
    t('cwe none refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); del b['findings'][0]['pc_reason']
    t('PC-1 without pc_reason refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][1]['pc_reason'] = 'should not be here'
    t('pc_reason on non-PC-1 refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][2]['title'] = 'truncated claim...'
    t('trailing ellipsis refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][2]['path'] = '/abs/path/c.yaml:3'
    t('absolute path refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][2]['path'] = 'conf/c.yaml'
    t('missing :line refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][2]['repo'] = '.claude'
    t('tooling locus refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['chains'][0]['hops'][1]['finding_id'] = 'F-9999'
    t('dangling chain hop refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['chains'][0]['hops'] = [{'finding_id': 'F-0001'}]
    t('one-hop chain refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['chains'][0]['status'] = 'narrative'
    t('bad chain status refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['app']['cmdb_id'] = '<CMDB e.g. APP001>'
    t('template placeholder refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['schema_version'] = '1.0'
    t('wrong schema_version refused', b, 'APP001_SCAN_REPORT.json', False)
    t('wrong filename refused', copy.deepcopy(g), 'REPORT.json', False)
    b = copy.deepcopy(g); b['declared_counts']['chains'] = 2
    t('chains count mismatch refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][1]['fix'] = None
    t('null fix refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][1]['fix'] = 'fix it'
    t('hollow fix refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][1]['fix'] = 'No code change required; documented public reference data.'
    t('no-change-with-reason accepted', b, 'APP001_SCAN_REPORT.json', True)
    b = copy.deepcopy(g); b['findings'][2]['path'] = 'PRIORS_example.json:12'
    t('staged-priors locus refused', b, 'APP001_SCAN_REPORT.json', False)
    b = copy.deepcopy(g); b['findings'][2]['also_affects'] = ['svc-d/conf/d.yaml:3', 'svc-e/conf/e.yaml:9']
    t('multi-site also_affects accepted', b, 'APP001_SCAN_REPORT.json', True)
    b = copy.deepcopy(g); b['findings'][2]['also_affects'] = ['/abs/path.yaml:3']
    t('absolute also_affects entry refused', b, 'APP001_SCAN_REPORT.json', False)
    b = _good(); b['findings'][0]['title'] = 'application.yml commits ssl key-password=hunter2secret to git'
    t('R18 literal credential value in title refused', b, 'APP001_SCAN_REPORT.json', False)
    b = _good(); b['findings'][0]['title'] = 'config quotes password=changeme placeholder; kind: bootstrap password'
    t('R18 placeholder/kind-only prose passes', b, 'APP001_SCAN_REPORT.json', True)
    print('scan_report_gate selftest %d/%d' % (ok, n))
    return 0 if ok == n else 1


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--selftest':
        sys.exit(selftest())
    if len(sys.argv) != 2:
        print(__doc__); sys.exit(2)
    p = sys.argv[1]
    try:
        doc = json.load(open(p))
    except Exception as e:
        print('SCAN-REPORT GATE: FAIL %s — not valid JSON: %s' % (p, e)); sys.exit(1)
    fails = check(doc, p)
    if fails:
        for f in fails:
            print('FAIL ' + f)
        print('SCAN-REPORT GATE: FAIL %s (%d rule failures)' % (p, len(fails)))
        sys.exit(1)
    print('SCAN-REPORT GATE: PASS %s' % p)


if __name__ == '__main__':
    main()
