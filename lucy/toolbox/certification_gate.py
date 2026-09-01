#!/usr/bin/env python3
# INVOCATION + OUTPUT-QUIET REQUIREMENT: run BY PATH.
"""certification_gate.py v1.2 — THE SIX CHECKS, AT REPORT GENERATION.

A single run may print CERTIFIED in its final line ONLY when this
gate prints CERTIFICATION: PASS on its finished artifacts. The gate
verifies six receipt-backed conditions from the run's own data;
downstream validation re-runs the identical gate on the pushed
artifacts. A run that cannot pass prints
PROCESS-COMPLETE and names the failing check — that is an honest
ending, not a defect.

Usage:
    certification_gate.py <COMPLETION.md> <receipts-dir>
    certification_gate.py --selftest

The six checks (each verified from receipts, never from prose alone):
 C1 VISITATION   files-opened total == census scannable file count
 C2 QUIET        every unit shows two consecutive quiet passes (the
                 per-unit bar is density-scaled, max(2, LOC/25K), computed
                 launcher-side and recorded as quiet_thresholds in the
                 receipt; this gate verifies units_quiet == units)
 C3 RECALL       found + cured + mint-error == 8 (cures rescored blind;
                 mint errors independently attested and receipted)
 C4 PRIORS       staged targets: adjudicated == staged, and every
                 NOT-EVIDENCED verdict carries an evidence receipt
                 (REFOUND + NOT-EVIDENCED == staged; zero bare rows).
                 A cold run (no priors staged) passes C4 as N/A.
 C5 INTEGRITY    pulse ledger: every lane death closed in order, orphans 0
 C6 GATES        seal-card gate PASS + scan-report gate PASS lines
                 present with their tokens/filenames.
Machine format: the run writes CERT_RECEIPT.json in the receipts dir
with the raw numbers; this gate recomputes the comparisons.
"""
import json, os, re, sys


def check(completion_text, receipt):
    """Return list of failure strings (empty == PASS).
    receipt = dict loaded from CERT_RECEIPT.json."""
    F = []
    r = receipt
    def need(key):
        v = r.get(key)
        if v is None:
            F.append('C0 CERT_RECEIPT.json missing field %r' % key)
        return v
    # Type law: every numeric receipt field must be an int. A string/float
    # counter previously skipped its check entirely (guarded isinstance with
    # no else-branch), letting a mistyped receipt certify (regression basis).
    for k in ('files_opened', 'census_files', 'units', 'units_quiet',
              'plants_found', 'plants_cured', 'plants_mint_error', 'priors_staged',
              'priors_refound', 'priors_not_evidenced',
              'priors_not_evidenced_receipted', 'priors_refound_verified',
              'priors_refound_refuted', 'priors_refound_folded',
              'canary_historical',
              'lane_deaths', 'lane_redispatched', 'lane_adopted',
              'lane_deaths_unreconciled', 'orphans',
              'planted_file_candidates', 'candidates_dispositioned',
              'dispositions_unresolved'):
        v = receipt.get(k)
        if v is not None and not isinstance(v, int):
            F.append('C0 TYPE: %s must be an integer, got %r' % (k, type(v).__name__))
    if F:
        return F
    # C1 visitation
    opened, census = need('files_opened'), need('census_files')
    if isinstance(opened, int) and isinstance(census, int) and opened != census:
        F.append('C1 VISITATION: opened %d != census %d' % (opened, census))
    # C2 quiet
    units, quiet_units = need('units'), need('units_quiet')
    if isinstance(units, int) and isinstance(quiet_units, int) and quiet_units != units:
        F.append('C2 QUIET: %d/%d units show two consecutive quiet passes'
                 % (quiet_units, units))
    # C3 recall
    found, cured = need('plants_found'), r.get('plants_cured', 0)
    # mint_error: independently adjudicated defective plants (receipted with a
    # basis on the seal card); the law stays additive and exhaustive.
    minterr = r.get('plants_mint_error', 0)
    if isinstance(found, int) and found + (cured or 0) + (minterr or 0) != 8:
        F.append('C3 RECALL: found %d + cured %s + mint-error %s != 8'
                 % (found, cured, minterr))
    # C3b canary mint mix: priors staged => >=4 historical canaries
    staged = r.get('priors_staged', 0)
    if staged:
        ch = need('canary_historical')
        if isinstance(ch, int) and ch < 4:
            F.append('C3 RECALL: %d historical canaries with priors staged (law: >=4, '
                     'deterministic draw; see mint_canaries.py receipt)' % ch)
    # C4 priors
    if staged:
        refound = need('priors_refound')
        notev = need('priors_not_evidenced')
        notev_receipted = need('priors_not_evidenced_receipted')
        if isinstance(refound, int) and isinstance(notev, int) and refound + notev != staged:
            F.append('C4 PRIORS: refound %d + not-evidenced %d != staged %d'
                     % (refound, notev, staged))
        if isinstance(notev, int) and isinstance(notev_receipted, int) and notev_receipted != notev:
            F.append('C4 PRIORS: %d not-evidenced verdicts but only %d carry evidence receipts'
                     % (notev, notev_receipted))
        # C4b Historical Disposition split — REQUIRED when priors staged (v1.2)
        disp = [r.get('priors_refound_' + k) for k in ('verified', 'refuted', 'folded')]
        if all(v is None for v in disp):
            F.append('C4 PRIORS: disposition split fields required when priors are staged')
        if any(v is not None for v in disp):
            if not all(isinstance(v, int) for v in disp):
                F.append('C4 PRIORS: disposition fields must be all-present integers')
            elif isinstance(refound, int) and sum(disp) != refound:
                F.append('C4 PRIORS: disposition verified %d + refuted %d + folded %d != refound %d'
                         % (disp[0], disp[1], disp[2], refound))
    # C5 integrity
    deaths, redisp = need('lane_deaths'), need('lane_redispatched')
    # adopted-empty is a legitimate liveness closure: a lane that dies again
    # after its relaunch may be adopted as an empty result (receipted).
    adopted = receipt.get('lane_adopted', 0) or 0
    orphans = need('orphans')
    # PULSE LAW IS ORDERED PER-LANE COVERAGE, NOT COUNT EQUALITY: the
    # launcher reduces the ledger in event order (a closure consumes only
    # a prior outstanding death on its own lane; over-closure is receipted
    # noise; invalid lane labels fail closed) and writes the outstanding
    # count into the receipt. Certification requires the field PRESENT and
    # ZERO — a receipt without it is not a current-format receipt and
    # fails closed (no silent legacy fallback).
    unreconciled = need('lane_deaths_unreconciled')
    if unreconciled is not None:
        if not isinstance(unreconciled, int) or isinstance(unreconciled, bool):
            F.append('C5 INTEGRITY: lane_deaths_unreconciled must be an integer')
        elif unreconciled != 0:
            F.append('C5 INTEGRITY: %d lane deaths have no closure (redispatch or adopted-empty)'
                     % unreconciled)
    if isinstance(orphans, int) and orphans != 0:
        F.append('C5 INTEGRITY: %d orphaned lanes' % orphans)
    # C5c attribution law: every candidate in a planter-modified file must
    # carry a clean-target disposition and none may be unresolved — the
    # published counts are untrustworthy otherwise (a plant-derived
    # finding can otherwise ship as genuine, and a genuine one be hidden).
    # Presence law first: attribution evidence must EXIST with the exact
    # schema — a missing/unreadable/wrong-schema disposition receipt must
    # never read as a complete empty disposition.
    if r.get('disposition_receipt_present') is not True:
        F.append('C5 INTEGRITY: disposition evidence missing — no valid '
                 'CANDIDATE_DISPOSITIONS receipt was presented at certification')
    elif r.get('disposition_receipt_schema') != 'lucy-dispositions/v1':
        F.append('C5 INTEGRITY: disposition receipt schema %r is not lucy-dispositions/v1'
                 % r.get('disposition_receipt_schema'))
    pfc = r.get('planted_file_candidates', 0) or 0
    disp = r.get('candidates_dispositioned', 0) or 0
    unres = r.get('dispositions_unresolved', 0) or 0
    if isinstance(pfc, int) and isinstance(disp, int) and pfc != disp:
        F.append('C5 INTEGRITY: %d planted-file candidates but only %d dispositioned' % (pfc, disp))
    if isinstance(unres, int) and unres != 0:
        F.append('C5 INTEGRITY: %d unresolved clean-target dispositions' % unres)
    # C6 gates — must appear in COMPLETION text with token/filename shapes
    if not re.search(r'SEAL-?\s?(CARD|TOKEN)[^\n]*(PASS|[0-9a-f]{16})', completion_text, re.I):
        F.append('C6 GATES: no seal-card PASS/token line in COMPLETION.md')
    if not re.search(r'SCAN-?REPORT GATE[^\n]*PASS', completion_text, re.I):
        F.append('C6 GATES: no scan-report gate PASS line in COMPLETION.md')
    return F


def _good():
    return {
        'files_opened': 12, 'census_files': 12,
        'units': 2, 'units_quiet': 2,
        'plants_found': 7, 'plants_cured': 1, 'canary_historical': 4,
        'priors_staged': 6, 'priors_refound': 4,
        'priors_refound_verified': 3, 'priors_refound_refuted': 1, 'priors_refound_folded': 0,
        'priors_not_evidenced': 2, 'priors_not_evidenced_receipted': 2,
        'lane_deaths': 1, 'lane_redispatched': 1, 'lane_deaths_unreconciled': 0, 'orphans': 0,
        'disposition_receipt_present': True,
        'disposition_receipt_schema': 'lucy-dispositions/v1',
    }


GOOD_COMPLETION = ('SEAL-CARD gate: PASS - SEAL-TOKEN: 0123456789abcdef\n'
                   'SCAN-REPORT GATE: PASS APP001_SCAN_REPORT.json\n')


def selftest():
    import copy
    n = ok = 0
    def t(name, rec, comp, want_pass):
        nonlocal n, ok
        n += 1
        fails = check(comp, rec)
        good = (not fails) == want_pass
        ok += good
        print('%-4s selftest %02d %s%s' % ('PASS' if good else 'FAIL', n, name,
              '' if good else ' - ' + '; '.join(fails[:2])))
    g = _good()
    t('clean certified run passes', g, GOOD_COMPLETION, True)
    b = copy.deepcopy(g); b['files_opened'] = 11
    t('C1 visitation shortfall refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['units_quiet'] = 1
    t('C2 unquiet unit refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['plants_found'] = 6
    t('C3 uncured recall miss refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['lane_deaths'] = 5; b['lane_redispatched'] = 5
    b['lane_adopted'] = 4; b['lane_deaths_unreconciled'] = 0
    t('C5 double-closure ledger with zero coverage gap certifies', b, GOOD_COMPLETION, True)
    b = copy.deepcopy(g); b['lane_deaths_unreconciled'] = 1
    t('C5 unclosed lane death refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); del b['lane_deaths_unreconciled']
    t('C5 receipt missing unreconciled field fails closed', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['priors_refound'] = 3
    t('C4 priors arithmetic gap refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['priors_not_evidenced_receipted'] = 1
    t('C4 bare not-evidenced verdicts refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['priors_staged'] = 0
    t('cold run (no priors) passes C4 as N/A', b, GOOD_COMPLETION, True)
    b = copy.deepcopy(g); b['canary_historical'] = 0
    t('C3b all-pattern mint with priors staged refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['priors_staged'] = 0; b.pop('canary_historical')
    t('C3b not required on a cold run', b, GOOD_COMPLETION, True)
    b = copy.deepcopy(g); b.update(priors_refound_verified=3, priors_refound_refuted=1,
                                   priors_refound_folded=0)
    t('C4b disposition table reconciles', b, GOOD_COMPLETION, True)
    b = copy.deepcopy(g); b.update(priors_refound_verified=3, priors_refound_refuted=0,
                                   priors_refound_folded=0)
    t('C4b disposition arithmetic gap refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['lane_redispatched'] = 19
    b['lane_deaths_unreconciled'] = 1
    t('C5 unredispatched death refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['orphans'] = 1
    t('C5 orphaned lane refused', b, GOOD_COMPLETION, False)
    t('C6 missing gate lines refused', copy.deepcopy(g), 'no gates here\n', False)
    b = copy.deepcopy(g); del b['census_files']
    t('missing receipt field refused', b, GOOD_COMPLETION, False)
    b = copy.deepcopy(g); b['files_opened'] = str(b['files_opened'])
    t('mistyped receipt field refused', b, GOOD_COMPLETION, False)
    d1 = copy.deepcopy(g); d1['planted_file_candidates'] = 5; d1['candidates_dispositioned'] = 4
    t('undispositioned planted-file candidate refused', d1, GOOD_COMPLETION, False)
    d2 = copy.deepcopy(g); d2['planted_file_candidates'] = 5; d2['candidates_dispositioned'] = 5; d2['dispositions_unresolved'] = 1
    t('unresolved disposition refused', d2, GOOD_COMPLETION, False)
    d3 = copy.deepcopy(g); d3['planted_file_candidates'] = 5; d3['candidates_dispositioned'] = 5; d3['dispositions_unresolved'] = 0
    t('complete dispositions certify', d3, GOOD_COMPLETION, True)
    d4 = copy.deepcopy(g); d4.pop('disposition_receipt_present')
    t('missing disposition evidence refused', d4, GOOD_COMPLETION, False)
    d5 = copy.deepcopy(g); d5['disposition_receipt_schema'] = 'lucy-dispositions/v0'
    t('wrong disposition schema refused', d5, GOOD_COMPLETION, False)
    d6 = copy.deepcopy(g); d6['planted_file_candidates'] = 0; d6['candidates_dispositioned'] = 0
    t('zero planted-file candidates with valid receipt certifies', d6, GOOD_COMPLETION, True)
    print('certification_gate selftest %d/%d' % (ok, n))
    return 0 if ok == n else 1


def main():
    if len(sys.argv) == 2 and sys.argv[1] == '--selftest':
        sys.exit(selftest())
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(2)
    comp = open(sys.argv[1], encoding='utf-8', errors='replace').read()
    rpath = os.path.join(sys.argv[2], 'CERT_RECEIPT.json')
    if not os.path.exists(rpath):
        print('CERTIFICATION: FAIL - CERT_RECEIPT.json not found in %s' % sys.argv[2])
        sys.exit(1)
    fails = check(comp, json.load(open(rpath)))
    if fails:
        for f in fails:
            print('CERT-FAIL ' + f)
        print('CERTIFICATION: FAIL - run is PROCESS-COMPLETE, not certified')
        sys.exit(1)
    print('CERTIFICATION: PASS - all six checks verified from receipts')
    sys.exit(0)


if __name__ == '__main__':
    main()
