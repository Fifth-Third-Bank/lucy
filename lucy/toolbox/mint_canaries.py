#!/usr/bin/env python3
# INVOCATION + OUTPUT-QUIET REQUIREMENT: run BY PATH.
"""mint_canaries.py v1.0 — THE MINT IS A SCRIPT, NOT A JUDGMENT CALL.

The mix is a mint-time fact, so this script decides it at mint time
and writes the receipt the gates read.

Usage:
    mint_canaries.py <staged-priors.json|NONE> <receipt-out.json>
    mint_canaries.py --selftest

Emits the run's canary plan:
 - plants: 8 pattern-plant slots, two per lens family (L1 auth,
   L2 secrets/crypto, L3 injection/dataflow, L4 infra/config). The
   session chooses exact host loci and edits; the FAMILY SPREAD is
   fixed here.
 - historical_canaries: when a priors file is staged, the 4 refind
   targets drawn by deterministic sha256 order of target id. These
   are NOT planted edits — they are real historical defects scored
   as canaries: found blind during review, or established by a COLD
   RE-READ receipt (fresh lane, no priors context, single file) at
   scoring time. Card composition: 4 drawn pattern plants + these 4.
 - canary_historical: the count the certification gate
   requires >= 4 whenever priors are staged.
BOOT LAW: this script runs BEFORE pass-1 dispatch; a missing or
mix-violating receipt at dispatch time is a boot-stop, not a
seal-time surprise.
"""
import hashlib, json, sys

FAMILIES = ('L1-auth', 'L1-auth', 'L2-secrets', 'L2-secrets',
            'L3-injection', 'L3-injection', 'L4-infra', 'L4-infra')


def plan(priors_path):
    out = {'mint': 'mint_canaries.py v1.0',
           'plants': [{'slot': i + 1, 'family': f, 'host_locus': '<session-chosen>'}
                      for i, f in enumerate(FAMILIES)],
           'historical_canaries': [], 'canary_historical': 0}
    if priors_path and priors_path != 'NONE':
        pri = json.load(open(priors_path))
        targets = [t for t in pri.get('refind_targets', []) if t.get('id')]
        seen, uniq = set(), []
        for t in targets:
            if t['id'] not in seen:
                seen.add(t['id']); uniq.append(t)
        draw = sorted(uniq, key=lambda t: hashlib.sha256(t['id'].encode()).hexdigest())[:4]
        out['historical_canaries'] = [
            {'id': t['id'], 'locus': t.get('locus', ''), 'title': t.get('title', '')[:120],
             'scoring': 'blind re-find during review, or COLD RE-READ receipt at scoring'}
            for t in draw]
        out['canary_historical'] = len(draw)
        out['draw_law'] = 'deterministic sha256(id) ascending over unique target ids'
    return out


def selftest():
    import tempfile, os
    ok = n = 0
    def t(name, cond):
        nonlocal ok, n
        n += 1; ok += bool(cond)
        print('%-4s selftest %02d %s' % ('PASS' if cond else 'FAIL', n, name))
    p = plan('NONE')
    t('cold run: 8 pattern slots, 0 historical', len(p['plants']) == 8 and p['canary_historical'] == 0)
    t('family spread fixed 2/2/2/2', [x['family'] for x in p['plants']] == list(FAMILIES))
    d = tempfile.mkdtemp(); f = os.path.join(d, 'PRIORS_example_APP001.json')
    json.dump({'refind_targets': [{'id': 'T-%03d' % i, 'locus': 'example-repo/f%d.py:1' % i,
                                   'title': 't'} for i in range(9)]}, open(f, 'w'))
    p1, p2 = plan(f), plan(f)
    t('primed run: 4 historical drawn', p1['canary_historical'] == 4)
    t('draw is deterministic', [x['id'] for x in p1['historical_canaries']] ==
      [x['id'] for x in p2['historical_canaries']])
    json.dump({'refind_targets': [{'id': 'DUP', 'locus': 'a', 'title': 't'}] * 6
               + [{'id': 'T-%d' % i, 'locus': 'b', 'title': 't'} for i in range(4)]},
              open(f, 'w'))
    p3 = plan(f)
    t('duplicate ids collapse before the draw',
      len(set(x['id'] for x in p3['historical_canaries'])) == 4)
    print('mint_canaries selftest %d/%d' % (ok, n))
    return 0 if ok == n else 1


if __name__ == '__main__':
    if len(sys.argv) == 2 and sys.argv[1] == '--selftest':
        sys.exit(selftest())
    if len(sys.argv) != 3:
        print(__doc__); sys.exit(2)
    receipt = plan(sys.argv[1])
    json.dump(receipt, open(sys.argv[2], 'w'), indent=1)
    print('MINT-PLAN: 8 pattern slots + %d historical canaries -> %s'
          % (receipt['canary_historical'], sys.argv[2]))
    sys.exit(0)
