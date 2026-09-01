#!/usr/bin/env python3
# INVOCATION + OUTPUT-QUIET REQUIREMENT: run BY PATH.
"""visitation_check.py v1.0 - NO ROCK UNTURNED, AS ARITHMETIC.
A sealed run could only ATTEST full visitation (counts, not lists). This
instrument makes it auditable: compare the union of per-lane read-set
manifests against the unit's census file list; the difference must be
empty or receipted. Usage:
  visitation_check.py <unit_files.txt> <readset1.txt> [readset2.txt ...]
  visitation_check.py --selftest
Prints VISITATION: union/in-scope + MISSING/GHOST lists. Exit 0 clean,
1 unreceipted-missing or ghost, 2 err. Flat equivalent: sort -u over the
readsets, comm -13/-23 against the sorted unit list."""
import sys
def load(p):
    try: return set(l.strip() for l in open(p,encoding='utf-8') if l.strip() and not l.startswith('#'))
    except Exception as e:
        print('VIS ERR: %s'%e); sys.exit(2)
def main(unit_p, readsets):
    scope=load(unit_p)
    union=set()
    for r in readsets: union|=load(r)
    missing=sorted(scope-union); ghost=sorted(union-scope)
    print('VISITATION: %d/%d (union-read/in-scope; %d lanes)'%(len(union&scope),len(scope),len(readsets)))
    rc=0
    if missing:
        print('MISSING (in-scope, read by NO lane): %d'%len(missing))
        for m in missing[:10]: print('  '+m)
        rc=1
    if ghost:
        print('GHOST (read but not in-scope): %d'%len(ghost))
        for g in ghost[:10]: print('  '+g)
        rc=1
    if rc==0: print('VISITATION: CLEAN (union == in-scope)')
    return rc
def selftest():
    import tempfile, os as _os, io as _io, contextlib
    d=tempfile.mkdtemp()
    u=_os.path.join(d,'u.txt'); a=_os.path.join(d,'a.txt'); b=_os.path.join(d,'b.txt')
    open(u,'w').write('f1.py\nf2.py\nf3.py\n')
    open(a,'w').write('f1.py\nf2.py\n'); open(b,'w').write('f2.py\nf3.py\n')
    ok=0
    buf=_io.StringIO()
    with contextlib.redirect_stdout(buf): rc=main(u,[a,b])
    ok+=(rc==0 and 'VISITATION: 3/3' in buf.getvalue() and 'CLEAN' in buf.getvalue())
    open(b,'w').write('f2.py\n')
    buf2=_io.StringIO()
    with contextlib.redirect_stdout(buf2): rc2=main(u,[a,b])
    ok+=(rc2==1 and 'MISSING' in buf2.getvalue() and 'f3.py' in buf2.getvalue())
    open(b,'w').write('f2.py\nf3.py\nrogue.py\n')
    buf3=_io.StringIO()
    with contextlib.redirect_stdout(buf3): rc3=main(u,[a,b])
    ok+=(rc3==1 and 'GHOST' in buf3.getvalue() and 'rogue.py' in buf3.getvalue())
    print('VISITATION SELFTEST: %d/3 PASS'%ok)
    return 0 if ok==3 else 1
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--selftest': sys.exit(selftest())
    if len(sys.argv)<3: print('VIS ERR: usage'); sys.exit(2)
    sys.exit(main(sys.argv[1], sys.argv[2:]))
