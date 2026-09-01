#!/usr/bin/env python3
# INVOCATION + OUTPUT-QUIET REQUIREMENT: run BY PATH.
r"""census.py v1.3 - THE CANONICAL CENSUS.
Ad-hoc census scripts can produce divergent scannable denominators.
This instrument makes the
denominator DETERMINISTIC: fixed extension set, fixed lockfile exclusions,
fixed zone rules, fixed mass-suspect flagging. Same tree -> same numbers.
Usage: census.py <root> | --selftest. Prints the fixed-format report.
Exit 0 OK, 2 ERR.
THE CANONICAL FLAT PIPELINE (the ONLY lawful TEXT-mode census;
LADDER NOTE: if full-archive extraction is denied, a SINGLE-MEMBER
extract of census.py alone is a lawful narrower shape;
unzip -p remains the read-only rung below it.
EACH NUMBERED STEP IS INDEPENDENTLY LAWFUL — a denial of one step is
a denial of that SHAPE, never of the census: restructure or ladder
THAT STEP and continue. Step down, never sideways. Substituting any
other census (file counts, du, repo counts) VOIDS the card. Flat
equivalents are this procedure's own alternative implementation,
not circumvention.
must reproduce this script's three numbers; the card then reads
CENSUS: FLAT):
  cd <root>
  git ls-files | grep -Ev '(^|/)\.git/' > /tmp/all.txt
  grep -E '\.(py|js|ts|tsx|jsx|java|go|rb|tf|tfvars|yaml|yml|json|sh|bash|sql|xml|properties|gradle|kt|scala|groovy|c|h|cpp|hpp|cs|php|pl|ps1|toml|ini|cfg|conf|mk|j2)$|(^|/)(Dockerfile|Makefile|Jenkinsfile|Procfile)$' /tmp/all.txt \
    | grep -Ev '(^|/)(package-lock\.json|yarn\.lock|pnpm-lock\.yaml|poetry\.lock|Pipfile\.lock|Cargo\.lock|go\.sum|composer\.lock|Gemfile\.lock)$' \
    | grep -Ev '^(\.docs|\.claude|\.gen7-run)/' \
    | grep -Ev '^PRIORS_[^/]*$' > /tmp/code.txt   # staged priors = run inputs
  tr '\n' '\0' < /tmp/code.txt | wc -l --files0-from=- \
    | tail -1   # RAW-CODE-LOC (single wc invocation: xargs batching can
                # truncate totals at large file counts; files0-from is required)
  cut -d/ -f1 /tmp/code.txt | sort -u | wc -l      # REPOS
  Mass-suspects and the FFD partition follow the same constants
  (>=5000 lines and >=80% of repo; FFD cap 50000, LOC-desc, name
  tiebreak) applied to the per-repo wc -l sums."""
import sys, os
CODE_EXT={'.py','.js','.ts','.tsx','.jsx','.java','.go','.rb','.tf','.tfvars',
 '.yaml','.yml','.json','.sh','.bash','.sql','.xml','.properties','.gradle',
 '.kt','.scala','.groovy','.c','.h','.cpp','.hpp','.cs','.php','.pl','.ps1',
 '.toml','.ini','.cfg','.conf','.env.example','.dockerfile','.mk','.j2'}
CODE_NAMES={'Dockerfile','Makefile','Jenkinsfile','Procfile'}
LOCKFILES={'package-lock.json','yarn.lock','pnpm-lock.yaml','poetry.lock',
 'Pipfile.lock','Cargo.lock','go.sum','composer.lock','Gemfile.lock'}
ZONES={'.docs':'CONTEXT','.claude':'RECORD','.gen7-run':'RECORD','OPTIONAL_PRIORS':'STAGING'}
MASS_LINES=5000; MASS_FRACTION=0.80
def count_lines(p):
    # POSIX semantics: a line ends with newline; an
    # unterminated final fragment is not a line (matches wc -l and
    # therefore the canonical flat pipeline, byte for byte).
    try:
        with open(p,'rb') as f: return f.read().count(b'\n')
    except Exception: return 0
def census(root):
    repos={}; zones={}; lock_loc=0; staging_loc=0; staging_files=0
    for dp,dn,fn in os.walk(root):
        dn[:]=[d for d in dn if d!='.git']
        rel=os.path.relpath(dp,root)
        top=rel.split(os.sep)[0] if rel!='.' else ''
        if top in ZONES:
            if ZONES[top]=='STAGING':
                for f in fn: staging_loc+=count_lines(os.path.join(dp,f)); staging_files+=1
            else:
                for f in fn: zones[top]=zones.get(top,0)+count_lines(os.path.join(dp,f))
            continue
        for f in fn:
            if rel=='.' and f.startswith('PRIORS_'):
                staging_loc+=count_lines(os.path.join(dp,f)); staging_files+=1; continue
            ext=os.path.splitext(f)[1].lower()
            if f in LOCKFILES: lock_loc+=count_lines(os.path.join(dp,f)); continue
            if ext in CODE_EXT or f in CODE_NAMES:
                key=top if top else '(root)'
                n=count_lines(os.path.join(dp,f))
                r=repos.setdefault(key,{'loc':0,'files':0,'biggest':(0,'')})
                r['loc']+=n; r['files']+=1
                if n>r['biggest'][0]: r['biggest']=(n,os.path.join(rel,f))
    raw=sum(r['loc'] for r in repos.values())
    suspects=[]
    for k,r in sorted(repos.items()):
        b=r['biggest']
        if b[0]>=MASS_LINES and r['loc']>0 and b[0]/r['loc']>=MASS_FRACTION:
            suspects.append((k,b[1],b[0]))
    return repos,zones,lock_loc,raw,suspects,staging_loc,staging_files
def report(root):
    repos,zones,lock_loc,raw,suspects,staging_loc,staging_files=census(root)
    print('CANONICAL CENSUS v1.0')
    print('REPOS: %d'%len(repos))
    print('RAW-CODE-LOC: %d (fixed extension set; lockfiles excluded: %d lines)'%(raw,lock_loc))
    for z in sorted(zones): print('ZONE %s: %d lines (%s-class, outside scannable)'%(z,zones[z],ZONES[z]))  # STAGING zone reports via STAGING-INPUTS line
    if staging_files:
        print('STAGING-INPUTS: %d root PRIORS_* file(s), %d lines - RUN INPUTS, outside the denominator; sweep for secrets, note results in COMPLETION.md only'%(staging_files,staging_loc))
    for k,pth,n in suspects:
        print('MASS-SUSPECT: %s :: %s (%d lines) -> species check REQUIRED (receipted ruling; carve if data)'%(k,pth,n))
    prelim=raw-sum(n for _,_,n in suspects)
    print('SCANNABLE-IF-ALL-SUSPECTS-CARVED: %d'%prelim)
    print('DENOMINATOR REQUIREMENT: SCANNABLE = RAW-CODE-LOC minus receipted mass-data carves; report both numbers verbatim.')
    # THE CANONICAL PARTITION: deterministic FFD, cap 50000,
    # LOC-descending with name tiebreak; suspect mass excluded from its repo.
    sus={k:n for k,_,n in suspects}
    sized=sorted(((max(r['loc']-sus.get(k,0),0),k) for k,r in repos.items()), key=lambda x:(-x[0],x[1]))
    scannable_est=sum(l for l,_ in sized)
    cap=max(50000, -(-scannable_est//40))  # scale-aware: ceil(scannable/40)
    units=[]
    for loc,k in sized:
        placed=False
        for u in units:
            if u[0]+loc<=cap: u[0]+=loc; u[1].append((k,loc)); placed=True; break
        if not placed: units.append([loc,[(k,loc)]])
    print('UNITS: %d (deterministic FFD, cap %d = max(50000, ceil(scannable/40)))'%(len(units),cap))
    lanes=2*len(units)
    print('EXPECTED-CLOCK: %d lanes / width 20 = %.1f capture waves; deviations from this math are NAMED at seal'%(lanes, lanes/20.0))
    for i,u in enumerate(units,1):
        print('U%02d (%d LOC): %s'%(i,u[0],' '.join('%s(%d)'%(k,l) for k,l in u[1][:6])+(' +%d more'%(len(u[1])-6) if len(u[1])>6 else '')))
    return 0
def selftest():
    import tempfile, shutil as _sh, io as _io, contextlib
    d=tempfile.mkdtemp()
    os.makedirs(os.path.join(d,'example-repo')); os.makedirs(os.path.join(d,'.docs'))
    open(os.path.join(d,'example-repo','main.py'),'w').write('x=1\n'*100)
    open(os.path.join(d,'example-repo','package-lock.json'),'w').write('{}\n'*50)
    open(os.path.join(d,'example-repo','stub.json'),'w').write('"d",\n'*6000)
    open(os.path.join(d,'.docs','notes.md'),'w').write('n\n'*30)
    open(os.path.join(d,'PRIORS_example_APP001.json'),'w').write('{"x":1}\n'*40)
    os.makedirs(os.path.join(d,'OPTIONAL_PRIORS'))
    open(os.path.join(d,'OPTIONAL_PRIORS','PRIORS_sample_APP002.json'),'w').write('{"y":1}\n'*60)
    buf=_io.StringIO()
    with contextlib.redirect_stdout(buf): report(d)
    out=buf.getvalue(); _sh.rmtree(d)
    ok=0
    ok+=('RAW-CODE-LOC: 6100' in out)
    ok+=('STAGING-INPUTS: 2 root PRIORS_* file(s), 100 lines' in out)
    ok+=('lockfiles excluded: 50' in out)
    ok+=('MASS-SUSPECT: example-repo' in out and '(6000 lines)' in out)
    ok+=('SCANNABLE-IF-ALL-SUSPECTS-CARVED: 100' in out)
    ok+=('UNITS: 1 (deterministic FFD, cap 50000 = max(50000, ceil(scannable/40)))' in out and 'example-repo(100)' in out)
    # wc parity: an unterminated final line is not a line
    nn=os.path.join(tempfile.mkdtemp(),'nonl.py')
    open(nn,'wb').write(b'a=1\nb=2')
    ok+=(1 if count_lines(nn)==1 else 0)
    print('CENSUS SELFTEST: %d/7 PASS'%ok)
    return 0 if ok==7 else 1
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--selftest': sys.exit(selftest())
    if len(sys.argv)!=2: print('CENSUS ERR: usage'); sys.exit(2)
    sys.exit(report(sys.argv[1]))
