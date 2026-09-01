#!/usr/bin/env python3
# INVOCATION + OUTPUT-QUIET REQUIREMENT: run BY PATH.
"""seal_card_gate.py v2.7 - deterministic validation for every terminal.

ASSESSMENT requires an explicit OPERATOR-TARGET or UNCONTROLLABLE receipt;
otherwise reachable continuation work is parked in CONTINUATION_STATE with
RESUME.txt. An all-pattern CANARY-MIX is valid only when no priors were staged.
Every terminal records census, conservation, opened canaries, closure basis,
whole visitation where required, and terminal precedence before card assembly.
Canary misses require per-miss CANARY-CURE or MINT-ERROR receipts. The full
hardened and closure checks run for supplied artifacts, and tokens print only
after the corresponding card passes.
Usage: seal_card_gate.py <SEAL_CARD.md> | --selftest.
Exit 0 PASS, 1 REFUSED, 2 ERR."""
import hashlib, sys, re
REQ=['RUN-ID','KIT','ROWS-TOTAL','VERIFIED-TOTAL','REFUTED-TOTAL','TIER-C','TIER-H','TIER-WP','TIER-M','TIER-L','TIER-INFO','CH-COURTED','PC-1','PC-2','BOUND-MIN','UNITS','CANARY','DURATION','DENIALS','MODE','DISPOSITION','VISITATION','SEAL-CLASS','FIRST-COURT-LAG','EXPECTED-CLOCK','CENSUS-FORM','STRICT-CHAPMAN','CANARY-MIX','FALSIFIERS','M-AUDIT','DEPTH-RATIO','REACH-DISCIPLINE','WIDTH-DISCIPLINE','PULSE-LEDGER','PRIORS','FRONTIER-CLOSE','SATURATION','ENGINE','AXIS-CENSUS','AXIS-CLOSURE','TERMINAL-PRECEDENCE','SEAL-ENTRY','CLOSURE-BASIS']
def num(t,k):
    m=re.search(r'^'+k+r':\s*(\d+)',t,re.M)
    return int(m.group(1)) if m else None
def hardened_checks(t):
    errs=[]
    # strict-floor tripwire: every unit's strict Chapman parsed; <0.50 needs a CURE-LAP line for that unit
    su=re.findall(r'U(\d+)\s+([0-9.]+)', re.search(r'^STRICT-CHAPMAN:(.*)$',t,re.M).group(1)) if re.search(r'^STRICT-CHAPMAN:',t,re.M) else []
    if not su: errs.append('STRICT-CHAPMAN must list per-unit values (U01 0.xx ...)')
    for u,v in su:
        if float(v)<0.50 and not re.search(r'^CURE-LAP:\s*U0?'+u+r'\b',t,re.M):
            errs.append('unit U%s strict %s < 0.50 without a CURE-LAP line — lap it before sealing'%(u,v))
    m=re.search(r'^CANARY-MIX:\s*(\d+)P\+(\d+)H\b',t,re.M)
    if not m: errs.append('CANARY-MIX must read nP+nH (pattern + historical-verified)')
    elif int(m.group(1))+int(m.group(2))!=8: errs.append('CANARY-MIX must total 8')
    elif int(m.group(2))<4 and not re.search(r'^PRIORS:\s*none staged',t,re.M):
        errs.append('CANARY-MIX must carry >=4 historical when priors were staged (deterministic hash-ordered draw); the all-pattern form is lawful ONLY with "PRIORS: none staged"')
    if not re.search(r'^FALSIFIERS:\s*(run\s+\d+/\d+|hermetic-off\s*\()',t,re.M):
        errs.append('FALSIFIERS must read "run n/m" or "hermetic-off (<named cause>)"')
    if not re.search(r'^M-AUDIT:\s*(\d+)/\1\s+re-derived\s+seed=[0-9a-f]{8}',t,re.M):
        errs.append('M-AUDIT must read "n/n re-derived seed=<sha8>" with equal counts (seed = sha256(RUN-ID)[:8]); FAILED or mismatched counts refuse the card')
    if not re.search(r'^DEPTH-RATIO:\s*[0-9.]+',t,re.M):
        errs.append('DEPTH-RATIO missing (bytes-read / scannable bytes; diagnostic)')
    ax=re.search(r'^AXIS-CENSUS:\s*(\d+)\s+declared\b.*exhausted',t,re.M)
    if not ax: errs.append('AXIS-CENSUS missing ("N declared ... exhausted" - the axis list is a courted finite census)')
    es_basis=bool(re.search(r'^CLOSURE-BASIS:\s*EXHAUSTIVE-SATURATED\b',t,re.M))
    ac=re.search(r'^AXIS-CLOSURE:\s*(\d+)/(\d+)',t,re.M)
    if not ac: errs.append('AXIS-CLOSURE missing (axes with per-stratum bound >=0.95 / axes declared)')
    elif ac.group(1)!=ac.group(2) and not es_basis: errs.append('AXIS-CLOSURE %s/%s - every declared stratum closes at >=0.95 within-axis, or the run keeps mining that stratum (or earns the EXHAUSTIVE-SATURATED basis)'%ac.groups())
    if ax and ac and ax.group(1)!=ac.group(2): errs.append('AXIS-CENSUS %s declared but AXIS-CLOSURE denominator %s - the census and the closure table must agree'%(ax.group(1),ac.group(2)))
    en=re.search(r'^ENGINE:\s*ONE-QUEUE\b',t,re.M)
    if not en: errs.append('ENGINE missing (must read ENGINE: ONE-QUEUE ... - the run operates as one work-queue at full width, all phases streaming)')
    st=re.search(r'^SATURATION:\s*avg\s+([0-9.]+)/(\d+)\s+idle-while-ready\s+(\d+)m',t,re.M)
    if not st: errs.append('SATURATION missing (avg W/cap idle-while-ready Nm)')
    elif int(st.group(3))>5: errs.append('SATURATION idle-while-ready %sm - freed slots must pull the next ready item; idle above 5m while work was queued is a width defect'%st.group(3))
    fc=re.search(r'^FRONTIER-CLOSE:\s*\S+',t,re.M)
    if not fc: errs.append('FRONTIER-CLOSE missing (elapsed when the risk frontier - battery-hit, auth/crypto/high-impact transactions/secrets/IaC, entry points - was dual-read complete)')
    pr=re.search(r'^PRIORS:\s*(none staged|(\d+)\s+loaded\s+(\d+)\s+refound-or-adjudicated)',t,re.M)
    if not pr: errs.append('PRIORS missing ("none staged" or "N loaded N refound-or-adjudicated")')
    elif pr.group(2) is not None and pr.group(2)!=pr.group(3): errs.append('PRIORS %s loaded but only %s refound-or-adjudicated - a verified finding never silently vanishes from a later certificate'%(pr.group(2),pr.group(3)))
    pl=re.search(r'^PULSE-LEDGER:\s*max-gap\s+(\d+)m\s+deaths\s+(\d+)\s+redispatched\s+(\d+)(?:\s+adopted\s+(\d+))?(?:\s+unreconciled\s+(\d+))?',t,re.M)
    if not pl: errs.append('PULSE-LEDGER missing (max-gap Nm deaths N redispatched N [adopted N] [unreconciled N])')
    # Pulse law is per-lane coverage: when the launcher prints the computed
    # unreconciled count, ZERO is the law (one death may legally collect two
    # closures, so count equality over-refuses). Cards without the field
    # keep the count-equality compatibility rule.
    elif pl.group(5) is not None:
        if int(pl.group(5))!=0: errs.append('PULSE-LEDGER %s lane deaths have no closure - every silent death is re-dispatched or receipted adopted-empty'%pl.group(5))
    elif int(pl.group(2))!=int(pl.group(3))+int(pl.group(4) or 0): errs.append('PULSE-LEDGER deaths %s != redispatched %s + adopted %s - every silent death is re-dispatched or receipted adopted-empty'%(pl.group(2),pl.group(3),pl.group(4) or 0))
    wd=re.search(r'^WIDTH-DISCIPLINE:\s*(\d+)/(\d+)',t,re.M)
    if not wd: errs.append('WIDTH-DISCIPLINE missing (phases at-width-or-receipted / shardable phases)')
    elif wd.group(1)!=wd.group(2): errs.append('WIDTH-DISCIPLINE %s/%s - a shardable phase ran narrow without an UNSHARDABLE receipt; only card assembly, token computation, and the seal push may be single-threaded'%wd.groups())
    rd=re.search(r'^REACH-DISCIPLINE:\s*(\d+)/(\d+)',t,re.M)
    if not rd: errs.append('REACH-DISCIPLINE missing (rows citing R0/R1 with full receipts / rows citing R0/R1)')
    elif rd.group(1)!=rd.group(2): errs.append('REACH-DISCIPLINE %s/%s — every R0/R1-cell row carries 4 receipts or prices at the next-lower reach; fix rows, not the card'%rd.groups())
    p1=num(t,'PC-1')
    if p1 and p1>0:
        rr=len(re.findall(r'^REACH-RECEIPT:\s*\S+',t,re.M))
        if rr<p1*4: errs.append('PC-1=%d claimed but only %d REACH-RECEIPT lines (need 4 per claim: edge-binding, route-binding, authorizer-binding, exposure bytes)'%(p1,rr))
    return errs
def seal_entry_check(t,cert):
    """Validate the printed pre-assembly gate on every terminal."""
    errs=[]
    m=re.search(r'^SEAL-ENTRY:\s*ran\s+\d{2}:\d{2}Z\b(.*)$',t,re.M)
    if not m:
        errs.append('SEAL-ENTRY must read "ran <hh:mmZ> census <raw/scannable/files> conservation <n>==<n> visitation <d>/<d> canaries <k> OPENED" — printed BEFORE any card assembly')
        return errs
    rest=m.group(1)
    if 'census' not in rest: errs.append('SEAL-ENTRY missing the census numbers; every card must include them')
    cm=re.search(r'conservation\s+(\d+)==(\d+)',rest)
    if not cm: errs.append('SEAL-ENTRY missing conservation n==n (candidate ledger: hits == emitted+folded+courted+refuted)')
    elif cm.group(1)!=cm.group(2): errs.append('SEAL-ENTRY conservation %s==%s — the candidate ledger does not conserve; reconcile before any terminal'%cm.groups())
    if cert and not re.search(r'canaries\s+8\s+OPENED',rest):
        errs.append('SEAL-ENTRY: all 8 canary files must be NAMED OPENED before a seal — a canary gap is a dispatch order')
    return errs
def wholeness_checks(t):
    """Validate the certified mandate as arithmetic, not prose."""
    errs=[]
    vm=re.search(r'^VISITATION:\s*(\d+)\s*/\s*(\d+)',t,re.M)
    if not vm: errs.append('VISITATION must read opened/census as integers')
    elif int(vm.group(1))!=int(vm.group(2)):
        errs.append('VISITATION %s/%s — the first rule: every scannable file is opened by a lane; a visitation gap is DISPATCH WORK, never a terminal — open the files and close the ledger'%vm.groups())
    cm=re.search(r'^CANARY:\s*(\d+)/8\b',t,re.M)
    if cm and int(cm.group(1))<8:
        n=int(cm.group(1)); cures=len(re.findall(r'^(?:CANARY-CURE|MINT-ERROR):\s*\S+',t,re.M))
        if cures<8-n:
            errs.append('CANARY %d/8 with %d cure/mint receipts — a canary miss is a DISPATCH ORDER: re-lane the miss region and rescore to a hit, or receipt the mint error; misses never ride into a terminal'%(n,cures))
    tp=re.search(r'^TERMINAL-PRECEDENCE:\s*ran\s+\d{2}:\d{2}Z\s+pre-assembly\s+verdict\s+(CERTIFY|BLOCK|ASSESS|CONTINUE)\b',t,re.M)
    if not tp: errs.append('TERMINAL-PRECEDENCE must read "ran <hh:mmZ> pre-assembly verdict CERTIFY|BLOCK|ASSESS" — the precedence check runs BEFORE card assembly')
    elif tp.group(1)=='CONTINUE': errs.append('TERMINAL-PRECEDENCE verdict CONTINUE — a card existing after a CONTINUE verdict is a contradiction; return the run to the queue')
    errs+=seal_entry_check(t,cert=True)
    return errs
def blocked_receipt(t):
    """v1.1: BLOCKED terminals must carry a MACHINE-CHECKABLE receipt."""
    m=re.search(r'^BLOCK-RECEIPT:\s*(SESSION-CEILING|DISPATCH-DENIED|LAP-YIELD-COLLAPSE)\b',t,re.M)
    if not m: return ['BLOCKED terminal without a BLOCK-RECEIPT class (SESSION-CEILING|DISPATCH-DENIED|LAP-YIELD-COLLAPSE)']
    cls=m.group(1); errs=seal_entry_check(t,cert=False)
    if cls=='LAP-YIELD-COLLAPSE':
        vm=re.search(r'^VISITATION:\s*(\d+)\s*/\s*(\d+)',t,re.M)
        if vm and int(vm.group(1))!=int(vm.group(2)):
            errs.append('LAP-YIELD-COLLAPSE over an open visitation ledger (%s/%s) — dead yield is UNPROVABLE while census files remain unopened; open the files, then measure the vein'%vm.groups())
        cm=re.search(r'^CANARY:\s*(\d+)/8\b',t,re.M)
        if cm and int(cm.group(1))<8 and len(re.findall(r'^(?:CANARY-CURE|MINT-ERROR):\s*\S+',t,re.M))<8-int(cm.group(1)):
            errs.append('canary misses are DISPATCH ORDERS, not block grounds — cure the miss regions or receipt the mint errors before any dead-yield claim')
        rows=re.findall(r'^LAP-HISTORY:\s*\d+\s+bound\s+([0-9.]+)\s+novelCH\s+(\d+)',t,re.M)
        if len(rows)<3: errs.append('LAP-YIELD-COLLAPSE needs >=3 LAP-HISTORY rows as "n bound x.xx novelCH m"; got %d'%len(rows))
        else:
            laps=[float(b) for b,_ in rows]; nov=[int(n) for _,n in rows]
            d1=laps[-2]-laps[-3]; d2=laps[-1]-laps[-2]
            if not (d1<0.02 and d2<0.02): errs.append('lap deltas %.3f/%.3f not both <0.02 - keep lapping'%(d1,d2))
            if nov[-1]>2 or nov[-2]>2: errs.append('rich vein - keep mining: novel court-confirmed C/H %d/%d on the last two laps (a scan is never blocked for succeeding; continue across sessions via CONTINUATION_STATE)'%(nov[-2],nov[-1]))
            if laps[-1]>=0.95: errs.append('final bound %.2f >= 0.95 - certify, not block'%laps[-1])
    elif cls=='SESSION-CEILING':
        errs.append('SESSION-CEILING reached: capacity is not an ending - commit CONTINUATION_STATE and continue or hand off; rate signals are weather (halve width, back off, resume)')
    elif cls=='DISPATCH-DENIED':
        if not re.search(r'^DENIAL-QUOTE:\s*\S+',t,re.M): errs.append('DISPATCH-DENIED needs the DENIAL-QUOTE ledger line')
    return errs
def crosscheck(t, findings_csv, chmap_csv):
    import csv
    errs=[]
    try:
        rows=list(csv.DictReader(open(findings_csv,encoding='utf-8')))
        total=num(t,'ROWS-TOTAL')
        if total!=len(rows): errs.append('ROWS-TOTAL %s != findings csv rows %d'%(total,len(rows)))
        tf=next((k for k in ('tier','TIER','severity','SEVERITY') if rows and k in rows[0]),None)
        if tf:
            hist={}
            for r in rows: hist[r[tf].strip().upper()[:4]]=hist.get(r[tf].strip().upper()[:4],0)+1
            pairs=(('TIER-C','CRIT'),('TIER-H','HIGH'),('TIER-M','MED'),('TIER-L','LOW'),('TIER-INFO','INFO'))
            for fld,key in pairs:
                want=num(t,fld); got=sum(v for k,v in hist.items() if k.startswith(key[:3]))
                if fld=='TIER-M': got=hist.get('MEDI',0)+hist.get('MED',0)
                if want is not None and want!=got and fld!='TIER-WP':
                    errs.append('%s %d != csv %d'%(fld,want,got))
    except Exception as e: errs.append('findings csv unreadable: %s'%e)
    try:
        crit=[r for r in rows if r.get(tf,'').strip().upper().startswith('CRIT')] if tf else []
        RC=('reach_domain','reach_stage','reach_method','reach_authorizer')
        for r in crit:
            missing=[c for c in RC if not r.get(c,'').strip()]
            if missing:
                errs.append('REACH-CHAIN: C row %s missing %s'%(r.get('key',r.get('KEY','?'))[:60],','.join(missing)))
    except Exception as e: errs.append('reach-chain check error: %s'%e)
    try:
        ch=sum(1 for _ in open(chmap_csv,encoding='utf-8'))-1
        want=num(t,'CH-COURTED')
        if want!=ch: errs.append('CH-COURTED %s != CH map rows %d'%(want,ch))
    except Exception as e: errs.append('CH map unreadable: %s'%e)
    return errs
def check(p, findings_csv=None, chmap_csv=None):
    try: t=open(p,encoding='utf-8').read()
    except Exception as e: print('GATE ERR: %s'%e); return 2
    missing=[k for k in REQ if not re.search(r'^'+k+r':',t,re.M)]
    if missing: print('SEAL-CARD: REFUSED - missing fields: '+', '.join(missing)); return 1
    total=num(t,'ROWS-TOTAL'); tiers=[num(t,k) for k in ('TIER-C','TIER-H','TIER-WP','TIER-M','TIER-L','TIER-INFO')]
    if None in tiers or total is None: print('SEAL-CARD: REFUSED - non-numeric tier/total field'); return 1
    vt=num(t,'VERIFIED-TOTAL'); rf=num(t,'REFUTED-TOTAL')
    if vt is None or rf is None or vt>total:
        print('SEAL-CARD: REFUSED - VERIFIED-TOTAL/REFUTED-TOTAL missing or VERIFIED exceeds ROWS-TOTAL'); return 1
    if sum(tiers)!=total:
        print('SEAL-CARD: REFUSED - tiers sum %d != ROWS-TOTAL %d (fix the counts, not the words)'%(sum(tiers),total)); return 1
    cf=re.search(r'^CENSUS-FORM:\s*(SCRIPT|SCRATCHPAD-COPY|FLAT-PIPELINE)\b',t,re.M)
    if not cf:
        print('SEAL-CARD: REFUSED - CENSUS-FORM must read SCRIPT, SCRATCHPAD-COPY, or FLAT-PIPELINE (any other census voids the card)'); return 1
    sc=re.search(r'^SEAL-CLASS:\s*(CERTIFIED|BLOCKED-UNCERTIFIED|ASSESSMENT)\b',t,re.M)
    if not sc:
        print('SEAL-CARD: REFUSED - SEAL-CLASS must read CERTIFIED or BLOCKED-UNCERTIFIED (assessments do not seal)'); return 1
    if sc and sc.group(1)=='BLOCKED-UNCERTIFIED':
        be=blocked_receipt(t)
        if be:
            for e2 in be: print('BLOCKED-RECEIPT REFUSED: '+e2)
            return 1
        print('BLOCK-TOKEN: '+hashlib.sha256((t+'|BLOCKED-VALID').encode()).hexdigest()[:16])
        print('SEAL-CARD: PASS (BLOCKED terminal with machine-valid receipt)'); return 0
    if sc and sc.group(1)=='ASSESSMENT':
        errs=seal_entry_check(t,cert=False)
        tpm=re.search(r'^TERMINAL-PRECEDENCE:.*verdict\s+(\w+)',t,re.M)
        if tpm and tpm.group(1)=='CONTINUE': errs.append('TERMINAL-PRECEDENCE verdict CONTINUE — a card after a CONTINUE verdict is a contradiction; return the run to the queue')
        if not (re.search(r'^OPERATOR-TARGET:\s*ASSESSMENT',t,re.M) or re.search(r'^UNCONTROLLABLE:\s*\S+',t,re.M)):
            errs.append('ASSESSMENT without receipts — PARK, do not terminal: reachable work means CONTINUATION_STATE + RESUME.txt; ASSESSMENT is lawful only with OPERATOR-TARGET: ASSESSMENT (quoted operator edit) or an UNCONTROLLABLE receipt')
        if errs:
            for e2 in errs: print('ASSESSMENT-FORM REFUSED: '+e2)
            return 1
        print('ASSESS-TOKEN: '+hashlib.sha256((t+'|ASSESSMENT-VALID').encode()).hexdigest()[:16])
        print('SEAL-CARD: PASS (ASSESSMENT terminal — NOT-A-SEAL, never a certificate; form validated + class token minted; THE CERTIFIED MANDATE stands: this label is an honest limit, not a product)'); return 0
    mc=re.search(r'^CANARY:\s*(\d+)/8\b',t,re.M)
    if not mc: print('SEAL-CARD: REFUSED - CANARY must read n/8 (the requirement set selects exactly 8)'); return 1
    if 'result impact: ZERO' not in t: print('SEAL-CARD: REFUSED - DENIALS line must end: result impact: ZERO (or the seal cannot claim it)'); return 1
    wh=wholeness_checks(t)
    if wh:
        for e2 in wh: print('WHOLENESS REFUSED: '+e2)
        return 1
    he=hardened_checks(t)
    if he:
        for e2 in he: print('HARDENED-CHECK REFUSED: '+e2)
        return 1
    cm0=re.search(r'^SEAL-CLASS:\s*(\S+)',t,re.M)
    if cm0 and cm0.group(1).upper().startswith('CERTIFIED'):
        bm=re.search(r'^BOUND-MIN:\s*([0-9.]+)',t,re.M)
        su2=re.findall(r'U\d+\s+([0-9.]+)', (re.search(r'^STRICT-CHAPMAN:(.*)$',t,re.M).group(1) if re.search(r'^STRICT-CHAPMAN:',t,re.M) else ''))
        rows2=re.findall(r'^LAP-HISTORY:\s*\d+\s+bound\s+[0-9.]+\s+novelCH\s+(\d+)',t,re.M)
        basis_m=re.search(r'^CLOSURE-BASIS:\s*(STANDARD-095|EXHAUSTIVE-SATURATED)\b',t,re.M)
        if not basis_m:
            print('CLOSURE-BASIS REFUSED: must read STANDARD-095 or EXHAUSTIVE-SATURATED — the certification door is named, never implied')
            return 1
        dead=len(rows2)>=2 and int(rows2[-1])<=2 and int(rows2[-2])<=2
        pop_ok=False
        axm=re.search(r'^AXIS-CLOSURE:\s*(\d+)/(\d+)',t,re.M)
        axc=re.search(r'^AXIS-CENSUS:\s*(\d+)\s+declared\b.*exhausted',t,re.M)
        if axm and axc and axm.group(1)==axm.group(2) and axc.group(1)==axm.group(2) and dead: pop_ok=True
        if su2 and min(float(x) for x in su2)>=0.95: pop_ok=True
        if not pop_ok and basis_m.group(1)=='EXHAUSTIVE-SATURATED':
            esr=re.search(r'^ES-RECEIPTS:\s*6/6\b',t,re.M)
            rec=re.search(r'^RECAPTURE:\s*\S+',t,re.M)
            if esr and rec and dead: pop_ok=True
            else:
                print('CLOSURE-STANDARD REFUSED: the EXHAUSTIVE-SATURATED door opens only on ES-RECEIPTS: 6/6 + at least one RECAPTURE receipt + dead novelty on the last two laps — a mined-out claim is proven, never asserted')
                return 1
        if not pop_ok:
            print('CLOSURE-STANDARD REFUSED: STANDARD-095 requires strict per-unit >=0.95 or whole per-axis closure with dead novelty; below the bar, dead novelty ALONE is never a door — run recapture laps (they lift the bound or reveal live heterogeneity), or earn the EXHAUSTIVE-SATURATED basis with its six receipts. Keep mining or end BLOCKED with receipts.')
            return 1

    if findings_csv and chmap_csv:
        errs=crosscheck(t,findings_csv,chmap_csv)
        if errs:
            print('SEAL-CARD: REFUSED - DERIVATION MISMATCH: '+' | '.join(errs)); return 1
        print('SEAL-TOKEN: '+hashlib.sha256((t+'|CERTIFIED-PASS').encode()).hexdigest()[:16])
        print('SEAL-CARD: PASS (arithmetic reconciled; wholeness+hardened+closure checked; DERIVED-CHECKED against the artifacts)'); return 0
    print('SEAL-TOKEN: '+hashlib.sha256((t+'|CERTIFIED-PASS').encode()).hexdigest()[:16])
    print('SEAL-CARD: PASS (arithmetic reconciled; wholeness+hardened+closure checked; form-only - artifacts not supplied)'); return 0
EXPECTED_SELFTESTS=50

def selftest():
    import tempfile, os as _os, io as _io, contextlib
    import csv as _csv
    good='\n'.join(['RUN-ID: r-example','KIT: 1.0.0','ROWS-TOTAL: 10','VERIFIED-TOTAL: 6','REFUTED-TOTAL: 2','TIER-C: 1','TIER-H: 2','TIER-WP: 1','TIER-M: 2','TIER-L: 3','TIER-INFO: 1','CH-COURTED: 3','PC-1: 0','PC-2: 3','BOUND-MIN: 0.95','UNITS: 5','CANARY: 8/8','DURATION: 1h','DENIALS: 2; result impact: ZERO','VISITATION: 12/12','SEAL-CLASS: CERTIFIED','FIRST-COURT-LAG: 3','CENSUS-FORM: SCRIPT','EXPECTED-CLOCK: 4 lanes / 1.0 waves; actual within band','MODE: CODE','STRICT-CHAPMAN: U01 0.95 U02 0.91 U03 0.90 U04 0.91 U05 0.95','LAP-HISTORY: 1 bound 0.88 novelCH 5','LAP-HISTORY: 2 bound 0.90 novelCH 1','LAP-HISTORY: 3 bound 0.91 novelCH 0','CANARY-MIX: 4P+4H','FALSIFIERS: run 12/12','M-AUDIT: 5/5 re-derived seed=ab12cd34','DEPTH-RATIO: 0.83','REACH-DISCIPLINE: 3/3','WIDTH-DISCIPLINE: 6/6','PULSE-LEDGER: max-gap 9m deaths 1 redispatched 1','PRIORS: 6 loaded 6 refound-or-adjudicated','FRONTIER-CLOSE: 0h10m (frontier 12 files dual-read; receipts in stitch/)','SATURATION: avg 3.5/4 idle-while-ready 0m','ENGINE: ONE-QUEUE (ladder 2; watchdogs paired; single-thread set 3)','AXIS-CENSUS: 5 declared (deep, auditor, dataflow, exploit, infra) - courted exhausted','AXIS-CLOSURE: 5/5','DISPOSITION: all DISCHARGED','TERMINAL-PRECEDENCE: ran 14:05Z pre-assembly verdict CERTIFY','SEAL-ENTRY: ran 14:04Z census 1000/800/12 conservation 12==12 visitation 12/12 canaries 8 OPENED','CLOSURE-BASIS: STANDARD-095'])+'\n'
    bad1=good.replace('TIER-M: 2','TIER-M: 4')
    bad2=good.replace('CANARY: 8/8','CANARY: 9/10')
    ok=0
    d2=tempfile.mkdtemp()
    fcsv=_os.path.join(d2,'F.csv'); ccsv=_os.path.join(d2,'CH.csv')
    with open(fcsv,'w') as fh:
        fh.write('key,tier,reach_domain,reach_stage,reach_method,reach_authorizer\n'+'a,CRITICAL,d.tf:1,s.tf:2,m.tf:3,auth.tf:4\n'+'b,HIGH,,,,\nc,HIGH,,,,\n'+'d,MEDIUM,,,,\ne,MEDIUM,,,,\n'+'f,LOW,,,,\ng,LOW,,,,\nh,LOW,,,,\n'+'i,INFO,,,,\n'+'j,WP,,,,\n')
    with open(ccsv,'w') as fh: fh.write('row,court\n1,x\n2,x\n3,x\n')
    f4=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f4.write(good); f4.close()
    buf4=_io.StringIO()
    with contextlib.redirect_stdout(buf4): rc4=check(f4.name,fcsv,ccsv)
    ok+=(rc4==0 and 'DERIVED-CHECKED' in buf4.getvalue())
    ok+=(1 if 'SEAL-TOKEN: ' in buf4.getvalue() else 0)
    bad3T=good.replace('SEAL-CLASS: CERTIFIED','SEAL-CLASS: ASSESSMENT')
    fb3=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); fb3.write(bad3T); fb3.close()
    bufT=_io.StringIO()
    with contextlib.redirect_stdout(bufT): check(fb3.name,fcsv,ccsv)
    ok+=(1 if 'SEAL-TOKEN' not in bufT.getvalue() else 0)
    with open(fcsv,'a') as fh: fh.write('k,HIGH,,,,\n')
    buf5=_io.StringIO()
    with contextlib.redirect_stdout(buf5): rc5=check(f4.name,fcsv,ccsv)
    ok+=(rc5==1 and 'DERIVATION MISMATCH' in buf5.getvalue())
    with open(fcsv,'w') as fh:
        fh.write('key,tier,reach_domain,reach_stage,reach_method,reach_authorizer\n'+'a,CRITICAL,d.tf:1,s.tf:2,m.tf:3,\n'+'b,HIGH,,,,\nc,HIGH,,,,\nd,MEDIUM,,,,\ne,MEDIUM,,,,\nf,LOW,,,,\ng,LOW,,,,\nh,LOW,,,,\ni,INFO,,,,\nj,WP,,,,\n')
    buf6=_io.StringIO()
    with contextlib.redirect_stdout(buf6): rc6=check(f4.name,fcsv,ccsv)
    ok+=(rc6==1 and 'REACH-CHAIN' in buf6.getvalue() and 'reach_authorizer' in buf6.getvalue())
    _os.unlink(f4.name)
    bad3=good.replace('SEAL-CLASS: CERTIFIED','SEAL-CLASS: ASSESSMENT')
    # Pulse coverage law: double-closure with unreconciled 0 passes; any
    # unclosed death fails; count equality remains enforced without the field.
    pulse_ok=good.replace('PULSE-LEDGER: max-gap 9m deaths 1 redispatched 1',
                          'PULSE-LEDGER: max-gap 9m deaths 5 redispatched 5 adopted 4 unreconciled 0')
    pulse_bad=good.replace('PULSE-LEDGER: max-gap 9m deaths 1 redispatched 1',
                           'PULSE-LEDGER: max-gap 9m deaths 5 redispatched 5 adopted 4 unreconciled 1')
    pulse_legacy_bad=good.replace('PULSE-LEDGER: max-gap 9m deaths 1 redispatched 1',
                                  'PULSE-LEDGER: max-gap 9m deaths 2 redispatched 1')
    for txt,exp in ((good,0),(bad1,1),(bad2,1),(bad3,1),(pulse_ok,0),(pulse_bad,1),(pulse_legacy_bad,1)):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp); _os.unlink(f.name)
    blk=good.replace('SEAL-CLASS: CERTIFIED','SEAL-CLASS: BLOCKED-UNCERTIFIED')
    blk_lap=blk+'BLOCK-RECEIPT: LAP-YIELD-COLLAPSE\nLAP-HISTORY: 1 bound 0.55 novelCH 1\nLAP-HISTORY: 2 bound 0.56 novelCH 2\nLAP-HISTORY: 3 bound 0.57 novelCH 0\n'
    blk_bad=blk+'BLOCK-RECEIPT: LAP-YIELD-COLLAPSE\nLAP-HISTORY: 1 bound 0.40 novelCH 0\nLAP-HISTORY: 2 bound 0.60 novelCH 0\nLAP-HISTORY: 3 bound 0.80 novelCH 0\n'
    for txt,exp,needle in ((blk,1,'without a BLOCK-RECEIPT'),(blk_lap,0,'BLOCK-TOKEN'),(blk_bad,1,'keep lapping'),(blk+'BLOCK-RECEIPT: DISPATCH-DENIED\nDENIAL-QUOTE: agent-spawn denied at 07:12Z\n',0,'BLOCK-TOKEN')):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    hb1=good.replace('U03 0.90','U03 0.40')
    hb2=good.replace('CANARY-MIX: 4P+4H','CANARY-MIX: 8P+0H')
    hb3=good.replace('PC-1: 0','PC-1: 1')
    hb4=hb1+'CURE-LAP: U03 dispatched, bound re-measured 0.62\n'
    for txt,exp,needle in ((hb1,1,'CURE-LAP'),(hb2,1,'historical'),(hb3,1,'REACH-RECEIPT'),(hb4,0,'SEAL-TOKEN')):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    rb1=good.replace('REACH-DISCIPLINE: 3/3','REACH-DISCIPLINE: 2/3')
    rb2=good.replace('REACH-DISCIPLINE: 3/3\n','')
    for txt,exp,needle in ((rb1,1,'next-lower reach'),(rb2,1,'REACH-DISCIPLINE')):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt if txt.endswith('\n') else txt+'\n'); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    blk_rich=blk+'BLOCK-RECEIPT: LAP-YIELD-COLLAPSE\nLAP-HISTORY: 1 bound 0.60 novelCH 40\nLAP-HISTORY: 2 bound 0.60 novelCH 35\nLAP-HISTORY: 3 bound 0.61 novelCH 30\n'
    for txt,exp,needle in ((blk_rich,1,'rich vein'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    blk_ceil=blk+'BLOCK-RECEIPT: SESSION-CEILING\nCEILING-USED: 95/100\n'
    for txt,exp,needle in ((blk_ceil,1,'SESSION-CEILING reached'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    wb1=good.replace('WIDTH-DISCIPLINE: 6/6','WIDTH-DISCIPLINE: 5/6')
    for txt,exp,needle in ((wb1,1,'UNSHARDABLE'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    pb1=good.replace('deaths 1 redispatched 1','deaths 2 redispatched 1')
    pb2=good.replace('deaths 1 redispatched 1','deaths 2 redispatched 1 adopted 1')
    for txt,exp,needle in ((pb1,1,'re-dispatched or receipted adopted-empty'),(pb2,0,'SEAL-TOKEN')):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    qb1=good.replace('6 loaded 6 refound','6 loaded 5 refound')
    for txt,exp,needle in ((qb1,1,'never silently vanishes'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    fb1='\n'.join(l for l in good.splitlines() if not l.startswith('FRONTIER-CLOSE'))+'\n'
    for txt,exp,needle in ((fb1,1,'FRONTIER-CLOSE'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    sb1=good.replace('idle-while-ready 0m','idle-while-ready 44m')
    for txt,exp,needle in ((sb1,1,'SATURATION'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    cb1=good.replace('U03 0.90','U03 0.55')
    cb2=good.replace('LAP-HISTORY: 3 bound 0.91 novelCH 0','LAP-HISTORY: 3 bound 0.91 novelCH 40')
    for txt,exp,needle in ((cb1,0,'SEAL-TOKEN'),(cb2,1,'CLOSURE-STANDARD')):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    eb1='\n'.join(l for l in good.splitlines() if not l.startswith('ENGINE'))+'\n'
    for txt,exp,needle in ((eb1,1,'ENGINE'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    xb1=good.replace('AXIS-CLOSURE: 5/5','AXIS-CLOSURE: 4/5')
    for txt,exp,needle in ((xb1,1,'AXIS-CLOSURE'),):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    vg1=good.replace('VISITATION: 12/12','VISITATION: 10/12')
    cn1=good.replace('CANARY: 8/8','CANARY: 6/8')
    cn2=cn1+'CANARY-CURE: C3 miss region re-laned U04, rescored HIT\nMINT-ERROR: C7 descriptor stale at mint, re-minted set sha ab12cd34\n'
    tp2=good.replace('verdict CERTIFY','verdict CONTINUE')
    tp1='\n'.join(l for l in good.splitlines() if not l.startswith('TERMINAL-PRECEDENCE'))+'\n'
    blk_gap=(blk+'BLOCK-RECEIPT: LAP-YIELD-COLLAPSE\nLAP-HISTORY: 1 bound 0.55 novelCH 1\nLAP-HISTORY: 2 bound 0.56 novelCH 2\nLAP-HISTORY: 3 bound 0.57 novelCH 0\n').replace('VISITATION: 12/12','VISITATION: 10/12')
    for txt,exp,needle in ((vg1,1,'DISPATCH WORK'),(cn1,1,'DISPATCH ORDER'),(cn2,0,'SEAL-TOKEN'),(tp1,1,'TERMINAL-PRECEDENCE'),(tp2,1,'contradiction'),(blk_gap,1,'UNPROVABLE')):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    xa1=good.replace('AXIS-CLOSURE: 5/5','AXIS-CLOSURE: 4/5')
    fcsv2=_os.path.join(d2,'F2.csv'); ccsv2=_os.path.join(d2,'CH2.csv')
    with open(fcsv2,'w') as fh:
        fh.write('key,tier,reach_domain,reach_stage,reach_method,reach_authorizer\n'+'a,CRITICAL,d.tf:1,s.tf:2,m.tf:3,auth.tf:4\n'+'b,HIGH,,,,\nc,HIGH,,,,\n'+'d,MEDIUM,,,,\ne,MEDIUM,,,,\n'+'f,LOW,,,,\ng,LOW,,,,\nh,LOW,,,,\n'+'i,INFO,,,,\n'+'j,WP,,,,\n')
    with open(ccsv2,'w') as fh: fh.write('row,court\n1,x\n2,x\n3,x\n')
    f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(xa1); f.close()
    buf=_io.StringIO()
    with contextlib.redirect_stdout(buf): rc=check(f.name,fcsv2,ccsv2)
    ok+=(rc==1 and 'AXIS-CLOSURE' in buf.getvalue() and 'SEAL-TOKEN' not in buf.getvalue()); _os.unlink(f.name)
    se1=good.replace('conservation 12==12','conservation 12==11')
    se2=good.replace(' canaries 8 OPENED','')
    es1=(good.replace('U03 0.90','U03 0.70').replace('AXIS-CLOSURE: 5/5','AXIS-CLOSURE: 4/5')
             .replace('CLOSURE-BASIS: STANDARD-095','CLOSURE-BASIS: EXHAUSTIVE-SATURATED')
         +'ES-RECEIPTS: 6/6 (visitation-closure · per-axis-recompute · recapture · conservation · frontier+entrypoints · courts+falsifiers)\nRECAPTURE: U03 two blind recapture laps, bound 0.68->0.70 flat, novelCH 0\n')
    es2='\n'.join(l for l in es1.splitlines() if not l.startswith('ES-RECEIPTS'))+'\n'
    as1='\n'.join(l for l in bad3.splitlines() if not l.startswith('ENGINE'))+'\n'
    np1=good.replace('CANARY-MIX: 4P+4H','CANARY-MIX: 8P+0H').replace('PRIORS: 6 loaded 6 refound-or-adjudicated','PRIORS: none staged')
    np2=good.replace('CANARY-MIX: 4P+4H','CANARY-MIX: 8P+0H')
    for txt,exp,needle in ((se1,1,'does not conserve'),(se2,1,'NAMED OPENED'),(es1,0,'SEAL-TOKEN'),(es2,1,'ES-RECEIPTS'),(as1,1,'ENGINE'),(bad3,1,'PARK'),(bad3+'OPERATOR-TARGET: ASSESSMENT ("TARGET: ASSESSMENT" edited at paste)\n',0,'ASSESS-TOKEN'),(np1,0,'SEAL-TOKEN'),(np2,1,'all-pattern form')):
        f=tempfile.NamedTemporaryFile('w',suffix='.md',delete=False); f.write(txt); f.close()
        buf=_io.StringIO()
        with contextlib.redirect_stdout(buf): rc=check(f.name)
        ok+=(rc==exp and needle in buf.getvalue()); _os.unlink(f.name)
    print('SEAL CARD GATE SELFTEST: %d/%d PASS'%(ok,EXPECTED_SELFTESTS))
    return 0 if ok==EXPECTED_SELFTESTS else 1
if __name__=='__main__':
    if len(sys.argv)>1 and sys.argv[1]=='--selftest': sys.exit(selftest())
    if len(sys.argv)==4: sys.exit(check(sys.argv[1],sys.argv[2],sys.argv[3]))
    if len(sys.argv)!=2: print('GATE ERR: usage: card [findings.csv chmap.csv]'); sys.exit(2)
    sys.exit(check(sys.argv[1]))
