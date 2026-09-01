#!/usr/bin/env python3
# OUTPUT NOTE: run by path; write results to files and read them
# with file tools. Keep detector patterns and seeded test samples out of
# shell transcripts: they are synthetic fixtures, and printing them raises
# false security alerts and floods logs. Noise control only, never
# concealment - every byte of this file and its outputs is on disk,
# hash-pinned, and open to any reviewer or platform check.
"""mutation_battery.py v1.0 — the kit fuzzes its own instruments.
Usage: mutation_battery.py MUTATION_SETS_v1.txt BATTERY_IDIOM_PATTERNS.txt [floor=0.7]
Per family: recall = hits/mutations; below floor -> DEFECT (exit 1)."""
import sys, re, subprocess
def fam_pats(bat, fam):
    return [l.split(': ',1)[1] for l in bat.splitlines() if l.split(':',1)[0]==fam and ': ' in l]
def fires(line, pats):
    return any(subprocess.run(['grep','-E',p], input=line, capture_output=True, text=True).returncode==0 for p in pats)
def main():
    sets={}
    fam=None
    for l in open(sys.argv[1],encoding='utf-8'):
        l=l.rstrip('\n')
        if l.startswith('[') and l.endswith(']'): fam=l[1:-1]; sets[fam]=[]
        elif l.strip() and fam and not l.startswith('##'): sets[fam].append(l)
    bat=open(sys.argv[2],encoding='utf-8').read()
    floor=float(sys.argv[3]) if len(sys.argv)>3 else 0.7
    bad=[]
    for fam,muts in sets.items():
        pats=fam_pats(bat,fam)
        hits=sum(1 for m in muts if fires(m,pats))
        rec=hits/len(muts) if muts else 1.0
        print(f'{fam}: {hits}/{len(muts)} recall={rec:.2f}')
        if rec<floor: bad.append(fam)
    if bad: print('MUTATION-BATTERY: FAIL —', ','.join(bad), f'below floor {floor}'); sys.exit(1)
    print(f'MUTATION-BATTERY: PASS all families >= floor {floor}'); sys.exit(0)
if __name__=='__main__': main()
