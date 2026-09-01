#!/usr/bin/env python3
# OUTPUT NOTE: run by path; write results to files and read them
# with file tools. Keep detector patterns and seeded test samples out of
# shell transcripts: they are synthetic fixtures, and printing them raises
# false security alerts and floods logs. Noise control only, never
# concealment - every byte of this file and its outputs is on disk,
# hash-pinned, and open to any reviewer or platform check.
"""SCAM BATTERY v1.1 — optional adversarial regression for a compatible
coverage instrument. Documents the forged-input boundary:
these attacks are run by an adversary who CONTROLS scan inputs.
The coverage estimate does not claim defense against forged inputs;
input integrity, replay, and evidence validation must be enforced by
the surrounding trust chain.

This battery is not used by the Lucy runtime. The public toolbox does not
ship a coverage instrument; pass a compatible module explicitly with
--instrument.
"""
import argparse
from pathlib import Path
import random
import runpy

random.seed(777)
N = 300
def honest(p=0.35): return {i for i in range(N) if random.random() < p}

def boot(assess):
    scans = [honest(), honest()]
    hist = [assess(scans[:1], None, diversified=True).coverage_lb,
            assess(scans[:2], None, diversified=True).coverage_lb]
    return scans, hist

def run_attack(assess, name, make_scan, trials=150, adaptive=True):
    fires = 0; covs = []
    for _ in range(trials):
        scans, hist = boot(assess)
        for k in range(3, 10):
            scans.append(make_scan(scans))
            v = assess(scans, hist, diversified=True)
            hist.append(v.coverage_lb)
            if v.decision == "STOP-SUCCESS":
                real = set().union(*scans) & set(range(N))
                fires += 1; covs.append(len(real) / N); break
            if adaptive and v.decision in ("REFUSE-CLONE",
                                           "REFUSE-DEGENERATE"):
                scans.pop()
            elif v.decision != "CONTINUE":
                break
    med = sorted(covs)[len(covs)//2] if covs else None
    print(f"{name:36s} certify {fires}/{trials} ({fires/trials:.0%})  "
          f"median TRUE coverage at cert: "
          f"{med if med is None else round(med, 3)}")

def subset_scan(scans):
    u = sorted(set().union(*scans))
    med = sorted(len(s) for s in scans)[len(scans)//2]
    return set(random.sample(u, min(len(u), med)))

PH = set(range(10000, 10080))
def phantom_scan(scans): return honest() | PH

def skim_scan(scans):
    u = sorted(set().union(*scans))
    med = sorted(len(s) for s in scans)[len(scans)//2]
    return set(random.sample(u, max(1, int(med * 0.31))))

def load_assess(path):
    namespace = runpy.run_path(str(path))
    assess = namespace.get("assess")
    if not callable(assess):
        raise ValueError("coverage instrument must define callable assess")
    return assess


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--instrument",
        type=Path,
        required=True,
        help="path to a compatible coverage-instrument Python module",
    )
    args = parser.parse_args()
    try:
        assess = load_assess(args.instrument)
    except (ImportError, OSError, ValueError):
        parser.error(
            "a compatible coverage instrument is required; use --instrument PATH"
        )
    random.seed(777)
    print("=== SCAM BATTERY ===")
    run_attack(assess, "SCAM-1 sustained-subset", subset_scan)
    run_attack(assess, "SCAM-2 phantom-IDs (80 fakes/scan)", phantom_scan,
               adaptive=False)
    run_attack(assess, "SCAM-3 floor-skim subsets (31%)", skim_scan)
    print("SCAM-4 attestation lie: caller-asserted flag — "
          "contractual integrity control required.")


if __name__ == "__main__":
    main()
