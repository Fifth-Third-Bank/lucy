#!/usr/bin/env python3
"""Run the selftests and smoke tests for every packaged gate.

This script depends only on files shipped in the public toolbox. It exits 0
only when every current gate accepts a valid input and rejects invalid input.
"""

from pathlib import Path
import subprocess
import sys
import tempfile


TOOLBOX = Path(__file__).resolve().parent
SELFTEST_GATES = (
    "certification_gate.py",
    "scan_report_gate.py",
    "seal_card_gate.py",
    "visitation_check.py",
)


def run(script: str, *args: Path | str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        [sys.executable, str(TOOLBOX / script), *(str(arg) for arg in args)],
        capture_output=True,
        text=True,
        check=False,
    )


def main() -> int:
    cases: list[tuple[str, bool, str]] = []
    for script in SELFTEST_GATES:
        result = run(script, "--selftest")
        cases.append((f"{script} selftest", result.returncode == 0,
                      result.stdout + result.stderr))

    with tempfile.TemporaryDirectory() as directory:
        root = Path(directory)

        conserved = root / "conserved.jsonl"
        conserved.write_text(
            '{"disposition":"folded"}\n{"disposition":"refuted"}\n',
            encoding="utf-8",
        )
        empty = root / "empty.jsonl"
        empty.write_text("", encoding="utf-8")
        malformed = root / "malformed.jsonl"
        malformed.write_text("{not-json\n", encoding="utf-8")
        for name, path, expected in (
            ("conservation accepts complete dispositions", conserved, 0),
            ("conservation rejects empty input", empty, 1),
            ("conservation rejects malformed input", malformed, 1),
        ):
            result = run("conservation_gate.py", path)
            cases.append((name, result.returncode == expected,
                          result.stdout + result.stderr))

        required = root / "required.txt"
        required.write_text("RESULT-TOKEN:\n", encoding="utf-8")
        complete = root / "complete.md"
        complete.write_text("RESULT-TOKEN: complete\n", encoding="utf-8")
        missing = root / "missing.md"
        missing.write_text("OTHER-TOKEN: complete\n", encoding="utf-8")
        promissory = root / "promissory.md"
        promissory.write_text("RESULT-TOKEN: pending\n", encoding="utf-8")
        for name, path, expected in (
            ("token gate accepts a completed value", complete, 0),
            ("token gate rejects a missing token", missing, 1),
            ("token gate rejects a promissory value", promissory, 1),
        ):
            result = run("token_gate.py", required, path)
            cases.append((name, result.returncode == expected,
                          result.stdout + result.stderr))

    failures = [(name, detail) for name, passed, detail in cases if not passed]
    passed = len(cases) - len(failures)
    status = "PASS" if not failures else "FAIL"
    print(f"GATES SELFTEST: {passed}/{len(cases)} {status}")
    for name, detail in failures:
        summary = " | ".join(line for line in detail.splitlines() if line)[:300]
        print(f"  FAIL {name}: {summary}")
    return 0 if not failures else 1


if __name__ == "__main__":
    raise SystemExit(main())
