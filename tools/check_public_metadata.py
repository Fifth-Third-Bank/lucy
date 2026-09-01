#!/usr/bin/env python3
"""Reject private provenance and machine-specific data in public text files."""

from __future__ import annotations

import argparse
from pathlib import Path
import re
import sys


EXCLUDED_DIRECTORIES = {".git", "__pycache__"}
TEXT_SUFFIXES = {
    "",
    ".cfg",
    ".conf",
    ".cs",
    ".go",
    ".hcl",
    ".ini",
    ".java",
    ".js",
    ".json",
    ".jsx",
    ".md",
    ".properties",
    ".py",
    ".rb",
    ".sh",
    ".tf",
    ".toml",
    ".ts",
    ".tsx",
    ".txt",
    ".xml",
    ".yml",
    ".yaml",
}
PUBLIC_IDENTITY_LABEL = (
    "Fifth" + " Third reference outside an approved public identity file"
)
PRIVATE_DOMAIN_LABEL = "Fifth" + " Third private email or web domain"
FORBIDDEN = (
    ("absolute macOS home path", re.compile(r"/" + r"Users/[^/\s]+/")),
    ("absolute Linux home path", re.compile(r"/" + r"home/[^/\s]+/")),
    (
        "legacy package label",
        re.compile("gen" + r"7(?:_kit(?:_v\d+_\d+)?)?", re.IGNORECASE),
    ),
    (
        "internal repository label",
        re.compile("lucy" + "-oss", re.IGNORECASE),
    ),
    (
        "internal application alias",
        re.compile(r"\bapp\d{1,3}(?:-[a-z0-9][a-z0-9-]*)?\b"),
    ),
    (
        "internal run identifier",
        re.compile(r"\br-[0-9a-f]{12}\b", re.IGNORECASE),
    ),
    (
        "internal narrative marker",
        re.compile(
            r"\b(?:field[ -](?:basis|record)|self[ -]scans?|"
            r"live[ -]shakedown|external[ -](?:scan|review)|"
            r"operator[ -]ruling|wave[ -]?\d+)\b",
            re.IGNORECASE,
        ),
    ),
    (
        PUBLIC_IDENTITY_LABEL,
        re.compile(r"\bFifth(?:\s+|[_-])Third(?:\b|_)", re.IGNORECASE),
    ),
    (
        PRIVATE_DOMAIN_LABEL,
        re.compile(r"(?<![A-Za-z0-9.-])(?:[A-Za-z0-9._%+-]+@)?53\.com\b", re.IGNORECASE),
    ),
)

# These are deliberate public identity, legal, and reporting locations.
PUBLIC_IDENTITY_PATHS = {
    Path("README.md"),
    Path("LICENSE"),
    Path("SECURITY.md"),
    Path("ACCEPTABLE_USE.md"),
    Path(".github/ISSUE_TEMPLATE/config.yml"),
    Path(".jenkins/release-deploy.yaml"),
}

# Census retains one historical scanner-state directory exclusion so old
# target trees keep stable counts. Do not expand this into a toolbox-wide skip.
COMPATIBILITY_EXCEPTIONS = {
    (Path("lucy/toolbox/census.py"), "legacy package label"),
}



def _release_files(root):
    """Files that can actually enter the release: tracked files when git
    metadata exists, an rglob fallback for exported archives. Inspecting
    gitignored scanner state would otherwise make the result depend on a
    developer's local working tree."""
    import subprocess

    if (root / ".git").exists():
        result = subprocess.run(
            ["git", "ls-files", "-z"], cwd=root, capture_output=True, text=True, check=False
        )
        if result.returncode == 0:
            return sorted(
                root / name for name in result.stdout.split("\0") if name.strip()
            )
    return sorted(root.rglob("*"))


def check(root: Path) -> list[str]:
    errors: list[str] = []
    for path in _release_files(root):
        if not path.is_file() or any(part in EXCLUDED_DIRECTORIES for part in path.parts):
            continue
        relative = path.relative_to(root)
        if path.suffix.lower() not in TEXT_SUFFIXES:
            continue
        try:
            content = path.read_text(encoding="utf-8")
        except UnicodeDecodeError:
            continue
        for line_number, line in enumerate(content.splitlines(), start=1):
            for label, pattern in FORBIDDEN:
                if pattern.search(line):
                    if (relative, label) in COMPATIBILITY_EXCEPTIONS:
                        continue
                    if (
                        relative in PUBLIC_IDENTITY_PATHS
                        and label == PUBLIC_IDENTITY_LABEL
                    ):
                        continue
                    errors.append(f"{relative}:{line_number}: {label}")
    return errors


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("root", nargs="?", type=Path, default=Path("."))
    return parser.parse_args()


def main() -> int:
    errors = check(parse_args().root.resolve())
    if errors:
        for error in errors:
            print(f"public metadata check failed: {error}", file=sys.stderr)
        return 1
    print("public metadata check passed")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
