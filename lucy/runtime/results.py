"""External results storage with mandatory pre-write redaction."""

from __future__ import annotations

from collections import Counter
from dataclasses import dataclass
import json
import os
from pathlib import Path, PurePosixPath
import re
import tempfile
from typing import Any


REDACTED = "[REDACTED]"
PATTERNS = (
    ("private-key", re.compile(r"-----BEGIN [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----[\s\S]*?-----END [A-Z0-9 ]*PRIVATE KEY(?: BLOCK)?-----")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{5,}\.[A-Za-z0-9_-]{5,}\b")),
    ("provider-key", re.compile(r"(?:\b|_)(?:sk-[A-Za-z0-9_-]{16,}|sk_(?:live|test)_[A-Za-z0-9]{10,}|ghp_[A-Za-z0-9]{20,}|gho_[A-Za-z0-9]{20,}|github_pat_[A-Za-z0-9_]{20,}|xox[baprs]-[A-Za-z0-9-]{10,}|AIza[A-Za-z0-9_-]{30,})\b")),
    ("aws-access-key", re.compile(r"\b(?:AKIA|ASIA)[A-Z0-9]{16}\b")),
    # AWS secret access keys have no marker prefix; catch the assignment form.
    ("aws-secret-key", re.compile(r"(?i)aws[_-]?secret[_-]?(?:access[_-]?)?key\s*[:=]\s*\\?[\"']?[A-Za-z0-9/+=]{30,}")),
    ("bearer-token", re.compile(r"(?i)\bBearer\s+[A-Za-z0-9._~+/=-]{12,}")),
    # JSON-escape-safe: the quoted alternatives must not start at an ESCAPED
    # quote (\") inside a serialized JSON string, and the bare alternative
    # must not swallow backslashes, or redaction can consume half of an
    # escaped quote pair and corrupt a JSONL artifact.
    # The name group tolerates identifier prefixes (DB_PASSWORD, JWT_SECRET):
    # Python \b never fires between '_' and a letter, so a \b-anchored
    # alternation does not match underscore-prefixed environment variables.
    ("credential-assignment-json", re.compile(r'(?i)\b([a-z0-9_-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token))(\s*[:=]\s*)\\"[^"\n\\]{6,}?\\"')),
    ("credential-assignment", re.compile(r"(?i)\b([a-z0-9_-]*(?:password|passwd|secret|api[_-]?key|access[_-]?token))(\s*[:=]\s*)((?<!\\)\"[^\"\n\\]{6,}\"|'[^'\n\\]{6,}'|[^\s,;\]\}\"'\\]{6,})")),
    ("email", re.compile(r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,}\b")),
    ("ssn", re.compile(r"\b\d{3}-\d{2}-\d{4}\b")),
)


def redact_text(content: str) -> tuple[str, dict[str, int]]:
    counts: Counter[str] = Counter()
    redacted = content
    for category, pattern in PATTERNS:
        def replacement(match: re.Match[str]) -> str:
            counts[category] += 1
            if category == "credential-assignment":
                return f"{match.group(1)}{match.group(2)}{REDACTED}"
            if category == "credential-assignment-json":
                return f'{match.group(1)}{match.group(2)}\\"{REDACTED}\\"' 
            if category == "bearer-token":
                return f"Bearer {REDACTED}"
            return REDACTED

        redacted = pattern.sub(replacement, redacted)
    return redacted, dict(sorted(counts.items()))


def redact_json(value: Any) -> tuple[Any, dict[str, int]]:
    serialized = json.dumps(value, sort_keys=True)
    redacted, counts = redact_text(serialized)
    return json.loads(redacted), counts


@dataclass(frozen=True)
class LocalResultsSink:
    root: Path
    target: Path

    @classmethod
    def create(cls, root: Path, target: Path) -> "LocalResultsSink":
        resolved_root = root.expanduser().resolve()
        resolved_target = target.expanduser().resolve()
        if resolved_root == resolved_target or resolved_target in resolved_root.parents:
            raise ValueError("results root must be outside the scanned repository")
        resolved_root.mkdir(parents=True, exist_ok=True, mode=0o700)
        try:
            resolved_root.chmod(0o700)
        except OSError:
            pass
        return cls(resolved_root, resolved_target)

    def write_text(self, relative_path: str, content: str) -> Path:
        redacted, counts = redact_text(content)
        destination = self._destination(relative_path)
        self._atomic_write(destination, redacted.encode("utf-8"))
        self._write_redaction_receipt(relative_path, counts)
        return destination

    def write_json(self, relative_path: str, value: Any) -> Path:
        redacted, counts = redact_json(value)
        destination = self._destination(relative_path)
        payload = (json.dumps(redacted, indent=2, sort_keys=True) + "\n").encode()
        self._atomic_write(destination, payload)
        self._write_redaction_receipt(relative_path, counts)
        return destination

    def _destination(self, relative_path: str) -> Path:
        pure = PurePosixPath(relative_path)
        if pure.is_absolute() or not pure.parts or any(part in {"", ".", ".."} for part in pure.parts):
            raise ValueError("artifact path must be a normalized relative path")
        destination = (self.root / Path(*pure.parts)).resolve()
        if self.root not in destination.parents:
            raise ValueError("artifact path escapes the results root")
        return destination

    def _write_redaction_receipt(self, artifact: str, counts: dict[str, int]) -> None:
        receipt_path = self._destination("receipts/redactions.jsonl")
        receipt_path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        record = {"artifact": artifact, "counts": counts, "total": sum(counts.values())}
        with receipt_path.open("a", encoding="utf-8") as output:
            output.write(json.dumps(record, sort_keys=True) + "\n")

    @staticmethod
    def _atomic_write(destination: Path, payload: bytes) -> None:
        destination.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        descriptor, temporary_name = tempfile.mkstemp(dir=destination.parent, prefix=".lucy-", suffix=".tmp")
        try:
            with os.fdopen(descriptor, "wb") as output:
                output.write(payload)
                output.flush()
                os.fsync(output.fileno())
            os.replace(temporary_name, destination)
        except BaseException:
            try:
                os.unlink(temporary_name)
            except FileNotFoundError:
                pass
            raise
