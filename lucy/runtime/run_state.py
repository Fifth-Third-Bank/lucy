"""Receipt-backed run identity and phase transitions."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import secrets
import tempfile
from typing import ClassVar

from lucy.runtime.results import LocalResultsSink


PHASES = (
    "preflight",
    "census",
    "partition",
    "certification-setup",
    "discovery",
    "reverification",
    "emit",
)
ENDINGS = ("WORKING", "CERTIFIED", "PROCESS-COMPLETE", "CHECKPOINTED", "BLOCKED")
TERMINAL_ENDINGS = frozenset(ENDINGS) - {"WORKING"}


def utc_minute(value: datetime) -> str:
    if value.tzinfo is None:
        raise ValueError("run start time must include a timezone")
    return value.astimezone(timezone.utc).replace(second=0, microsecond=0).strftime(
        "%Y-%m-%dT%H:%MZ"
    )


def compute_run_id(head_sha: str, started_at: datetime, session_id: str) -> str:
    if not head_sha or not session_id:
        raise ValueError("head SHA and session ID are required")
    material = f"{head_sha} {utc_minute(started_at)} {session_id}".encode()
    return "r-" + hashlib.sha256(material).hexdigest()[:12]


@dataclass
class RunState:
    schema: str
    run_id: str
    target: str
    head_sha: str
    started_at: str
    session_id: str
    platform: str
    model: str
    phase: str = PHASES[0]
    status: str = "WORKING"
    completed_at: str | None = None
    message: str | None = None

    SCHEMA: ClassVar[str] = "lucy-run-state/v1"

    @classmethod
    def create(
        cls,
        target: Path,
        head_sha: str,
        model: str,
        started_at: datetime | None = None,
        session_id: str | None = None,
    ) -> "RunState":
        started_at = started_at or datetime.now(timezone.utc)
        session_id = session_id or secrets.token_hex(8)
        return cls(
            schema=cls.SCHEMA,
            run_id=compute_run_id(head_sha, started_at, session_id),
            target=str(target.resolve()),
            head_sha=head_sha,
            started_at=started_at.astimezone(timezone.utc).isoformat(),
            session_id=session_id,
            platform="claude-code",
            model=model,
        )

    def advance(self, phase: str) -> None:
        self._require_working()
        if phase not in PHASES:
            raise ValueError(f"unknown phase: {phase}")
        current_index = PHASES.index(self.phase)
        requested_index = PHASES.index(phase)
        if requested_index not in {current_index, current_index + 1}:
            raise ValueError(f"cannot advance from {self.phase} to {phase}")
        self.phase = phase

    def finish(self, status: str, message: str, completed_at: datetime | None = None) -> None:
        self._require_working()
        if status not in TERMINAL_ENDINGS:
            raise ValueError(f"invalid terminal status: {status}")
        if status in {"CERTIFIED", "PROCESS-COMPLETE"} and self.phase != "emit":
            raise ValueError(f"{status} requires the emit phase")
        if not message.strip():
            raise ValueError("terminal status requires a message")
        completed_at = completed_at or datetime.now(timezone.utc)
        self.status = status
        self.message = message.strip()
        self.completed_at = completed_at.astimezone(timezone.utc).isoformat()

    def save(self, state_root: Path) -> Path:
        """Compatibility writer for trusted external state roots."""
        run_directory = state_root / "runs" / self.run_id
        run_directory.mkdir(parents=True, exist_ok=True)
        destination = run_directory / "run.json"
        payload = json.dumps(asdict(self), indent=2, sort_keys=True) + "\n"
        descriptor, temporary_name = tempfile.mkstemp(
            dir=run_directory, prefix=".run-", suffix=".json"
        )
        try:
            with os.fdopen(descriptor, "w", encoding="utf-8") as output:
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
        return destination

    def save_to_sink(self, sink: LocalResultsSink) -> Path:
        return sink.write_json(f"runs/{self.run_id}/run.json", asdict(self))

    @classmethod
    def load(cls, path: Path) -> "RunState":
        data = json.loads(path.read_text(encoding="utf-8"))
        if data.get("schema") != cls.SCHEMA:
            raise ValueError("unsupported run-state schema")
        state = cls(**data)
        if state.phase not in PHASES or state.status not in ENDINGS:
            raise ValueError("run state contains an invalid phase or status")
        return state

    def _require_working(self) -> None:
        if self.status != "WORKING":
            raise ValueError(f"run already ended as {self.status}")