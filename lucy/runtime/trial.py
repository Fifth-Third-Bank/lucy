#!/usr/bin/env python3
"""Prepare and inspect a safe LUCY trial workspace."""

from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import json
import os
import re
from pathlib import Path
import secrets
import shutil
import signal
import subprocess
import sys
import tempfile
from typing import Any

from lucy.runtime.results import LocalResultsSink
from lucy.runtime.run_state import compute_run_id
from lucy.runtime.planter import launch_claude_planter, validate_answer_key


_PATTERN_IGNORE = shutil.ignore_patterns(
    ".git",
    ".claude",
    ".codex",
    ".mcp.json",
    "__pycache__",
    "*.pyc",
    ".venv",
    ".lucy",
    "OUTBOX",
    "AGENTS.md",
    "CLAUDE.md",
    "CLAUDE.local.md",
)


_CASEFOLD_IGNORE = {
    ".git",
    ".claude",
    ".codex",
    ".mcp.json",
    ".venv",
    ".lucy",
    "outbox",
    "agents.md",
    "claude.md",
    "claude.local.md",
}


def COPY_IGNORE(src, names):  # noqa: N802 - keeps the copytree call sites stable
    """Pattern ignores plus symlink stripping: a link in the untrusted repo
    must never be copied into the workspace, where readers and the detector
    battery would follow it to files outside the scanned code. Names are
    ALSO matched casefolded: on a case-insensitive filesystem (macOS APFS
    default) a hostile '.Claude/settings.local.json' resolves as '.claude'
    for the planter session while sailing past a case-sensitive fnmatch."""
    import os

    ignored = set(_PATTERN_IGNORE(src, names))
    for name in names:
        if os.path.islink(os.path.join(src, name)):
            ignored.add(name)
        if name.casefold() in _CASEFOLD_IGNORE:
            ignored.add(name)
    return ignored

FIXTURE_DISCLOSURE_PATHS = ("tools", "tests", "docs", "Makefile", "README.md")


def custody_home() -> Path:
    """Answer-key custody root - OUTSIDE the results tree. The reviewer is
    granted paths under the results root, so the key must never be a sibling.
    Override with
    LUCY_CUSTODY_HOME; 0700 always."""
    root = Path(
        os.environ.get("LUCY_CUSTODY_HOME") or Path.home() / ".lucy" / "custody"
    ).expanduser().resolve()
    root.mkdir(parents=True, exist_ok=True)
    root.chmod(0o700)
    return root


def _recorded_custody_home(results_root: Path, run_id: str) -> Path:
    """Find a custom custody root without trusting a bare public locator.

    A locator in public ``trial.json`` is accepted only when the destination
    is private, owned by this user, outside results, and contains a private
    launcher-held trial record matching this run's immutable paths/hashes.
    """
    resolved_results = results_root.expanduser().resolve()
    current = Path(
        os.environ.get("LUCY_CUSTODY_HOME") or Path.home() / ".lucy" / "custody"
    ).expanduser().resolve()
    if (current / "runs" / run_id / "trial.json").is_file():
        return current
    public_path = resolved_results / "runs" / run_id / "trial.json"
    if not public_path.is_file():
        return current
    try:
        public = json.loads(public_path.read_text(encoding="utf-8"))
        candidate = Path(str(public.get("custody_home", ""))).expanduser().resolve()
        held_path = candidate / "runs" / run_id / "trial.json"
        if not candidate.is_dir() or not held_path.is_file():
            return current
        if candidate == resolved_results or candidate in resolved_results.parents or resolved_results in candidate.parents:
            return current
        candidate_stat = candidate.stat()
        held_stat = held_path.stat()
        if candidate_stat.st_uid != os.getuid() or held_stat.st_uid != os.getuid():
            return current
        if candidate_stat.st_mode & 0o077 or held_stat.st_mode & 0o077:
            return current
        held = json.loads(held_path.read_text(encoding="utf-8"))
        for field in ("run_id", "workspace", "results_root", "baseline_sha256"):
            if str(held.get(field, "")) != str(public.get(field, "")):
                return current
        expected_workspace = resolved_results / "workspaces" / run_id
        if Path(str(held["workspace"])).resolve() != expected_workspace.resolve():
            return current
        if Path(str(held["results_root"])).resolve() != resolved_results:
            return current
        return candidate
    except (KeyError, OSError, ValueError, json.JSONDecodeError):
        return current


def content_hash(root: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(item for item in root.rglob("*") if item.is_file()):
        relative = path.relative_to(root)
        if any(part in {".git", "__pycache__", ".venv", ".lucy", "OUTBOX"} for part in relative.parts):
            continue
        digest.update(relative.as_posix().encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def run(command: list[str], *, cwd: Path) -> subprocess.CompletedProcess[str]:
    result = subprocess.run(command, cwd=cwd, capture_output=True, text=True, check=False)
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
        raise RuntimeError(f"command failed: {' '.join(command)}: {detail}")
    return result


def require_host_tools(
    review_host: str,
    planter: str,
    *,
    claude_binary: str = "claude",
    codex_binary: str = "codex",
) -> None:
    """Fail before copying/planting when a selected CLI is unavailable.

    Only selected tools are checked: a Codex-only operator never needs
    Claude installed, and a Claude-only operator never needs Codex.
    """
    required: dict[str, str] = {}
    if review_host == "claude" or planter == "claude":
        required["Claude Code"] = claude_binary
    codex_selected = review_host == "codex" or planter == "codex"
    if codex_selected:
        required["Codex CLI"] = codex_binary
    for label, binary in required.items():
        candidate = Path(binary).expanduser()
        exists = (
            candidate.is_file() and os.access(candidate, os.X_OK)
            if candidate.is_absolute() or len(candidate.parts) > 1
            else shutil.which(binary) is not None
        )
        if not exists:
            raise ValueError(
                f"{label} executable not found: {binary!r}; install it or pass "
                f"{'--claude-bin' if label == 'Claude Code' else '--codex-bin'}"
            )
    if codex_selected and sys.platform.startswith("linux") and shutil.which("bwrap") is None:
        raise ValueError(
            "Codex CLI on Linux requires bubblewrap (bwrap) for its command "
            "sandbox; install it with your operating system's package manager"
        )


def _reader_unit_paths(workspace: Path) -> set[str]:
    from lucy.runtime.units import compute_units

    plan = compute_units(workspace)
    return {
        path
        for unit in plan.get("units", [])
        for path in unit.get("files", [])
    }


def _validate_canary_coverage(
    answer_key: dict,
    workspace: Path,
    *,
    baseline_paths: set[str] | None = None,
) -> None:
    """Reject planted truth outside baseline or post-plant reader units."""
    covered = _reader_unit_paths(workspace)
    if baseline_paths is not None:
        covered &= baseline_paths
    planted = [
        str(row.get("path", ""))
        for row in answer_key.get("canaries", [])
        if not row.get("historical")
    ]
    missing = [path for path in planted if path not in covered]
    if missing:
        raise ValueError(
            f"planter selected {len(missing)} canary path(s) outside the "
            "reader-unit census; refusing an impossible recall trial"
        )


PLANT_ATTEMPTS = 3


def _replay_or_raise(answer_key: dict) -> None:
    """Oracle replay: prove the key is passable through the PRODUCTION
    fold + scoring pipeline before any reader lane spends a dollar."""
    from lucy.runtime.preflight import oracle_replay

    replay = oracle_replay(answer_key)
    if not replay["passed"]:
        raise ValueError(
            "oracle replay: a perfect reader scores only "
            f"{replay['matched']}/{replay['total']} at jitter "
            f"{replay['jitter']} (slots {replay['missed_slots']} unmatchable "
            "through fold + 1:1 scoring) — the key must be replanted, not read"
        )


def _plant_with_retries(
    planter: str,
    workspace: Path,
    *,
    claude_binary: str,
    codex_binary: str,
    codex_model: str,
    codex_reasoning_effort: str,
    codex_metrics_path: Path | None,
    planter_budget_usd: float | None,
    baseline_paths: set[str],
) -> dict:
    """Plant, validate, and oracle-replay — replanting on rejection.

    A rejected key is retried rather than ending the run. The workspace
    is reset to baseline between attempts so a failed plant never leaks
    into the next key, and the rejection reason is handed to the fresh
    planter so it does not repeat the mistake."""
    last_error: Exception | None = None
    for attempt in range(1, PLANT_ATTEMPTS + 1):
        if attempt > 1:
            run(["git", "checkout", "-q", "--", "."], cwd=workspace)
            run(["git", "clean", "-qfd"], cwd=workspace)
        try:
            if planter == "openai":
                from lucy.runtime.host import OpenAIHost
                from lucy.runtime.planter import launch_host_planter

                answer_key = launch_host_planter(
                    workspace,
                    Path(__file__).parents[1],
                    OpenAIHost(max_budget_usd=planter_budget_usd),
                )
            elif planter == "codex":
                from lucy.runtime.host import CodexAgentHost
                from lucy.runtime.planter import launch_host_planter

                answer_key = launch_host_planter(
                    workspace,
                    Path(__file__).parents[1],
                    CodexAgentHost(
                        codex_binary=codex_binary,
                        model=codex_model,
                        reasoning_effort=codex_reasoning_effort,
                        metrics_path=codex_metrics_path,
                    ),
                    retry_hint=str(last_error)[:400] if last_error else "",
                )
            else:
                answer_key = launch_claude_planter(
                    workspace,
                    Path(__file__).parents[1],
                    claude_binary=claude_binary,
                    max_budget_usd=planter_budget_usd,
                    retry_hint=str(last_error)[:400] if last_error else "",
                )
            _validate_canary_coverage(
                answer_key, workspace, baseline_paths=baseline_paths
            )
            _replay_or_raise(answer_key)
            return answer_key
        except (ValueError, RuntimeError) as error:
            last_error = error
            if attempt == PLANT_ATTEMPTS:
                raise
            print(
                f"{_lucy_prefix()} planting attempt {attempt} rejected "
                f"({str(error)[:200]}) — resetting workspace and replanting "
                f"(attempt {attempt + 1}/{PLANT_ATTEMPTS})",
                file=sys.stderr,
            )
    raise RuntimeError("unreachable")


def prepare_trial(
    target: Path,
    results_root: Path,
    *,
    custody_root: Path,
    planter: str = "claude",
    claude_binary: str = "claude",
    codex_binary: str = "codex",
    codex_model: str = "gpt-5.6-sol",
    codex_reasoning_effort: str = "high",
    review_host: str = "claude",
    planter_budget_usd: float | None = None,
    priors_path: Path | None = None,
    cold_priors: bool = False,
) -> dict[str, str]:
    target = target.expanduser().resolve()
    if not target.is_dir():
        raise ValueError("target repository does not exist")
    priors = None
    if priors_path is not None:
        from lucy.runtime.priors import load_priors

        priors_path = priors_path.expanduser().resolve()
        if target in priors_path.parents or priors_path.parent == target:
            raise ValueError(
                "priors must live OUTSIDE the scanned repository (they map its history)"
            )
        priors = load_priors(priors_path)
    if planter not in {"claude", "codex", "fixture", "openai"}:
        raise ValueError("planter must be claude, codex, openai, or fixture")
    if review_host not in {"claude", "codex", "openai"}:
        raise ValueError("review host must be claude, codex, or openai")
    if planter == "fixture" and not (target / "tools" / "plant_canaries.py").is_file():
        raise ValueError("fixture target does not provide tools/plant_canaries.py")
    sink = LocalResultsSink.create(results_root, target)
    started_at = datetime.now(timezone.utc)
    baseline_hash = content_hash(target)
    run_id = compute_run_id(baseline_hash, started_at, secrets.token_hex(8))
    workspace = sink.root / "workspaces" / run_id
    if workspace.exists():
        raise ValueError(f"trial workspace already exists: {workspace}")
    # symlinks=True copies links as links (never following them — a link out
    # of the estate must not pull external content into the workspace);
    # ignore_dangling_symlinks tolerates broken links in the source tree.
    shutil.copytree(
        target, workspace, ignore=COPY_IGNORE, symlinks=True, ignore_dangling_symlinks=True
    )
    if planter == "fixture":
        for relative in FIXTURE_DISCLOSURE_PATHS:
            path = workspace / relative
            if path.is_dir():
                shutil.rmtree(path)
            elif path.exists():
                path.unlink()

    run(["git", "init", "-q"], cwd=workspace)
    # CRLF estates: by default git treats the CR itself as trailing
    # whitespace on every added line. cr-at-eol teaches the
    # check about CRLF; literal trailing spaces are still caught.
    run(["git", "config", "core.whitespace", "cr-at-eol"], cwd=workspace)
    run(["git", "add", "--all"], cwd=workspace)
    run(
        [
            "git",
            "-c",
            "user.name=LUCY Trial",
            "-c",
            "user.email=lucy@example.invalid",
            "commit",
            "-q",
            "-m",
            "Trial baseline",
        ],
        cwd=workspace,
    )
    # Freeze the reader universe before the planter can mutate bytes.  An
    # edit cannot make an originally excluded file eligible (for example by
    # adding a shebang), and a plant that removes its own eligibility is also
    # rejected by the post-plant half of this intersection.
    baseline_reader_paths = _reader_unit_paths(workspace)

    custody = custody_root.expanduser().resolve()
    if custody.exists() and any(custody.iterdir()):
        raise ValueError("custody root must be empty")
    custody.mkdir(parents=True, exist_ok=True)
    custody.chmod(0o700)
    try:
        # Plantability census BEFORE the planter spends a dollar. ADVISORY:
        # it warns loudly but never refuses — the census predicts planter
        # behavior while the placement law (class-blind, two distinct files
        # per family) stays the only enforcing rule, so a bucketing gap can
        # never refuse an otherwise valid estate.
        from lucy.runtime.planter import plant_feasibility

        feasibility = plant_feasibility(baseline_reader_paths)
        if not feasibility["feasible"]:
            counts = feasibility["eligible_files"]
            print(
                f"{_lucy_prefix()} WARNING: plant feasibility census — "
                + ", ".join(
                    f"{family} has only {counts[family]} eligible file(s)"
                    for family in feasibility["infeasible_families"]
                )
                + "; the placement law needs two different files per family, "
                "so planting may be rejected at key validation (advisory "
                "census: families may legitimately plant outside their "
                "usual file classes)",
                file=sys.stderr,
            )
        elif feasibility["tight_families"]:
            print(
                f"{_lucy_prefix()} WARNING: plant feasibility is tight for "
                + ", ".join(feasibility["tight_families"])
                + " (2-3 eligible files) — the planter has little placement "
                "choice; recall statistics for those families lean on few files",
                file=sys.stderr,
            )
        if planter in ("claude", "codex", "openai"):
            answer_key = _plant_with_retries(
                planter,
                workspace,
                claude_binary=claude_binary,
                codex_binary=codex_binary,
                codex_model=codex_model,
                codex_reasoning_effort=codex_reasoning_effort,
                codex_metrics_path=(
                    sink.root / "runs" / run_id / "receipts" / "CODEX_USAGE.jsonl"
                    if planter == "codex"
                    else None
                ),
                planter_budget_usd=planter_budget_usd,
                baseline_paths=baseline_reader_paths,
            )
        else:
            temporary_parent = Path(tempfile.mkdtemp(prefix="lucy-plants-", dir=sink.root))
            planted = temporary_parent / "planted"
            try:
                run(
                    [
                        sys.executable,
                        str(target / "tools" / "plant_canaries.py"),
                        "--source",
                        str(target),
                        "--output",
                        str(planted),
                    ],
                    cwd=target,
                )
                for relative in ("apps", "shared", "infra", "deploy"):
                    source_path = planted / relative
                    destination = workspace / relative
                    if destination.exists():
                        shutil.rmtree(destination)
                    shutil.copytree(source_path, destination)
                raw_answer = json.loads(
                    (planted / "ANSWER_KEY.json").read_text(encoding="utf-8")
                )
                answer_key = {
                    "schema": "lucy-answer-key/v1",
                    "canaries": [
                        {
                            "slot": row["slot"],
                            "family": row["family"],
                            "path": row["path"],
                            "line": row["line"],
                            "title": row["title"],
                            "reachability": row.get(
                                "reachability",
                                "fixture oracle: exercised by the fixture app's request path",
                            ),
                            "mutation_sha256": hashlib.sha256(
                                (workspace / row["path"])
                                .read_text(encoding="utf-8")
                                .splitlines()[row["line"] - 1]
                                .encode()
                            ).hexdigest(),
                        }
                        for row in raw_answer["canaries"]
                    ],
                }
                answer_key = validate_answer_key(answer_key, workspace)
            finally:
                shutil.rmtree(temporary_parent, ignore_errors=True)
        _validate_canary_coverage(
            answer_key, workspace, baseline_paths=baseline_reader_paths
        )
        # Re-asserted for every planter path (the retry loop already ran it
        # for agent planters; this also covers the fixture planter).
        _replay_or_raise(answer_key)
        _battery_prescreen(answer_key, workspace, custody)
        historical_count = 0
        skipped_priors: list[str] = []
        if priors is not None:
            from lucy.runtime.priors import draw_historical_canaries

            historical, skipped_priors = draw_historical_canaries(
                priors, workspace, covered_paths=baseline_reader_paths
            )
            historical_count = len(historical)
            answer_key = dict(answer_key)
            answer_key["canaries"] = list(answer_key["canaries"]) + historical
            priors_copy = custody / "PRIORS.json"
            priors_copy.write_text(
                json.dumps(priors, indent=2, sort_keys=True) + "\n", encoding="utf-8"
            )
            priors_copy.chmod(0o600)
        answer_payload = (json.dumps(answer_key, indent=2, sort_keys=True) + "\n").encode()
        answer_path = custody / "ANSWER_KEY.json"
        answer_path.write_bytes(answer_payload)
        answer_path.chmod(0o600)
        custody_record = {
            "schema": "lucy-canary-custody/v1",
            "run_id": run_id,
            "answer_key": str(answer_path),
            "answer_key_sha256": hashlib.sha256(answer_payload).hexdigest(),
        }
        custody_path = custody / "custody.json"
        custody_path.write_text(
            json.dumps(custody_record, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        custody_path.chmod(0o600)
        family_counts: dict[str, int] = {}
        for plant in answer_key["canaries"]:
            if plant.get("historical"):
                continue
            family_counts[plant["family"]] = family_counts.get(plant["family"], 0) + 1
        commitment = {
            "schema": "lucy-mint-commitment/v1",
            "plant_count": len(answer_key["canaries"]) - historical_count,
            "family_counts": family_counts,
            "answer_key_sha256": custody_record["answer_key_sha256"],
            "historical_canaries": historical_count,
        }
        if skipped_priors:
            commitment["historical_skipped_unresolvable"] = skipped_priors
        sink.write_json(f"runs/{run_id}/receipts/MINT_COMMITMENT.json", commitment)
        if priors is not None and not cold_priors:
            # Priors heat (recall-first default): non-canary priors are
            # injected into reader briefs MECHANICALLY via per-unit heat
            # files. Guardrails: exclusion radius withholds canaries and
            # their neighbors (receipted); sweeps stay cold; dispositions
            # are tagged briefed/blind.
            from lucy.runtime.priors import heat_exclusions

            historical_rows = [
                row for row in answer_key["canaries"] if row.get("historical")
            ]
            heated, withheld = heat_exclusions(priors, historical_rows, workspace)
            sink.write_json(
                f"runs/{run_id}/receipts/PRIORS_HEATED.json",
                {
                    "schema": "lucy-priors-heat/v1",
                    "heated": heated,
                    "withheld": withheld,
                    "sweeps": "cold by design",
                },
            )
        (workspace / "PLANT_NOTICE.txt").write_text(
            "8 temporary recall-test edits exist in this disposable working copy; "
            "loci are committed under an external key hash; never merge or deploy.\n",
            encoding="utf-8",
        )
    except BaseException:
        shutil.rmtree(custody, ignore_errors=True)
        # A workspace without a completed trial record is unusable — remove
        # it so an interrupted planter never strands a half-copied estate.
        shutil.rmtree(workspace, ignore_errors=True)
        raise

    status = run(["git", "status", "--short"], cwd=workspace).stdout.splitlines()
    changed = [line for line in status if "PLANT_NOTICE.txt" not in line]
    if not changed:
        raise RuntimeError("planter made no source/config changes")
    planted_rows = [
        row for row in answer_key.get("canaries", []) if not row.get("historical")
    ]
    if len(planted_rows) != 8:
        raise RuntimeError("planter did not produce eight planted answer-key rows")
    for relative in ("apps", "shared", "infra", "deploy"):
        for path in (workspace / relative).rglob("*"):
            if path.is_file():
                try:
                    if "LUCY_CANARY:" in path.read_text(encoding="utf-8"):
                        raise RuntimeError(f"planted source exposes canary marker: {path}")
                except UnicodeDecodeError:
                    pass

    # DESTROY THE GIT ORACLE: the pre-plant baseline commit plus uncommitted
    # plants would let `git diff` reveal the complete answer key.
    # Re-init: the planted state becomes the only commit, so status/diff are
    # clean and history carries no pre-plant snapshot.
    shutil.rmtree(workspace / ".git", ignore_errors=True)
    run(["git", "init", "-q"], cwd=workspace)
    # CRLF estates: by default git treats the CR itself as trailing
    # whitespace on every added line. cr-at-eol teaches the
    # check about CRLF; literal trailing spaces are still caught.
    run(["git", "config", "core.whitespace", "cr-at-eol"], cwd=workspace)
    run(["git", "add", "--all"], cwd=workspace)
    run(
        [
            "git",
            "-c",
            "user.name=lucy",
            "-c",
            "user.email=lucy@localhost.invalid",
            "commit",
            "-q",
            "-m",
            "Workspace baseline",
        ],
        cwd=workspace,
    )

    from lucy.runtime.loop_policy import lane_cap

    trial = {
        "schema": "lucy-trial/v1",
        "run_id": run_id,
        "target": str(target),
        "workspace": str(workspace),
        "results_root": str(sink.root),
        "run_directory": str(sink.root / "runs" / run_id),
        "mint_commitment": str(sink.root / "runs" / run_id / "receipts" / "MINT_COMMITMENT.json"),
        "baseline_sha256": baseline_hash,
        "started_at": started_at.isoformat(),
        "host": review_host,
        "model": codex_model if review_host == "codex" else "",
        "reasoning_effort": (
            codex_reasoning_effort if review_host == "codex" else ""
        ),
        "max_lanes": lane_cap(),
        "custody_home": str(custody_root.parent.resolve()),
        "_custody": str(custody_path),
    }
    sink.write_json(
        f"runs/{run_id}/trial.json",
        {key: value for key, value in trial.items() if not key.startswith("_")},
    )
    # Custody-held duplicate: resume/recapture must never trust workspace/
    # target/baseline paths from the reviewer-writable run directory.
    (custody_path.parent / "trial.json").write_text(
        json.dumps(
            {key: value for key, value in trial.items() if not key.startswith("_")},
            sort_keys=True,
        ),
        encoding="utf-8",
    )
    (custody_path.parent / "trial.json").chmod(0o600)
    return trial


def prepare_fixture_trial(
    target: Path, results_root: Path, *, custody_root: Path
) -> dict[str, str]:
    """Test-only deterministic oracle for repository integration tests."""
    return prepare_trial(
        target, results_root, planter="fixture", custody_root=custody_root
    )


_FAMILY_KEYWORDS = {
    "L1-auth": ("auth", "authz", "access", "session", "token", "role", "tenant", "ownership", "idor", "permission"),
    "L2-secrets": ("secret", "credential", "key", "crypto", "password", "tls", "certificate", "signature", "hash"),
    "L3-injection": ("injection", "sql", "command", "path", "traversal", "ssrf", "deserial", "template", "xss", "parser"),
    "L4-infra": ("infra", "config", "iam", "ingress", "container", "privilege", "pipeline", "supply", "exposure", "network"),
}


def _family_compatible(family: str, finding: dict[str, object]) -> bool:
    """A plant counts as found when the reporting reader's lens matches the
    plant's family, or the finding's category text clearly belongs to it.
    Cross-lens credit is deliberate: the source method's plants were routinely
    found by neighboring lenses — but an unrelated defect class in the same
    file never scores the plant."""
    if str(finding.get("lens", "")) == family:
        return True
    category = (str(finding.get("category", "")) + " " + str(finding.get("title", ""))).lower()
    return any(keyword in category for keyword in _FAMILY_KEYWORDS.get(family, ()))


_SCANNABLE_SUFFIXES = {
    ".py", ".java", ".kt", ".ts", ".tsx", ".js", ".jsx", ".go", ".rb", ".cs",
    ".clj", ".cljs", ".scala", ".php", ".sh", ".sql", ".tf", ".yaml", ".yml",
    ".json", ".xml", ".properties", ".toml", ".cfg", ".ini", ".gradle", ".c",
    ".cc", ".cpp", ".h", ".rs", ".swift", ".jsp", ".html", ".vue", ".env",
}


def _workspace_line_count(workspace: Path) -> int:
    """Fresh launcher-side scannable-line count (saturation denominator)."""
    total = 0
    for path in workspace.rglob("*"):
        if not path.is_file() or path.is_symlink():
            continue
        if any(part in {".git", "__pycache__", ".venv", "node_modules"} for part in path.parts):
            continue
        if path.suffix.lower() not in _SCANNABLE_SUFFIXES:
            continue
        try:
            with path.open("r", encoding="utf-8", errors="ignore") as handle:
                total += sum(1 for _ in handle)
        except OSError:
            continue
    return total




def match_canaries(
    answer_key: dict[str, Any], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Pure canary matcher (no filesystem writes, no custody movement).

    Match rule: same file AND lens-family compatible AND within a 40-line
    window of the plant. Used by score_recall (authoritative, receipt-
    writing) and by the recapture cure loop's SILENT launcher-side check —
    silent scoring never touches the run directory and never surfaces
    mid-run (the no-mid-run-recall-display invariant holds)."""
    results = []
    # ONE-TO-ONE assignment: a single candidate must never satisfy multiple
    # slots; otherwise a blanket row could double-count. Slots are processed
    # in slot order (deterministic
    # rescoring); each slot greedily takes its nearest unclaimed candidate.
    claimed: set[str] = set()
    for canary in sorted(answer_key.get("canaries", []), key=lambda row: row.get("slot", 0)):
        matches = sorted(
            (
                finding
                for finding in findings
                if finding.get("path") == canary.get("path")
                and str(finding.get("id", id(finding))) not in claimed
                and _family_compatible(str(canary.get("family", "")), finding)
                and isinstance(finding.get("line"), int)
                and abs(finding["line"] - int(canary.get("line", 0))) <= 40
            ),
            key=lambda finding: abs(finding["line"] - int(canary.get("line", 0))),
        )
        best = matches[0] if matches else None
        if best is not None:
            claimed.add(str(best.get("id", id(best))))
        results.append(
            {
                "slot": canary["slot"],
                "family": canary["family"],
                "found": best is not None,
                "match_basis": "file+family+line<=40 (1:1)" if best is not None else "none",
                "line_distance": (
                    abs(best["line"] - int(canary.get("line", 0))) if best is not None else None
                ),
                "matched_candidate_id": str(best.get("id")) if best is not None and best.get("id") else None,
                "historical": bool(canary.get("historical")),
            }
        )
    return results


FOLD_RADIUS = 10  # must mirror artifacts.fold_candidate's locus radius


def diagnose_recall_shadow(
    answer_key: dict[str, Any], findings: list[dict[str, Any]]
) -> list[dict[str, Any]]:
    """Structural diagnosis of missed slots (launcher-side, custody-derived;
    output carries slot numbers and mechanisms only — never loci).

    fold-shadow: a sibling same-family plant sits in the same file within
    the locus-fold radius, so every accurate report of this plant folds
    into the sibling's candidate and 1:1 scoring can never mint a second
    match. Blind cure laps cannot repair this structure.

    claim-shadow: compatible candidates exist inside the match window but
    every one is already claimed by another slot — curable only if a NEW
    distinct candidate appears.

    cold-miss: nothing compatible nearby; the plant genuinely went unseen —
    the case blind cure laps exist for."""
    slots = match_canaries(answer_key, findings)
    canaries = {
        row["slot"]: row
        for row in answer_key.get("canaries", [])
        if not row.get("historical")
    }
    claimed = {
        slot["matched_candidate_id"]
        for slot in slots
        if slot.get("matched_candidate_id")
    }
    diagnosis = []
    for slot in slots:
        if slot["historical"] or slot["found"]:
            continue
        canary = canaries.get(slot["slot"])
        if canary is None:
            continue
        mechanism = "cold-miss"
        shadowed_by = None
        for other in canaries.values():
            if (
                other["slot"] != canary["slot"]
                and str(other.get("family")) == str(canary.get("family"))
                and str(other.get("path")) == str(canary.get("path"))
                and abs(int(other.get("line", 0)) - int(canary.get("line", 0)))
                <= FOLD_RADIUS
            ):
                mechanism = "fold-shadow"
                shadowed_by = other["slot"]
                break
        if mechanism == "cold-miss":
            window = [
                finding
                for finding in findings
                if str(finding.get("path")) == str(canary.get("path"))
                and _family_compatible(str(canary.get("family", "")), finding)
                and isinstance(finding.get("line"), int)
                and abs(finding["line"] - int(canary.get("line", 0))) <= 40
            ]
            if window and all(str(row.get("id")) in claimed for row in window):
                mechanism = "claim-shadow"
        entry: dict[str, Any] = {"slot": slot["slot"], "mechanism": mechanism}
        if shadowed_by is not None:
            entry["shadowed_by_slot"] = shadowed_by
        diagnosis.append(entry)
    return diagnosis


def score_recall(run_directory: Path, custody_path: Path, workspace: Path, results_root: Path) -> dict[str, object]:
    sink = LocalResultsSink.create(results_root, workspace)
    run_directory = run_directory.resolve()
    custody = json.loads(custody_path.read_text(encoding="utf-8"))
    # The key is ALWAYS the sibling of custody.json - never a recorded
    # absolute path (a tampered custody record must not point scoring at an
    # attacker-chosen file), and its bytes must re-hash to the recorded
    # commitment before any score is computed.
    key_path = custody_path.parent / "ANSWER_KEY.json"
    key_bytes = key_path.read_bytes()
    key_sha256 = hashlib.sha256(key_bytes).hexdigest()
    # Fail closed on a MISSING commitment too: a custody record without the
    # digest is itself evidence of tampering, not a free pass.
    if key_sha256 != custody.get("answer_key_sha256"):
        raise ValueError(
            "answer key bytes do not match the custody commitment; refusing to score"
        )
    answer_key = json.loads(key_bytes.decode("utf-8"))
    # Locus drift check: the validator hashed every planted line at plant
    # time (mutation_sha256); re-hash now. The workspace is frozen for the
    # whole run, so any mismatch is corruption evidence — a stale or
    # clobbered locus makes that slot's measurement invalid (the class the
    # --mint-error-slot help text anticipates). Recorded, never fatal:
    # scoring stays pure and adjudication consumes the flag.
    locus_drift_slots: list[int] = []
    for canary in answer_key.get("canaries", []):
        expected = canary.get("mutation_sha256")
        if canary.get("historical") or not expected:
            continue
        try:
            planted_lines = (workspace / str(canary["path"])).read_text(
                encoding="utf-8"
            ).splitlines()
            actual = hashlib.sha256(
                planted_lines[int(canary["line"]) - 1].encode()
            ).hexdigest()
        except (OSError, IndexError, ValueError, KeyError):
            actual = ""
        if actual != expected:
            locus_drift_slots.append(int(canary.get("slot", 0)))
    findings_path = run_directory / "candidates.jsonl"
    findings = []
    if findings_path.exists():
        for line in findings_path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                findings.append(json.loads(line))
    results = match_canaries(answer_key, findings)
    for row in results:
        if row["slot"] in locus_drift_slots:
            row["locus_drift"] = True
    # Cure provenance: a slot found NOW that the prior authoritative scoring
    # (launcher-held receipt) recorded as missed was refound by a blind
    # recapture lap — a CANARY-CURE, never conflated with cold recall.
    # Mint-error adjudications (operator-attested; see recapture
    # --mint-error-slot) are carried forward from the held receipt.
    held_path = custody_home() / "runs" / str(custody.get("run_id", "")) / "RECALL_RECEIPT.json"
    prior = {}
    prior_document: dict[str, Any] = {}
    if held_path.is_file():
        try:
            prior_document = json.loads(held_path.read_text(encoding="utf-8"))
            prior = {row["slot"]: row for row in prior_document.get("slots", [])}
        except (OSError, ValueError, json.JSONDecodeError):
            prior, prior_document = {}, {}
    for row in results:
        before = prior.get(row["slot"], {})
        if before.get("cured") or (row["found"] and not before.get("found") and prior):
            row["cured"] = bool(row["found"])
        if before.get("mint_error") and not row["found"]:
            row["mint_error"] = True
            row["mint_error_basis"] = before.get("mint_error_basis", "operator attestation")
    plant_rows = [row for row in results if not row["historical"]]
    historical_rows = [row for row in results if row["historical"]]
    found_count = sum(1 for row in plant_rows if row["found"])
    cured_count = sum(1 for row in plant_rows if row.get("cured"))
    cold_count = found_count - cured_count
    mint_error_count = sum(1 for row in plant_rows if row.get("mint_error"))
    # Saturation law: 8/8 is only meaningful if the candidate set could NOT
    # have blanketed unknown loci. A shotgun needs roughly one multi-family
    # row per 80 lines per file (~LOC/80 repo-wide). The conservative
    # LOC/100 threshold remains well above ordinary targeted reporting. The
    # denominator is a fresh launcher-side count — never a reviewer-writable receipt.
    scannable_lines = _workspace_line_count(workspace)
    saturation_limit = max(64, scannable_lines // 100)
    saturated = len(findings) > saturation_limit
    # Certification law: cold + cured + adjudicated mint errors must
    # account for all eight plants. Cures and mint errors are receipted
    # per-slot and surface on the seal card — never silently blended.
    status = "PASS" if (found_count + mint_error_count) == len(plant_rows) == 8 else "FAIL"
    if saturated:
        status = "SATURATED"
    # Locus drift on any slot NOT excluded by mint-error attestation
    # invalidates the whole measurement: the planted bytes are no longer
    # what the validator hashed, so a nearby-candidate match proves nothing.
    # Invalid measurement bytes must never coexist with a certificate.
    # INVALID is deliberately not FAIL: blind cure
    # laps cannot repair a corrupted workspace, so the ladder must not
    # spend against it.
    blocking_drift = [
        slot
        for slot in locus_drift_slots
        if not any(
            row["slot"] == slot and row.get("mint_error") for row in results
        )
    ]
    if blocking_drift:
        status = "INVALID"
    receipt = {
        "schema": "lucy-recall-receipt/v1",
        "run_id": custody["run_id"],
        "answer_key_sha256": custody["answer_key_sha256"],
        "found": found_count,
        # The cumulative cure-lap budget must SURVIVE rescoring: this
        # receipt overwrites the launcher-held copy, and losing the counter
        # would reset the budget every scoring pass, which both unbounds the ladder and blocks planted mint-error
        # attestation (its precondition reads this counter).
        "cure_laps": int(prior_document.get("cure_laps", 0) or 0),
        "cold": cold_count,
        "cured": cured_count,
        "mint_error": mint_error_count,
        "total": len(plant_rows),
        "historical_total": len(historical_rows),
        "historical_found": sum(1 for row in historical_rows if row["found"]),
        "status": status,
        "candidate_count": len(findings),
        "saturation_limit": saturation_limit,
        "locus_drift_slots": sorted(locus_drift_slots),
        "locus_drift_blocking": sorted(blocking_drift),
        "source": "reader-candidates",
        "slots": results,
    }
    priors_copy = custody_path.parent / "PRIORS.json"
    if priors_copy.is_file():
        sink.write_text(
            str((run_directory / "receipts" / "PRIORS_STAGED.json").relative_to(sink.root)),
            priors_copy.read_text(encoding="utf-8"),
        )
    sink.write_json(
        str((run_directory / "receipts" / "RECALL_RECEIPT.json").relative_to(sink.root)),
        receipt,
    )
    # Destroy custody only when the review actually finalized. An interrupted
    # run is scored provisionally, but the key must survive so --resume can
    # re-score after the remaining lanes land.
    if (run_directory / "findings.jsonl").is_file():
        # RETAIN custody in custody territory instead of destroying it: a
        # canary miss is a dispatch order (seal-card law) — recapture must be
        # able to re-lane the miss region and RESCORE, which needs the key.
        # The key stays 0600 under the deny-walled custody
        # home and is disposed of when the run actually certifies.
        held = custody_home() / "runs" / str(custody["run_id"])
        held.mkdir(parents=True, exist_ok=True, mode=0o700)
        if custody_path.parent.resolve() != held.resolve():
            for name in ("custody.json", "ANSWER_KEY.json", "PRIORS.json", "trial.json", "MINT_CONFIDENCE.json"):
                source = custody_path.parent / name
                if source.is_file():
                    shutil.move(str(source), str(held / name))
                    (held / name).chmod(0o600)
            shutil.rmtree(custody_path.parent, ignore_errors=True)
        # Launcher-held copy of the scored receipt, OUTSIDE the reviewer-
        # writable run directory: a later resume/recapture re-certifies from
        # this, never from a reviewer-writable run-directory copy.
        (held / "RECALL_RECEIPT.json").write_text(
            json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8"
        )
        (held / "RECALL_RECEIPT.json").chmod(0o600)
    else:
        receipt["provisional"] = True
    return receipt


def assess_process_complete(
    run_directory: Path,
    workspace: Path,
    target: Path,
    results_root: Path,
) -> dict[str, object]:
    sink = LocalResultsSink.create(results_root, workspace)
    run_directory = run_directory.resolve()
    required = ("COMPLETION.md", "FINDINGS.md", "findings.jsonl", "candidates.jsonl")
    missing = [name for name in required if not (run_directory / name).is_file()]
    if (run_directory / "staging").exists():
        missing.append("staging-not-deleted")
    completion = ""
    if (run_directory / "COMPLETION.md").is_file():
        completion = (run_directory / "COMPLETION.md").read_text(encoding="utf-8")
        sink.write_text(
            str((run_directory / "COMPLETION.md").relative_to(sink.root)), completion
        )
    trial_document = json.loads((run_directory / "trial.json").read_text(encoding="utf-8"))
    target_unchanged = content_hash(target.resolve()) == trial_document["baseline_sha256"]
    # The reviewer must have written EXTERNAL-PENDING (it never scores its own
    # recall); after external scoring/certification that line is rewritten to
    # the scored value, which is equally valid on re-assessment (resume).
    recall_line_ok = bool(
        "RECALL: EXTERNAL-PENDING" in completion
        or re.search(r"RECALL: \d+/8", completion)
    )
    process_complete = not missing and recall_line_ok and target_unchanged
    return {
        "status": "PASS" if process_complete else "FAIL",
        "required_artifacts": {name: (run_directory / name).is_file() for name in required},
        "staging_deleted": not (run_directory / "staging").exists(),
        "completion_external_recall_pending": recall_line_ok,
        "target_unchanged": target_unchanged,
        "errors": missing,
    }


def write_trial_verdict(
    run_directory: Path,
    workspace: Path,
    target: Path,
    results_root: Path,
    recall: dict[str, object],
) -> dict[str, object]:
    sink = LocalResultsSink.create(results_root, workspace)
    process = assess_process_complete(run_directory, workspace, target, results_root)
    verdict = {
        "schema": "lucy-trial-verdict/v1",
        # run_id rides in the verdict so the launcher epilogue can print an
        # exact copy-pasteable resume command as the LAST line of output.
        "run_id": run_directory.resolve().name,
        "status": "PASS" if process["status"] == recall.get("status") == "PASS" else "FAIL",
        "process": process,
        "recall": {
            "status": recall.get("status"),
            "found": recall.get("found"),
            "total": recall.get("total"),
            "source": recall.get("source"),
            "answer_key_sha256": recall.get("answer_key_sha256"),
        },
    }
    sink.write_json(
        str((run_directory.resolve() / "TRIAL_VERDICT.json").relative_to(sink.root)), verdict
    )
    return verdict


def direct_claude_environment() -> dict[str, str]:
    environment = dict(os.environ)
    for name in (
        "CLAUDE_CODE_USE_BEDROCK",
        "CLAUDE_CODE_USE_MANTLE",
        "CLAUDE_CODE_USE_VERTEX",
        "CLAUDE_CODE_USE_FOUNDRY",
        "ANTHROPIC_CUSTOM_HEADERS",
        "ANTHROPIC_BEDROCK_REGION_PREFIX",
        "AWS_PROFILE",
        "AWS_REGION",
        "AWS_DEFAULT_REGION",
        "AWS_BEARER_TOKEN_BEDROCK",
    ):
        environment.pop(name, None)
    model = environment.get("ANTHROPIC_MODEL", "")
    if model.startswith(("us.anthropic.", "global.anthropic.", "anthropic.")):
        environment.pop("ANTHROPIC_MODEL", None)
    environment["CLAUDE_CODE_SKIP_PROMPT_HISTORY"] = "1"
    environment["CLAUDE_CODE_DISABLE_AUTO_MEMORY"] = "1"
    environment["CLAUDE_CODE_DISABLE_CLAUDE_MDS"] = "1"
    # Print-mode sessions wait indefinitely for their reader/court subagents;
    # a finite background-wait ceiling can terminate an active lane.
    environment.setdefault("CLAUDE_CODE_PRINT_BG_WAIT_CEILING_MS", "0")
    return environment


def estimate_cost(target: Path) -> dict[str, object]:
    """Pre-dispatch cost projection from the census (printed before any spend).

    Bands scale with scannable LOC and account for the mandatory affinity-depth
    economy in the reader contract. Override the unit price with
    LUCY_USD_PER_MTOKEN when your account pricing differs.
    """
    from lucy.runtime.units import compute_units

    plan = compute_units(target.expanduser().resolve())
    loc = int(plan.get("scannable_loc", 0))
    tokens_low, tokens_high = loc * 40, loc * 110
    usd_per_mtoken = float(os.environ.get("LUCY_USD_PER_MTOKEN", "5"))
    return {
        "scannable_loc": loc,
        "units": len(plan.get("units", [])),
        "estimated_tokens": {"low": tokens_low, "high": tokens_high},
        "estimated_usd": {
            "low": round(tokens_low / 1_000_000 * usd_per_mtoken, 2),
            "high": round(tokens_high / 1_000_000 * usd_per_mtoken, 2),
        },
        "usd_per_mtoken": usd_per_mtoken,
    }


def _reviewer_command(
    run_id: str,
    run_directory: Path,
    *,
    claude_binary: str,
    print_mode: bool,
    max_budget_usd: float | None,
    resume: bool = False,
) -> list[str]:
    from lucy.runtime.loop_policy import lane_cap

    prompt = f"/lucy --run-id {run_id} --run-dir {run_directory} --max-lanes {lane_cap()}"
    if resume:
        prompt += " --resume"
    if print_mode:
        prompt += " --noninteractive"
    claude_home = Path(os.environ.get("CLAUDE_CONFIG_DIR", str(Path.home() / ".claude")))
    installed_skill = claude_home / "skills" / "lucy"
    command = [
        claude_binary,
        "--setting-sources",
        "user",
        "--settings",
        json.dumps(
            {
                "env": {
                    "CLAUDE_CODE_USE_BEDROCK": "",
                    "CLAUDE_CODE_USE_MANTLE": "",
                    "CLAUDE_CODE_USE_VERTEX": "",
                    "CLAUDE_CODE_USE_FOUNDRY": "",
                    "ANTHROPIC_CUSTOM_HEADERS": "",
                    "ANTHROPIC_MODEL": "",
                    "AWS_PROFILE": "",
                    "AWS_REGION": "",
                },
                # Custody deny-wall: session-wide (covers subagents), so even
                # a fully prompt-injected reviewer cannot Read/Glob/Grep the
                # live answer key. Deny rules require the //absolute form to
                # block out-of-cwd reads.
                "permissions": {
                    "deny": [
                        f"Read(//{str(custody_home()).lstrip('/')}/**)",
                        f"Edit(//{str(custody_home()).lstrip('/')}/**)",
                    ]
                },
            },
            separators=(",", ":"),
        ),
        "--add-dir",
        str(run_directory),
        str(installed_skill),
        "--permission-mode",
        "manual",
        "--name",
        f"LUCY {run_id}",
        # Pinned surface: read-only search, near-read-only git, and the
        # skill's own wrapper commands. Never unpinned python3/git — those
        # grant network egress and arbitrary writes. Pass the grants in both
        # modes so unattended runs do not stall. Equals form is required:
        # --allowedTools is variadic and otherwise swallows a following bare
        # prompt argument as a tool name. Design of the write surface:
        # - NO bare Write: Edit(path) rules cover all file-editing tools,
        #   so path-scoped Edit rules are the entire write grant.
        # - Edit scoped to staging/** and COMPLETION.md only: receipts stay
        #   wrapper-written, closing receipt forgery via file tools.
        # - Agent scoped to the two pinned lucy agents.
        # - NO Bash(git diff *): --no-index read anything, --output wrote
        #   anywhere; and the answer key is no longer a working-tree diff.
        "--allowedTools="
        "Read,Grep,Glob,Agent(lucy-reader),Agent(lucy-court),ScheduleWakeup,"
        f"Edit(//{str(run_directory).lstrip('/')}/staging/**),"
        f"Edit(//{str(run_directory).lstrip('/')}/COMPLETION.md),"
        "Bash(git status *),Bash(git rev-parse *),Bash(git ls-files *),"
        "Bash(lucy-merge *),Bash(lucy-finalize *),Bash(lucy-units *),Bash(lucy-report *),Bash(lucy-toolbox *)",
    ]
    if print_mode:
        command.extend(
            [
                "--print",
                "--no-session-persistence",
                "--output-format",
                "text",
            ]
        )
        if max_budget_usd is not None:
            command.extend(["--max-budget-usd", str(max_budget_usd)])
    command.append(prompt)
    return command


def _run_state_fingerprint(run_directory: Path) -> tuple:
    """Cheap progress fingerprint for the reviewer relaunch guard: the
    name+size census of staging and receipts plus run-level artifacts. Any
    newly staged lane, receipt, or merge output changes it."""
    entries = []
    for directory in (run_directory / "staging", run_directory / "receipts"):
        if directory.is_dir():
            for path in sorted(directory.iterdir()):
                try:
                    entries.append((path.name, path.stat().st_size))
                except OSError:
                    entries.append((path.name, -1))
    for name in ("candidates.jsonl", "findings.jsonl", "COMPLETION.md"):
        path = run_directory / name
        entries.append((name, path.stat().st_size if path.is_file() else -1))
    return tuple(entries)


def _reviewer_incomplete(run_directory: Path) -> str | None:
    """None when the reviewer finalized (findings.jsonl exists); otherwise a
    short human diagnosis of how far it got, for the relaunch guard."""
    if (run_directory / "findings.jsonl").is_file():
        return None
    staging = run_directory / "staging"
    if not staging.is_dir():
        return "exited before staging anything"
    lanes = len(list(staging.glob("lane-pass*")))
    units = len(
        [
            listing
            for listing in staging.glob("UNIT-*.txt")
            if not listing.name.endswith(("-BATTERY.txt", "-PRIORS.txt"))
        ]
    )
    return (
        f"exited mid-run: staging has {units} unit listing(s) and "
        f"{lanes} lane file(s), but no findings.jsonl"
    )


def _run_reviewer(command: list[str], workspace: Path, run_directory: Path) -> int:
    """Run the reviewer with its output pumped live to the console (and any
    active tee log) instead of buffering until exit."""
    import sys as _sys

    from lucy.runtime.progress import pump_subprocess

    environment = direct_claude_environment()
    # Wrapper run pin: lucy-merge/finalize/units refuse a --run-dir that
    # disagrees with this, because Bash prefix grants are argument-blind.
    environment["LUCY_RUN_DIR"] = str(run_directory)
    process = subprocess.Popen(
        command,
        cwd=workspace,
        env=environment,
        stdout=subprocess.PIPE,
        stderr=subprocess.STDOUT,
        text=True,
    )
    pump_subprocess(process, [_sys.stdout])
    return process.wait()


def _write_codex_usage_receipt(run_directory: Path, results_root: Path) -> None:
    """Publish token/timing totals for Codex invocations in this run."""
    metrics = run_directory / "receipts" / "CODEX_USAGE.jsonl"
    if not metrics.is_file():
        return
    from lucy.runtime.host import summarize_codex_usage

    summary = summarize_codex_usage(metrics)
    sink = LocalResultsSink.create(results_root, run_directory)
    sink.write_json(
        str((run_directory / "receipts" / "CODEX_USAGE.json").relative_to(sink.root)),
        summary,
    )


def _score_and_conclude(
    run_directory: Path,
    custody: Path,
    workspace: Path,
    target: Path,
    results_root: Path,
    run_id: str,
    started_at: str,
    *,
    certify: bool,
    claude_binary: str = "claude",
    disposition_host: object | None = None,
) -> dict[str, object]:
    _write_codex_usage_receipt(run_directory, results_root)
    try:
        receipt = score_recall(run_directory, custody, workspace, results_root)
    except (OSError, ValueError, json.JSONDecodeError) as error:
        receipt = {"status": "BLOCKED", "error": str(error), "found": 0, "total": 8}
    # Disposition law replaces the old proximity-window annotation: every
    # candidate in a planter-modified file is adjudicated against a fresh
    # CLEAN copy of the target (causation, not proximity — a plant-derived
    # finding can cite a far sink; a genuine defect can sit beside a plant).
    dispositions = _disposition_pass(
        run_directory, workspace, target, results_root, receipt,
        claude_binary=claude_binary, disposition_host=disposition_host,
    )
    _write_codex_usage_receipt(run_directory, results_root)
    verdict = write_trial_verdict(run_directory, workspace, target, results_root, receipt)
    # Certification runs whenever the review FINALIZED, not only on a PASS
    # verdict: a recall-degraded run still owes the operator its gated report
    # and receipts; the gates themselves refuse CERTIFIED and the ending is
    # honestly PROCESS-COMPLETE.
    # The scored receipt OBJECT is handed to certification directly; the
    # reviewer-writable receipts-file copy must never be the C3 input.
    process = verdict.get("process") if isinstance(verdict.get("process"), dict) else {}
    finalized = bool(process.get("required_artifacts", {}).get("findings.jsonl"))
    if certify and (verdict.get("status") == "PASS" or finalized):
        from lucy.runtime.seal import generate_certification

        try:
            certification = generate_certification(
                run_directory, workspace, results_root, run_id, started_at,
                recall_receipt=receipt, dispositions=dispositions,
            )
        except (OSError, ValueError, json.JSONDecodeError) as error:
            certification = {
                "certified": False,
                "error": str(error),
                "final_line": f"REVIEW-COMPLETE {run_id} PROCESS-COMPLETE",
            }
        verdict = dict(verdict)
        verdict["certification"] = certification
        if certification.get("certified"):
            # The key's job is done only now; retained custody is disposed of
            # at true completion, never at a failing score.
            shutil.rmtree(custody_home() / "runs" / run_id, ignore_errors=True)
    return verdict



def _disposition_pass(
    run_directory: Path,
    workspace: Path,
    target: Path,
    results_root: Path,
    receipt: dict[str, object],
    *,
    claude_binary: str = "claude",
    disposition_host: object | None = None,
) -> dict[str, object] | None:
    """Adjudicate planted-file candidates on a clean target copy, write the
    receipt, and rewrite findings synthetic flags. Returns the receipt
    object (certification consumes the OBJECT, never the file). Uses the
    launcher-held answer key (retained custody), so it runs post-scoring."""
    from lucy.runtime.dispositions import adjudicate_planted_candidates, apply_dispositions

    run_id = run_directory.name
    key_path = custody_home() / "runs" / run_id / "ANSWER_KEY.json"
    if not key_path.is_file():
        return None
    try:
        key = json.loads(key_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None
    planted_files = {
        str(row["path"]) for row in key.get("canaries", []) if not row.get("historical")
    }
    matched = {
        str(row.get("matched_candidate_id"))
        for row in receipt.get("slots", []) or []
        if row.get("matched_candidate_id")
    }
    if disposition_host is None:
        from lucy.runtime.host import ClaudeAgentHost

        disposition_host = ClaudeAgentHost(claude_binary=claude_binary)
    from lucy.runtime.loop_policy import lane_cap

    dispositions = adjudicate_planted_candidates(
        run_directory, target, planted_files, matched, disposition_host,
        copy_ignore=COPY_IGNORE, max_workers=lane_cap(),
    )
    sink = LocalResultsSink.create(results_root, workspace)
    sink.write_json(
        str((run_directory / "receipts" / "CANDIDATE_DISPOSITIONS.json").relative_to(sink.root)),
        dispositions,
    )
    apply_dispositions(run_directory, workspace, results_root, dispositions)
    return dispositions

def _battery_signal(output: str, path: str, line: int) -> bool:
    """True when a deterministic battery hit lands within 40 lines of the
    locus. JSONL rows are parsed exactly (path equality + integer line);
    non-JSON lines fall back to a colon/whitespace-tolerant number scan —
    a same-file hit with a parseable line NUMBER far away is NOT a signal."""
    import re as _re

    for hit_line in output.splitlines():
        if path not in hit_line:
            continue
        try:
            row = json.loads(hit_line)
        except (ValueError, TypeError):
            row = None
        if isinstance(row, dict):
            row_path = str(row.get("path", row.get("file", "")))
            row_line = row.get("line")
            if row_path == path and isinstance(row_line, int) and abs(row_line - line) <= 40:
                return True
            continue
        numbers = [int(n) for n in _re.findall(r"[:\s](\d+)", hit_line)]
        if numbers and any(abs(n - line) <= 40 for n in numbers):
            return True
    return False

def _battery_prescreen(answer_key: dict, workspace: Path, custody_dir: Path) -> None:
    """Detectability pre-screen at mint: run the pinned detector battery on
    the PLANTED copy and record, per plant, whether a deterministic signal
    lands near its locus. WARNING-ONLY by design — requiring battery-
    findability would select for shallow plants and cheapen the metric.
    The per-slot detail (it names loci) is written to CUSTODY, never the
    run directory; stdout gets counts only. This surfaces a defective mint
    before reader dispatch."""
    import re as _re

    battery = Path(__file__).parents[1] / "toolbox" / "detector_battery_v3_3_1.py"
    try:
        from lucy.runtime.assets import verify_asset

        verify_asset(battery)
        result = subprocess.run(
            [sys.executable, str(battery), str(workspace)],
            capture_output=True, text=True, check=False, timeout=600,
        )
        output = result.stdout
    except Exception:
        return
    confidence = []
    visible = 0
    for row in answer_key.get("canaries", []):
        if row.get("historical"):
            continue
        signal = _battery_signal(output, str(row.get("path")), int(row.get("line", 0)))
        visible += signal
        confidence.append({"slot": row.get("slot"), "battery_signal": signal})
    (custody_dir / "MINT_CONFIDENCE.json").write_text(
        json.dumps({"schema": "lucy-mint-confidence/v1", "slots": confidence},
                   indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    (custody_dir / "MINT_CONFIDENCE.json").chmod(0o600)
    # No console output: the pre-screen is an operator-facing custody record
    # (MINT_CONFIDENCE.json), and the old "battery-visible plants" banner was
    # scanner-internals jargon on the first screen a user sees.

def _attest_mint_error(run_id: str, slots: list[tuple[int, str]]) -> None:
    """Record an OPERATOR attestation that planted slots are defective
    mints. Guards: honored only after the blind cure budget is exhausted
    (self-forgiveness prevention — the scanner can never mint-error its own
    miss), only for slots the authoritative receipt shows as missed, and
    receipted per-slot with its basis into the launcher-held receipt."""
    held = custody_home() / "runs" / run_id / "RECALL_RECEIPT.json"
    if not held.is_file():
        raise ValueError("no launcher-held recall receipt; run a scoring pass first")
    receipt = json.loads(held.read_text(encoding="utf-8"))
    slot_rows = {row["slot"]: row for row in receipt.get("slots", [])}
    attesting_plants = [s for s, _ in slots if not slot_rows.get(s, {}).get("historical")]
    if attesting_plants and int(receipt.get("cure_laps", 0) or 0) < 2:
        raise ValueError(
            "mint-error attestation refused for planted slot(s) "
            f"{attesting_plants}: the blind cure budget "
            f"({receipt.get('cure_laps', 0)}/2 laps) is not exhausted — "
            "cure attempts come before adjudication"
        )
    rows = {row["slot"]: row for row in receipt.get("slots", [])}
    for slot, basis in slots:
        row = rows.get(slot)
        if row is None:
            raise ValueError(f"slot {slot} is not a canary slot")
        if row.get("found"):
            raise ValueError(f"slot {slot} was found; mint-error does not apply")
        row["mint_error"] = True
        row["mint_error_operator_basis"] = basis
        if row.get("historical"):
            # Historical slots are score-only conversion artifacts (their
            # loci and families come from a priors-file conversion, not a
            # controlled plant), so their mint errors are conversion-quality
            # adjudications — exempt from the plant-slot cure-lap
            # precondition, which exists to stop the scanner forgiving
            # reader misses of REAL plants.
            row["mint_error_basis"] = f"operator attestation (historical conversion defect): {basis}"
        else:
            row["mint_error_basis"] = f"operator attestation: {basis}"
    held.write_text(json.dumps(receipt, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(
        f"[lucy] mint-error attested for slot(s) {sorted(s for s, _ in slots)}; "
        "the next scoring pass counts them under found + cured + mint_error == 8",
        file=sys.stderr,
    )

def _lucy_prefix() -> str:
    """The '[lucy]' launcher-message prefix, Opal on a terminal (matching the
    progress reporter's prefix) and plain in pipes/logs without a tty."""
    from lucy.runtime.progress import OPAL

    if bool(getattr(sys.stderr, "isatty", lambda: False)()):
        return f"\033[{OPAL}m[lucy]\033[0m"
    return "[lucy]"


def launch_trial(
    target: Path,
    results_root: Path,
    *,
    claude_binary: str = "claude",
    codex_binary: str = "codex",
    codex_model: str = "gpt-5.6-sol",
    codex_reasoning_effort: str = "high",
    print_mode: bool = False,
    max_budget_usd: float | None = None,
    planter: str = "claude",
    planter_budget_usd: float | None = None,
    certify: bool = False,
    priors_path: Path | None = None,
    cold_priors: bool = False,
    host: str = "claude",
    quiet: bool = False,
) -> tuple[int, dict[str, object]]:
    require_host_tools(
        host,
        planter,
        claude_binary=claude_binary,
        codex_binary=codex_binary,
    )
    # Custody lives under the 0700 results root (never world-readable /tmp),
    # is preserved under custody_home()/runs/<run-id> if interrupted (for
    # --resume), and is destroyed after scoring.
    resolved_results = results_root.expanduser().resolve()
    resolved_results.mkdir(parents=True, exist_ok=True, mode=0o700)
    custody_directory = Path(
        tempfile.mkdtemp(prefix=".lucy-custody-", dir=custody_home())
    )
    trial: dict[str, Any] = {}
    try:
        if not quiet:
            print(
                f"{_lucy_prefix()} preparing: copying the estate into a disposable workspace, "
                "then an isolated planter hides the recall canaries — several "
                "minutes of silence on a large estate is normal here",
                file=sys.stderr,
            )
        trial = prepare_trial(
            target,
            results_root,
            custody_root=custody_directory,
            planter=planter,
            claude_binary=claude_binary,
            codex_binary=codex_binary,
            codex_model=codex_model,
            codex_reasoning_effort=codex_reasoning_effort,
            review_host=host,
            planter_budget_usd=planter_budget_usd,
            priors_path=priors_path,
            cold_priors=cold_priors,
        )
        workspace = Path(trial["workspace"])
        run_directory = Path(trial["run_directory"])
        custody = Path(trial["_custody"])
        print(
            json.dumps(
                {key: value for key, value in trial.items() if not key.startswith("_")},
                indent=2,
                sort_keys=True,
            )
        )
        if not quiet:
            print(
                f"{_lucy_prefix()} planter validated; custody sealed; reviewer starting "
                f"(run {trial['run_id']})",
                file=sys.stderr,
            )
        from lucy.runtime.progress import ProgressReporter

        disposition_host = None
        with ProgressReporter(run_directory, quiet=quiet):
            if host in {"codex", "openai"}:
                # Launcher hosts own orchestration (passes, quiet
                # law, sweeps, courts); the model runs only inside tool loops.
                from lucy.runtime.host import BudgetExceeded, CodexAgentHost, OpenAIHost
                from lucy.runtime.orchestrator import run_review

                if host == "codex":
                    agent_host = CodexAgentHost(
                        codex_binary=codex_binary,
                        model=codex_model,
                        reasoning_effort=codex_reasoning_effort,
                        metrics_path=run_directory / "receipts" / "CODEX_USAGE.jsonl",
                    )
                else:
                    agent_host = OpenAIHost(max_budget_usd=max_budget_usd)
                disposition_host = agent_host
                return_code = 0
                try:
                    summary = run_review(
                        agent_host,
                        workspace,
                        run_directory,
                        resolved_results,
                        max_lanes=int(trial.get("max_lanes") or 0) or None,
                    )
                    print(json.dumps({"review": summary}, sort_keys=True))
                except BudgetExceeded as error:
                    print(f"REVIEW BLOCKED {trial['run_id']} {error}")
                    return_code = 4
                completed_returncode = return_code
            else:
                # Guarded relaunch, same stagnation law as recapture: an
                # unattended reviewer session may end its turn at phase
                # boundaries because a wakeup cannot fire in a piped
                # subprocess.
                # Progress since the previous attempt resets the strike
                # count; only consecutive stagnant attempts count against
                # the cap. The diagnosis always prints, quiet or not.
                completed_returncode = 0
                stagnant_cap = 3
                attempt_cap = 25
                stagnant = 0
                attempt = 0
                while True:
                    attempt += 1
                    if attempt > 1:
                        # A relaunched reviewer must never see the drawn
                        # historical canaries (regenerated from custody at
                        # rescore time) — same rule as resume_trial.
                        (run_directory / "receipts" / "PRIORS_STAGED.json").unlink(
                            missing_ok=True
                        )
                    before = _run_state_fingerprint(run_directory)
                    command = _reviewer_command(
                        trial["run_id"],
                        run_directory,
                        claude_binary=claude_binary,
                        print_mode=print_mode,
                        max_budget_usd=max_budget_usd,
                        resume=attempt > 1,
                    )
                    completed_returncode = _run_reviewer(command, workspace, run_directory)
                    diagnosis = _reviewer_incomplete(run_directory)
                    if diagnosis is None:
                        break
                    progressed = _run_state_fingerprint(run_directory) != before
                    stagnant = 0 if progressed else stagnant + 1
                    if stagnant < stagnant_cap and attempt < attempt_cap:
                        print(
                            f"{_lucy_prefix()} reviewer (exit {completed_returncode}) "
                            f"{diagnosis} — "
                            f"{'progress made' if progressed else f'no progress ({stagnant}/{stagnant_cap} stagnant)'}"
                            f"; relaunching with --resume (attempt {attempt + 1})",
                            file=sys.stderr,
                        )
                        continue
                    print(
                        f"{_lucy_prefix()} reviewer (exit {completed_returncode}) "
                        f"{diagnosis} — giving up after {attempt} attempts "
                        f"({stagnant} consecutive without progress); "
                        f"scoring what exists (expect FAIL). Resume later with: "
                        f"lucy scan --resume {trial['run_id']} --results {results_root}",
                        file=sys.stderr,
                    )
                    break
        verdict = _score_and_conclude(
            run_directory,
            custody,
            workspace,
            target,
            results_root,
            trial["run_id"],
            trial["started_at"],
            certify=certify,
            claude_binary=claude_binary,
            disposition_host=disposition_host,
        )
        return completed_returncode, verdict
    finally:
        if custody_directory.exists():
            if trial.get("run_id"):
                preserved = custody_home() / "runs" / trial["run_id"]
                preserved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
                if not preserved.exists():
                    shutil.move(str(custody_directory), str(preserved))
                else:
                    shutil.rmtree(custody_directory, ignore_errors=True)
            else:
                shutil.rmtree(custody_directory, ignore_errors=True)


def resume_trial(
    results_root: Path,
    run_id: str,
    *,
    claude_binary: str = "claude",
    codex_binary: str = "codex",
    codex_model: str | None = None,
    codex_reasoning_effort: str | None = None,
    print_mode: bool = False,
    max_budget_usd: float | None = None,
    certify: bool = False,
    host: str | None = None,
) -> tuple[int, dict[str, object]]:
    """Resume an interrupted run from its receipts.

    Reconstructs workspace/run-dir/custody from the results sink. If the
    reviewer never finalized (no findings.jsonl), it is relaunched with a
    --resume flag so the skill adopts existing staging instead of redoing
    passes. Recall is scored from preserved custody; if custody is gone the
    run honestly reports recall BLOCKED rather than guessing.
    """
    resolved_results = results_root.expanduser().resolve()
    recorded_custody = _recorded_custody_home(resolved_results, run_id)
    os.environ["LUCY_CUSTODY_HOME"] = str(recorded_custody)
    run_directory = resolved_results / "runs" / run_id
    trial_path = run_directory / "trial.json"
    if not trial_path.is_file():
        raise ValueError(f"no run to resume: {trial_path} missing")
    custody = custody_home() / "runs" / run_id / "custody.json"
    if not custody.is_file():
        # Migration seam: runs started before custody moved out of the
        # results root preserved custody at <results>/.custody/<run-id>.
        legacy = resolved_results / ".custody" / run_id / "custody.json"
        if legacy.is_file():
            custody = legacy
    if not custody.is_file():
        # SIGKILL seam (crash-only rule): a hard kill skips launch_trial's
        # finally, stranding custody in its mkdtemp dir. Adopt only the orphan
        # whose custody.json names THIS run.
        adopted = _adopt_orphaned_custody(run_id)
        if adopted is not None:
            custody = adopted
    # trial.json in the run directory is reviewer-writable; prefer the
    # custody-held duplicate, and in every case derive the workspace from
    # the results-root convention rather than a recorded absolute path.
    custody_trial = custody.parent / "trial.json"
    if custody_trial.is_file():
        trial = json.loads(custody_trial.read_text(encoding="utf-8"))
    else:
        trial = json.loads(trial_path.read_text(encoding="utf-8"))
    workspace = resolved_results / "workspaces" / run_id
    if Path(trial["workspace"]).resolve() != workspace.resolve():
        raise ValueError(
            f"trial.json workspace does not match the results-root convention "
            f"({trial['workspace']} != {workspace}); refusing to resume"
        )
    target = Path(trial["target"])
    if not workspace.is_dir():
        raise ValueError(f"workspace missing; cannot resume: {workspace}")
    selected_host = host or str(trial.get("host") or "claude")
    if selected_host not in {"claude", "codex", "openai"}:
        raise ValueError(f"unsupported stored review host: {selected_host}")
    selected_codex_model = codex_model or str(trial.get("model") or "gpt-5.6-sol")
    selected_codex_reasoning = codex_reasoning_effort or str(
        trial.get("reasoning_effort") or "high"
    )
    reviewer_needed = not (run_directory / "findings.jsonl").is_file()
    # A completed, already-scored run can be reconstructed entirely from its
    # launcher-held receipt. Do not require a provider CLI when resume will
    # invoke no model (operators may inspect old runs after changing hosts).
    # Retained custody means scoring/disposition may still need a clean-copy
    # court, so preflight remains mandatory in that case.
    if reviewer_needed or custody.is_file():
        require_host_tools(
            selected_host,
            selected_host,
            claude_binary=claude_binary,
            codex_binary=codex_binary,
        )
    return_code = 0
    reviewer_ran_this_resume = reviewer_needed
    disposition_host = None
    if not (run_directory / "findings.jsonl").is_file():
        # The staged-priors receipt names the drawn historical canaries; a
        # relaunched reviewer must never see it (it is regenerated from
        # custody at rescore time).
        (run_directory / "receipts" / "PRIORS_STAGED.json").unlink(missing_ok=True)
        from lucy.runtime.progress import ProgressReporter

        with ProgressReporter(run_directory):
            if selected_host == "claude":
                command = _reviewer_command(
                    run_id,
                    run_directory,
                    claude_binary=claude_binary,
                    print_mode=print_mode,
                    max_budget_usd=max_budget_usd,
                    resume=True,
                )
                return_code = _run_reviewer(command, workspace, run_directory)
            else:
                from lucy.runtime.host import CodexAgentHost, OpenAIHost
                from lucy.runtime.orchestrator import run_review

                if selected_host == "codex":
                    disposition_host = CodexAgentHost(
                        codex_binary=codex_binary,
                        model=selected_codex_model,
                        reasoning_effort=selected_codex_reasoning,
                        metrics_path=run_directory / "receipts" / "CODEX_USAGE.jsonl",
                    )
                else:
                    disposition_host = OpenAIHost(max_budget_usd=max_budget_usd)
                run_review(
                    disposition_host,
                    workspace,
                    run_directory,
                    resolved_results,
                    max_lanes=int(trial.get("max_lanes") or 0) or None,
                )
    if disposition_host is None and selected_host == "codex":
        from lucy.runtime.host import CodexAgentHost

        disposition_host = CodexAgentHost(
            codex_binary=codex_binary,
            model=selected_codex_model,
            reasoning_effort=selected_codex_reasoning,
            metrics_path=run_directory / "receipts" / "CODEX_USAGE.jsonl",
        )
    elif disposition_host is None and selected_host == "openai":
        from lucy.runtime.host import OpenAIHost

        disposition_host = OpenAIHost(max_budget_usd=max_budget_usd)
    if not custody.is_file():
        # Custody gone. The ONLY adoptable receipt is the launcher-held copy
        # written at genuine scoring time into custody territory — never the
        # run-directory copy (reviewer-writable; its anchor MINT_COMMITMENT
        # lives there too, so hash agreement proves nothing). With no
        # held receipt either, recall is honestly BLOCKED; certification
        # still runs so the operator gets the report, and the C3 gate
        # refuses CERTIFIED.
        held_receipt = custody_home() / "runs" / run_id / "RECALL_RECEIPT.json"
        if held_receipt.is_file() and not reviewer_ran_this_resume:
            receipt = json.loads(held_receipt.read_text(encoding="utf-8"))
        else:
            receipt = {
                "status": "BLOCKED",
                "found": 0,
                "total": 8,
                "reason": (
                    "custody unavailable and no launcher-held recall receipt"
                    + ("; a reviewer session ran during this resume" if reviewer_ran_this_resume else "")
                ),
                "provisional": True,
            }
        verdict = write_trial_verdict(
            run_directory, workspace, target, resolved_results, receipt
        )
        finalized = (run_directory / "findings.jsonl").is_file()
        if certify and (verdict.get("status") == "PASS" or finalized):
            from lucy.runtime.seal import generate_certification

            verdict = dict(verdict)
            verdict["certification"] = generate_certification(
                run_directory, workspace, resolved_results, run_id,
                trial["started_at"], recall_receipt=receipt,
            )
        return return_code, verdict
    verdict = _score_and_conclude(
        run_directory,
        custody,
        workspace,
        target,
        resolved_results,
        run_id,
        trial["started_at"],
        certify=certify,
        claude_binary=claude_binary,
        disposition_host=disposition_host,
    )
    return return_code, verdict



def parse_args() -> argparse.Namespace:
    # --log/--quiet live on a shared parent so they are accepted BOTH before
    # and after the subcommand (users naturally append them last).
    # SUPPRESS defaults so the subparser copy never clobbers a value parsed
    # before the subcommand; main() normalizes the attributes afterwards.
    common = argparse.ArgumentParser(add_help=False)
    common.add_argument(
        "--log",
        type=Path,
        default=argparse.SUPPRESS,
        help="tee all launcher output (stdout+stderr, progress, reviewer "
        "output) to this file as well as the console",
    )
    common.add_argument(
        "--quiet",
        action="store_true",
        default=argparse.SUPPRESS,
        help="suppress the default progress milestones (receipt-derived "
        "phase/lane/court lines printed to stderr during the run)",
    )
    parser = argparse.ArgumentParser(description=__doc__, parents=[common])
    subparsers = parser.add_subparsers(dest="command", required=True)
    for name in ("launch", "scan"):
        sub = subparsers.add_parser(
            name,
            parents=[common],
            help="scan = full review with certification; launch = trial (no certification)",
        )
        sub.add_argument("--target", type=Path, default=None, help="required unless --resume")
        sub.add_argument("--results", type=Path, required=True)
        sub.add_argument("--claude-bin", default="claude")
        sub.add_argument("--print", action="store_true")
        sub.add_argument(
            "--max-budget-usd",
            type=float,
            default=None,
            help="FIDELITY TRADE-OFF: unlimited by default (recall first). "
            "Setting a cap protects spend, but a run stopped on budget may "
            "miss findings and cannot certify until resumed/recaptured.",
        )
        sub.add_argument(
            "--planter",
            choices=("auto", "claude", "codex", "openai", "fixture"),
            default="auto",
            help="canary planter host; auto uses the selected review host",
        )
        sub.add_argument(
            "--planter-budget-usd",
            type=float,
            default=None,
            help="FIDELITY TRADE-OFF: unlimited by default; a capped planter "
            "may fail to place all 8 recall canaries, blocking certification.",
        )
        sub.add_argument("--estimate-only", action="store_true")
        sub.add_argument(
            "--resume",
            metavar="RUN_ID",
            default=None,
            help="resume an interrupted run from its receipts instead of starting fresh",
        )
        sub.add_argument(
            "--priors",
            type=Path,
            default=None,
            help="historical findings file (lucy-priors/oss-1), kept outside the target; "
            "enables refind accounting and 4 score-only historical canaries",
        )
        sub.add_argument(
            "--cold-priors",
            action="store_true",
            help="disable priors heat: staged priors are used only for canaries "
            "and refind accounting, never injected into reader briefs (the "
            "pre-heat posture; priors then never transit model context)",
        )
        sub.add_argument(
            "--host",
            choices=("claude", "codex", "openai"),
            default=None,
            help="review host: claude (default), codex (saved Codex login), or openai (EXPERIMENTAL: "
            "launcher-owned orchestration over an OpenAI-compatible API; requires "
            "OPENAI_API_KEY + OPENAI_MODEL; not yet validated against the evaluation corpus)",
        )
        sub.add_argument("--codex-bin", default="codex")
        sub.add_argument(
            "--codex-model",
            default=None,
            help="Codex model (new runs default to gpt-5.6-sol; resumes reuse the recorded model)",
        )
        sub.add_argument(
            "--codex-reasoning",
            choices=("minimal", "low", "medium", "high", "xhigh", "max", "ultra"),
            default=None,
            help="new Codex runs default to high; resumes reuse the recorded value",
        )
    export = subparsers.add_parser(
        "export", parents=[common], help="derive SARIF from a gated report"
    )
    export.add_argument("report", type=Path)
    export.add_argument("--output", type=Path, default=None)
    recapture = subparsers.add_parser(
        "recapture",
        parents=[common],
        help="reopen reading for below-bar units on a finalized run, re-court, re-seal",
    )
    recapture.add_argument("--run", required=True, metavar="RUN_ID")
    recapture.add_argument("--results", type=Path, required=True)
    recapture.add_argument(
        "--max-laps",
        type=int,
        default=None,
        help="FIDELITY TRADE-OFF: laps are uncapped by default (recall first; "
        "stops on convergence or receipted stagnation). Setting a cap may stop "
        "the run before all findings are captured.",
    )
    from lucy.runtime.host import LANE_BUDGET_USD_DEFAULT

    recapture.add_argument(
        "--lane-budget-usd",
        type=float,
        default=LANE_BUDGET_USD_DEFAULT,
        help="per-lane spend cap (runaway-loop protection; lanes bill "
        "actuals, so raising it rarely changes real cost). See "
        "LANE_BUDGET_USD_DEFAULT for the default rationale. A budget-killed "
        "lane aborts the recapture fail-closed rather than counting its "
        "partial output toward quiet.",
    )
    recapture.add_argument(
        "--cure-lap-budget",
        type=int,
        default=None,
        help="operator policy: total blind cure laps allowed CUMULATIVELY "
        "across all commands for this run (default 2). Laps stay fully "
        "blind and every cure is receipted with its lap count on the seal "
        "card, so raising this widens spend, never weakens the claim.",
    )
    recapture.add_argument(
        "--mint-error-slot",
        action="append",
        default=None,
        metavar="SLOT:BASIS",
        help="operator attestation that the planted canary in SLOT is a "
        "defective mint (semantically inert or unreachable) — receipted "
        "with basis 'operator attestation' and counted in the recall law "
        "found + cured + mint_error == 8; never inferable by the scanner "
        "itself, and only honored after the blind cure budget is exhausted",
    )
    recapture.add_argument(
        "--host",
        choices=("claude", "codex", "openai"),
        default=None,
        help="defaults to the host recorded when the run was launched",
    )
    recapture.add_argument("--claude-bin", default="claude")
    recapture.add_argument("--codex-bin", default="codex")
    recapture.add_argument("--codex-model", default=None)
    recapture.add_argument(
        "--codex-reasoning",
        choices=("minimal", "low", "medium", "high", "xhigh", "max", "ultra"),
        default=None,
        help="defaults to the reasoning effort recorded with the run",
    )
    adjudicate = subparsers.add_parser(
        "adjudicate",
        parents=[common],
        help="post-verdict advisory: judge whether missed recall slots were "
        "findable (writes ADJUDICATION.md; never attests mint-error itself)",
    )
    adjudicate.add_argument("--run", required=True, metavar="RUN_ID")
    adjudicate.add_argument("--results", type=Path, required=True)
    adjudicate.add_argument(
        "--target",
        type=Path,
        default=None,
        help="pristine target the run scanned (defaults to the path recorded "
        "in trial.json; required if that copy no longer exists)",
    )
    adjudicate.add_argument("--claude-bin", default="claude")
    adjudicate.add_argument(
        "--host", choices=("claude", "codex", "openai"), default=None,
        help="defaults to the host recorded when the run was launched",
    )
    adjudicate.add_argument("--codex-bin", default="codex")
    adjudicate.add_argument("--codex-model", default=None)
    adjudicate.add_argument(
        "--codex-reasoning",
        choices=("minimal", "low", "medium", "high", "xhigh", "max", "ultra"),
        default=None,
    )
    return parser.parse_args()


def _print_certification(doc: dict[str, object]) -> None:
    """End-of-run output: the six-check certification table with totals,
    then — always as the literal last line — the verdict line."""
    certification = doc.get("certification")
    if not isinstance(certification, dict):
        return
    from lucy.runtime.seal import render_certification_summary

    summary = render_certification_summary(certification)
    if summary:
        print(summary)
    final_line = certification.get("final_line")
    if final_line:
        if getattr(sys.stdout, "isatty", lambda: False)():
            from lucy.runtime.progress import EMERALD, TOPAZ

            code = EMERALD if str(final_line).endswith("CERTIFIED") else TOPAZ
            final_line = f"\033[1;{code}m{final_line}\033[0m"
        print(final_line)


def _print_resume_epilogue(receipt: dict, args: Any, run_id: str | None) -> None:
    """When a run ends unfinished, the exact resume command must be the
    LITERAL LAST LINE of output — not a hint buried mid-log above the
    verdict JSON, where it can scroll out of view."""
    certification = receipt.get("certification")
    if isinstance(certification, dict):
        # Finalized review: the state-aware certification ending already
        # owns the advice (recapture / adjudicate / accept).
        return
    if receipt.get("status") == "PASS":
        return
    run_id = run_id or str(receipt.get("run_id") or "")
    if not run_id:
        return
    results = getattr(args, "results", None)
    log_path = getattr(args, "log", None)
    command = f"lucy scan --resume {run_id} --results {results}"
    if log_path:
        command += f" --log {log_path}"
    print(
        f"\n{_lucy_prefix()} run incomplete — completed work is saved and is "
        "never re-paid. Resume (prefix with caffeinate -dims for long runs):"
    )
    print(f"  {command}")


def _recorded_host(
    results_root: Path, run_id: str
) -> tuple[str, str | None, str | None, int | None]:
    """Resolve host settings from launcher-held metadata when available."""
    resolved_results = results_root.expanduser().resolve()
    custody_trial = _recorded_custody_home(resolved_results, run_id) / "runs" / run_id / "trial.json"
    public_trial = resolved_results / "runs" / run_id / "trial.json"
    source = custody_trial if custody_trial.is_file() else public_trial
    if not source.is_file():
        raise ValueError(f"no run metadata for {run_id}")
    trial = json.loads(source.read_text(encoding="utf-8"))
    host = str(trial.get("host") or "claude")
    if host not in {"claude", "codex", "openai"}:
        raise ValueError(f"unsupported stored review host: {host}")
    model = str(trial.get("model") or "") or None
    reasoning_effort = str(trial.get("reasoning_effort") or "") or None
    max_lanes = int(trial["max_lanes"]) if trial.get("max_lanes") else None
    return host, model, reasoning_effort, max_lanes


_BUDGET_ERROR_MARKERS = ("Exceeded USD budget", "budget exhausted")


def budget_recovery_notice(
    command: str,
    error_text: str,
    *,
    run_id: str | None = None,
    results: str | None = None,
    lane_budget_usd: float | None = None,
) -> list[str]:
    """Operator guidance printed after a budget-killed lane aborts the run.

    Fail-closed stays the law — a budget-killed lane's partial output must
    never count toward quiet convergence — so this never softens the exit
    code; it only explains the stop and hands back the exact rerun. The cap
    is spend protection, not a claim: cures stay blind and lap-receipted,
    so raising it widens spend, never weakens the certification."""
    if not any(marker in error_text for marker in _BUDGET_ERROR_MARKERS):
        return []
    lines = [
        " why:   a lane hit its spend cap mid-read and was stopped. LUCY fails",
        "        closed here on purpose: a budget-killed lane's partial output",
        "        must never count toward quiet convergence.",
        " state: nothing is lost — finished lanes, receipts, and the cure-lap",
        "        ledger are preserved; rerunning resumes from them.",
    ]
    if command == "recapture" and run_id and results:
        if not lane_budget_usd:
            from lucy.runtime.host import LANE_BUDGET_USD_DEFAULT

            lane_budget_usd = LANE_BUDGET_USD_DEFAULT
        suggested = int(lane_budget_usd * 4)
        lines.append(
            f" next:  lucy recapture --run {run_id} --results {results} "
            f"--lane-budget-usd {suggested}"
        )
        lines.append(
            f"        (per-lane cap; worst case = lanes x laps x ${suggested}, "
            "but lanes only bill what they use)"
        )
    else:
        results_text = results or "<results-dir>"
        lines.append(
            f" next:  lucy scan --resume <run-id> --results {results_text} "
            "with --max-budget-usd raised, or omitted for full fidelity"
        )
    lines.append(
        " note:  the cap is spend protection only — raising it widens spend,"
    )
    lines.append(
        "        never weakens the claim; keeping it re-runs into the same wall."
    )
    return lines


def _adopt_orphaned_custody(run_id: str) -> Path | None:
    """Find a stranded .lucy-custody-* temp dir whose custody.json names
    run_id; move it to the preserved location and return its custody.json.
    Only the run-id FIELD of custody.json is read — never the answer key."""
    home = custody_home()
    for candidate in sorted(home.glob(".lucy-custody-*")):
        record_path = candidate / "custody.json"
        if not record_path.is_file():
            continue
        try:
            record = json.loads(record_path.read_text(encoding="utf-8"))
        except (OSError, ValueError, json.JSONDecodeError):
            continue
        if str(record.get("run_id", "")) != run_id:
            continue
        preserved = home / "runs" / run_id
        preserved.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if preserved.exists():
            return None
        shutil.move(str(candidate), str(preserved))
        print(
            f"{_lucy_prefix()} adopted orphaned custody for {run_id} "
            "(a previous launcher was killed before preservation could run)",
            file=sys.stderr,
        )
        return preserved / "custody.json"
    return None


def _terminate_to_exit(signum: int, frame: object) -> None:
    """Translate SIGTERM into SystemExit so every finally block runs.

    Python's default SIGTERM action kills the process WITHOUT unwinding, which
    can strand the answer key in a temporary custody directory.
    Crash-only rule: any polite termination must reach the finallys;
    only SIGKILL may skip them, and resume must cope with that."""
    raise SystemExit(128 + signum)


def install_terminate_handler() -> None:
    signal.signal(signal.SIGTERM, _terminate_to_exit)


def main() -> int:
    install_terminate_handler()
    args = parse_args()
    args.log = getattr(args, "log", None)
    args.quiet = getattr(args, "quiet", False)
    if args.log is not None:
        from lucy.runtime.progress import Tee

        # The tee log persists reviewer output derived from scanned code;
        # it gets the same two protections as every other artifact: private
        # modes (0700 dir / 0600 file) and pre-write redaction (in Tee).
        args.log.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        log_fd = os.open(str(args.log), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        log_handle = os.fdopen(log_fd, "a", encoding="utf-8")
        sys.stdout = Tee(sys.stdout, log_handle)  # type: ignore[assignment]
        sys.stderr = Tee(sys.stderr, log_handle)  # type: ignore[assignment]
    try:
        if args.command == "recapture":
            from lucy.runtime.recapture import run_recapture

            resolved_results = args.results.expanduser().resolve()
            os.environ["LUCY_CUSTODY_HOME"] = str(
                _recorded_custody_home(resolved_results, args.run)
            )
            if getattr(args, "mint_error_slot", None):
                attestations = []
                for spec in args.mint_error_slot:
                    slot_text, _, basis = str(spec).partition(":")
                    if not slot_text.strip().isdigit() or len(basis.strip()) < 12:
                        raise ValueError(
                            "--mint-error-slot requires SLOT:BASIS with a "
                            "concrete auditable basis (>=12 chars), e.g. "
                            '9:"converted locus is stale; line content unrelated to prior title"'
                        )
                    attestations.append((int(slot_text), basis.strip()))
                _attest_mint_error(args.run, attestations)

            run_directory = resolved_results / "runs" / args.run
            # Workspace by results-root convention — trial.json in the run
            # directory is reviewer-writable and must not steer agent cwd.
            workspace = resolved_results / "workspaces" / args.run
            recorded_host, recorded_model, recorded_reasoning, recorded_max_lanes = _recorded_host(
                resolved_results, args.run
            )
            selected_host = args.host or recorded_host
            require_host_tools(
                selected_host,
                selected_host,
                claude_binary=args.claude_bin,
                codex_binary=args.codex_bin,
            )
            if selected_host == "openai":
                from lucy.runtime.host import OpenAIHost

                agent_host = OpenAIHost()
            elif selected_host == "codex":
                from lucy.runtime.host import CodexAgentHost

                agent_host = CodexAgentHost(
                    codex_binary=args.codex_bin,
                    model=args.codex_model or recorded_model or "gpt-5.6-sol",
                    reasoning_effort=args.codex_reasoning or recorded_reasoning or "high",
                    metrics_path=run_directory / "receipts" / "CODEX_USAGE.jsonl",
                )
            else:
                from lucy.runtime.host import ClaudeAgentHost

                agent_host = ClaudeAgentHost(
                    claude_binary=args.claude_bin, lane_budget_usd=args.lane_budget_usd
                )
            from lucy.runtime.progress import ProgressReporter

            with ProgressReporter(run_directory, quiet=args.quiet):
                from lucy.runtime.recapture import CURE_LAP_BUDGET

                receipt = run_recapture(
                    agent_host, run_directory, workspace, resolved_results,
                    max_laps=args.max_laps,
                    cure_lap_budget=(
                        args.cure_lap_budget
                        if args.cure_lap_budget is not None
                        else CURE_LAP_BUDGET
                    ),
                    operator_budget=args.cure_lap_budget is not None,
                    width=recorded_max_lanes,
                )
            print(json.dumps({"recapture": receipt}, indent=2, sort_keys=True))
            exit_code, verdict = resume_trial(
                resolved_results,
                args.run,
                claude_binary=args.claude_bin,
                codex_binary=args.codex_bin,
                codex_model=args.codex_model,
                codex_reasoning_effort=args.codex_reasoning,
                certify=True,
                host=selected_host,
            )
            print(json.dumps(verdict, indent=2, sort_keys=True))
            _print_certification(verdict)
            return 0 if (verdict.get("certification") or {}).get("certified") else 3
        if args.command == "adjudicate":
            from lucy.runtime.adjudicate import run_adjudication

            resolved_results = args.results.expanduser().resolve()
            run_directory = resolved_results / "runs" / args.run
            workspace = resolved_results / "workspaces" / args.run
            recorded_host, recorded_model, recorded_reasoning, _ = _recorded_host(
                resolved_results, args.run
            )
            selected_host = args.host or recorded_host
            require_host_tools(
                selected_host,
                selected_host,
                claude_binary=args.claude_bin,
                codex_binary=args.codex_bin,
            )
            if selected_host == "codex":
                from lucy.runtime.host import CodexAgentHost

                adjudication_host = CodexAgentHost(
                    codex_binary=args.codex_bin,
                    model=args.codex_model or recorded_model or "gpt-5.6-sol",
                    reasoning_effort=args.codex_reasoning or recorded_reasoning or "high",
                    metrics_path=run_directory / "receipts" / "CODEX_USAGE.jsonl",
                )
            elif selected_host == "openai":
                from lucy.runtime.host import OpenAIHost

                adjudication_host = OpenAIHost()
            else:
                from lucy.runtime.host import ClaudeAgentHost

                adjudication_host = ClaudeAgentHost(claude_binary=args.claude_bin)
            adjudicate_target = args.target
            if adjudicate_target is None:
                trial_doc = json.loads(
                    (run_directory / "trial.json").read_text(encoding="utf-8")
                )
                adjudicate_target = Path(str(trial_doc.get("target", "")))
            adjudicate_target = adjudicate_target.expanduser().resolve()
            if not adjudicate_target.is_dir():
                print(
                    "run failed: the pristine target copy is required for the "
                    f"diff oracle and {adjudicate_target} does not exist — "
                    "pass --target",
                    file=sys.stderr,
                )
                return 2
            print(
                f"{_lucy_prefix()} adjudicator running — one read-only agent "
                "over the evidence brief; silence until the verdict is "
                "normal (typically 5-15 minutes, 60-minute cap)",
                file=sys.stderr,
            )
            verdict_path = run_adjudication(
                run_directory,
                adjudicate_target,
                workspace,
                adjudication_host,
            )
            _write_codex_usage_receipt(run_directory, resolved_results)
            # The verdict IS the product: print it, never just a path.
            print(verdict_path.read_text(encoding="utf-8"))
            print(f"written to: {verdict_path}")
            print(
                f"{_lucy_prefix()} advisory only: any --mint-error-slot "
                "attestation remains an operator decision.",
                file=sys.stderr,
            )
            return 0
        if args.command == "export":
            from lucy.runtime.sarif import to_sarif

            report = json.loads(args.report.read_text(encoding="utf-8"))
            output = args.output or args.report.with_suffix(".sarif")
            output.write_text(
                json.dumps(to_sarif(report), indent=2) + "\n", encoding="utf-8"
            )
            print(str(output))
            return 0
        if args.resume:
            exit_code, receipt = resume_trial(
                args.results,
                args.resume,
                claude_binary=args.claude_bin,
                codex_binary=args.codex_bin,
                codex_model=args.codex_model,
                codex_reasoning_effort=args.codex_reasoning,
                print_mode=args.print,
                max_budget_usd=args.max_budget_usd,
                certify=(args.command == "scan"),
                host=args.host,
            )
            print(json.dumps(receipt, indent=2, sort_keys=True))
            _print_certification(receipt)
            _print_resume_epilogue(receipt, args, args.resume)
            return exit_code if exit_code else (0 if receipt.get("status") == "PASS" else 3)
        if args.target is None:
            print("run failed: --target is required unless --resume is given", file=sys.stderr)
            return 2
        selected_host = args.host or "claude"
        selected_planter = selected_host if args.planter == "auto" else args.planter
        selected_codex_model = args.codex_model or "gpt-5.6-sol"
        selected_codex_reasoning = args.codex_reasoning or "high"
        if selected_planter == "fixture" and os.environ.get("LUCY_FIXTURE_PLANTER") != "allow":
            print(
                "run failed: --planter fixture executes tools/plant_canaries.py "
                "FROM THE SCANNED REPOSITORY and exists for test estates only. "
                "Set LUCY_FIXTURE_PLANTER=allow if that is genuinely intended.",
                file=sys.stderr,
            )
            return 2
        if (selected_host == "codex" or selected_planter == "codex") and (
            args.max_budget_usd is not None or args.planter_budget_usd is not None
        ):
            print(
                "run failed: dollar budget flags are not enforceable with saved-login "
                "Codex runs; use workspace usage controls or omit the flags",
                file=sys.stderr,
            )
            return 2
        estimate = estimate_cost(args.target)
        estimate["confidence"] = (
            "heuristic; reasoning-heavy workloads can exceed this band — "
            "treat it as planning guidance, not a budget"
        )
        estimate["host"] = selected_host
        if selected_host == "codex":
            estimate["estimated_usd"] = None
            estimate.pop("usd_per_mtoken", None)
            estimate["cost_note"] = (
                "saved-login Codex usage is plan/credit based; token usage is "
                "receipted after the run, but codex exec exposes no authoritative "
                "per-run dollar charge"
            )
        print(json.dumps({"cost_estimate": estimate}, indent=2, sort_keys=True))
        # Target-shape guards. Empty (or binary-only) repositories are a
        # clean, honest non-event, not an error; tiny ones get a warning
        # rather than a cryptic planter failure ten minutes in.
        scannable = int(estimate.get("scannable_loc", 0) or 0)
        if scannable == 0:
            print(
                f"{_lucy_prefix()} target has no scannable source; nothing to scan.",
                file=sys.stderr,
            )
            print(json.dumps({"schema": "lucy-trial-verdict/v1", "status": "NOTHING_TO_SCAN"}))
            return 0
        if scannable < 400:
            print(
                f"{_lucy_prefix()} WARNING: only {scannable} scannable lines. The "
                "8-canary recall protocol needs room to hide mutations; on a "
                "target this small the planter may fail and certification "
                "statistics are unreliable.",
                file=sys.stderr,
            )
        if args.max_budget_usd is not None or args.planter_budget_usd is not None:
            notice_paint = "\033[33m" if getattr(sys.stderr, "isatty", lambda: False)() else ""
            print(
                (notice_paint or "") + "FIDELITY NOTICE: a budget cap is set. LUCY's priority is recall; "
                "a run stopped on budget may miss findings and will not certify "
                "until resumed or recaptured. Remove the cap for full fidelity."
                + ("\033[0m" if notice_paint else ""),
                file=sys.stderr,
            )
        if args.estimate_only:
            return 0
        exit_code, receipt = launch_trial(
            args.target,
            args.results,
            claude_binary=args.claude_bin,
            codex_binary=args.codex_bin,
            codex_model=selected_codex_model,
            codex_reasoning_effort=selected_codex_reasoning,
            print_mode=args.print,
            max_budget_usd=args.max_budget_usd,
            planter=selected_planter,
            planter_budget_usd=args.planter_budget_usd,
            certify=(args.command == "scan"),
            priors_path=args.priors,
            cold_priors=args.cold_priors,
            host=selected_host,
            quiet=args.quiet,
        )
        print(json.dumps(receipt, indent=2, sort_keys=True))
        _print_certification(receipt)
        _print_resume_epilogue(receipt, args, None)
        return exit_code if exit_code else (0 if receipt.get("status") == "PASS" else 3)
    except KeyboardInterrupt:
        print(
            f"\n{_lucy_prefix()} interrupted. If a run id was printed, resume with: "
            "lucy scan --resume <run-id> --results <results-dir>",
            file=sys.stderr,
        )
        return 130
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as error:
        print(f"run failed: {error}", file=sys.stderr)
        for line in budget_recovery_notice(
            getattr(args, "command", "") or "",
            str(error),
            run_id=getattr(args, "run", None),
            results=(str(args.results) if getattr(args, "results", None) else None),
            lane_budget_usd=getattr(args, "lane_budget_usd", None),
        ):
            print(line, file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
