"""Launch and validate a separate ephemeral Claude canary planter."""

from __future__ import annotations

from collections import Counter
import hashlib
import json
import os
from pathlib import Path
import re
import subprocess
from typing import Any

from lucy.runtime.syntax_check import SyntaxValidationError, validate_mutation


FAMILIES = ("L1-auth", "L2-secrets", "L3-injection", "L4-infra")
FORBIDDEN_PATH_PARTS = {
    ".claude",
    ".github",
    "docs",
    "examples",
    "fixture",
    "fixtures",
    "node_modules",
    "tests",
    "test",
    "vendor",
    "vendored",
}


def forbidden_paths_clause() -> str:
    """The enforced no-plant directory list, spelled out for the planter's
    prompt. The validator rejects the whole answer key on any violation, so
    the agent must see the exact machine-enforced names, not a paraphrase."""
    names = ", ".join(sorted(FORBIDDEN_PATH_PARTS))
    return (
        "HARD CONSTRAINT: never plant in a file whose path contains any of "
        f"these directory names (the launcher rejects the entire run if you do): {names}. "
        "Also never leave trailing whitespace on any line you add or change - "
        "the diff is whitespace-validated and one trailing space rejects the run."
    )


def placement_clause() -> str:
    """Placement law, spelled out for the planter's prompt (same machine-
    enforcement rule as the forbidden-path list: the validator rejects the
    whole key on violation, so the agent must see the exact law)."""
    return (
        "PLACEMENT LAW: the two plants of each family must land in TWO "
        "DIFFERENT FILES (the launcher rejects the entire answer key if a "
        "family's plants share a file — report folding can merge nearby "
        "same-family defects, and a merged report can never satisfy two "
        "recall slots). Spread the eight plants across eight distinct "
        "locations in at least five different files."
    )
FORBIDDEN_MARKERS = re.compile(
    r"(?i)\b(lucy|canary|planted|scanner|vulnerability|intentionally insecure)\b"
)
# Marker validation is DIFF-SCOPED: only lines the planter ADDED are checked.
# Real estates legitimately contain words like "synthetic" in identifiers
# (e.g. SyntheticAccount), so whole-file scanning would reject valid targets;
# "synthetic" is therefore only forbidden on added lines when it appears as a
# standalone giveaway, handled by the added-line regex below.
ADDED_LINE_MARKERS = re.compile(
    r"(?i)\b(lucy|canary|planted|scanner|vulnerability|intentionally insecure|recall.test)\b"
)


def planter_environment() -> dict[str, str]:
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
    return environment


def launch_claude_planter(
    workspace: Path,
    skill_root: Path,
    *,
    claude_binary: str = "claude",
    max_budget_usd: float | None = None,
    retry_hint: str = "",
) -> dict[str, Any]:
    schema = (skill_root / "planter" / "answer-key.schema.json").read_text(encoding="utf-8")
    system_prompt = (skill_root / "planter" / "SYSTEM.md").read_text(encoding="utf-8")
    command = [
        claude_binary,
        "--safe-mode",
        "--setting-sources",
        "local",
        "--settings",
        '{"env":{"CLAUDE_CODE_USE_BEDROCK":"","ANTHROPIC_MODEL":"","ANTHROPIC_CUSTOM_HEADERS":""}}',
        "--print",
        "--no-session-persistence",
        "--permission-mode",
        "acceptEdits",
        "--tools",
        "Read,Edit,Grep,Glob",
        "--system-prompt",
        system_prompt,
        "--json-schema",
        schema,
        "--output-format",
        "json",
    ]
    if max_budget_usd is not None:
        command.extend(["--max-budget-usd", str(max_budget_usd)])
    command.append(
        "Inspect this disposable repository, plant the eight required defects, "
        "and return the answer key. "
        + forbidden_paths_clause()
        + " "
        + placement_clause()
        + (
            f" A previous planting attempt was rejected by the validator: {retry_hint} "
            "— the workspace has been reset; plant fresh and do not repeat that mistake."
            if retry_hint
            else ""
        )
    )
    result = subprocess.run(
        command,
        cwd=workspace,
        env=planter_environment(),
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        detail = (result.stderr or result.stdout or f"exit {result.returncode}").strip()
        raise RuntimeError(f"Claude planter failed: {detail}")
    response = json.loads(result.stdout)
    answer_key = response.get("structured_output")
    if not isinstance(answer_key, dict):
        raise ValueError("Claude planter returned no structured_output")
    return validate_answer_key(answer_key, workspace)


def launch_host_planter(workspace: Path, skill_root: Path, host: Any) -> dict[str, Any]:
    """Plant via an API host agent loop (edit-capable workspace tools only).

    Same mechanical validation as the Claude planter; the host planter has no
    shell, no network, and no paths outside the disposable workspace.
    """
    system_prompt = (skill_root / "planter" / "SYSTEM.md").read_text(encoding="utf-8")
    response = host.run_agent(
        system=system_prompt,
        task=(
            "Inspect this disposable repository with your tools, plant the eight "
            "required defects by editing existing files, then return ONLY the "
            "answer-key JSON object (schema lucy-answer-key/v1: {\"schema\":..., "
            "\"canaries\":[{\"slot\":1,\"family\":\"L1-auth\",\"path\":...,"
            "\"line\":...,\"title\":...,\"reachability\":\"<caller/route "
            "that makes the defect real>\"}]}). No markdown. "
            + forbidden_paths_clause()
            + " "
            + placement_clause()
        ),
        workspace=workspace,
        allow_edit=True,
        max_turns=120,
    )
    text = response.strip()
    start, end = text.find("{"), text.rfind("}")
    if start < 0 or end <= start:
        raise ValueError("host planter returned no answer-key JSON")
    answer_key = json.loads(text[start : end + 1])
    return validate_answer_key(answer_key, workspace)


def _normalize_trailing_whitespace(workspace: Path) -> None:
    """Cure the whitespace tells git flags on exactly the planted lines.

    Planters can leave them despite prompt rules. Two shapes exist: literal trailing
    spaces, and a CRLF line inside an otherwise-LF diff (the Edit tool mixes
    endings; git reports the stray CR as trailing whitespace). Both are
    mechanical, so the cure is mechanical AND byte-exact: work in binary
    (text mode's universal newlines silently eat the CR — the first fix
    attempt missed for exactly that reason), rstrip spaces/tabs/CR from only
    the flagged line, and re-terminate it with the file's majority ending.
    Anything this cannot cure still fails closed downstream."""
    for _ in range(3):
        check = subprocess.run(
            ["git", "diff", "--check"], cwd=workspace, capture_output=True, text=True, check=False
        )
        if check.returncode == 0:
            return
        fixed_any = False
        for report in check.stdout.splitlines():
            match = re.match(r"^(.+?):(\d+): trailing whitespace\.$", report.strip())
            if not match:
                continue
            path = workspace / match.group(1)
            index = int(match.group(2)) - 1
            try:
                blob = path.read_bytes()
            except OSError:
                continue
            lines = blob.splitlines(keepends=True)
            if not (0 <= index < len(lines)):
                continue
            crlf = blob.count(b"\r\n")
            majority = b"\r\n" if crlf > blob.count(b"\n") - crlf else b"\n"
            line = lines[index]
            had_newline = line.endswith(b"\n")
            body = line.rstrip(b" \t\r\n")
            replacement = body + (majority if had_newline else b"")
            if replacement != line:
                lines[index] = replacement
                path.write_bytes(b"".join(lines))
                fixed_any = True
        if not fixed_any:
            return


def validate_answer_key(answer_key: dict[str, Any], workspace: Path) -> dict[str, Any]:
    if answer_key.get("schema") != "lucy-answer-key/v1":
        raise ValueError("unsupported answer-key schema")
    _normalize_trailing_whitespace(workspace)
    changed_entries = _changed_entries(workspace)
    invalid_statuses = {
        path: status for path, status in changed_entries.items() if status not in {" M", "M "}
    }
    if invalid_statuses:
        raise ValueError(f"planter must only modify existing files: {invalid_statuses}")
    changed_paths = set(changed_entries)
    canaries = answer_key.get("canaries")
    if not isinstance(canaries, list) or len(canaries) != 8:
        raise ValueError("answer key must contain exactly eight canaries")
    slots = [row.get("slot") for row in canaries if isinstance(row, dict)]
    if sorted(slots) != list(range(1, 9)):
        raise ValueError("answer-key slots must be exactly 1 through 8")
    counts = Counter(str(row.get("family")) for row in canaries)
    if counts != Counter({family: 2 for family in FAMILIES}):
        raise ValueError(f"invalid canary family spread: {dict(counts)}")
    check_placement_law(canaries)
    loci = set()
    normalized_rows = []
    for row in canaries:
        relative = Path(str(row.get("path", "")))
        if relative.is_absolute() or ".." in relative.parts or not relative.parts:
            raise ValueError("answer-key paths must be normalized and relative")
        if any(part.lower() in FORBIDDEN_PATH_PARTS for part in relative.parts):
            raise ValueError(f"canary uses forbidden path: {relative}")
        if relative.as_posix() not in changed_paths:
            raise ValueError(f"answer-key path was not modified: {relative}")
        line_number = row.get("line")
        if not isinstance(line_number, int) or isinstance(line_number, bool) or line_number < 1:
            raise ValueError("canary line must be a positive integer")
        # Semantic mint-quality floor: the planter must NAME the concrete
        # caller/route that makes each defect real. A mutation with no caller
        # is semantically inert even if it passes structural validation.
        # Recorded for adjudication;
        # reviewers never see it.
        reachability = str(row.get("reachability", "")).strip()
        if len(reachability) < 12:
            raise ValueError(
                f"canary slot {row.get('slot')} missing reachability rationale "
                "(name the caller/route that makes the defect real)"
            )
        path = workspace / relative
        file_content = path.read_text(encoding="utf-8")
        for added_line_number, added_text in _added_lines(workspace, relative.as_posix()):
            if ADDED_LINE_MARKERS.search(added_text):
                raise ValueError(
                    f"planted diff exposes scanner terminology: {relative}:{added_line_number}"
                )
        lines = file_content.splitlines()
        if line_number > len(lines):
            raise ValueError(f"canary line is outside file: {relative}:{line_number}")
        line = lines[line_number - 1]
        if FORBIDDEN_MARKERS.search(line):
            raise ValueError(f"planted line exposes scanner terminology: {relative}:{line_number}")
        locus = (relative.as_posix(), line_number)
        if locus in loci:
            raise ValueError(f"duplicate canary locus: {relative}:{line_number}")
        loci.add(locus)
        normalized = dict(row)
        normalized["mutation_sha256"] = hashlib.sha256(line.encode()).hexdigest()
        normalized_rows.append(normalized)
    if set(changed_paths) != {str(row["path"]) for row in canaries}:
        raise ValueError("planter changed files not represented in answer key")
    bases = _validate_changed_syntax(workspace, changed_paths)
    for normalized in normalized_rows:
        normalized["syntax_validation"] = bases.get(str(normalized["path"]), "heuristic")
    diff_check = subprocess.run(
        ["git", "diff", "--check"], cwd=workspace, capture_output=True, text=True, check=False
    )
    if diff_check.returncode != 0:
        raise ValueError(f"planted diff failed whitespace validation: {diff_check.stdout.strip()}")
    return {"schema": "lucy-answer-key/v1", "canaries": normalized_rows}


def check_placement_law(canaries: list[dict[str, Any]]) -> None:
    """PLACEMENT LAW: same-family plants must land in different files.

    Locus folding can merge nearby same-lens reports, and readers can merge
    adjacent same-class sinks into one row, leaving one candidate to serve
    two slots under 1:1 scoring. Disjoint files make each slot's candidate pool
    independent, which also makes greedy 1:1 assignment optimal."""
    by_family: dict[str, list[str]] = {}
    for row in canaries:
        if not isinstance(row, dict) or row.get("historical"):
            continue
        by_family.setdefault(str(row.get("family")), []).append(
            str(row.get("path", ""))
        )
    for family, paths in sorted(by_family.items()):
        if len(set(paths)) != len(paths):
            raise ValueError(
                f"placement law: both {family} plants share one file "
                f"({paths[0]}) — same-family plants must land in different "
                "files (a folded or merged report can never satisfy two "
                "slots under 1:1 recall scoring)"
            )


# Plantability census. ADVISORY, never a law: the placement law itself is
# class-blind (any two distinct files satisfy it), so the census predicts
# planter behavior — it must never hard-refuse a run because its suffix list
# is narrower than the reader universe (for example, extensionless shebang
# scripts and other census-supported types).
#
# Input paths come FROM the reader-unit census, so reader eligibility is
# already decided upstream; this only buckets eligible files into family
# classes. Anything eligible that is not config/IaC is code ("source"),
# which makes the bucketing match the reader universe by construction.
_PLANT_CONFIG_SUFFIXES = {
    ".yml", ".yaml", ".properties", ".json", ".xml", ".toml", ".ini",
    ".cfg", ".conf", ".env",
}
_PLANT_IAC_SUFFIXES = {".tf", ".tfvars"}
_PLANT_IAC_NAMES = ("dockerfile", "docker-compose", "jenkinsfile", "containerfile")

# Where each family USUALLY plants (advisory prediction; families may
# legitimately plant elsewhere — e.g. an L4 TLS-verification defect in
# code — which is exactly why the census only warns).
FAMILY_PLANT_CLASSES = {
    "L1-auth": ("source", "config"),
    "L2-secrets": ("source", "config"),
    "L3-injection": ("source",),
    "L4-infra": ("iac", "config"),
}


def classify_plantable(path: str) -> set[str]:
    """Bucket one READER-ELIGIBLE path into plant classes; empty only for
    the forbidden-plant directories (eligibility itself is upstream)."""
    parts = Path(path).parts
    if any(part.lower() in FORBIDDEN_PATH_PARTS for part in parts):
        return set()
    name = Path(path).name.lower()
    suffix = Path(path).suffix.lower()
    classes: set[str] = set()
    if suffix in _PLANT_CONFIG_SUFFIXES:
        classes.add("config")
    if suffix in _PLANT_IAC_SUFFIXES or any(name.startswith(m) for m in _PLANT_IAC_NAMES):
        classes.add("iac")
    if not classes:
        # Reader-eligible and neither config nor IaC = code, including
        # extensionless shebang scripts (the census already admitted them).
        classes.add("source")
    return classes


def plant_feasibility(candidate_paths: set[str]) -> dict[str, Any]:
    """Deterministic pre-plant census: can every family place two plants
    in two different files inside the reader universe?

    Advisory only — the caller WARNS on shortfall (naming the thin file
    class) and lets key validation remain the enforcing law."""
    eligible: dict[str, int] = {}
    for family, wanted in FAMILY_PLANT_CLASSES.items():
        count = 0
        for path in candidate_paths:
            if classify_plantable(path) & set(wanted):
                count += 1
        eligible[family] = count
    infeasible = sorted(f for f, n in eligible.items() if n < 2)
    tight = sorted(f for f, n in eligible.items() if 2 <= n <= 3)
    return {
        "eligible_files": eligible,
        "infeasible_families": infeasible,
        "tight_families": tight,
        "feasible": not infeasible,
    }


def _changed_entries(workspace: Path) -> dict[str, str]:
    result = subprocess.run(
        ["git", "status", "--short"], cwd=workspace, capture_output=True, text=True, check=True
    )
    paths = {}
    for line in result.stdout.splitlines():
        if not line.strip():
            continue
        path = line[3:].strip()
        if " -> " in path:
            path = path.split(" -> ", 1)[1]
        paths[path] = line[:2]
    return paths


def _validate_changed_syntax(workspace: Path, changed_paths: set[str]) -> dict[str, str]:
    """Validate mutations across all supported languages.

    Compares post-mutation parse health against the committed baseline
    (``git show HEAD:path``) so pre-existing parse damage in a real estate
    never blocks planting; only NEW damage does. Returns path -> basis.
    """
    bases: dict[str, str] = {}
    for relative in sorted(changed_paths):
        path = workspace / relative
        after = path.read_text(encoding="utf-8")
        show = subprocess.run(
            ["git", "show", f"HEAD:{relative}"],
            cwd=workspace,
            capture_output=True,
            text=True,
            check=False,
        )
        before = show.stdout if show.returncode == 0 else ""
        try:
            bases[relative] = validate_mutation(relative, before, after)
        except SyntaxValidationError as error:
            raise ValueError(f"planted file failed syntax validation: {error}") from error
    return bases


def _added_lines(workspace: Path, relative: str) -> list[tuple[int, str]]:
    """Return (new_line_number, text) for every line the plant ADDED."""
    diff = subprocess.run(
        ["git", "diff", "-U0", "--", relative],
        cwd=workspace,
        capture_output=True,
        text=True,
        check=False,
    ).stdout
    added: list[tuple[int, str]] = []
    new_line = 0
    for line in diff.splitlines():
        if line.startswith("@@"):
            match = re.search(r"\+(\d+)", line)
            new_line = int(match.group(1)) if match else 0
        elif line.startswith("+") and not line.startswith("+++"):
            added.append((new_line, line[1:]))
            new_line += 1
    return added
