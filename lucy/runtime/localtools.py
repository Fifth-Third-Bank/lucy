"""Workspace-bound file tools for API-driven agent loops.

These are the ONLY capabilities an API-hosted reader/court/planter gets: no
shell, no network, no paths outside the workspace. This is a strictly smaller
surface than the Claude Code host's pinned allowlist.
"""

from __future__ import annotations

import fnmatch
from pathlib import Path
import re
from typing import Any


MAX_READ_LINES = 400
MAX_GREP_HITS = 200


class WorkspaceTools:
    def __init__(self, workspace: Path, allow_edit: bool = False) -> None:
        self.workspace = workspace.resolve()
        self.allow_edit = allow_edit

    def _resolve(self, relative: str) -> Path:
        path = (self.workspace / relative).resolve()
        if path != self.workspace and self.workspace not in path.parents:
            raise ValueError(f"path escapes workspace: {relative}")
        return path

    def read_file(self, path: str, offset: int = 1, limit: int = MAX_READ_LINES) -> str:
        resolved = self._resolve(path)
        if not resolved.is_file():
            return f"ERROR: no such file: {path}"
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
        offset = max(1, int(offset))
        limit = min(int(limit), MAX_READ_LINES)
        window = lines[offset - 1 : offset - 1 + limit]
        body = "\n".join(f"{offset + index}\t{text}" for index, text in enumerate(window))
        suffix = "" if offset - 1 + limit >= len(lines) else f"\n... ({len(lines)} lines total)"
        return body + suffix

    def grep(self, pattern: str, glob: str = "**/*") -> str:
        try:
            expression = re.compile(pattern)
        except re.error as error:
            return f"ERROR: bad pattern: {error}"
        hits: list[str] = []
        for path in sorted(self.workspace.rglob("*")):
            if not path.is_file() or ".git" in path.parts:
                continue
            relative = path.relative_to(self.workspace).as_posix()
            if not fnmatch.fnmatch(relative, glob):
                continue
            try:
                for number, line in enumerate(
                    path.read_text(encoding="utf-8", errors="replace").splitlines(), 1
                ):
                    if expression.search(line):
                        hits.append(f"{relative}:{number}: {line.strip()[:200]}")
                        if len(hits) >= MAX_GREP_HITS:
                            return "\n".join(hits) + "\n... (hit cap)"
            except OSError:
                continue
        return "\n".join(hits) if hits else "no matches"

    def list_files(self, glob: str = "**/*") -> str:
        names = [
            path.relative_to(self.workspace).as_posix()
            for path in sorted(self.workspace.rglob("*"))
            if path.is_file() and ".git" not in path.parts
            and fnmatch.fnmatch(path.relative_to(self.workspace).as_posix(), glob)
        ]
        return "\n".join(names[:2000])

    def edit_file(self, path: str, old: str, new: str) -> str:
        if not self.allow_edit:
            return "ERROR: editing is not permitted for this role"
        resolved = self._resolve(path)
        if not resolved.is_file():
            return f"ERROR: no such file: {path}"
        content = resolved.read_text(encoding="utf-8", errors="replace")
        if old not in content:
            return "ERROR: old text not found"
        if content.count(old) > 1:
            return "ERROR: old text is not unique; include more context"
        resolved.write_text(content.replace(old, new, 1), encoding="utf-8")
        return "ok"

    def dispatch(self, name: str, arguments: dict[str, Any]) -> str:
        handlers = {
            "read_file": lambda: self.read_file(
                str(arguments.get("path", "")),
                int(arguments.get("offset", 1) or 1),
                int(arguments.get("limit", MAX_READ_LINES) or MAX_READ_LINES),
            ),
            "grep": lambda: self.grep(
                str(arguments.get("pattern", "")), str(arguments.get("glob", "**/*"))
            ),
            "list_files": lambda: self.list_files(str(arguments.get("glob", "**/*"))),
            "edit_file": lambda: self.edit_file(
                str(arguments.get("path", "")),
                str(arguments.get("old", "")),
                str(arguments.get("new", "")),
            ),
        }
        handler = handlers.get(name)
        if handler is None:
            return f"ERROR: unknown tool {name}"
        try:
            return handler()
        except ValueError as error:
            return f"ERROR: {error}"


def tool_schemas(allow_edit: bool = False) -> list[dict[str, Any]]:
    schemas = [
        {
            "type": "function",
            "function": {
                "name": "read_file",
                "description": "Read a file from the workspace (line-numbered; bounded window).",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "path": {"type": "string"},
                        "offset": {"type": "integer"},
                        "limit": {"type": "integer"},
                    },
                    "required": ["path"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "grep",
                "description": "Regex search across workspace files; optional glob filter.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "pattern": {"type": "string"},
                        "glob": {"type": "string"},
                    },
                    "required": ["pattern"],
                },
            },
        },
        {
            "type": "function",
            "function": {
                "name": "list_files",
                "description": "List workspace files matching a glob.",
                "parameters": {
                    "type": "object",
                    "properties": {"glob": {"type": "string"}},
                    "required": [],
                },
            },
        },
    ]
    if allow_edit:
        schemas.append(
            {
                "type": "function",
                "function": {
                    "name": "edit_file",
                    "description": "Replace one unique occurrence of old text with new text.",
                    "parameters": {
                        "type": "object",
                        "properties": {
                            "path": {"type": "string"},
                            "old": {"type": "string"},
                            "new": {"type": "string"},
                        },
                        "required": ["path", "old", "new"],
                    },
                },
            }
        )
    return schemas
