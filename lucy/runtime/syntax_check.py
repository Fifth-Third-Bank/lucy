"""Multi-language syntax validation for planted mutations.

Primary engine: tree-sitter grammars (via ``tree_sitter_language_pack`` or the
older ``tree_sitter_languages``). Rule: a mutation may introduce NO NEW parse
errors relative to the pre-mutation content — real estates legitimately contain
files that never parsed cleanly, so absolute-zero-error rules would block
planting there.

Python/JSON/TOML keep exact stdlib parsers. Unknown extensions (and any file
when tree-sitter is unavailable) fall back to a delimiter-balance heuristic.
Every validation records its basis: ``stdlib`` | ``tree-sitter`` |
``heuristic``.
"""

from __future__ import annotations

import ast
import json
import tomllib
from typing import Callable, Optional


TREE_SITTER_LANGUAGES = {
    ".java": "java",
    ".kt": "kotlin",
    ".kts": "kotlin",
    ".cs": "csharp",
    ".js": "javascript",
    ".mjs": "javascript",
    ".cjs": "javascript",
    ".jsx": "javascript",
    ".ts": "typescript",
    ".tsx": "tsx",
    ".rb": "ruby",
    ".go": "go",
    ".php": "php",
    ".rs": "rust",
    ".c": "c",
    ".h": "c",
    ".cpp": "cpp",
    ".cc": "cpp",
    ".hpp": "cpp",
    ".tf": "hcl",
    ".hcl": "hcl",
    ".yaml": "yaml",
    ".yml": "yaml",
    ".sh": "bash",
    ".bash": "bash",
    ".sql": "sql",
    ".swift": "swift",
    ".scala": "scala",
    ".groovy": "groovy",
    ".lua": "lua",
}

_PAIRS = {"(": ")", "[": "]", "{": "}"}
_CLOSERS = {close: open_ for open_, close in _PAIRS.items()}


class SyntaxValidationError(ValueError):
    """A mutation introduced new syntax damage."""


def _get_parser(language: str):
    try:
        from tree_sitter_language_pack import get_parser  # type: ignore

        return get_parser(language)
    except Exception:
        pass
    try:
        from tree_sitter_languages import get_parser  # type: ignore

        return get_parser(language)
    except Exception:
        return None


def tree_sitter_available(extension: str) -> bool:
    language = TREE_SITTER_LANGUAGES.get(extension.lower())
    return language is not None and _get_parser(language) is not None


def _count_errors(parser, content: str) -> int:
    tree = parser.parse(content.encode("utf-8", "replace"))
    count = 0
    cursor = tree.walk()
    visited = False
    while True:
        node = cursor.node
        if not visited:
            if node.type == "ERROR" or node.is_missing:
                count += 1
            if cursor.goto_first_child():
                continue
        if cursor.goto_next_sibling():
            visited = False
            continue
        if not cursor.goto_parent():
            return count
        visited = True


def _balance_score(content: str) -> int:
    """Crude delimiter imbalance count, string/comment-blind by design."""
    stack: list[str] = []
    imbalance = 0
    for char in content:
        if char in _PAIRS:
            stack.append(char)
        elif char in _CLOSERS:
            if stack and stack[-1] == _CLOSERS[char]:
                stack.pop()
            else:
                imbalance += 1
    return imbalance + len(stack)


def _stdlib_check(extension: str, content: str) -> Optional[Callable[[], None]]:
    if extension == ".py":
        return lambda: ast.parse(content)
    if extension == ".json":
        return lambda: json.loads(content)
    if extension == ".toml":
        return lambda: tomllib.loads(content)
    return None


def validate_mutation(path: str, before: str, after: str) -> str:
    """Validate that ``after`` introduces no new syntax damage vs ``before``.

    Returns the validation basis. Raises :class:`SyntaxValidationError` when
    the mutation makes the file measurably worse.
    """
    extension = "." + path.rsplit(".", 1)[-1].lower() if "." in path else ""
    name = path.rsplit("/", 1)[-1]
    if name in {"Dockerfile", "Makefile", "Jenkinsfile"}:
        extension = {"Dockerfile": ".dockerfile", "Makefile": ".mk", "Jenkinsfile": ".groovy"}[name]

    checker = _stdlib_check(extension, after)
    if checker is not None:
        try:
            checker()
        except (SyntaxError, json.JSONDecodeError, tomllib.TOMLDecodeError) as error:
            raise SyntaxValidationError(f"{path}: {error}") from error
        return "stdlib"

    if extension in {".yaml", ".yml"} and "\t" in after and "\t" not in before:
        raise SyntaxValidationError(f"{path}: mutation introduced YAML tab indentation")

    language = TREE_SITTER_LANGUAGES.get(extension)
    if language is not None:
        parser = _get_parser(language)
        if parser is not None:
            before_errors = _count_errors(parser, before)
            after_errors = _count_errors(parser, after)
            if after_errors > before_errors:
                raise SyntaxValidationError(
                    f"{path}: mutation introduced {after_errors - before_errors} new "
                    f"parse error(s) ({language})"
                )
            return "tree-sitter"

    if _balance_score(after) > _balance_score(before):
        raise SyntaxValidationError(f"{path}: mutation worsened delimiter balance")
    return "heuristic"
