"""Unit tests for multi-language mutation syntax validation."""

from __future__ import annotations

from pathlib import Path
import sys
import unittest

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from lucy.runtime.syntax_check import (  # noqa: E402
    SyntaxValidationError,
    tree_sitter_available,
    validate_mutation,
)


class StdlibValidationTests(unittest.TestCase):
    def test_python_mutation_must_parse(self) -> None:
        self.assertEqual(validate_mutation("a.py", "x = 1\n", "x = 2\n"), "stdlib")
        with self.assertRaises(SyntaxValidationError):
            validate_mutation("a.py", "x = 1\n", "x = = 2\n")

    def test_json_and_toml(self) -> None:
        self.assertEqual(validate_mutation("a.json", "{}", '{"a": 1}'), "stdlib")
        with self.assertRaises(SyntaxValidationError):
            validate_mutation("a.json", "{}", "{broken")
        self.assertEqual(validate_mutation("a.toml", "a = 1\n", "a = 2\n"), "stdlib")

    def test_yaml_tab_introduction_rejected(self) -> None:
        with self.assertRaises(SyntaxValidationError):
            validate_mutation("a.yaml", "a: 1\n", "a:\n\tb: 2\n")

    def test_unknown_extension_uses_heuristic(self) -> None:
        self.assertEqual(
            validate_mutation("a.xyz", "call(1)\n", "call(2)\n"), "heuristic"
        )
        with self.assertRaises(SyntaxValidationError):
            validate_mutation("a.xyz", "call(1)\n", "call(2\n")


class TreeSitterValidationTests(unittest.TestCase):
    def setUp(self) -> None:
        if not tree_sitter_available(".java"):
            self.skipTest("tree-sitter grammars not installed")

    def test_java_mutation_no_new_errors(self) -> None:
        good = "class A { void f() {} }"
        self.assertEqual(
            validate_mutation("A.java", good, "class A { void f() { int x = 1; } }"),
            "tree-sitter",
        )
        with self.assertRaises(SyntaxValidationError):
            validate_mutation("A.java", good, "class A { void f() { int x = ; } }")

    def test_preexisting_damage_never_blocks(self) -> None:
        broken = "class B { void g() { int y = ; } }"
        self.assertEqual(
            validate_mutation("B.java", broken, broken.replace("int y", "int z")),
            "tree-sitter",
        )

    def test_terraform_and_csharp(self) -> None:
        self.assertEqual(
            validate_mutation(
                "m.tf",
                'resource "aws_x" "y" { a = 1 }',
                'resource "aws_x" "y" { a = 2 }',
            ),
            "tree-sitter",
        )
        with self.assertRaises(SyntaxValidationError):
            validate_mutation("P.cs", "class P { }", "class P { void f( }")


if __name__ == "__main__":
    unittest.main()
