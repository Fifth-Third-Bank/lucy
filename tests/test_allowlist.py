"""Permission-surface lint: no unpinned shell grants anywhere in the product.

Guards the phase-0 security decision: the skill and launcher may grant only
read-only git verbs, read-only search, and the pinned lucy-* wrappers. An
unpinned python3/git/bash grant is an egress and write channel.
"""

from __future__ import annotations

from pathlib import Path
import re
import unittest

ROOT = Path(__file__).resolve().parents[1]

FORBIDDEN = (
    re.compile(r"Bash\(python3 \*\)"),
    re.compile(r"Bash\(git \*\)"),
    re.compile(r"Bash\(\*\)"),
    re.compile(r"Bash\(sh \*\)"),
    re.compile(r"Bash\(bash \*\)"),
    re.compile(r"Bash\(find \*\)"),
    re.compile(r"Bash\(curl"),
    re.compile(r"Bash\(wget"),
)
SURFACES = (
    ROOT / "lucy" / "SKILL.md",
    ROOT / "lucy" / "runtime" / "trial.py",
    ROOT / "lucy" / "agents" / "lucy-reader.md",
    ROOT / "lucy" / "agents" / "lucy-court.md",
)


class AllowlistLintTests(unittest.TestCase):
    def test_no_unpinned_shell_grants(self) -> None:
        for surface in SURFACES:
            content = surface.read_text(encoding="utf-8")
            for pattern in FORBIDDEN:
                self.assertIsNone(
                    pattern.search(content),
                    f"{surface.name}: forbidden permission grant {pattern.pattern}",
                )

    def test_skill_git_verbs_are_read_only(self) -> None:
        content = (ROOT / "lucy" / "SKILL.md").read_text(encoding="utf-8")
        header = content.split("---", 2)[1]
        granted = re.findall(r"Bash\(git ([a-z-]+)", header)
        self.assertTrue(granted)
        self.assertLessEqual(set(granted), {"status", "diff", "rev-parse", "ls-files"})

    def test_marker_words_match_between_prompt_and_validator(self) -> None:
        from lucy.runtime.planter import ADDED_LINE_MARKERS

        system = (ROOT / "lucy" / "planter" / "SYSTEM.md").read_text(encoding="utf-8")
        for word in ("LUCY", "canary", "planted", "scanner", "vulnerability"):
            self.assertIn(word, system)
            self.assertTrue(
                ADDED_LINE_MARKERS.search(f"x = 1  # {word} here"),
                f"validator misses documented marker word: {word}",
            )


if __name__ == "__main__":
    unittest.main()


class AgentToolSurfaceTests(unittest.TestCase):
    def test_agents_have_no_bare_bash_grant(self) -> None:
        """A bare `Bash` token in agent frontmatter is unpinned shell for the
        two agents whose context is filled with untrusted repository content.
        This covers bare grants that parenthesized-form linting cannot see."""
        for agent in ("lucy-reader.md", "lucy-court.md"):
            frontmatter = (ROOT / "lucy" / "agents" / agent).read_text().split("---")[1]
            tools_line = next(
                line for line in frontmatter.splitlines() if line.startswith("tools:")
            )
            self.assertNotRegex(tools_line, r"\bBash\b", agent)

    def test_reviewer_allowlist_has_no_bare_search_shell(self) -> None:
        """rg/grep shell grants are unconstrained (flags like --pre execute
        commands; absolute paths escape confinement). The pinned Grep tool
        covers the need."""
        trial = (ROOT / "lucy" / "runtime" / "trial.py").read_text()
        self.assertNotIn("Bash(rg", trial)
        self.assertNotIn("Bash(grep", trial)

    def test_reviewer_pins_allowlist_in_both_modes(self) -> None:
        """The pinned tool surface must reach the reviewer in default mode
        too, as a single --allowedTools=... argv element (the flag is
        variadic; a following bare prompt argument gets swallowed as a tool
        name), with the run directory pinned via an Edit(path) rule because
        file permission checks match only Edit rules."""
        import os
        import tempfile
        from unittest.mock import patch

        from lucy.runtime.trial import _reviewer_command

        with tempfile.TemporaryDirectory() as custody, patch.dict(
            os.environ, {"LUCY_CUSTODY_HOME": str(Path(custody) / "custody")}
        ):
            for print_mode in (False, True):
                command = _reviewer_command(
                    "r-test",
                    Path("/tmp/results/runs/r-test"),
                    claude_binary="claude",
                    print_mode=print_mode,
                    max_budget_usd=None,
                )
                self.assertNotIn("--allowedTools", command)
                surface = next(
                    arg for arg in command if arg.startswith("--allowedTools=")
                )
                # Write surface: Edit rules pinned to staging + COMPLETION.md
                # only; no bare Write (Edit rules cover all file-editing tools);
                # Agent scoped to the two lucy agents; no git diff (--no-index
                # read anything, --output wrote anywhere — and the workspace
                # git re-init means diff carries no answer key anyway).
                self.assertIn("Edit(//tmp/results/runs/r-test/staging/**)", surface)
                self.assertIn("Edit(//tmp/results/runs/r-test/COMPLETION.md)", surface)
                self.assertNotIn(",Write,", surface)
                self.assertNotIn("Bash(git diff", surface)
                self.assertNotIn("Agent,", surface)
                self.assertIn("Agent(lucy-reader)", surface)
                self.assertIn("Bash(lucy-merge *)", surface)
                self.assertTrue(command[-1].startswith("/lucy "))
                # Custody deny-wall rides in --settings for the whole session
                # (covers subagents): even a prompt-injected reviewer cannot
                # Read/Glob/Grep the live answer key.
                settings = command[command.index("--settings") + 1]
                self.assertIn('"deny"', settings)
                self.assertIn("custody", settings)


class WrapperShadowingTests(unittest.TestCase):
    def test_wrappers_do_not_import_from_cwd(self) -> None:
        """CWE-427 regression: running a wrapper with CWD inside a scanned
        repo that ships a hostile lucy/ package must import the installed
        package, not the CWD one."""
        import subprocess
        import tempfile

        with tempfile.TemporaryDirectory() as tmp:
            hostile = Path(tmp) / "lucy"
            hostile.mkdir()
            marker = Path(tmp) / "PWNED"
            (hostile / "__init__.py").write_text(
                f"open({str(marker)!r}, 'w').write('x')\n"
            )
            (hostile / "runtime").mkdir()
            (hostile / "runtime" / "__init__.py").write_text("")
            (hostile / "runtime" / "units.py").write_text(
                f"open({str(marker)!r}, 'w').write('x')\n"
            )
            for wrapper in ("lucy-units", "lucy"):
                result = subprocess.run(
                    [str(ROOT / "lucy" / "bin" / wrapper), "--help"],
                    cwd=tmp,
                    capture_output=True,
                    text=True,
                    timeout=60,
                )
                self.assertEqual(result.returncode, 0, result.stderr)
                self.assertFalse(
                    marker.exists(),
                    f"hostile lucy/ package in CWD was imported by {wrapper}",
                )
            self.assertEqual(result.returncode, 0, result.stderr)
