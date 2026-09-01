import os
from pathlib import Path
import shutil
import subprocess
import sys
import tempfile
import unittest


ROOT = Path(__file__).parents[1]


class InstallTests(unittest.TestCase):
    @staticmethod
    def _tool_path(home: Path, *, hosts: tuple[str, ...]) -> str:
        """Build a deterministic PATH independent of developer host installs."""
        tools = home / "test-bin"
        tools.mkdir()
        git = shutil.which("git")
        if git is None:
            raise unittest.SkipTest("git is required to exercise install.sh")
        (tools / "git").symlink_to(git)
        for host in hosts:
            executable = tools / host
            executable.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            executable.chmod(0o755)
        if "codex" in hosts:
            # Codex's Linux command sandbox requires the system bwrap helper.
            bwrap = tools / "bwrap"
            bwrap.write_text("#!/bin/sh\nexit 0\n", encoding="utf-8")
            bwrap.chmod(0o755)
        # Keep the active interpreter in its original directory. Relocating a
        # venv Python through a temporary symlink loses venv package discovery
        # on Linux, making installed dependencies falsely appear absent.
        return os.pathsep.join(
            (str(tools), str(Path(sys.executable).parent), "/bin", "/usr/bin")
        )

    def test_installs_with_claude_codex_or_both(self) -> None:
        for hosts in (("claude",), ("codex",), ("claude", "codex")):
            with self.subTest(hosts=hosts), tempfile.TemporaryDirectory() as directory:
                home = Path(directory)
                config = home / "claude-config"
                environment = dict(
                    os.environ,
                    HOME=str(home),
                    CLAUDE_CONFIG_DIR=str(config),
                    PATH=self._tool_path(home, hosts=hosts),
                )
                completed = subprocess.run(
                    [str(ROOT / "install.sh")],
                    cwd=ROOT,
                    env=environment,
                    check=True,
                    capture_output=True,
                    text=True,
                )
                self.assertTrue((config / "skills" / "lucy" / "SKILL.md").is_file())
                self.assertTrue((config / "agents" / "lucy-reader.md").is_file())
                self.assertTrue((config / "agents" / "lucy-court.md").is_file())
                self.assertTrue((home / ".local" / "bin" / "lucy").is_file())
                self.assertFalse(
                    (home / ".local" / "bin" / "lucy-trial").exists(),
                    "retired legacy alias must not be installed",
                )
                self.assertIn("rg (ripgrep) was not found", completed.stderr)

    def test_refuses_install_without_either_review_host(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            environment = dict(
                os.environ,
                HOME=str(home),
                CLAUDE_CONFIG_DIR=str(home / "claude"),
                PATH=self._tool_path(home, hosts=()),
            )
            completed = subprocess.run(
                [str(ROOT / "install.sh")],
                cwd=ROOT,
                env=environment,
                check=False,
                capture_output=True,
                text=True,
            )
            self.assertNotEqual(completed.returncode, 0)
            self.assertIn("either Claude Code or Codex CLI", completed.stderr)
            self.assertFalse((home / ".local" / "bin" / "lucy").exists())


if __name__ == "__main__":
    unittest.main()
