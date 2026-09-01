import os
from pathlib import Path
import subprocess
import tempfile
import unittest


ROOT = Path(__file__).parents[1]


class InstallTests(unittest.TestCase):
    def test_installs_skill_agents_and_command_into_temporary_home(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            home = Path(directory)
            config = home / "claude"
            environment = dict(os.environ, HOME=str(home), CLAUDE_CONFIG_DIR=str(config))
            subprocess.run([str(ROOT / "install.sh")], cwd=ROOT, env=environment, check=True)
            self.assertTrue((config / "skills" / "lucy" / "SKILL.md").is_file())
            self.assertTrue((config / "agents" / "lucy-reader.md").is_file())
            self.assertTrue((config / "agents" / "lucy-court.md").is_file())
            self.assertTrue((home / ".local" / "bin" / "lucy").is_file())
            self.assertFalse(
                (home / ".local" / "bin" / "lucy-trial").exists(),
                "retired legacy alias must not be installed",
            )


if __name__ == "__main__":
    unittest.main()