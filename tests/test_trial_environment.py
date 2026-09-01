import os
import inspect
import unittest

from lucy.runtime.planter import planter_environment
from lucy.runtime.trial import direct_claude_environment, launch_trial


class TrialEnvironmentTests(unittest.TestCase):
    def test_removes_cloud_provider_configuration(self) -> None:
        names = {
            "CLAUDE_CODE_USE_BEDROCK": "1",
            "AWS_PROFILE": "example",
            "AWS_REGION": "us-east-1",
            "ANTHROPIC_CUSTOM_HEADERS": "guardrail",
            "ANTHROPIC_MODEL": "us.anthropic.claude-opus-5",
        }
        original = {name: os.environ.get(name) for name in names}
        try:
            os.environ.update(names)
            environment = direct_claude_environment()
        finally:
            for name, value in original.items():
                if value is None:
                    os.environ.pop(name, None)
                else:
                    os.environ[name] = value
        for name in names:
            self.assertNotIn(name, environment)
        self.assertEqual("1", environment["CLAUDE_CODE_SKIP_PROMPT_HISTORY"])
        self.assertEqual("1", environment["CLAUDE_CODE_DISABLE_AUTO_MEMORY"])
        self.assertEqual("1", environment["CLAUDE_CODE_DISABLE_CLAUDE_MDS"])

    def test_planter_is_also_ephemeral_and_direct_claude_only(self) -> None:
        original = os.environ.get("CLAUDE_CODE_USE_BEDROCK")
        try:
            os.environ["CLAUDE_CODE_USE_BEDROCK"] = "1"
            environment = planter_environment()
        finally:
            if original is None:
                os.environ.pop("CLAUDE_CODE_USE_BEDROCK", None)
            else:
                os.environ["CLAUDE_CODE_USE_BEDROCK"] = original
        self.assertNotIn("CLAUDE_CODE_USE_BEDROCK", environment)
        self.assertEqual("1", environment["CLAUDE_CODE_SKIP_PROMPT_HISTORY"])
        self.assertEqual("1", environment["CLAUDE_CODE_DISABLE_AUTO_MEMORY"])
        self.assertEqual("1", environment["CLAUDE_CODE_DISABLE_CLAUDE_MDS"])

    def test_public_launcher_defaults_to_claude_planter(self) -> None:
        self.assertEqual("claude", inspect.signature(launch_trial).parameters["planter"].default)


if __name__ == "__main__":
    unittest.main()