from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class SkillFileTests(unittest.TestCase):
    def test_skill_and_agents_have_required_frontmatter(self) -> None:
        files = [
            ROOT / "lucy" / "SKILL.md",
            ROOT / "lucy" / "agents" / "lucy-reader.md",
            ROOT / "lucy" / "agents" / "lucy-court.md",
        ]
        for path in files:
            content = path.read_text(encoding="utf-8")
            self.assertTrue(content.startswith("---\n"), path)
            frontmatter = content.split("---", 2)[1]
            self.assertIn("name:", frontmatter, path)
            self.assertIn("description:", frontmatter, path)
        skill = files[0].read_text(encoding="utf-8")
        self.assertNotIn("Bedrock model", skill)
        self.assertIn("Never search for an answer key", skill)
        self.assertIn("EXTERNAL-RECALL PROCESS-COMPLETE", skill)


if __name__ == "__main__":
    unittest.main()