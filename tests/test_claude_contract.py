from pathlib import Path
import unittest


ROOT = Path(__file__).parents[1]


class ClaudeContractTests(unittest.TestCase):
    def test_readme_preserves_claude_default_and_documents_codex_alternative(self) -> None:
        readme = (ROOT / "README.md").read_text(encoding="utf-8")
        self.assertIn("Claude Code 2.1.245+", readme)
        self.assertIn("/loop", readme)
        self.assertIn("up to 20 concurrent subagents", readme)
        self.assertIn("Scheduled wakeups", readme)
        self.assertIn("Claude remains the default", readme)
        self.assertIn("lucy scan --host codex", readme)
        self.assertIn("does not require Claude Code or an OpenAI API key", readme)

    def test_report_module_implements_legacy_contract_not_a_replacement(self) -> None:
        # Guard intent (unchanged): the withdrawn replacement schema must never
        # return. The runtime report module exists ONLY to assemble the legacy
        # schema_version 2.0 contract and validate it with the pinned gate.
        self.assertFalse((ROOT / "lucy" / "schemas" / "lucy-v1.schema.json").exists())
        report_source = (ROOT / "lucy" / "runtime" / "report.py").read_text(encoding="utf-8")
        self.assertIn('"schema_version": "2.0"', report_source)
        self.assertIn("scan_report_gate.py", report_source)
        self.assertNotIn("lucy-v1.schema", report_source)


if __name__ == "__main__":
    unittest.main()
