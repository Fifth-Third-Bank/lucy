import json
from pathlib import Path
import tempfile
import unittest

from lucy.runtime.results import LocalResultsSink, REDACTED


class LocalResultsSinkTests(unittest.TestCase):
    def test_rejects_results_inside_target(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            target = Path(directory) / "target"
            target.mkdir()
            with self.assertRaisesRegex(ValueError, "outside"):
                LocalResultsSink.create(target / ".lucy", target)

    def test_redacts_before_writing_text_and_receipts_only_counts(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            sink = LocalResultsSink.create(base / "results", target)
            destination = sink.write_text(
                "runs/r-test/FINDINGS.md",
                "Authorization: Bearer abcdefghijklmnop\nemail=person@example.com\npassword=hunter-two\n",
            )
            written = destination.read_text(encoding="utf-8")
            self.assertNotIn("abcdefghijklmnop", written)
            self.assertNotIn("person@example.com", written)
            self.assertNotIn("hunter-two", written)
            self.assertIn(REDACTED, written)
            receipt = (base / "results" / "receipts" / "redactions.jsonl").read_text()
            self.assertNotIn("hunter-two", receipt)
            record = json.loads(receipt)
            self.assertEqual(3, record["total"])

    def test_json_redaction_preserves_shape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            sink = LocalResultsSink.create(base / "results", target)
            destination = sink.write_json(
                "runs/r-test/findings.json",
                {"finding": {"evidence": "api_key=secret-value", "severity": "HIGH"}},
            )
            document = json.loads(destination.read_text())
            self.assertEqual("HIGH", document["finding"]["severity"])
            self.assertIn(REDACTED, document["finding"]["evidence"])

    def test_rejects_artifact_path_escape(self) -> None:
        with tempfile.TemporaryDirectory() as directory:
            base = Path(directory)
            target = base / "target"
            target.mkdir()
            sink = LocalResultsSink.create(base / "results", target)
            with self.assertRaisesRegex(ValueError, "normalized"):
                sink.write_text("../outside.txt", "no")


if __name__ == "__main__":
    unittest.main()